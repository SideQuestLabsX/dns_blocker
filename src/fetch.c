#include "fetch.h"

#include <string.h>

#if defined(PROFILE_ENCRYPTED)
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#endif

static bool IsHexDigit(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

static uint8_t HexValue(uint8_t c)
{
    if(c <= '9')
        return (uint8_t)(c - '0');
    return (uint8_t)((c | 0x20) - 'a' + 10);
}

static bool EqualFold(const uint8_t *data, size_t len, const char *expected)
{
    if(strlen(expected) != len)
        return false;

    for(size_t i = 0; i < len; i++)
    {
        unsigned char left  = data[i];
        unsigned char right = (unsigned char)expected[i];
        if(left >= 'A' && left <= 'Z')
            left = (unsigned char)(left + ('a' - 'A'));
        if(right >= 'A' && right <= 'Z')
            right = (unsigned char)(right + ('a' - 'A'));
        if(left != right)
            return false;
    }

    return true;
}

static size_t FindCrlf(const uint8_t *data, size_t from, size_t len)
{
    for(size_t i = from; i + 1 < len; i++)
    {
        if(data[i] == '\r' && data[i + 1] == '\n')
            return i;
    }

    return SIZE_MAX;
}

static bool ParseDecimal(const uint8_t *data, size_t len, size_t *out)
{
    if(len == 0)
        return false;

    size_t value = 0;
    for(size_t i = 0; i < len; i++)
    {
        size_t digit = (size_t)(data[i] - '0');
        if(data[i] < '0' || data[i] > '9'
           || value > (SIZE_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }

    *out = value;
    return true;
}

bool FetchStatusIsRedirect(unsigned status)
{
    return status == 301 || status == 302 || status == 303
        || status == 307 || status == 308;
}

bool FetchParseUrl(const char *url, FetchUrl *out)
{
    static const char scheme[] = "https://";

    if(url == NULL || out == NULL)
        return false;

    memset(out, 0, sizeof *out);
    out->port = 443;

    size_t len = 0;
    while(len < CFG_FETCH_URL_BYTES && url[len] != '\0')
        len++;
    if(len >= CFG_FETCH_URL_BYTES || len <= sizeof scheme - 1)
        return false;
    if(!EqualFold((const uint8_t *)url, sizeof scheme - 1, scheme))
        return false;

    size_t at        = sizeof scheme - 1;
    size_t authority = at;
    while(at < len && url[at] != '/')
    {
        /* Userinfo can point the request at one host while the text reads like
           another, so a redirect carrying it is refused */
        if(url[at] == '@')
            return false;
        at++;
    }

    size_t hostEnd = at;
    size_t colon   = SIZE_MAX;
    for(size_t i = authority; i < hostEnd; i++)
    {
        if(url[i] == ':')
            colon = i;
    }

    if(colon != SIZE_MAX)
    {
        size_t port = 0;
        if(!ParseDecimal((const uint8_t *)url + colon + 1,
                         hostEnd - colon - 1, &port)
           || port == 0 || port > 65535)
            return false;
        out->port = (uint16_t)port;
        hostEnd   = colon;
    }

    size_t hostLen = hostEnd - authority;
    if(hostLen == 0 || hostLen >= sizeof out->host)
        return false;

    for(size_t i = 0; i < hostLen; i++)
    {
        unsigned char c = (unsigned char)url[authority + i];
        if(c <= ' ' || c >= 0x7f)
            return false;
        out->host[i] = (char)c;
    }

    size_t pathLen = len - at;
    if(pathLen == 0)
    {
        out->path[0] = '/';
        return true;
    }

    if(pathLen >= sizeof out->path)
        return false;

    for(size_t i = 0; i < pathLen; i++)
    {
        unsigned char c = (unsigned char)url[at + i];
        if(c <= ' ' || c >= 0x7f)
            return false;
        out->path[i] = (char)c;
    }

    return true;
}

static bool ParseStatusLine(const uint8_t *data, size_t lineEnd,
                            unsigned *status)
{
    static const char prefix[] = "HTTP/1.";

    if(lineEnd < sizeof prefix + 4
       || memcmp(data, prefix, sizeof prefix - 1) != 0
       || (data[7] != '0' && data[7] != '1')
       || data[8] != ' ')
        return false;

    size_t value = 0;
    if(!ParseDecimal(data + 9, 3, &value))
        return false;

    /* A three-digit field cannot overflow unsigned, so the range check is
       about what this client is willing to act on */
    if(value < 100 || value > 599)
        return false;

    if(lineEnd > 12 && data[12] != ' ')
        return false;

    *status = (unsigned)value;
    return true;
}

FetchParse FetchParseHeaders(const uint8_t *data, size_t len,
                             FetchHeaders *out, size_t *headerEnd)
{
    if(data == NULL || out == NULL || headerEnd == NULL)
        return FetchParse_Failed;

    memset(out, 0, sizeof *out);

    size_t lineEnd = FindCrlf(data, 0, len);
    if(lineEnd == SIZE_MAX)
        return len >= CFG_FETCH_HEADER_BYTES
             ? FetchParse_Failed : FetchParse_Incomplete;

    if(!ParseStatusLine(data, lineEnd, &out->status))
        return FetchParse_Failed;

    bool bSeenLength = false;
    size_t at = lineEnd + 2;

    for(;;)
    {
        if(at + 1 < len && data[at] == '\r' && data[at + 1] == '\n')
        {
            *headerEnd = at + 2;
            return FetchParse_Ok;
        }

        lineEnd = FindCrlf(data, at, len);
        if(lineEnd == SIZE_MAX)
            return len >= CFG_FETCH_HEADER_BYTES
                 ? FetchParse_Failed : FetchParse_Incomplete;

        size_t colon = at;
        while(colon < lineEnd && data[colon] != ':')
            colon++;
        if(colon == at || colon == lineEnd)
            return FetchParse_Failed;

        size_t valueAt = colon + 1;
        while(valueAt < lineEnd && (data[valueAt] == ' ' || data[valueAt] == '\t'))
            valueAt++;

        size_t valueEnd = lineEnd;
        while(valueEnd > valueAt
              && (data[valueEnd - 1] == ' ' || data[valueEnd - 1] == '\t'))
            valueEnd--;

        const uint8_t *name    = data + at;
        size_t         nameLen = colon - at;
        const uint8_t *value    = data + valueAt;
        size_t         valueLen = valueEnd - valueAt;

        if(EqualFold(name, nameLen, "content-length"))
        {
            size_t parsed = 0;
            if(!ParseDecimal(value, valueLen, &parsed))
                return FetchParse_Failed;
            /* Two lengths that disagree let a proxy and this client frame the
               same stream differently */
            if(bSeenLength && parsed != out->contentLength)
                return FetchParse_Failed;
            out->contentLength     = parsed;
            out->bHasContentLength = true;
            bSeenLength            = true;
        }
        else if(EqualFold(name, nameLen, "transfer-encoding"))
        {
            /* Every hop of the real release carries Content-Length. Refusing
               chunked keeps a decoder out of this path entirely */
            if(!EqualFold(value, valueLen, "identity"))
                return FetchParse_Failed;
        }
        else if(EqualFold(name, nameLen, "location"))
        {
            if(valueLen == 0 || valueLen >= sizeof out->location)
                return FetchParse_Failed;
            memcpy(out->location, value, valueLen);
            out->location[valueLen] = '\0';
        }

        at = lineEnd + 2;
    }
}

bool FetchFindDigest(const uint8_t *data, size_t len, const char *assetName,
                     uint8_t digest[FETCH_DIGEST_BYTES])
{
    if(data == NULL || assetName == NULL || digest == NULL)
        return false;

    size_t nameLen = strlen(assetName);
    if(nameLen == 0)
        return false;

    size_t at = 0;
    while(at < len)
    {
        size_t lineEnd = at;
        while(lineEnd < len && data[lineEnd] != '\n')
            lineEnd++;

        size_t trimmed = lineEnd;
        while(trimmed > at
              && (data[trimmed - 1] == '\r' || data[trimmed - 1] == ' '))
            trimmed--;

        /* `sha256sum` writes two spaces, or a space and a mode marker */
        size_t want = FETCH_DIGEST_BYTES * 2 + 2 + nameLen;
        if(trimmed - at == want
           && data[at + FETCH_DIGEST_BYTES * 2] == ' '
           && memcmp(data + at + FETCH_DIGEST_BYTES * 2 + 2, assetName,
                     nameLen) == 0)
        {
            size_t i = 0;
            for(; i < FETCH_DIGEST_BYTES * 2; i++)
            {
                if(!IsHexDigit(data[at + i]))
                    break;
            }

            if(i == FETCH_DIGEST_BYTES * 2)
            {
                for(size_t b = 0; b < FETCH_DIGEST_BYTES; b++)
                {
                    digest[b] = (uint8_t)((HexValue(data[at + b * 2]) << 4)
                                        | HexValue(data[at + b * 2 + 1]));
                }
                return true;
            }
        }

        at = (lineEnd < len) ? lineEnd + 1 : len;
    }

    return false;
}

#if defined(PROFILE_ENCRYPTED)

static bool WriteAll(int fd, const uint8_t *data, size_t len)
{
    size_t at = 0;
    while(at < len)
    {
        ssize_t wrote = write(fd, data + at, len - at);
        if(wrote < 0)
        {
            if(errno == EINTR)
                continue;
            return false;
        }
        at += (size_t)wrote;
    }

    return true;
}

static bool BuildRequest(FetchJob *job)
{
    char host[CFG_FETCH_HOST_BYTES + 8];
    int  hostLen = (job->url.port == 443)
                 ? snprintf(host, sizeof host, "%s", job->url.host)
                 : snprintf(host, sizeof host, "%s:%u", job->url.host,
                            (unsigned int)job->url.port);
    if(hostLen <= 0 || (size_t)hostLen >= sizeof host)
        return false;

    int len = snprintf((char *)job->request, sizeof job->request,
                       "GET %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: dns_blocker\r\n"
                       "Accept: */*\r\n"
                       "Connection: close\r\n\r\n",
                       job->url.path, host);
    if(len <= 0 || (size_t)len >= sizeof job->request)
        return false;

    job->requestLen = (size_t)len;
    return true;
}

static void ResetChannel(FetchJob *job)
{
    TlsChannelClose(&job->channel);
    if(job->fd >= 0)
        close(job->fd);
    job->fd = -1;
}

static bool Connect(FetchJob *job, TlsBackend *backend,
                    const struct sockaddr_storage *addr, socklen_t addrLen)
{
    if(!BuildRequest(job))
        return false;

    job->state        = FetchState_Connect;
    job->sent         = 0;
    job->held         = 0;
    job->bodyGot      = 0;
    job->bodyExpected = 0;
    job->memoryLen    = 0;
    job->status       = 0;
    job->channel.fd   = -1;

    int fd = socket(addr->ss_family,
                    SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return false;

    int connected = connect(fd, (const struct sockaddr *)addr, addrLen);
    if(connected != 0 && errno != EINPROGRESS)
    {
        close(fd);
        return false;
    }

    if(TlsChannelStart(backend, &job->channel, fd, job->url.host) != TlsIo_Ok)
    {
        close(fd);
        job->channel.fd = -1;
        return false;
    }

    job->fd = fd;
    if(connected == 0)
    {
        job->state        = FetchState_Handshake;
        job->channel.want = TlsIo_WantWrite;
    }

    return true;
}

bool FetchBegin(FetchJob *job, TlsBackend *backend, const char *url,
                const struct sockaddr_storage *addr, socklen_t addrLen,
                int sink, size_t maxBody)
{
    if(job == NULL || backend == NULL || !backend->bReady || addr == NULL
       || maxBody == 0)
        return false;

    memset(job, 0, sizeof *job);
    job->fd      = -1;
    job->sink    = sink;
    job->maxBody = maxBody;
    job->state   = FetchState_Idle;

    if(!FetchParseUrl(url, &job->url))
        return false;

    return Connect(job, backend, addr, addrLen);
}

bool FetchBeginToMemory(FetchJob *job, TlsBackend *backend, const char *url,
                        const struct sockaddr_storage *addr, socklen_t addrLen,
                        uint8_t *out, size_t cap)
{
    if(out == NULL || cap == 0)
        return false;

    if(!FetchBegin(job, backend, url, addr, addrLen, -1, cap))
        return false;

    job->memory    = out;
    job->memoryLen = 0;
    return true;
}

size_t FetchBodyLength(const FetchJob *job)
{
    return (job != NULL) ? job->memoryLen : 0;
}

bool FetchFollow(FetchJob *job, TlsBackend *backend,
                 const struct sockaddr_storage *addr, socklen_t addrLen)
{
    if(job == NULL || backend == NULL || addr == NULL
       || job->redirects >= CFG_FETCH_MAX_REDIRECTS)
        return false;

    job->redirects++;
    ResetChannel(job);
    return Connect(job, backend, addr, addrLen);
}

const char *FetchRedirectHost(const FetchJob *job)
{
    return (job != NULL) ? job->url.host : NULL;
}

short FetchEvents(const FetchJob *job)
{
    if(job == NULL || job->fd < 0)
        return 0;

    if(job->state == FetchState_Connect)
        return POLLOUT;

    return TlsChannelEvents(&job->channel);
}

static FetchStep BodyBytes(FetchJob *job, const uint8_t *data, size_t len)
{
    if(len == 0)
        return FetchStep_Again;

    /* More bytes than the length promised. The extra belongs to nothing this
       client asked for */
    if(len > job->bodyExpected - job->bodyGot)
        return FetchStep_Failed;

    if(job->sink >= 0 && !WriteAll(job->sink, data, len))
        return FetchStep_Failed;

    if(job->memory != NULL)
    {
        if(len > job->maxBody - job->memoryLen)
            return FetchStep_Failed;
        memcpy(job->memory + job->memoryLen, data, len);
        job->memoryLen += len;
    }

    mbedtls_sha256_update(&job->sha, data, len);
    job->bodyGot += len;

    return (job->bodyGot == job->bodyExpected)
         ? FetchStep_Done : FetchStep_Again;
}

static FetchStep OnHeaders(FetchJob *job, const FetchHeaders *headers,
                           size_t headerEnd)
{
    job->status = headers->status;

    if(FetchStatusIsRedirect(headers->status))
    {
        /* Overwrites the target, so the caller resolves the new host and the
           next request builds from it */
        if(headers->location[0] == '\0'
           || !FetchParseUrl(headers->location, &job->url))
            return FetchStep_Failed;

        return FetchStep_Redirect;
    }

    /* Every hop of the release carries a length, so a 200 without one is a
       response this client cannot frame */
    if(headers->status != 200 || !headers->bHasContentLength
       || headers->contentLength > job->maxBody)
        return FetchStep_Failed;

    job->bodyExpected = headers->contentLength;
    job->state        = FetchState_ReadBody;

    mbedtls_sha256_init(&job->sha);
    if(mbedtls_sha256_starts(&job->sha, 0) != 0)
        return FetchStep_Failed;
    job->bShaReady = true;

    if(job->bodyExpected == 0)
    {
        job->state = FetchState_Done;
        return FetchStep_Done;
    }

    FetchStep step = BodyBytes(job, job->buffer + headerEnd,
                               job->held - headerEnd);
    if(step == FetchStep_Done)
        job->state = FetchState_Done;

    return step;
}

FetchStep FetchProgress(FetchJob *job)
{
    if(job == NULL || job->fd < 0)
        return FetchStep_Failed;

    if(job->state == FetchState_Connect)
    {
        int       error    = 0;
        socklen_t errorLen = sizeof error;
        if(getsockopt(job->fd, SOL_SOCKET, SO_ERROR, &error, &errorLen) != 0
           || error != 0)
            return FetchStep_Failed;

        job->state = FetchState_Handshake;
    }

    if(job->state == FetchState_Handshake)
    {
        TlsIo result = TlsChannelHandshake(&job->channel);
        if(result == TlsIo_WantRead || result == TlsIo_WantWrite)
            return FetchStep_Again;
        if(result != TlsIo_Ok)
            return FetchStep_Failed;

        job->state        = FetchState_Write;
        job->channel.want = TlsIo_WantWrite;
    }

    if(job->state == FetchState_Write)
    {
        ssize_t wrote = TlsChannelWrite(&job->channel,
                                        job->request + job->sent,
                                        job->requestLen - job->sent);
        if(wrote == TlsIo_WantRead || wrote == TlsIo_WantWrite)
            return FetchStep_Again;
        if(wrote <= 0)
            return FetchStep_Failed;

        job->sent += (size_t)wrote;
        if(job->sent < job->requestLen)
        {
            job->channel.want = TlsIo_WantWrite;
            return FetchStep_Again;
        }

        job->state        = FetchState_ReadHeaders;
        job->held         = 0;
        job->channel.want = TlsIo_WantRead;
    }

    if(job->state == FetchState_ReadHeaders)
    {
        if(job->held >= sizeof job->buffer)
            return FetchStep_Failed;

        ssize_t got = TlsChannelRead(&job->channel, job->buffer + job->held,
                                     sizeof job->buffer - job->held);
        if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
            return FetchStep_Again;
        if(got <= 0)
            return FetchStep_Failed;

        job->held += (size_t)got;

        FetchHeaders headers;
        size_t       headerEnd = 0;
        FetchParse   parsed    = FetchParseHeaders(job->buffer, job->held,
                                                   &headers, &headerEnd);
        if(parsed == FetchParse_Failed)
            return FetchStep_Failed;
        if(parsed == FetchParse_Incomplete)
            return FetchStep_Again;

        return OnHeaders(job, &headers, headerEnd);
    }

    if(job->state == FetchState_ReadBody)
    {
        ssize_t got = TlsChannelRead(&job->channel, job->buffer,
                                     sizeof job->buffer);
        if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
            return FetchStep_Again;

        /* A close before the declared length is a truncated file, and a
           truncated trie must never reach the rename */
        if(got <= 0)
            return FetchStep_Failed;

        FetchStep step = BodyBytes(job, job->buffer, (size_t)got);
        if(step == FetchStep_Done)
            job->state = FetchState_Done;

        return step;
    }

    return (job->state == FetchState_Done)
         ? FetchStep_Done : FetchStep_Failed;
}

bool FetchDigest(FetchJob *job, uint8_t out[FETCH_DIGEST_BYTES])
{
    if(job == NULL || out == NULL || !job->bShaReady
       || job->state != FetchState_Done)
        return false;

    return mbedtls_sha256_finish(&job->sha, out) == 0;
}

void FetchEnd(FetchJob *job)
{
    if(job == NULL)
        return;

    ResetChannel(job);

    if(job->bShaReady)
    {
        mbedtls_sha256_free(&job->sha);
        job->bShaReady = false;
    }

    job->state = FetchState_Idle;
}

#endif
