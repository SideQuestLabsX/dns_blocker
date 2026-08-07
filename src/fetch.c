#include "fetch.h"

#include <string.h>

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
