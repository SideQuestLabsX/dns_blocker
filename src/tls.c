#define _GNU_SOURCE

#include "tls.h"

#if defined(PROFILE_ENCRYPTED)

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

static bool G_ALLOCATOR_ACTIVE;

static int RandomBytes(void *context, unsigned char *out, size_t len)
{
    (void)context;

    size_t at = 0;
    while(at < len)
    {
        ssize_t got = getrandom(out + at, len - at, 0);

        if(got > 0)
        {
            at += (size_t)got;
            continue;
        }

        if(got < 0 && errno == EINTR)
            continue;

        return -1;
    }

    return 0;
}

static int SocketSend(void *context, const unsigned char *data, size_t len)
{
    TlsChannel *channel = context;

    if(len > INT_MAX)
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    ssize_t sent = send(channel->fd, data, len, MSG_NOSIGNAL);
    if(sent >= 0)
        return (int)sent;

    if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return MBEDTLS_ERR_SSL_WANT_WRITE;

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int SocketReceive(void *context, unsigned char *out, size_t len)
{
    TlsChannel *channel = context;

    if(len > INT_MAX)
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    ssize_t got = recv(channel->fd, out, len, 0);
    if(got > 0)
        return (int)got;
    if(got == 0)
        return MBEDTLS_ERR_SSL_CONN_EOF;

    if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return MBEDTLS_ERR_SSL_WANT_READ;

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static TlsIo Translate(int result, TlsChannel *channel)
{
    if(result == 0)
    {
        channel->want = TlsIo_WantRead;
        return TlsIo_Ok;
    }

    if(result == MBEDTLS_ERR_SSL_WANT_READ)
    {
        channel->want = TlsIo_WantRead;
        return TlsIo_WantRead;
    }

    if(result == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        channel->want = TlsIo_WantWrite;
        return TlsIo_WantWrite;
    }

    if(result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
       || result == MBEDTLS_ERR_SSL_CONN_EOF)
        return TlsIo_Closed;

    return TlsIo_Error;
}

static bool DerObjectSize(const uint8_t *der, size_t remaining, size_t *out)
{
    if(remaining < 2 || der[0] != 0x30)
        return false;

    size_t header = 2;
    size_t body   = der[1];

    if((der[1] & 0x80u) != 0)
    {
        size_t bytes = der[1] & 0x7Fu;
        if(bytes == 0 || bytes > sizeof(size_t) || remaining - 2 < bytes)
            return false;

        header += bytes;
        body = 0;
        for(size_t i = 0; i < bytes; i++)
        {
            if(body > (SIZE_MAX >> 8))
                return false;
            body = (body << 8) | der[2 + i];
        }
    }

    if(header > remaining || body > remaining - header)
        return false;

    *out = header + body;
    return true;
}

static bool ParseTrust(mbedtls_x509_crt *ca, const uint8_t *der, size_t len)
{
    size_t at = 0;

    while(at < len)
    {
        size_t certLen = 0;
        if(!DerObjectSize(der + at, len - at, &certLen)
           || mbedtls_x509_crt_parse_der_nocopy(ca, der + at, certLen) != 0)
            return false;

        at += certLen;
    }

    return at == len;
}

bool TlsBackendInit(TlsBackend *backend, Arena *arena,
                    const uint8_t *caDer, size_t caLen)
{
    if(backend == NULL || arena == NULL || arena->base == NULL
       || caDer == NULL || caLen == 0 || G_ALLOCATOR_ACTIVE)
        return false;

    memset(backend, 0, sizeof *backend);
    backend->arena = arena;

    mbedtls_memory_buffer_alloc_init(arena->base, arena->size);
    G_ALLOCATOR_ACTIVE = true;
    backend->bAllocatorReady = true;

    mbedtls_x509_crt_init(&backend->ca);
    backend->bCaReady = true;

    if(!ParseTrust(&backend->ca, caDer, caLen))
        goto fail;

    mbedtls_ssl_config_init(&backend->config);
    backend->bConfigReady = true;

    int result = mbedtls_ssl_config_defaults(&backend->config,
                                             MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT);
    if(result != 0)
        goto fail;

    mbedtls_ssl_conf_authmode(&backend->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&backend->config, &backend->ca, NULL);
    mbedtls_ssl_conf_rng(&backend->config, RandomBytes, NULL);
    backend->bReady = true;
    return true;

fail:
    TlsBackendFree(backend);
    return false;
}

void TlsBackendFree(TlsBackend *backend)
{
    if(backend == NULL)
        return;

    if(backend->bConfigReady)
        mbedtls_ssl_config_free(&backend->config);
    if(backend->bCaReady)
        mbedtls_x509_crt_free(&backend->ca);

    if(backend->bAllocatorReady && G_ALLOCATOR_ACTIVE)
    {
        mbedtls_memory_buffer_alloc_free();
        G_ALLOCATOR_ACTIVE = false;
    }

    memset(backend, 0, sizeof *backend);
}

TlsIo TlsChannelStart(TlsBackend *backend, TlsChannel *channel, int fd,
                      const char *hostname)
{
    if(backend == NULL || channel == NULL || !backend->bReady || fd < 0
       || hostname == NULL || hostname[0] == '\0')
        return TlsIo_Error;

    memset(channel, 0, sizeof *channel);
    channel->fd   = fd;
    channel->want = TlsIo_WantRead;

    mbedtls_ssl_init(&channel->ssl);
    channel->bSslReady = true;

    int result = mbedtls_ssl_setup(&channel->ssl, &backend->config);
    if(result != 0)
    {
        TlsChannelClose(channel);
        return TlsIo_Error;
    }

    result = mbedtls_ssl_set_hostname(&channel->ssl, hostname);
    if(result != 0)
    {
        TlsChannelClose(channel);
        return TlsIo_Error;
    }

    mbedtls_ssl_set_bio(&channel->ssl, channel, SocketSend, SocketReceive, NULL);
    channel->bReady = true;
    return TlsIo_Ok;
}

TlsIo TlsChannelHandshake(TlsChannel *channel)
{
    if(channel == NULL || !channel->bReady)
        return TlsIo_Error;

    return Translate(mbedtls_ssl_handshake(&channel->ssl), channel);
}

ssize_t TlsChannelRead(TlsChannel *channel, uint8_t *out, size_t cap)
{
    if(channel == NULL || !channel->bReady || out == NULL || cap == 0)
        return TlsIo_Error;

    int result = mbedtls_ssl_read(&channel->ssl, out, cap);
    if(result > 0)
    {
        channel->want = TlsIo_WantRead;
        return result;
    }
    if(result == 0)
        return TlsIo_Closed;

    return Translate(result, channel);
}

ssize_t TlsChannelWrite(TlsChannel *channel, const uint8_t *data, size_t len)
{
    if(channel == NULL || !channel->bReady || data == NULL || len == 0)
        return TlsIo_Error;

    int result = mbedtls_ssl_write(&channel->ssl, data, len);
    if(result > 0)
        return result;

    return Translate(result, channel);
}

short TlsChannelEvents(const TlsChannel *channel)
{
    if(channel == NULL || !channel->bReady || channel->want == TlsIo_WantRead)
        return POLLIN;

    if(channel->want == TlsIo_WantWrite)
        return POLLOUT;

    return 0;
}

void TlsChannelClose(TlsChannel *channel)
{
    if(channel == NULL)
        return;

    if(channel->bSslReady)
    {
        (void)mbedtls_ssl_close_notify(&channel->ssl);
        mbedtls_ssl_free(&channel->ssl);
    }

    if(channel->fd >= 0)
        close(channel->fd);

    channel->bSslReady = false;
    channel->bReady    = false;
    channel->fd        = -1;
    channel->want      = TlsIo_Error;
}

#else

#include <string.h>

bool TlsBackendInit(TlsBackend *backend, Arena *arena,
                    const uint8_t *caDer, size_t caLen)
{
    (void)caDer;
    (void)caLen;

    if(backend == NULL || arena == NULL)
        return false;

    memset(backend, 0, sizeof *backend);
    backend->arena  = arena;
    backend->bReady = true;
    return true;
}

void TlsBackendFree(TlsBackend *backend)
{
    if(backend != NULL)
        memset(backend, 0, sizeof *backend);
}

TlsIo TlsChannelStart(TlsBackend *backend, TlsChannel *channel, int fd,
                      const char *hostname)
{
    (void)backend;
    (void)channel;
    (void)fd;
    (void)hostname;
    return TlsIo_Error;
}

TlsIo TlsChannelHandshake(TlsChannel *channel)
{
    (void)channel;
    return TlsIo_Error;
}

ssize_t TlsChannelRead(TlsChannel *channel, uint8_t *out, size_t cap)
{
    (void)channel;
    (void)out;
    (void)cap;
    return TlsIo_Error;
}

ssize_t TlsChannelWrite(TlsChannel *channel, const uint8_t *data, size_t len)
{
    (void)channel;
    (void)data;
    (void)len;
    return TlsIo_Error;
}

short TlsChannelEvents(const TlsChannel *channel)
{
    (void)channel;
    return 0;
}

void TlsChannelClose(TlsChannel *channel)
{
    if(channel != NULL)
        memset(channel, 0, sizeof *channel);
}

#endif
