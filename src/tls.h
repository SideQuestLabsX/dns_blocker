#ifndef DNS_BLOCKER_TLS_H
#define DNS_BLOCKER_TLS_H

#include "arena.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(PROFILE_ENCRYPTED)
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#endif

typedef enum
{
    TlsIo_Ok         = 0,
    TlsIo_Error      = -1,
    TlsIo_WantRead   = -2,
    TlsIo_WantWrite  = -3,
    TlsIo_Closed     = -4
} TlsIo;

typedef struct
{
#if defined(PROFILE_ENCRYPTED)
    mbedtls_ssl_config config;
    mbedtls_x509_crt   ca;
    bool                bConfigReady;
    bool                bCaReady;
    bool                bAllocatorReady;
#endif
    Arena *arena;
    bool   bReady;
} TlsBackend;

typedef struct
{
#if defined(PROFILE_ENCRYPTED)
    mbedtls_ssl_context ssl;
    bool                bSslReady;
#endif
    int    fd;
    TlsIo  want;
    bool   bReady;
} TlsChannel;

/* Initializes mbedTLS with the supplied DER trust chain and arena allocator */
bool TlsBackendInit(TlsBackend *backend, Arena *arena,
                    const uint8_t *caDer, size_t caLen);

void TlsBackendFree(TlsBackend *backend);

/* Binds a nonblocking socket to a TLS client session */
TlsIo TlsChannelStart(TlsBackend *backend, TlsChannel *channel, int fd,
                      const char *hostname);

TlsIo TlsChannelHandshake(TlsChannel *channel);
ssize_t TlsChannelRead(TlsChannel *channel, uint8_t *out, size_t cap);
ssize_t TlsChannelWrite(TlsChannel *channel, const uint8_t *data, size_t len);
short TlsChannelEvents(const TlsChannel *channel);
void TlsChannelClose(TlsChannel *channel);

#endif
