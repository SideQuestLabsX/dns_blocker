#ifndef DNS_BLOCKER_FETCH_H
#define DNS_BLOCKER_FETCH_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A bounded HTTPS GET for the blocklist release. The body is never held whole:
   a 6.5MB trie streams past this code to a staging file. Everything here
   parses bytes that arrived from the network, so the parsing entry points take
   a buffer and a length and are testable without a socket. */

#define FETCH_DIGEST_BYTES 32

typedef struct
{
    char     host[CFG_FETCH_HOST_BYTES];
    char     path[CFG_FETCH_PATH_BYTES];
    uint16_t port;
} FetchUrl;

typedef struct
{
    unsigned status;
    size_t   contentLength;
    bool     bHasContentLength;
    char     location[CFG_FETCH_URL_BYTES];
} FetchHeaders;

typedef enum
{
    FetchParse_Ok,
    FetchParse_Incomplete,
    FetchParse_Failed
} FetchParse;

/* Absolute `https://` only. A redirect that leaves TLS, carries userinfo or
   names a port this daemon has no reason to reach is refused rather than
   followed. */
bool FetchParseUrl(const char *url, FetchUrl *out);

/* Returns Incomplete until the blank line arrives. `headerEnd` is set to the
   first body byte, so the caller knows what part of its buffer is already
   payload. */
FetchParse FetchParseHeaders(const uint8_t *data, size_t len,
                             FetchHeaders *out, size_t *headerEnd);

bool FetchStatusIsRedirect(unsigned status);

/* Picks one line out of a `sha256sum` listing. The published file names every
   asset in the release, so the caller has to say which one it came for. */
bool FetchFindDigest(const uint8_t *data, size_t len, const char *assetName,
                     uint8_t digest[FETCH_DIGEST_BYTES]);

#if defined(PROFILE_ENCRYPTED)

#include "tls.h"

#include <mbedtls/sha256.h>
#include <sys/socket.h>

typedef enum
{
    FetchState_Idle,
    FetchState_Connect,
    FetchState_Handshake,
    FetchState_Write,
    FetchState_ReadHeaders,
    FetchState_ReadBody,
    FetchState_Done
} FetchState;

typedef enum
{
    FetchStep_Again,
    FetchStep_Done,
    FetchStep_Redirect,
    FetchStep_Failed
} FetchStep;

/* Why a transfer stopped. The daemon uses this for retry policy and logs */
typedef enum
{
    FetchFail_None,
    FetchFail_Url,
    FetchFail_Request,
    FetchFail_Socket,
    FetchFail_Tls,
    FetchFail_Write,
    FetchFail_Read,
    FetchFail_Header,
    FetchFail_Status,
    FetchFail_Body,
    FetchFail_Redirects
} FetchFail;

/* One transfer. The caller owns the storage and the staging descriptor, so
   nothing here allocates. The body is written out as it arrives and hashed on
   the way past, which is what keeps a 6.5MB trie off the heap and out of the
   arena. */
typedef struct
{
    TlsChannel channel;
    FetchState state;
    FetchUrl   url;

    int      fd;
    int      sink;
    uint8_t *memory;
    size_t   memoryLen;
    size_t   maxBody;
    size_t   sent;
    size_t   requestLen;
    size_t   held;
    size_t   bodyGot;
    size_t   bodyExpected;
    unsigned  redirects;
    unsigned  status;
    FetchFail fail;

    mbedtls_sha256_context sha;
    bool bShaReady;

    uint8_t request[CFG_FETCH_REQUEST_BYTES];
    uint8_t buffer[CFG_FETCH_HEADER_BYTES];
    char    location[CFG_FETCH_URL_BYTES];
} FetchJob;

/* `addr` is the resolved peer. Nothing in this file resolves a name, so the
   caller decides how `url`'s host became an address. `sink` receives the body
   and stays the caller's to close. */
bool FetchBegin(FetchJob *job, TlsBackend *backend, const char *url,
                const struct sockaddr_storage *addr, socklen_t addrLen,
                int sink, size_t maxBody);

/* Same transfer, with the body kept in `out` instead of written to a
   descriptor. For the digest listing, which is a few hundred bytes. `maxBody`
   becomes `cap`, so a larger response is refused at the header rather than
   part-way through. */
bool FetchBeginToMemory(FetchJob *job, TlsBackend *backend, const char *url,
                        const struct sockaddr_storage *addr, socklen_t addrLen,
                        uint8_t *out, size_t cap);

/* Bytes written into the memory sink. Valid after FetchStep_Done. */
size_t FetchBodyLength(const FetchJob *job);

/* Follows the redirect the last step reported, against a freshly resolved
   address for `job->url.host`. Refuses once the hop count is spent. */
bool FetchFollow(FetchJob *job, TlsBackend *backend,
                 const struct sockaddr_storage *addr, socklen_t addrLen);

bool FetchRetry(FetchJob *job, TlsBackend *backend,
                const struct sockaddr_storage *addr, socklen_t addrLen);

short FetchEvents(const FetchJob *job);
FetchStep FetchProgress(FetchJob *job);

/* A short reason for the last failure, for a log line. Never NULL. */
const char *FetchFailText(const FetchJob *job);

/* Valid after FetchStep_Redirect. Parsed already, so the caller resolves
   `job->url.host` rather than re-reading the raw header. */
const char *FetchRedirectHost(const FetchJob *job);

/* Valid after FetchStep_Done. Covers the final body only, so redirect hops
   never enter the hash. */
bool FetchDigest(FetchJob *job, uint8_t out[FETCH_DIGEST_BYTES]);

void FetchEnd(FetchJob *job);

#endif

#endif
