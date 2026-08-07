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

#endif
