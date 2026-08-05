#ifndef DNS_BLOCKER_UPSTREAM_H
#define DNS_BLOCKER_UPSTREAM_H

#include "verify.h"
#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct
{
    struct sockaddr_storage addr;
    socklen_t               addrLen;

    uint64_t queries;
    uint64_t timeouts;
    uint64_t mismatches;
    uint64_t rejected;
    uint64_t failures;

    VerifyResult lastReject;
} Upstream;

/* One outstanding query. The socket stays open until the answer arrives or the
   caller gives up, and the kernel keeps the ephemeral source port bound to it,
   so an off-path attacker has to guess the port as well as the ID.

   The question is kept as it was sent, with 0x20 case applied, because that is
   what the answer has to echo. */
typedef struct
{
    int          fd;
    uint16_t     id;
    WireQuestion asked;
} UpstreamExchange;

/* Accepts a literal IPv4 or IPv6 address only. Resolving a name here would
   need the resolver this daemon is trying to be. */
bool UpstreamInit(Upstream *upstream, const char *address, uint16_t port);

/* Opens a socket, applies a fresh transaction ID and 0x20 case, and sends. The
   caller polls exchange->fd for readability and then calls UpstreamComplete. */
bool UpstreamBegin(Upstream *upstream, const uint8_t *query, size_t queryLen,
                   UpstreamExchange *exchange);

typedef enum
{
    UpstreamRead_Answer,
    UpstreamRead_Again,
    UpstreamRead_Empty
} UpstreamRead;

/* Reads one datagram and checks it. UpstreamRead_Again means the datagram was
   not a usable answer and the exchange is still open, which is what lets a
   forged packet lose the race instead of ending it. */
UpstreamRead UpstreamComplete(Upstream *upstream, const UpstreamExchange *exchange,
                              uint8_t *out, size_t cap, size_t *outLen);

void UpstreamEnd(UpstreamExchange *exchange);

#endif
