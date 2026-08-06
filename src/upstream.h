#ifndef DNS_BLOCKER_UPSTREAM_H
#define DNS_BLOCKER_UPSTREAM_H

#include "config.h"
#include "verify.h"
#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* No sample yet. It sorts last, so the configured order decides which upstream
   is used until a measurement exists. */
#define UPSTREAM_RTT_NONE   UINT32_MAX
#define UPSTREAM_NONE       SIZE_MAX

typedef struct
{
    struct sockaddr_storage addr;
    socklen_t               addrLen;

    uint32_t srttMs;
    uint32_t downUntilMs;
    uint16_t consecutiveFailures;
    bool     bDown;

    uint64_t queries;
    uint64_t mismatches;
    uint64_t rejected;
    uint64_t failures;
    uint64_t probes;

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
    size_t       index;
    uint32_t     sentMs;
    WireQuestion asked;
} UpstreamExchange;

/* The configured resolvers and their measured latency. A query goes to one of
   them, so no resolver sees the whole stream. Ranking comes from real answers
   for the selected upstream and from a rotating probe for the rest. */
typedef struct
{
    Upstream members[CFG_MAX_UPSTREAMS];
    size_t   count;

    WireName         probeName;
    UpstreamExchange probe;
    size_t           probeNext;
    uint32_t         probeDeadlineMs;
    uint32_t         probeExpiryMs;
    bool             bProbing;
    bool             bProbeUsable;

    uint64_t probesSent;
    uint64_t probeFailures;
} UpstreamPool;

void UpstreamPoolInit(UpstreamPool *pool, uint32_t nowMs);

/* Accepts a literal IPv4 or IPv6 address only. Resolving a name here would
   need the resolver this daemon is trying to be. */
bool UpstreamPoolAdd(UpstreamPool *pool, const char *address, uint16_t port);

/* Lowest measured round trip among the upstreams still in service, with the
   configured order breaking a tie. Pass the index of an upstream that has just
   failed as avoid, or UPSTREAM_NONE.

   Held-down upstreams are skipped, but an empty result is not returned while
   the pool has a member: a resolver that fails closed takes the network down.
   UPSTREAM_NONE comes back only from an empty pool. */
size_t UpstreamPoolSelect(const UpstreamPool *pool, uint32_t nowMs, size_t avoid);

/* Folds one round trip measurement in and returns the upstream to service. */
void UpstreamPoolSample(UpstreamPool *pool, size_t index, uint32_t rttMs);

/* Counts a failure and holds the upstream down once they run consecutively. */
void UpstreamPoolFail(UpstreamPool *pool, size_t index, uint32_t nowMs);

/* True when the probe interval has passed and there is another upstream worth
   measuring. The caller adds its own condition: the daemon does not probe while
   nothing is querying it. */
bool UpstreamPoolProbeDue(const UpstreamPool *pool, uint32_t nowMs);

/* Sends one probe to one upstream that is not the selected one, rotating the
   target. False when nothing was sent, and the interval restarts either way. */
bool UpstreamPoolProbeBegin(UpstreamPool *pool, uint32_t nowMs);

/* Reads the probe answer. Same checks as a client answer, so a forged datagram
   cannot rank an upstream. */
void UpstreamPoolProbeReadable(UpstreamPool *pool, uint32_t nowMs);

/* Gives up on an unanswered probe, which counts as a failure for its target. */
void UpstreamPoolProbeSweep(UpstreamPool *pool, uint32_t nowMs);

/* Opens a socket, applies a fresh transaction ID and 0x20 case, and sends. The
   caller polls exchange->fd for readability and then calls UpstreamComplete. */
bool UpstreamBegin(UpstreamPool *pool, size_t index, const uint8_t *query,
                   size_t queryLen, uint32_t nowMs, UpstreamExchange *exchange);

typedef enum
{
    UpstreamRead_Answer,
    UpstreamRead_Again,
    UpstreamRead_Empty
} UpstreamRead;

/* Reads one datagram and checks it. UpstreamRead_Again means the datagram was
   not a usable answer and the exchange is still open, which is what lets a
   forged packet lose the race instead of ending it. An accepted answer is also
   the round trip sample for the upstream that sent it. */
UpstreamRead UpstreamComplete(UpstreamPool *pool, const UpstreamExchange *exchange,
                              uint32_t nowMs, uint8_t *out, size_t cap,
                              size_t *outLen);

void UpstreamEnd(UpstreamExchange *exchange);

#endif
