#ifndef DNS_BLOCKER_UPSTREAM_H
#define DNS_BLOCKER_UPSTREAM_H

#include "config.h"
#include "latency.h"
#include "tls.h"
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

typedef enum
{
    UpstreamTransport_Plaintext,
    UpstreamTransport_Dot,
    UpstreamTransport_Doh
} UpstreamTransport;

typedef struct
{
    struct sockaddr_storage addr;
    socklen_t               addrLen;
    UpstreamTransport       transport;
    char                    hostname[CFG_TLS_HOSTNAME_BYTES];
    char                    path[CFG_DOH_PATH_BYTES];

    uint32_t srttMs;
    uint32_t downUntilMs;
    uint16_t consecutiveFailures;
    bool     bDown;

    /* Refused the protocol rather than failed to answer, so waiting changes
       nothing. Selection skips it while any other member can still be used, and
       an accepted answer clears it. */
    bool     bUnusable;

    uint64_t queries;
    uint64_t mismatches;
    uint64_t rejected;
    uint64_t failures;
    uint64_t probes;

    /* Unsmoothed round-trip distribution for status reporting */
    LatencyHist latency;

    VerifyResult lastReject;
} Upstream;

/* An upstream that answers a UDP query with TC set is saying the answer does
   not fit a datagram, so the same question goes out again over TCP. Available
   in both profiles, because the conditional PTR router is plaintext whatever
   the profile carries client queries. */
typedef enum
{
    UpstreamTcp_Idle,
    UpstreamTcp_Connect,
    UpstreamTcp_Write,
    UpstreamTcp_ReadLength,
    UpstreamTcp_ReadBody
} UpstreamTcpState;

/* One fallback at a time a pool. A second truncated answer is delivered as it
   arrived, which is what the daemon did before this existed, so capacity here
   costs a large answer its second half and never costs a client its reply. */
typedef struct
{
    UpstreamTcpState state;
    size_t  sent;
    size_t  got;
    size_t  requestLen;
    size_t  responseLen;
    bool    bUsed;
    uint8_t request[2 + CFG_TX_QUERY_BYTES];
    uint8_t response[2 + CFG_TCP_MSG_BYTES];
} UpstreamTcpSlot;

#if defined(PROFILE_ENCRYPTED)
typedef enum
{
    DotState_Connect,
    DotState_Handshake,
    DotState_Write,
    DotState_ReadLength,
    DotState_ReadBody,
    DohState_ReadHeaders,
    DohState_ReadBody,
    DohState_ExpectClose
} DotState;

/* One channel. A slot is free, bound to an exchange, or open and idle against
   the upstream it was dialled for, which is what takes the handshake off every
   query after the first. */
typedef struct
{
    TlsChannel channel;
    DotState   state;
    size_t     sent;
    size_t     got;
    size_t     requestLen;
    size_t     responseLen;
    size_t     member;
    uint32_t   idleUntilMs;
    bool       bUsed;
    /* Open with no exchange on it. Nothing may be in flight, because a reader
       that finds bytes on an idle channel treats them as the server hanging up */
    bool       bOpen;
    /* This exchange started on an already-open channel, so a failure before the
       first response byte is the server having closed it rather than a fault */
    bool       bReused;
    bool       bAnswered;
    /* Cleared by a Connection: close in the response, and by the reuse switch */
    bool       bKeepOpen;
    /* The peer answered, with an HTTP status this client cannot use. A refusal
       is permanent until the server changes, unlike a timeout */
    bool       bRefused;
    uint8_t    query[CFG_DOH_REQUEST_BYTES + CFG_TX_QUERY_BYTES];
    uint8_t    response[CFG_DOH_HEADER_BYTES + CFG_TCP_MSG_BYTES];
} UpstreamTlsSlot;
#endif

struct UpstreamPool;

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
    size_t       tlsSlot;
    uint32_t     sentMs;
    UpstreamTransport transport;
    struct UpstreamPool *pool;
    WireQuestion asked;
    /* Holds the pool's TCP slot after a truncated UDP answer */
    bool         bTcpFallback;
} UpstreamExchange;

/* The configured resolvers and their measured latency. A query goes to one of
   them, so no resolver sees the whole stream. Ranking comes from real answers
   for the selected upstream and from a rotating probe for the rest. */
typedef struct UpstreamPool
{
    Upstream members[CFG_MAX_UPSTREAMS];
    size_t   count;
    TlsBackend *tls;

#if defined(PROFILE_ENCRYPTED)
    UpstreamTlsSlot tlsSlots[CFG_TLS_SLOTS];
#endif

    UpstreamTcpSlot tcpSlot;
    uint64_t        tcpFallbacks;

    WireName         probeName;
    UpstreamExchange probe;
    size_t           probeNext;
    uint32_t         probeDeadlineMs;
    uint32_t         probeExpiryMs;
    bool             bProbing;
    bool             bProbeUsable;

    uint64_t probesSent;
    uint64_t probeFailures;

    uint64_t channelOpens;
    uint64_t channelReuses;
    /* Reused channels the server had already closed. The query goes out
       again on a fresh one, so this counts latency */
    uint64_t channelStale;
} UpstreamPool;

void UpstreamPoolInit(UpstreamPool *pool, uint32_t nowMs);

/* Accepts a literal IPv4 or IPv6 address only. Resolving a name here would
   need the resolver this daemon is trying to be. */
bool UpstreamPoolAdd(UpstreamPool *pool, const char *address, uint16_t port);
bool UpstreamPoolAddDot(UpstreamPool *pool, const char *address, uint16_t port,
                        const char *hostname);
bool UpstreamPoolAddDoh(UpstreamPool *pool, const char *address, uint16_t port,
                        const char *hostname, const char *path);
void UpstreamPoolSetTlsBackend(UpstreamPool *pool, TlsBackend *backend);

#if defined(PROFILE_ENCRYPTED)
/* Reserves one shared slot for a complete fetch run. Two slots must be
   available before acquisition, including idle channels that can be closed */
bool UpstreamPoolAcquireFetchChannel(UpstreamPool *pool, size_t *slotIndex,
                                     TlsChannel **channel);
void UpstreamPoolReleaseFetchChannel(UpstreamPool *pool, size_t slotIndex);
#endif

/* Lowest measured round trip among the upstreams still in service, with the
   configured order breaking a tie. Pass the index of an upstream that has just
   failed as avoid, or UPSTREAM_NONE.

   Held-down upstreams are skipped, but an empty result is not returned while
   the pool has a member: a resolver that fails closed takes the network down.
   UPSTREAM_NONE comes back only from an empty pool. */
size_t UpstreamPoolSelect(const UpstreamPool *pool, uint32_t nowMs, size_t avoid);
size_t UpstreamPoolSelectExcept(const UpstreamPool *pool, uint32_t nowMs,
                                uint32_t excludedMask);

/* Folds one round trip measurement in and returns the upstream to service. */
void UpstreamPoolSample(UpstreamPool *pool, size_t index, uint32_t rttMs);

/* Counts a failure and holds the upstream down once they run consecutively. */
void UpstreamPoolFail(UpstreamPool *pool, size_t index, uint32_t nowMs);

/* A failure the server will repeat: it answered and refused the protocol. Kept
   out of selection while any other member is usable, cleared by an answer. */
void UpstreamPoolRefuse(UpstreamPool *pool, size_t index, uint32_t nowMs);

/* True when the probe interval has passed and there is another upstream worth
   measuring. The caller adds its own condition: the daemon does not probe while
   nothing is querying it. */
bool UpstreamPoolProbeDue(const UpstreamPool *pool, uint32_t nowMs);

/* Sends one probe to one upstream that is not the selected one, rotating the
   target. False when nothing was sent, and the interval restarts either way. */
bool UpstreamPoolProbeBegin(UpstreamPool *pool, uint32_t nowMs);

void UpstreamPoolProbeReadable(UpstreamPool *pool, uint32_t nowMs);

/* Gives up on an unanswered probe, which counts as a failure for its target. */
void UpstreamPoolProbeSweep(UpstreamPool *pool, uint32_t nowMs);

typedef enum
{
    UpstreamStart_Started,
    UpstreamStart_Busy,
    UpstreamStart_Failed
} UpstreamStart;

/* Starts an exchange, caller polls UpstreamEvents before UpstreamComplete */
UpstreamStart UpstreamBegin(UpstreamPool *pool, size_t index,
                            const uint8_t *query, size_t queryLen,
                            uint32_t nowMs, UpstreamExchange *exchange);

short UpstreamEvents(const UpstreamExchange *exchange);

typedef enum
{
    UpstreamRead_Answer,
    UpstreamRead_Again,
    UpstreamRead_Empty,
    /* A reused channel died before it answered anything. No resolver failed, so
       the caller ends the exchange and sends the same query to the same upstream
       on a fresh channel. Only a reused channel returns this, so one exchange
       cannot produce it twice */
    UpstreamRead_Stale,
    UpstreamRead_Failed
} UpstreamRead;

/* Sends the same question to the same upstream over TCP, after a UDP answer
   came back truncated. Draws a fresh transaction ID, source port and 0x20 case,
   so every check that guards the UDP answer guards this one. False leaves the
   exchange untouched, which lets the caller deliver the truncated answer. */
bool UpstreamBeginTcp(UpstreamPool *pool, UpstreamExchange *exchange,
                      const uint8_t *query, size_t queryLen, uint32_t nowMs);

/* UpstreamRead_Again keeps the exchange open for another poll event */
UpstreamRead UpstreamComplete(UpstreamPool *pool, UpstreamExchange *exchange,
                               uint32_t nowMs, uint8_t *out, size_t cap,
                               size_t *outLen);

/* True while an exchange sits on a channel it inherited and nothing has come
   back on it. A timeout there describes the channel rather than the resolver, so
   the caller resends instead of retrying, and it can time out sooner than a
   query that had to handshake. */
bool UpstreamExchangeReusedIdle(const UpstreamExchange *exchange);

/* Keeps the channel open for the next query to the same upstream when the
   exchange answered and neither side asked to close, and closes it otherwise.
   A reused channel that answered nothing takes the rest of that upstream's held
   channels with it: they are dead for the same reason, and each would cost a
   query to discover. nowMs starts the idle timeout. */
void UpstreamEnd(UpstreamExchange *exchange, uint32_t nowMs);

/* Open channels no exchange holds. The caller polls them for readability, which
   on an idle channel means the server hung up, and closes those it reports. The
   pool owns the descriptors: never read, write or close one. */
size_t UpstreamPoolIdleChannels(const UpstreamPool *pool, size_t *slots,
                                int *fds, size_t cap);
void UpstreamPoolIdleClose(UpstreamPool *pool, size_t slot);

/* Closes the channels whose idle timeout has passed, so this side hangs up
   before the server does. */
void UpstreamPoolIdleSweep(UpstreamPool *pool, uint32_t nowMs);

void UpstreamPoolCloseChannels(UpstreamPool *pool);

#endif
