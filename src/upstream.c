#define _GNU_SOURCE

#include "upstream.h"

#include "config.h"
#include "msg.h"
#include "verify.h"
#include "wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static bool Elapsed(uint32_t nowMs, uint32_t deadlineMs)
{
    return (int32_t)(nowMs - deadlineMs) >= 0;
}

static uint16_t RandomId(void)
{
    uint16_t id = 0;

    while(getrandom(&id, sizeof id, 0) != (ssize_t)sizeof id)
    {
        if(errno != EINTR)
            return 0;
    }

    return id;
}

/* 0x20 encoding. DNS matches names without regard to case, so the case of the
   question is free entropy on top of the transaction ID and the source port.
   A resolver echoes the question byte for byte, and VerifyResponse requires
   that, so an attacker has to guess the case of every letter as well. */
static void ApplyCaseRandomisation(uint8_t *msg, size_t len)
{
#if CFG_UPSTREAM_0X20
    Reader     reader;
    WireHeader header;
    uint8_t    bits[CFG_MAX_NAME_BYTES];

    ReaderInit(&reader, msg, len);
    if(!WireParseHeader(&reader, &header) || header.qdCount != 1)
        return;

    size_t start = reader.pos;
    WireName name;
    if(!WireReadName(&reader, &name))
        return;

    size_t nameBytes = reader.pos - start;
    if(nameBytes > sizeof bits)
        return;

    /* One draw for the whole name. A per-byte call would be the same entropy
       at many times the syscall cost. */
    if(getrandom(bits, nameBytes, 0) != (ssize_t)nameBytes)
        return;

    for(size_t i = 0; i < nameBytes; i++)
    {
        uint8_t c = msg[start + i];

        if(c >= 'a' && c <= 'z' && (bits[i] & 1u))
            msg[start + i] = (uint8_t)(c - 32);
        else if(c >= 'A' && c <= 'Z' && (bits[i] & 1u) == 0)
            msg[start + i] = (uint8_t)(c + 32);
    }
#else
    (void)msg;
    (void)len;
#endif
}

void UpstreamPoolInit(UpstreamPool *pool, uint32_t nowMs)
{
    memset(pool, 0, sizeof *pool);

    for(size_t i = 0; i < CFG_MAX_UPSTREAMS; i++)
        pool->members[i].srttMs = UPSTREAM_RTT_NONE;

    pool->probe.fd        = -1;
    pool->probeDeadlineMs = nowMs + CFG_UPSTREAM_PROBE_MS;
    pool->bProbeUsable    = WireEncodeName(CFG_UPSTREAM_PROBE_NAME,
                                           &pool->probeName);
}

bool UpstreamPoolAdd(UpstreamPool *pool, const char *address, uint16_t port)
{
    if(pool->count >= CFG_MAX_UPSTREAMS)
        return false;

    Upstream *member = &pool->members[pool->count];

    struct sockaddr_in *v4 = (struct sockaddr_in *)&member->addr;
    if(inet_pton(AF_INET, address, &v4->sin_addr) == 1)
    {
        v4->sin_family  = AF_INET;
        v4->sin_port    = htons(port);
        member->addrLen = sizeof *v4;
        pool->count++;
        return true;
    }

    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&member->addr;
    if(inet_pton(AF_INET6, address, &v6->sin6_addr) == 1)
    {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        member->addrLen = sizeof *v6;
        pool->count++;
        return true;
    }

    memset(member, 0, sizeof *member);
    member->srttMs = UPSTREAM_RTT_NONE;
    return false;
}

static bool InService(const Upstream *member, uint32_t nowMs)
{
    return !member->bDown || Elapsed(nowMs, member->downUntilMs);
}

/* bInServiceOnly separates the two passes. The first honours the hold, and the
   second ignores it, so a pool that is entirely down still forwards. */
static size_t BestOf(const UpstreamPool *pool, uint32_t nowMs, size_t avoid,
                     bool bInServiceOnly)
{
    size_t best = UPSTREAM_NONE;

    for(size_t i = 0; i < pool->count; i++)
    {
        const Upstream *member = &pool->members[i];

        if(i == avoid)
            continue;
        if(bInServiceOnly && !InService(member, nowMs))
            continue;

        /* Strictly less, so the configured order breaks a tie and an unmeasured
           pool at boot resolves to the first address. */
        if(best == UPSTREAM_NONE || member->srttMs < pool->members[best].srttMs)
            best = i;
    }

    return best;
}

size_t UpstreamPoolSelect(const UpstreamPool *pool, uint32_t nowMs, size_t avoid)
{
    size_t best = BestOf(pool, nowMs, avoid, true);

    if(best == UPSTREAM_NONE)
        best = BestOf(pool, nowMs, avoid, false);
    if(best == UPSTREAM_NONE && avoid != UPSTREAM_NONE)
        best = BestOf(pool, nowMs, UPSTREAM_NONE, false);

    return best;
}

void UpstreamPoolSample(UpstreamPool *pool, size_t index, uint32_t rttMs)
{
    if(index >= pool->count)
        return;

    Upstream *member = &pool->members[index];

    /* RFC 6298 smoothing, alpha 1/8, which shifts rather than divides. */
    if(member->srttMs == UPSTREAM_RTT_NONE)
        member->srttMs = rttMs;
    else
        member->srttMs = member->srttMs - (member->srttMs >> 3) + (rttMs >> 3);

    member->consecutiveFailures = 0;
    member->bDown               = false;
}

void UpstreamPoolFail(UpstreamPool *pool, size_t index, uint32_t nowMs)
{
    if(index >= pool->count)
        return;

    Upstream *member = &pool->members[index];

    member->failures++;
    if(member->consecutiveFailures < UINT16_MAX)
        member->consecutiveFailures++;

    if(member->consecutiveFailures >= CFG_UPSTREAM_DOWN_FAILURES)
    {
        member->bDown       = true;
        member->downUntilMs = nowMs + CFG_UPSTREAM_DOWN_MS;
    }
}

bool UpstreamPoolProbeDue(const UpstreamPool *pool, uint32_t nowMs)
{
    return pool->bProbeUsable && pool->count > 1 && !pool->bProbing
        && Elapsed(nowMs, pool->probeDeadlineMs);
}

bool UpstreamPoolProbeBegin(UpstreamPool *pool, uint32_t nowMs)
{
    uint8_t query[CFG_UDP_MSG_BYTES];
    size_t  queryLen = 0;

    if(!UpstreamPoolProbeDue(pool, nowMs))
        return false;

    /* The interval restarts whether or not the probe goes out, so a pool that
       cannot be probed does not retry on every pass through the poll loop. */
    pool->probeDeadlineMs = nowMs + CFG_UPSTREAM_PROBE_MS;

    /* The selected upstream is timed by the queries it already answers, so a
       probe is spent on one of the others. */
    size_t selected = UpstreamPoolSelect(pool, nowMs, UPSTREAM_NONE);
    size_t target   = UPSTREAM_NONE;

    for(size_t step = 0; step < pool->count; step++)
    {
        size_t candidate = (pool->probeNext + step) % pool->count;

        if(candidate != selected)
        {
            target = candidate;
            break;
        }
    }

    if(target == UPSTREAM_NONE)
        return false;

    pool->probeNext = (target + 1) % pool->count;

    if(!MsgBuildQuery(query, sizeof query, &pool->probeName, WIRE_TYPE_A,
                      RandomId(), &queryLen))
        return false;

    if(!UpstreamBegin(pool, target, query, queryLen, nowMs, &pool->probe))
        return false;

    pool->members[target].probes++;
    pool->probesSent++;
    pool->probeExpiryMs = nowMs + CFG_UPSTREAM_TIMEOUT_MS;
    pool->bProbing      = true;
    return true;
}

void UpstreamPoolProbeReadable(UpstreamPool *pool, uint32_t nowMs)
{
    uint8_t answer[CFG_UDP_MSG_BYTES];
    size_t  answerLen = 0;

    if(!pool->bProbing)
        return;

    /* Only the arrival time is wanted, so the answer goes nowhere. The name is
       a constant, so the probe describes no client. */
    if(UpstreamComplete(pool, &pool->probe, nowMs, answer, sizeof answer,
                        &answerLen) != UpstreamRead_Answer)
        return;

    UpstreamEnd(&pool->probe);
    pool->bProbing = false;
}

void UpstreamPoolProbeSweep(UpstreamPool *pool, uint32_t nowMs)
{
    if(!pool->bProbing || !Elapsed(nowMs, pool->probeExpiryMs))
        return;

    pool->probeFailures++;
    UpstreamPoolFail(pool, pool->probe.index, nowMs);

    UpstreamEnd(&pool->probe);
    pool->bProbing = false;
}

bool UpstreamBegin(UpstreamPool *pool, size_t index, const uint8_t *query,
                   size_t queryLen, uint32_t nowMs, UpstreamExchange *exchange)
{
    uint8_t    sent[CFG_UDP_MSG_BYTES];
    Reader     reader;
    WireHeader header;

    exchange->fd    = -1;
    exchange->index = index;

    if(index >= pool->count)
        return false;

    Upstream *member = &pool->members[index];

    if(queryLen < WIRE_HEADER_BYTES || queryLen > sizeof sent
       || member->addrLen == 0)
        return false;

    memcpy(sent, query, queryLen);
    exchange->id = RandomId();
    MsgSetId(sent, queryLen, exchange->id);
    ApplyCaseRandomisation(sent, queryLen);

    /* Parsed after randomisation, so the stored question carries the case the
       answer has to echo. */
    ReaderInit(&reader, sent, queryLen);
    if(!WireParseHeader(&reader, &header) || header.qdCount != 1
       || !WireParseQuestion(&reader, &exchange->asked))
        return false;

    int fd = socket(member->addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return false;

    if(connect(fd, (struct sockaddr *)&member->addr, member->addrLen) != 0
       || send(fd, sent, queryLen, 0) != (ssize_t)queryLen)
    {
        close(fd);
        return false;
    }

    exchange->fd     = fd;
    exchange->sentMs = nowMs;
    member->queries++;
    return true;
}

UpstreamRead UpstreamComplete(UpstreamPool *pool, const UpstreamExchange *exchange,
                              uint32_t nowMs, uint8_t *out, size_t cap,
                              size_t *outLen)
{
    ssize_t got = recv(exchange->fd, out, cap, MSG_DONTWAIT);

    if(got < 0)
        return UpstreamRead_Empty;

    if(exchange->index >= pool->count)
        return UpstreamRead_Again;

    Upstream *member = &pool->members[exchange->index];

    if(got < (ssize_t)WIRE_HEADER_BYTES)
        return UpstreamRead_Again;

    if(MsgId(out, (size_t)got) != exchange->id)
    {
        member->mismatches++;
        return UpstreamRead_Again;
    }

    VerifyResult verdict = VerifyAnswer(&exchange->asked, out, (size_t)got);
    if(verdict != VerifyResult_Ok)
    {
        member->rejected++;
        member->lastReject = verdict;
        return UpstreamRead_Again;
    }

    /* Every check has passed, so this is the daemon's own query coming back and
       its arrival time measures that upstream and no other. */
    UpstreamPoolSample(pool, exchange->index, nowMs - exchange->sentMs);

    *outLen = (size_t)got;
    return UpstreamRead_Answer;
}

void UpstreamEnd(UpstreamExchange *exchange)
{
    if(exchange->fd >= 0)
        close(exchange->fd);

    exchange->fd = -1;
}
