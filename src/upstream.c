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
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

_Static_assert(CFG_MAX_UPSTREAMS <= 32, "upstream exclusion mask is too small");

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
    {
        pool->members[i].srttMs = UPSTREAM_RTT_NONE;
        LatencyReset(&pool->members[i].latency);
    }

#if defined(PROFILE_ENCRYPTED)
    /* A zeroed descriptor is stdin, and a slot that is closed without ever
       having been dialled would take it down with it */
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
        pool->tlsSlots[i].channel.fd = -1;
#endif

    pool->probe.fd        = -1;
    pool->probe.tlsSlot   = UPSTREAM_NONE;
    pool->probeDeadlineMs = nowMs + CFG_UPSTREAM_PROBE_MS;
    pool->bProbeUsable    = WireEncodeName(CFG_UPSTREAM_PROBE_NAME,
                                           &pool->probeName);
}

static bool PoolAdd(UpstreamPool *pool, const char *address, uint16_t port,
                    UpstreamTransport transport, const char *hostname,
                    const char *path)
{
    if(pool->count >= CFG_MAX_UPSTREAMS || address == NULL)
        return false;

    Upstream *member = &pool->members[pool->count];

    if(transport == UpstreamTransport_Dot
       || transport == UpstreamTransport_Doh)
    {
        if(hostname == NULL || hostname[0] == '\0'
           || strlen(hostname) >= sizeof member->hostname)
            return false;

        for(size_t i = 0; hostname[i] != '\0'; i++)
        {
            if((unsigned char)hostname[i] <= 0x20u
               || (unsigned char)hostname[i] >= 0x7Fu)
                return false;
        }

        memcpy(member->hostname, hostname, strlen(hostname) + 1);
    }

    if(transport == UpstreamTransport_Doh)
    {
        if(path == NULL || path[0] != '/'
           || strlen(path) >= sizeof member->path)
            return false;

        for(size_t i = 0; path[i] != '\0'; i++)
        {
            if((unsigned char)path[i] <= 0x20u
               || (unsigned char)path[i] >= 0x7Fu)
                return false;
        }

        memcpy(member->path, path, strlen(path) + 1);
    }

    member->transport = transport;

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

bool UpstreamPoolAdd(UpstreamPool *pool, const char *address, uint16_t port)
{
    return PoolAdd(pool, address, port, UpstreamTransport_Plaintext, NULL, NULL);
}

bool UpstreamPoolAddDot(UpstreamPool *pool, const char *address, uint16_t port,
                        const char *hostname)
{
    return PoolAdd(pool, address, port, UpstreamTransport_Dot, hostname, NULL);
}

bool UpstreamPoolAddDoh(UpstreamPool *pool, const char *address, uint16_t port,
                        const char *hostname, const char *path)
{
    return PoolAdd(pool, address, port, UpstreamTransport_Doh, hostname, path);
}

void UpstreamPoolSetTlsBackend(UpstreamPool *pool, TlsBackend *backend)
{
    if(pool != NULL)
        pool->tls = backend;
}

static bool InService(const Upstream *member, uint32_t nowMs)
{
    return !member->bDown || Elapsed(nowMs, member->downUntilMs);
}

/* The two flags separate the passes. Honouring the hold comes first, then
   ignoring it, then ignoring the refusal as well, so a pool where every member
   is broken still forwards. */
static size_t BestOf(const UpstreamPool *pool, uint32_t nowMs,
                     uint32_t excludedMask, bool bInServiceOnly,
                     bool bUsableOnly)
{
    size_t best = UPSTREAM_NONE;

    for(size_t i = 0; i < pool->count; i++)
    {
        const Upstream *member = &pool->members[i];

        if(i < 32 && (excludedMask & (UINT32_C(1) << i)) != 0)
            continue;
        if(bInServiceOnly && !InService(member, nowMs))
            continue;
        if(bUsableOnly && member->bUnusable)
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
    uint32_t excludedMask = (avoid < 32) ? UINT32_C(1) << avoid : 0;
    return UpstreamPoolSelectExcept(pool, nowMs, excludedMask);
}

size_t UpstreamPoolSelectExcept(const UpstreamPool *pool, uint32_t nowMs,
                                uint32_t excludedMask)
{
    size_t best = BestOf(pool, nowMs, excludedMask, true, true);

    if(best == UPSTREAM_NONE)
        best = BestOf(pool, nowMs, excludedMask, false, true);
    if(best == UPSTREAM_NONE)
        best = BestOf(pool, nowMs, excludedMask, false, false);
    if(best == UPSTREAM_NONE && excludedMask != 0)
        best = BestOf(pool, nowMs, 0, false, false);

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

    /* Status histograms share a microsecond scale */
    LatencyAdd(&member->latency, (rttMs > UINT32_MAX / 1000u)
                                 ? UINT32_MAX : rttMs * 1000u);

    member->consecutiveFailures = 0;
    member->bDown               = false;
    member->bUnusable           = false;
}

/* The peer answered and refused the protocol. Counted as a failure, and kept
   out of selection while anything else can be used, because retrying a server
   that cannot speak HTTP/1.1 spends a client's query on a certainty. */
void UpstreamPoolRefuse(UpstreamPool *pool, size_t index, uint32_t nowMs)
{
    if(index >= pool->count)
        return;

    pool->members[index].bUnusable = true;
    UpstreamPoolFail(pool, index, nowMs);
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

    if(UpstreamBegin(pool, target, query, queryLen, nowMs, &pool->probe)
       != UpstreamStart_Started)
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
    UpstreamRead result = UpstreamComplete(pool, &pool->probe, nowMs, answer,
                                           sizeof answer, &answerLen);
    if(result == UpstreamRead_Again || result == UpstreamRead_Empty)
        return;

    if(result == UpstreamRead_Failed)
    {
        pool->probeFailures++;
        UpstreamPoolFail(pool, pool->probe.index, nowMs);
    }

    UpstreamEnd(&pool->probe, nowMs);
    pool->bProbing = false;
}

void UpstreamPoolProbeSweep(UpstreamPool *pool, uint32_t nowMs)
{
    if(!pool->bProbing || !Elapsed(nowMs, pool->probeExpiryMs))
        return;

    pool->probeFailures++;
    UpstreamPoolFail(pool, pool->probe.index, nowMs);

    UpstreamEnd(&pool->probe, nowMs);
    pool->bProbing = false;
}

static bool PrepareQuery(const uint8_t *query, size_t queryLen,
                         UpstreamExchange *exchange, uint8_t *sent,
                         size_t cap)
{
    Reader     reader;
    WireHeader header;

    if(queryLen < WIRE_HEADER_BYTES || queryLen > cap)
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

    return true;
}

static bool BeginPlaintext(Upstream *member, const uint8_t *sent,
                           size_t queryLen, UpstreamExchange *exchange)
{
    int fd = socket(member->addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return false;

    if(connect(fd, (struct sockaddr *)&member->addr, member->addrLen) != 0
       || send(fd, sent, queryLen, 0) != (ssize_t)queryLen)
    {
        close(fd);
        return false;
    }

    exchange->fd = fd;
    return true;
}

bool UpstreamBeginTcp(UpstreamPool *pool, UpstreamExchange *exchange,
                      const uint8_t *query, size_t queryLen, uint32_t nowMs)
{
    if(pool == NULL || exchange == NULL || query == NULL
       || exchange->transport != UpstreamTransport_Plaintext
       || exchange->bTcpFallback || pool->tcpSlot.bUsed
       || exchange->index >= pool->count
       || queryLen < WIRE_HEADER_BYTES || queryLen > CFG_TX_QUERY_BYTES)
        return false;

    UpstreamTcpSlot *slot = &pool->tcpSlot;
    Upstream *member      = &pool->members[exchange->index];

    /* A fresh draw, so the TCP answer is checked against its own ID and case
       rather than inheriting the ones the truncated datagram already used */
    if(!PrepareQuery(query, queryLen, exchange, slot->request + 2,
                     sizeof slot->request - 2))
        return false;

    int fd = socket(member->addr.ss_family,
                    SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return false;

    int connected = connect(fd, (struct sockaddr *)&member->addr,
                            member->addrLen);
    if(connected != 0 && errno != EINPROGRESS)
    {
        close(fd);
        return false;
    }

    slot->request[0] = (uint8_t)(queryLen >> 8);
    slot->request[1] = (uint8_t)queryLen;
    slot->requestLen = queryLen + 2;
    slot->sent       = 0;
    slot->got        = 0;
    slot->responseLen = 0;
    slot->bUsed      = true;
    slot->state      = (connected == 0) ? UpstreamTcp_Write
                                        : UpstreamTcp_Connect;

    if(exchange->fd >= 0)
        close(exchange->fd);

    exchange->fd           = fd;
    exchange->bTcpFallback = true;
    exchange->sentMs       = nowMs;
    pool->tcpFallbacks++;
    return true;
}

/* Mirrors the DoT machine: fall-through states, so one wake-up can advance
   several, and every partial result asks for another event */
static UpstreamRead TcpProgress(UpstreamExchange *exchange, uint8_t *out,
                                size_t cap, size_t *outLen)
{
    UpstreamTcpSlot *slot = &exchange->pool->tcpSlot;

    if(slot->state == UpstreamTcp_Connect)
    {
        int       error    = 0;
        socklen_t errorLen = sizeof error;
        if(getsockopt(exchange->fd, SOL_SOCKET, SO_ERROR, &error, &errorLen) != 0
           || error != 0)
            return UpstreamRead_Failed;

        slot->state = UpstreamTcp_Write;
    }

    if(slot->state == UpstreamTcp_Write)
    {
        ssize_t wrote = send(exchange->fd, slot->request + slot->sent,
                             slot->requestLen - slot->sent, MSG_DONTWAIT);
        if(wrote < 0)
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                 ? UpstreamRead_Again : UpstreamRead_Failed;

        slot->sent += (size_t)wrote;
        if(slot->sent < slot->requestLen)
            return UpstreamRead_Again;

        slot->state = UpstreamTcp_ReadLength;
        slot->got   = 0;
    }

    if(slot->state == UpstreamTcp_ReadLength)
    {
        ssize_t got = recv(exchange->fd, slot->response + slot->got,
                           2 - slot->got, MSG_DONTWAIT);
        if(got < 0)
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                 ? UpstreamRead_Again : UpstreamRead_Failed;
        if(got == 0)
            return UpstreamRead_Failed;

        slot->got += (size_t)got;
        if(slot->got < 2)
            return UpstreamRead_Again;

        slot->responseLen = ((size_t)slot->response[0] << 8) | slot->response[1];
        if(slot->responseLen < WIRE_HEADER_BYTES
           || slot->responseLen > CFG_TCP_MSG_BYTES
           || slot->responseLen > cap)
            return UpstreamRead_Failed;

        slot->state = UpstreamTcp_ReadBody;
    }

    if(slot->state == UpstreamTcp_ReadBody)
    {
        size_t  have = slot->got - 2;
        ssize_t got  = recv(exchange->fd, slot->response + slot->got,
                            slot->responseLen - have, MSG_DONTWAIT);
        if(got < 0)
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                 ? UpstreamRead_Again : UpstreamRead_Failed;
        if(got == 0)
            return UpstreamRead_Failed;

        slot->got += (size_t)got;
        if(slot->got - 2 < slot->responseLen)
            return UpstreamRead_Again;

        memcpy(out, slot->response + 2, slot->responseLen);
        *outLen = slot->responseLen;
        return UpstreamRead_Answer;
    }

    return UpstreamRead_Failed;
}

#if defined(PROFILE_ENCRYPTED)
_Static_assert(CFG_TLS_SLOTS >= CFG_TLS_FETCH_MIN_FREE_SLOTS,
               "the fetch reservation cannot exceed the slot count");

static void SlotClose(UpstreamTlsSlot *slot)
{
    TlsChannelClose(&slot->channel);
    memset(slot, 0, sizeof *slot);
    slot->channel.fd = -1;
}

/* Three passes, in the order that costs least. An open channel to the same
   upstream is the handshake this exists to skip, so it wins wherever it sits in
   the array. Then a free slot. Then the idle channel nearest its own timeout,
   which is what keeps capacity at CFG_TLS_SLOTS concurrent exchanges however
   many channels are held open. */
static size_t AcquireTlsSlot(UpstreamPool *pool, size_t member)
{
    size_t spare = UPSTREAM_NONE;

#if CFG_TLS_REUSE
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        UpstreamTlsSlot *slot = &pool->tlsSlots[i];

        if(!slot->bUsed && slot->bOpen && slot->member == member)
        {
            slot->bUsed   = true;
            slot->bOpen   = false;
            slot->bReused = true;
            return i;
        }
    }
#endif

    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        UpstreamTlsSlot *slot = &pool->tlsSlots[i];

        if(slot->bUsed)
            continue;

        if(!slot->bOpen)
        {
            slot->bUsed   = true;
            slot->bReused = false;
            return i;
        }

        if(spare == UPSTREAM_NONE
           || (int32_t)(slot->idleUntilMs
                        - pool->tlsSlots[spare].idleUntilMs) < 0)
            spare = i;
    }

    if(spare == UPSTREAM_NONE)
        return UPSTREAM_NONE;

    SlotClose(&pool->tlsSlots[spare]);
    pool->tlsSlots[spare].bUsed = true;
    return spare;
}

bool UpstreamPoolAcquireFetchChannel(UpstreamPool *pool, size_t *slotIndex,
                                     TlsChannel **channel)
{
    if(slotIndex == NULL || channel == NULL)
        return false;

    *slotIndex = UPSTREAM_NONE;
    *channel   = NULL;

    if(pool == NULL || pool->tls == NULL || !pool->tls->bReady)
        return false;

    size_t freeSlots = 0;
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        if(!pool->tlsSlots[i].bUsed)
            freeSlots++;
    }

    if(freeSlots < CFG_TLS_FETCH_MIN_FREE_SLOTS)
        return false;

    size_t acquired = AcquireTlsSlot(pool, UPSTREAM_NONE);
    if(acquired == UPSTREAM_NONE)
        return false;

    UpstreamTlsSlot *slot = &pool->tlsSlots[acquired];
    slot->member = UPSTREAM_NONE;
    *slotIndex   = acquired;
    *channel     = &slot->channel;
    return true;
}

void UpstreamPoolReleaseFetchChannel(UpstreamPool *pool, size_t slotIndex)
{
    if(pool == NULL || slotIndex >= CFG_TLS_SLOTS)
        return;

    UpstreamTlsSlot *slot = &pool->tlsSlots[slotIndex];
    if(slot->bUsed && slot->member == UPSTREAM_NONE)
        SlotClose(slot);
}

/* The server closed one channel to this upstream, so the others it holds open
   are closed for the same reason and would each cost a query to discover. */
static void DropIdleChannels(UpstreamPool *pool, size_t member)
{
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        UpstreamTlsSlot *slot = &pool->tlsSlots[i];

        if(!slot->bUsed && slot->bOpen && slot->member == member)
            SlotClose(slot);
    }
}

static bool BuildTlsRequest(UpstreamTlsSlot *slot, const Upstream *member,
                            const uint8_t *sent, size_t queryLen)
{
    if(member->transport == UpstreamTransport_Dot)
    {
        slot->query[0] = (uint8_t)(queryLen >> 8);
        slot->query[1] = (uint8_t)queryLen;
        memcpy(slot->query + 2, sent, queryLen);
        slot->requestLen = queryLen + 2;
        return true;
    }

    if(member->transport != UpstreamTransport_Doh)
        return false;

    uint16_t port = (member->addr.ss_family == AF_INET)
                  ? ntohs(((const struct sockaddr_in *)&member->addr)->sin_port)
                  : ntohs(((const struct sockaddr_in6 *)&member->addr)->sin6_port);
    char host[CFG_TLS_HOSTNAME_BYTES + 8];
    int hostLen = (port == 443)
                ? snprintf(host, sizeof host, "%s", member->hostname)
                : snprintf(host, sizeof host, "%s:%u", member->hostname,
                           (unsigned int)port);
    if(hostLen <= 0 || (size_t)hostLen >= sizeof host)
        return false;

    char header[CFG_DOH_REQUEST_BYTES];
    int headerLen = snprintf(header, sizeof header,
                             "POST %s HTTP/1.1\r\n"
                             "Host: %s\r\n"
                             "Accept: application/dns-message\r\n"
                             "Content-Type: application/dns-message\r\n"
                             "Content-Length: %zu\r\n"
                             "Connection: %s\r\n\r\n",
                             member->path, host, queryLen,
                             CFG_TLS_REUSE ? "keep-alive" : "close");
    if(headerLen <= 0 || (size_t)headerLen >= CFG_DOH_REQUEST_BYTES
       || (size_t)headerLen + queryLen > sizeof slot->query)
        return false;

    memcpy(slot->query, header, (size_t)headerLen);
    memcpy(slot->query + headerLen, sent, queryLen);
    slot->requestLen = (size_t)headerLen + queryLen;
    return true;
}

static UpstreamStart BeginTls(UpstreamPool *pool, size_t index,
                              Upstream *member, const uint8_t *sent,
                              size_t queryLen, UpstreamExchange *exchange)
{
    if(pool->tls == NULL || !pool->tls->bReady
       || queryLen > CFG_TX_QUERY_BYTES)
        return UpstreamStart_Failed;

    size_t slotIndex = AcquireTlsSlot(pool, index);
    if(slotIndex == UPSTREAM_NONE)
        return UpstreamStart_Busy;

    UpstreamTlsSlot *slot = &pool->tlsSlots[slotIndex];
    bool bReused     = slot->bReused;
    slot->state      = DotState_Connect;
    slot->sent       = 0;
    slot->got        = 0;
    slot->requestLen = 0;
    slot->responseLen = 0;
    slot->member     = index;
    slot->bAnswered  = false;
    slot->bRefused   = false;
    slot->bKeepOpen  = CFG_TLS_REUSE != 0;

    if(!BuildTlsRequest(slot, member, sent, queryLen))
        goto fail;

    /* The handshake this whole feature exists to skip */
    if(bReused)
    {
        slot->state        = DotState_Write;
        slot->channel.want = TlsIo_WantWrite;
        exchange->fd       = slot->channel.fd;
        exchange->tlsSlot  = slotIndex;
        pool->channelReuses++;
        return UpstreamStart_Started;
    }

    slot->channel.fd = -1;

    int fd = socket(member->addr.ss_family,
                    SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if(fd < 0)
        goto fail;

    int connected = connect(fd, (struct sockaddr *)&member->addr,
                            member->addrLen);
    if(connected != 0 && errno != EINPROGRESS)
    {
        close(fd);
        goto fail;
    }

    if(TlsChannelStart(pool->tls, &slot->channel, fd, member->hostname)
       != TlsIo_Ok)
        goto fail;

    if(connected == 0)
    {
        slot->state = DotState_Handshake;
        slot->channel.want = TlsIo_WantWrite;
    }

    exchange->fd      = fd;
    exchange->tlsSlot = slotIndex;
    pool->channelOpens++;
    return UpstreamStart_Started;

fail:
    SlotClose(slot);
    return UpstreamStart_Failed;
}
#endif

UpstreamStart UpstreamBegin(UpstreamPool *pool, size_t index,
                            const uint8_t *query, size_t queryLen,
                            uint32_t nowMs, UpstreamExchange *exchange)
{
    uint8_t sent[CFG_UDP_MSG_BYTES];

    exchange->fd        = -1;
    exchange->index     = index;
    exchange->tlsSlot   = UPSTREAM_NONE;
    exchange->pool      = pool;

    if(index >= pool->count)
        return UpstreamStart_Failed;

    Upstream *member = &pool->members[index];

    if(member->addrLen == 0
       || !PrepareQuery(query, queryLen, exchange, sent, sizeof sent))
        return UpstreamStart_Failed;

    exchange->transport = member->transport;

    UpstreamStart result = UpstreamStart_Failed;
    if(member->transport == UpstreamTransport_Plaintext)
    {
        result = BeginPlaintext(member, sent, queryLen, exchange)
               ? UpstreamStart_Started : UpstreamStart_Failed;
    }
#if defined(PROFILE_ENCRYPTED)
    else if(member->transport == UpstreamTransport_Dot
            || member->transport == UpstreamTransport_Doh)
        result = BeginTls(pool, index, member, sent, queryLen, exchange);
#endif

    if(result != UpstreamStart_Started)
        return result;

    exchange->sentMs = nowMs;
    member->queries++;
    return UpstreamStart_Started;
}

short UpstreamEvents(const UpstreamExchange *exchange)
{
    if(exchange == NULL || exchange->fd < 0)
        return 0;

    if(exchange->transport == UpstreamTransport_Plaintext)
    {
        if(!exchange->bTcpFallback || exchange->pool == NULL)
            return POLLIN;

        const UpstreamTcpSlot *slot = &exchange->pool->tcpSlot;
        return (slot->state == UpstreamTcp_Connect
                || slot->state == UpstreamTcp_Write) ? POLLOUT : POLLIN;
    }

#if defined(PROFILE_ENCRYPTED)
    if(exchange->pool == NULL || exchange->tlsSlot >= CFG_TLS_SLOTS)
        return 0;

    const UpstreamTlsSlot *slot = &exchange->pool->tlsSlots[exchange->tlsSlot];
    if(slot->state == DotState_Connect)
        return POLLOUT;

    return TlsChannelEvents(&slot->channel);
#else
    return 0;
#endif
}

#if defined(PROFILE_ENCRYPTED)
static bool EqualHeader(const uint8_t *data, size_t len, const char *expected)
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

/* A Connection value is a token list and only close matters here, so a
   case-insensitive substring is enough: a false match costs a channel, never an
   answer. */
static bool HeaderHasClose(const uint8_t *data, size_t len)
{
    static const char token[] = "close";
    size_t            tokenLen = sizeof token - 1;

    for(size_t i = 0; i + tokenLen <= len; i++)
    {
        if(EqualHeader(data + i, tokenLen, token))
            return true;
    }

    return false;
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

static bool ParseDohHeaders(UpstreamTlsSlot *slot, size_t headerEnd, size_t cap)
{
    size_t lineEnd = FindCrlf(slot->response, 0, headerEnd);
    if(lineEnd == SIZE_MAX || lineEnd < 12
       || memcmp(slot->response, "HTTP/1.1 200", 12) != 0
       || (lineEnd > 12 && slot->response[12] != ' '))
    {
        /* Three statuses say this request shape is never acceptable, and the
           client sends the same shape every time: 415 rejects the media type,
           501 the method and 505 the HTTP version. Quad9 answers 505 because
           its endpoint is HTTP/2 only. Everything else, 503 included, is the
           server having a bad minute and worth retrying */
        if(lineEnd != SIZE_MAX && lineEnd >= 12
           && memcmp(slot->response, "HTTP/1.1 ", 9) == 0
           && (memcmp(slot->response + 9, "415", 3) == 0
               || memcmp(slot->response + 9, "501", 3) == 0
               || memcmp(slot->response + 9, "505", 3) == 0))
            slot->bRefused = true;

        return false;
    }

    bool   bContentLength = false;
    bool   bContentType   = false;
    size_t contentLength  = 0;
    size_t at = lineEnd + 2;

    while(at + 2 < headerEnd)
    {
        lineEnd = FindCrlf(slot->response, at, headerEnd);
        if(lineEnd == SIZE_MAX || lineEnd == at)
            return false;

        size_t colon = at;
        while(colon < lineEnd && slot->response[colon] != ':')
            colon++;
        if(colon == at || colon == lineEnd)
            return false;

        size_t valueAt = colon + 1;
        while(valueAt < lineEnd
              && (slot->response[valueAt] == ' '
                  || slot->response[valueAt] == '\t'))
            valueAt++;
        size_t valueEnd = lineEnd;
        while(valueEnd > valueAt
              && (slot->response[valueEnd - 1] == ' '
                  || slot->response[valueEnd - 1] == '\t'))
            valueEnd--;

        if(EqualHeader(slot->response + at, colon - at, "content-length"))
        {
            if(bContentLength
               || !ParseDecimal(slot->response + valueAt,
                                valueEnd - valueAt, &contentLength))
                return false;
            bContentLength = true;
        }
        else if(EqualHeader(slot->response + at, colon - at, "content-type"))
        {
            static const char type[] = "application/dns-message";
            size_t valueLen = valueEnd - valueAt;
            if(bContentType || valueLen < sizeof type - 1
               || !EqualHeader(slot->response + valueAt, sizeof type - 1, type)
               || (valueLen > sizeof type - 1
                   && slot->response[valueAt + sizeof type - 1] != ';'))
                return false;
            bContentType = true;
        }
        else if(EqualHeader(slot->response + at, colon - at,
                            "transfer-encoding"))
        {
            return false;
        }
        else if(EqualHeader(slot->response + at, colon - at, "connection"))
        {
            if(HeaderHasClose(slot->response + valueAt, valueEnd - valueAt))
                slot->bKeepOpen = false;
        }

        at = lineEnd + 2;
    }

    if(!bContentLength || !bContentType
       || contentLength < WIRE_HEADER_BYTES
       || contentLength > CFG_TCP_MSG_BYTES || contentLength > cap)
        return false;

    size_t bodyBytes = slot->got - headerEnd;
    if(bodyBytes > contentLength)
        return false;

    memmove(slot->response, slot->response + headerEnd, bodyBytes);
    slot->got         = bodyBytes;
    slot->responseLen = contentLength;
    slot->state       = DohState_ReadBody;
    return true;
}

/* A reused channel that dies before its first response byte is the server having
   closed an idle connection, which is ordinary. Anything else is a fault. */
static UpstreamRead TlsFail(const UpstreamTlsSlot *slot)
{
    return (slot->bReused && slot->got == 0) ? UpstreamRead_Stale
                                             : UpstreamRead_Failed;
}

static UpstreamRead TlsProgress(UpstreamExchange *exchange, uint8_t *out,
                                size_t cap, size_t *outLen)
{
    if(exchange->pool == NULL || exchange->tlsSlot >= CFG_TLS_SLOTS)
        return UpstreamRead_Failed;

    UpstreamTlsSlot *slot = &exchange->pool->tlsSlots[exchange->tlsSlot];

    if(slot->state == DotState_Connect)
    {
        int error = 0;
        socklen_t errorLen = sizeof error;
        if(getsockopt(exchange->fd, SOL_SOCKET, SO_ERROR, &error, &errorLen) != 0
           || error != 0)
            return UpstreamRead_Failed;

        slot->state = DotState_Handshake;
    }

    if(slot->state == DotState_Handshake)
    {
        TlsIo result = TlsChannelHandshake(&slot->channel);
        if(result == TlsIo_WantRead || result == TlsIo_WantWrite)
            return UpstreamRead_Again;
        if(result != TlsIo_Ok)
            return UpstreamRead_Failed;

        slot->state = DotState_Write;
        slot->channel.want = TlsIo_WantWrite;
    }

    if(slot->state == DotState_Write)
    {
        ssize_t wrote = TlsChannelWrite(&slot->channel, slot->query + slot->sent,
                                         slot->requestLen - slot->sent);
        if(wrote == TlsIo_WantRead || wrote == TlsIo_WantWrite)
            return UpstreamRead_Again;
        if(wrote <= 0)
            return TlsFail(slot);

        slot->sent += (size_t)wrote;
        if(slot->sent < slot->requestLen)
        {
            slot->channel.want = TlsIo_WantWrite;
            return UpstreamRead_Again;
        }

        slot->state = (exchange->transport == UpstreamTransport_Dot)
                    ? DotState_ReadLength : DohState_ReadHeaders;
        slot->got   = 0;
        slot->channel.want = TlsIo_WantRead;
    }

    if(slot->state == DotState_ReadLength)
    {
        ssize_t got = TlsChannelRead(&slot->channel, slot->response + slot->got,
                                     2 - slot->got);
        if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
            return UpstreamRead_Again;
        if(got <= 0)
            return TlsFail(slot);

        slot->got += (size_t)got;
        if(slot->got < 2)
            return UpstreamRead_Again;

        slot->responseLen = ((size_t)slot->response[0] << 8) | slot->response[1];
        if(slot->responseLen < WIRE_HEADER_BYTES
           || slot->responseLen > CFG_TCP_MSG_BYTES
           || slot->responseLen > cap)
            return UpstreamRead_Failed;

        slot->state = DotState_ReadBody;
    }

    if(slot->state == DotState_ReadBody)
    {
        size_t have = slot->got - 2;
        ssize_t got = TlsChannelRead(&slot->channel, slot->response + slot->got,
                                     slot->responseLen - have);
        if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
            return UpstreamRead_Again;
        if(got <= 0)
            return UpstreamRead_Failed;

        slot->got += (size_t)got;
        if(slot->got - 2 < slot->responseLen)
            return UpstreamRead_Again;

        memcpy(out, slot->response + 2, slot->responseLen);
        *outLen = slot->responseLen;
        slot->bAnswered = true;
        return UpstreamRead_Answer;
    }

    if(slot->state == DohState_ReadHeaders)
    {
        if(slot->got >= CFG_DOH_HEADER_BYTES)
            return UpstreamRead_Failed;

        ssize_t got = TlsChannelRead(&slot->channel,
                                     slot->response + slot->got,
                                     CFG_DOH_HEADER_BYTES - slot->got);
        if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
            return UpstreamRead_Again;
        if(got <= 0)
            return TlsFail(slot);

        slot->got += (size_t)got;
        size_t headerEnd = SIZE_MAX;
        for(size_t i = 0; i + 3 < slot->got; i++)
        {
            if(memcmp(slot->response + i, "\r\n\r\n", 4) == 0)
            {
                headerEnd = i + 4;
                break;
            }
        }

        if(headerEnd == SIZE_MAX)
            return (slot->got < CFG_DOH_HEADER_BYTES)
                 ? UpstreamRead_Again : UpstreamRead_Failed;
        if(!ParseDohHeaders(slot, headerEnd, cap))
            return UpstreamRead_Failed;
    }

    if(slot->state == DohState_ReadBody)
    {
        if(slot->got < slot->responseLen)
        {
            ssize_t got = TlsChannelRead(&slot->channel,
                                         slot->response + slot->got,
                                         slot->responseLen - slot->got);
            if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
                return UpstreamRead_Again;
            if(got <= 0)
                return UpstreamRead_Failed;
            slot->got += (size_t)got;
        }

        if(slot->got < slot->responseLen)
            return UpstreamRead_Again;

        slot->bAnswered = true;

        /* Content-Length ends the message, so a channel that is staying open
           answers here. Waiting for a close would be waiting forever */
        if(slot->bKeepOpen)
        {
            memcpy(out, slot->response, slot->responseLen);
            *outLen = slot->responseLen;
            return UpstreamRead_Answer;
        }

        slot->state = DohState_ExpectClose;
    }

    if(slot->state == DohState_ExpectClose)
    {
        uint8_t extra;
        ssize_t got = TlsChannelRead(&slot->channel, &extra, sizeof extra);
        if(got == TlsIo_WantRead || got == TlsIo_WantWrite)
            return UpstreamRead_Again;
        if(got != TlsIo_Closed)
            return UpstreamRead_Failed;

        memcpy(out, slot->response, slot->responseLen);
        *outLen = slot->responseLen;
        return UpstreamRead_Answer;
    }

    return UpstreamRead_Failed;
}
#endif

/* A datagram failing a check may be an off-path forgery racing the real answer,
   so plaintext UDP keeps listening. Nothing better follows on a stream */
static UpstreamRead RejectRead(const UpstreamExchange *exchange)
{
    return (exchange->transport == UpstreamTransport_Plaintext
            && !exchange->bTcpFallback)
         ? UpstreamRead_Again : UpstreamRead_Failed;
}

UpstreamRead UpstreamComplete(UpstreamPool *pool, UpstreamExchange *exchange,
                              uint32_t nowMs, uint8_t *out, size_t cap,
                              size_t *outLen)
{
    ssize_t got = -1;

    if(exchange->transport == UpstreamTransport_Plaintext
       && exchange->bTcpFallback)
    {
        UpstreamRead result = TcpProgress(exchange, out, cap, outLen);
        if(result != UpstreamRead_Answer)
            return result;

        got = (ssize_t)*outLen;
    }
    else if(exchange->transport == UpstreamTransport_Plaintext)
    {
        got = recv(exchange->fd, out, cap, MSG_DONTWAIT);

        if(got < 0)
            return UpstreamRead_Empty;

        *outLen = (size_t)got;
    }
#if defined(PROFILE_ENCRYPTED)
    else if(exchange->transport == UpstreamTransport_Dot
            || exchange->transport == UpstreamTransport_Doh)
    {
        UpstreamRead result = TlsProgress(exchange, out, cap, outLen);
        if(result != UpstreamRead_Answer)
        {
            if(result == UpstreamRead_Failed
               && exchange->tlsSlot < CFG_TLS_SLOTS
               && pool->tlsSlots[exchange->tlsSlot].bRefused)
                UpstreamPoolRefuse(pool, exchange->index, nowMs);

            return result;
        }
        got = (ssize_t)*outLen;
    }
#endif
    else
    {
        return UpstreamRead_Failed;
    }

    if(exchange->index >= pool->count)
        return UpstreamRead_Failed;

    Upstream *member = &pool->members[exchange->index];

    if(got < (ssize_t)WIRE_HEADER_BYTES)
        return RejectRead(exchange);

    if(MsgId(out, (size_t)got) != exchange->id)
    {
        member->mismatches++;
        return RejectRead(exchange);
    }

    VerifyResult verdict = VerifyAnswer(&exchange->asked, out, (size_t)got);
    if(verdict != VerifyResult_Ok)
    {
        member->rejected++;
        member->lastReject = verdict;
        return RejectRead(exchange);
    }

    /* Every check has passed, so this is the daemon's own query coming back and
       its arrival time measures that upstream and no other. */
    UpstreamPoolSample(pool, exchange->index, nowMs - exchange->sentMs);

    *outLen = (size_t)got;
    return UpstreamRead_Answer;
}

void UpstreamEnd(UpstreamExchange *exchange, uint32_t nowMs)
{
#if !defined(PROFILE_ENCRYPTED)
    (void)nowMs;
#endif

    if((exchange->transport == UpstreamTransport_Dot
        || exchange->transport == UpstreamTransport_Doh)
       && exchange->pool != NULL)
    {
#if defined(PROFILE_ENCRYPTED)
        if(exchange->tlsSlot < CFG_TLS_SLOTS)
        {
            UpstreamTlsSlot *slot = &exchange->pool->tlsSlots[exchange->tlsSlot];

            /* Only a channel that carried a whole answer is worth keeping.
               Anything else is a channel of unknown state, and reusing one of
               those spends a client's query finding out */
            if(slot->bAnswered && slot->bKeepOpen)
            {
                slot->bUsed       = false;
                slot->bOpen       = true;
                slot->bReused     = false;
                slot->idleUntilMs = nowMs + CFG_TLS_IDLE_MS;
            }
            else
            {
                /* Inherited and answered nothing. Counted here rather than at
                   the read, because a channel dropped by a middlebox says
                   nothing at all and only ever ends on a timeout */
                bool   bDead  = slot->bReused && !slot->bAnswered;
                size_t member = slot->member;

                SlotClose(slot);

                if(bDead)
                {
                    exchange->pool->channelStale++;
                    DropIdleChannels(exchange->pool, member);
                }
            }
        }
#endif
    }
    else if(exchange->fd >= 0)
    {
        close(exchange->fd);
    }

    if(exchange->bTcpFallback && exchange->pool != NULL)
    {
        exchange->pool->tcpSlot.bUsed = false;
        exchange->pool->tcpSlot.state = UpstreamTcp_Idle;
    }

    exchange->fd           = -1;
    exchange->tlsSlot      = UPSTREAM_NONE;
    exchange->pool         = NULL;
    exchange->bTcpFallback = false;
}

bool UpstreamExchangeReusedIdle(const UpstreamExchange *exchange)
{
#if defined(PROFILE_ENCRYPTED)
    if(exchange == NULL || exchange->pool == NULL
       || exchange->tlsSlot >= CFG_TLS_SLOTS)
        return false;

    const UpstreamTlsSlot *slot = &exchange->pool->tlsSlots[exchange->tlsSlot];
    return slot->bReused && slot->got == 0;
#else
    (void)exchange;
    return false;
#endif
}

size_t UpstreamPoolIdleChannels(const UpstreamPool *pool, size_t *slots,
                                int *fds, size_t cap)
{
    size_t count = 0;

#if defined(PROFILE_ENCRYPTED)
    for(size_t i = 0; i < CFG_TLS_SLOTS && count < cap; i++)
    {
        const UpstreamTlsSlot *slot = &pool->tlsSlots[i];

        if(slot->bUsed || !slot->bOpen || slot->channel.fd < 0)
            continue;

        slots[count] = i;
        fds[count]   = slot->channel.fd;
        count++;
    }
#else
    (void)pool;
    (void)slots;
    (void)fds;
    (void)cap;
#endif

    return count;
}

void UpstreamPoolIdleClose(UpstreamPool *pool, size_t slot)
{
#if defined(PROFILE_ENCRYPTED)
    /* The bUsed guard carries the whole safety of reporting readiness by slot.
       An exchange in the same poll pass may already have taken this slot, and
       the descriptor the caller saw belonged to the channel that was here
       before it */
    if(slot < CFG_TLS_SLOTS && !pool->tlsSlots[slot].bUsed)
        SlotClose(&pool->tlsSlots[slot]);
#else
    (void)pool;
    (void)slot;
#endif
}

void UpstreamPoolIdleSweep(UpstreamPool *pool, uint32_t nowMs)
{
#if defined(PROFILE_ENCRYPTED)
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        UpstreamTlsSlot *slot = &pool->tlsSlots[i];

        if(!slot->bUsed && slot->bOpen && Elapsed(nowMs, slot->idleUntilMs))
            SlotClose(slot);
    }
#else
    (void)pool;
    (void)nowMs;
#endif
}

void UpstreamPoolCloseChannels(UpstreamPool *pool)
{
#if defined(PROFILE_ENCRYPTED)
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        if(!pool->tlsSlots[i].bUsed)
            SlotClose(&pool->tlsSlots[i]);
    }
#else
    (void)pool;
#endif
}
