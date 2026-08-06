#define _GNU_SOURCE

#include "server.h"

#include "msg.h"
#include "wire.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint32_t ServerNowSeconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint32_t)now.tv_sec;
}

uint32_t ServerNowMilliseconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint32_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

static bool Elapsed(uint32_t nowMs, uint32_t deadlineMs)
{
    return (int32_t)(nowMs - deadlineMs) >= 0;
}

static bool SetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int OpenSocket(int family, int type, uint16_t port)
{
    int fd = socket(family, type | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return -1;

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    /* Without V6ONLY a v6 wildcard bind also claims v4 on Linux, and the
       second bind then fails on an address that is already taken. */
    if(family == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);

    struct sockaddr_storage address;
    socklen_t               addressLen;

    memset(&address, 0, sizeof address);

    if(family == AF_INET)
    {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family      = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_ANY);
        v4->sin_port        = htons(port);
        addressLen          = sizeof *v4;
    }
    else
    {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr   = in6addr_any;
        v6->sin6_port   = htons(port);
        addressLen      = sizeof *v6;
    }

    if(bind(fd, (struct sockaddr *)&address, addressLen) != 0
       || !SetNonBlocking(fd))
    {
        close(fd);
        return -1;
    }

    if(type == SOCK_STREAM && listen(fd, CFG_TCP_SLOTS) != 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

bool ServerOpen(Server *server, Cache *cache, UpstreamPool *upstreams,
                const Blocklist *blocklist, const HostMap *hosts,
                UpstreamPool *ptrRouter, const uint8_t *ptrPrefix,
                uint8_t ptrPrefixBits,
                Arena *connArena, Arena *txArena, uint16_t port)
{
    memset(server, 0, sizeof *server);

    server->cache          = cache;
    server->upstreams      = upstreams;
    server->ptrRouter      = ptrRouter;
    server->blocklist      = blocklist;
    server->hosts          = hosts;
    server->nextGeneration = 1;
    server->fdUdp4         = -1;
    server->fdUdp6         = -1;
    server->fdTcp4         = -1;
    server->fdTcp6         = -1;

    if(ptrRouter != NULL && ptrRouter->count != 0)
    {
        if(ptrPrefix == NULL || ptrPrefixBits > 32)
            return false;

        memcpy(server->ptrPrefix, ptrPrefix, sizeof server->ptrPrefix);
        server->ptrPrefixBits = ptrPrefixBits;
        server->bPtrRoute     = true;
    }

    server->conns = ARENA_ARRAY(connArena, Connection, CFG_TCP_SLOTS);
    if(server->conns == NULL)
        return false;

    server->transactions = ARENA_ARRAY(txArena, Transaction, CFG_TX_SLOTS);
    if(server->transactions == NULL)
        return false;

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
        server->conns[i].fd = -1;

    for(size_t i = 0; i < CFG_TX_SLOTS; i++)
        server->transactions[i].exchange.fd = -1;

    server->fdUdp4 = OpenSocket(AF_INET, SOCK_DGRAM, port);
    server->fdTcp4 = OpenSocket(AF_INET, SOCK_STREAM, port);

    if(server->fdUdp4 < 0 || server->fdTcp4 < 0)
    {
        ServerClose(server);
        return false;
    }

    server->fdUdp6 = OpenSocket(AF_INET6, SOCK_DGRAM, port);
    server->fdTcp6 = OpenSocket(AF_INET6, SOCK_STREAM, port);

    if(server->fdUdp6 < 0 || server->fdTcp6 < 0)
        fputs("dns_blocker: no IPv6 listener, clients using an IPv6 resolver "
              "will bypass filtering\n", stderr);

    return true;
}

static void CloseConnection(Connection *conn)
{
    if(conn->fd >= 0)
        close(conn->fd);

    conn->fd        = -1;
    conn->want      = 0;
    conn->got       = 0;
    conn->sent      = 0;
    conn->replyLen  = 0;
    conn->bWriting  = false;
    conn->bAwaiting = false;
}

static void TxRelease(Transaction *tx)
{
    UpstreamEnd(&tx->exchange);
    tx->pool   = NULL;
    tx->bActive = false;
}

void ServerClose(Server *server)
{
    int *fds[] = { &server->fdUdp4, &server->fdUdp6,
                   &server->fdTcp4, &server->fdTcp6 };

    for(size_t i = 0; i < sizeof fds / sizeof fds[0]; i++)
    {
        if(*fds[i] >= 0)
            close(*fds[i]);

        *fds[i] = -1;
    }

    if(server->transactions != NULL)
    {
        for(size_t i = 0; i < CFG_TX_SLOTS; i++)
            TxRelease(&server->transactions[i]);
    }

    if(server->upstreams != NULL && server->upstreams->bProbing)
    {
        UpstreamEnd(&server->upstreams->probe);
        server->upstreams->bProbing = false;
    }

    if(server->conns == NULL)
        return;

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
        CloseConnection(&server->conns[i]);
}

/* Sends a finished answer to whoever asked for it. */
static void Deliver(Server *server, const ClientRef *client,
                    const uint8_t *reply, size_t replyLen)
{
    if(!client->bOverTcp)
    {
        sendto(client->listenFd, reply, replyLen, 0,
               (const struct sockaddr *)&client->from, client->fromLen);
        return;
    }

    Connection *conn = &server->conns[client->connIndex];

    /* The client may have gone away, and the slot may already belong to
       another connection. */
    if(conn->fd < 0 || conn->generation != client->connGeneration)
        return;

    if(replyLen + 2 > sizeof conn->buf)
    {
        CloseConnection(conn);
        return;
    }

    conn->buf[0] = (uint8_t)(replyLen >> 8);
    conn->buf[1] = (uint8_t)replyLen;
    memcpy(conn->buf + 2, reply, replyLen);
    conn->replyLen  = replyLen + 2;
    conn->sent      = 0;
    conn->bWriting  = true;
    conn->bAwaiting = false;
}

static void Fail(Server *server, Transaction *tx, uint16_t rcode)
{
    uint8_t reply[CFG_TX_QUERY_BYTES];
    size_t  replyLen = 0;

    server->failures++;

    if(MsgBuildReply(reply, sizeof reply, tx->query, tx->queryLen,
                     rcode, &replyLen))
    {
        MsgSetId(reply, replyLen, tx->clientId);
        Deliver(server, &tx->client, reply, replyLen);
    }
    else if(tx->client.bOverTcp)
    {
        CloseConnection(&server->conns[tx->client.connIndex]);
    }

    TxRelease(tx);
}

/* Oldest first, so a flood displaces the queries closest to giving up rather
   than refusing the new ones. */
static Transaction *TxAcquire(Server *server)
{
    Transaction *oldest = NULL;

    for(size_t i = 0; i < CFG_TX_SLOTS; i++)
    {
        Transaction *tx = &server->transactions[i];

        if(!tx->bActive)
            return tx;

        if(oldest == NULL || (int32_t)(tx->deadlineMs - oldest->deadlineMs) < 0)
            oldest = tx;
    }

    server->evictedTransactions++;
    Fail(server, oldest, MSG_RCODE_SERVFAIL);
    return oldest;
}

static UpstreamStart TxSend(Transaction *tx)
{
    uint32_t nowMs = ServerNowMilliseconds();
    if(tx->pool == NULL)
        return UpstreamStart_Failed;

    size_t index = UpstreamPoolSelectExcept(tx->pool, nowMs,
                                            tx->attemptedMask);

    if(index == UPSTREAM_NONE)
        return UpstreamStart_Failed;

    if(index < 32)
        tx->attemptedMask |= UINT32_C(1) << index;

    UpstreamStart result = UpstreamBegin(tx->pool, index, tx->query,
                                         tx->queryLen, nowMs, &tx->exchange);
    if(result != UpstreamStart_Started)
        return result;

    tx->deadlineMs = nowMs + CFG_UPSTREAM_TIMEOUT_MS;
    return UpstreamStart_Started;
}

static bool TxStart(Server *server, UpstreamPool *pool, const uint8_t *query,
                    size_t queryLen, const ClientRef *client,
                    uint16_t clientId, uint16_t advertised)
{
    if(queryLen > CFG_TX_QUERY_BYTES)
        return false;

    Transaction *tx = TxAcquire(server);

    memcpy(tx->query, query, queryLen);
    tx->pool          = pool;
    tx->queryLen      = (uint16_t)queryLen;
    tx->client        = *client;
    tx->clientId      = clientId;
    tx->advertised    = advertised;
    tx->attemptedMask = 0;
    tx->attempts      = 1;
    tx->bActive       = true;

    UpstreamStart result = TxSend(tx);
    while(result == UpstreamStart_Failed
          && tx->attempts <= CFG_UPSTREAM_RETRIES)
    {
        UpstreamPoolFail(tx->pool, tx->exchange.index,
                         ServerNowMilliseconds());
        tx->attempts++;
        server->retries++;
        result = TxSend(tx);
    }

    if(result != UpstreamStart_Started)
    {
        if(result == UpstreamStart_Failed)
            UpstreamPoolFail(tx->pool, tx->exchange.index,
                             ServerNowMilliseconds());
        tx->bActive = false;
        return false;
    }

    server->forwarded++;
    return true;
}

static void TxFinish(Server *server, Transaction *tx,
                     uint8_t *reply, size_t replyLen)
{
    (void)CacheInsert(server->cache, reply, replyLen, ServerNowSeconds());
    MsgSetId(reply, replyLen, tx->clientId);

    if(!tx->client.bOverTcp && replyLen > tx->advertised)
    {
        size_t shortLen = 0;
        server->truncated++;

        if(MsgBuildTruncated(reply, CFG_TCP_MSG_BYTES, tx->query, tx->queryLen,
                             &shortLen))
        {
            MsgSetId(reply, shortLen, tx->clientId);
            Deliver(server, &tx->client, reply, shortLen);
        }

        TxRelease(tx);
        return;
    }

    Deliver(server, &tx->client, reply, replyLen);
    TxRelease(tx);
}

static bool TxRetry(Server *server, Transaction *tx, uint32_t nowMs)
{
    UpstreamPoolFail(tx->pool, tx->exchange.index, nowMs);

    while(tx->attempts <= CFG_UPSTREAM_RETRIES)
    {
        UpstreamEnd(&tx->exchange);
        tx->attempts++;
        server->retries++;

        UpstreamStart result = TxSend(tx);
        if(result == UpstreamStart_Started)
            return true;
        if(result == UpstreamStart_Failed)
            UpstreamPoolFail(tx->pool, tx->exchange.index, nowMs);
        else
            break;
    }

    Fail(server, tx, MSG_RCODE_SERVFAIL);
    return false;
}

static void TxReadable(Server *server, Transaction *tx, uint32_t nowMs)
{
    uint8_t reply[CFG_TCP_MSG_BYTES];
    size_t  replyLen = 0;

    UpstreamRead got = UpstreamComplete(tx->pool, &tx->exchange, nowMs,
                                        reply, sizeof reply, &replyLen);

    if(got == UpstreamRead_Failed)
    {
        (void)TxRetry(server, tx, nowMs);
        return;
    }

    if(got != UpstreamRead_Answer)
        return;

    TxFinish(server, tx, reply, replyLen);
}

static void TxSweep(Server *server, uint32_t nowMs)
{
    for(size_t i = 0; i < CFG_TX_SLOTS; i++)
    {
        Transaction *tx = &server->transactions[i];

        if(!tx->bActive || !Elapsed(nowMs, tx->deadlineMs))
            continue;

        (void)TxRetry(server, tx, nowMs);
    }
}

typedef enum
{
    Handled_Reply,
    Handled_Deferred,
    Handled_Drop
} Handled;

/* Nothing in the map matched, so the query carries on down the normal path. */
#define LOCAL_NOT_OURS ((Handled)-1)

static Handled LocalReply(Server *server, const uint8_t *query, size_t queryLen,
                          uint8_t *out, size_t cap, size_t *outLen,
                          uint16_t type, const uint8_t *rdata, size_t rdataLen)
{
    server->local++;

    if(rdata == NULL)
    {
        /* NODATA and NXDOMAIN both answer with the question and no records. */
        if(MsgBuildReply(out, cap, query, queryLen, type, outLen))
            return Handled_Reply;

        return Handled_Drop;
    }

    if(MsgBuildAnswer(out, cap, query, queryLen, type, CFG_LOCAL_TTL_SEC,
                      rdata, rdataLen, outLen))
        return Handled_Reply;

    return Handled_Drop;
}

static bool ShouldForwardPtr(const Server *server, const WireQuestion *question)
{
    uint8_t addr[16];
    uint8_t addrLen = 0;

    if(!server->bPtrRoute || server->ptrRouter == NULL
       || question->type != WIRE_TYPE_PTR
       || question->klass != WIRE_CLASS_IN
       || !HostsReverseAddress(&question->name, addr, &addrLen))
        return false;

    return HostsAddressInPrefix(addr, addrLen, server->ptrPrefix,
                                server->ptrPrefixBits);
}

/* The map is the operator's own statement about their network, so it is
   consulted before the blocklist and before the cache. A local answer costs no
   upstream query and takes no cache slot. */
static Handled AnswerLocal(Server *server, const uint8_t *query, size_t queryLen,
                           const WireQuestion *question, uint8_t *out,
                           size_t cap, size_t *outLen)
{
    const HostMap *map = server->hosts;
    uint8_t        addr[16];
    uint8_t        addrLen = 0;

    if(map == NULL)
        return LOCAL_NOT_OURS;

    if(question->klass != WIRE_CLASS_IN)
        return LOCAL_NOT_OURS;

    if(HostsReverseAddress(&question->name, addr, &addrLen))
    {
        const HostEntry *entry = HostsByAddress(map, addr, addrLen);

        if(entry != NULL)
        {
            if(question->type == WIRE_TYPE_PTR)
            {
                return LocalReply(server, query, queryLen, out, cap, outLen,
                                  WIRE_TYPE_PTR, entry->name.wire,
                                  entry->name.len);
            }

            return LocalReply(server, query, queryLen, out, cap, outLen,
                              MSG_RCODE_NOERROR, NULL, 0);
        }

#if CFG_PRIVATE_PTR_LOCAL
        if(HostsAddressIsPrivate(addr, addrLen)
           && !ShouldForwardPtr(server, question))
        {
            return LocalReply(server, query, queryLen, out, cap, outLen,
                              MSG_RCODE_NXDOMAIN, NULL, 0);
        }
#endif

        return LOCAL_NOT_OURS;
    }

    const HostEntry *entry = NULL;
    bool             bNameExists = false;

    if(HostsLookup(map, &question->name, question->type, &entry, &bNameExists))
    {
        return LocalReply(server, query, queryLen, out, cap, outLen,
                          question->type, entry->addr, entry->addrLen);
    }

    /* The name is ours but carries no record of that type, which is NODATA. */
    if(bNameExists)
    {
        return LocalReply(server, query, queryLen, out, cap, outLen,
                          MSG_RCODE_NOERROR, NULL, 0);
    }

    /* A name in the local domain that the map does not have is answered here
       too. Forwarding it hands a public resolver the names of devices on this
       network, and the answer comes back NXDOMAIN regardless. */
    if(HostsNameIsLocal(map, &question->name))
    {
        return LocalReply(server, query, queryLen, out, cap, outLen,
                          MSG_RCODE_NXDOMAIN, NULL, 0);
    }

    return LOCAL_NOT_OURS;
}

static Handled HandleQuery(Server *server, const uint8_t *query, size_t queryLen,
                           uint8_t *out, size_t cap, size_t *outLen,
                           const ClientRef *client)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion question;
    WireEdns     edns;

    server->queries++;

    ReaderInit(&reader, query, queryLen);
    if(!WireParseHeader(&reader, &header))
    {
        server->malformed++;
        return Handled_Drop;
    }

    /* The listen socket accepts queries. A message with QR set is a
       response. Two resolvers that point at each other trade one forever. */
    if((header.flags & MSG_FLAG_QR) != 0)
    {
        server->malformed++;
        return Handled_Drop;
    }

    if(header.qdCount != 1 || !WireParseQuestion(&reader, &question))
    {
        server->malformed++;
        if(MsgBuildReply(out, cap, query, queryLen, MSG_RCODE_FORMERR, outLen))
            return Handled_Reply;
        return Handled_Drop;
    }

    uint16_t clientId   = MsgId(query, queryLen);
    uint16_t advertised = 512;

    Handled local = AnswerLocal(server, query, queryLen, &question, out, cap,
                                outLen);
    if(local != LOCAL_NOT_OURS)
        return local;

    /* Answered here, so a blocked name never reaches the upstream and never
       takes a cache slot. */
    if(server->blocklist != NULL
       && BlocklistContains(server->blocklist, &question.name))
    {
        server->blocked++;

        if(MsgBuildReply(out, cap, query, queryLen, CFG_BLOCKED_RCODE, outLen))
            return Handled_Reply;

        return Handled_Drop;
    }

    if(WireFindEdns(query, queryLen, &edns) && edns.bPresent)
        advertised = (edns.payloadSize < 512) ? 512 : edns.payloadSize;

    if(CacheLookup(server->cache, &question.name, question.type, question.klass,
                   ServerNowSeconds(), out, cap, outLen))
    {
        server->hits++;
        MsgSetId(out, *outLen, clientId);

        if(!client->bOverTcp && *outLen > advertised)
        {
            server->truncated++;
            if(MsgBuildTruncated(out, cap, query, queryLen, outLen))
                return Handled_Reply;
            return Handled_Drop;
        }

        return Handled_Reply;
    }

    if(ShouldForwardPtr(server, &question))
    {
        if(TxStart(server, server->ptrRouter, query, queryLen, client, clientId,
                   advertised))
            return Handled_Deferred;

        server->failures++;
        if(MsgBuildReply(out, cap, query, queryLen, MSG_RCODE_SERVFAIL, outLen))
            return Handled_Reply;

        return Handled_Drop;
    }

    if(TxStart(server, server->upstreams, query, queryLen, client, clientId,
               advertised))
        return Handled_Deferred;

    server->failures++;
    if(MsgBuildReply(out, cap, query, queryLen, MSG_RCODE_SERVFAIL, outLen))
        return Handled_Reply;

    return Handled_Drop;
}

static void ServiceUdp(Server *server, int fd)
{
    uint8_t   query[CFG_UDP_MSG_BYTES];
    uint8_t   reply[CFG_TCP_MSG_BYTES];
    size_t    replyLen = 0;
    ClientRef client;

    memset(&client, 0, sizeof client);
    client.bOverTcp = false;
    client.listenFd = fd;
    client.fromLen  = sizeof client.from;

    ssize_t got = recvfrom(fd, query, sizeof query, 0,
                           (struct sockaddr *)&client.from, &client.fromLen);
    if(got < 0)
        return;

    if(HandleQuery(server, query, (size_t)got, reply, sizeof reply, &replyLen,
                   &client) != Handled_Reply)
        return;

    sendto(fd, reply, replyLen, 0,
           (struct sockaddr *)&client.from, client.fromLen);
}

static void AcceptConnection(Server *server, int listener)
{
    int fd = accept(listener, NULL, NULL);
    if(fd < 0)
        return;

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        Connection *conn = &server->conns[i];

        if(conn->fd >= 0)
            continue;

        if(!SetNonBlocking(fd))
            break;

        conn->fd             = fd;
        conn->generation     = server->nextGeneration++;
        conn->want           = 0;
        conn->got            = 0;
        conn->sent           = 0;
        conn->replyLen       = 0;
        conn->bWriting       = false;
        conn->bAwaiting      = false;
        conn->idleDeadlineMs = ServerNowMilliseconds() + CFG_TCP_IDLE_MS;
        return;
    }

    /* At capacity, close the connection immediately. The client gets a
       defined result, and the backlog stays bounded. */
    server->refusedConnections++;
    close(fd);
}

static void ServiceConnection(Server *server, Connection *conn, size_t index)
{
    conn->idleDeadlineMs = ServerNowMilliseconds() + CFG_TCP_IDLE_MS;

    if(conn->bWriting)
    {
        ssize_t wrote = send(conn->fd, conn->buf + conn->sent,
                             conn->replyLen - conn->sent, MSG_NOSIGNAL);
        if(wrote <= 0)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                CloseConnection(conn);
            return;
        }

        conn->sent += (size_t)wrote;
        if(conn->sent < conn->replyLen)
            return;

        /* RFC 7766 keep-alive: the same connection may carry another query. */
        conn->bWriting = false;
        conn->want     = 0;
        conn->got      = 0;
        conn->sent     = 0;
        conn->replyLen = 0;
        return;
    }

    size_t  target = (conn->want == 0) ? 2 : 2 + conn->want;
    ssize_t got    = recv(conn->fd, conn->buf + conn->got, target - conn->got, 0);

    if(got == 0)
    {
        CloseConnection(conn);
        return;
    }

    if(got < 0)
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            CloseConnection(conn);
        return;
    }

    conn->got += (size_t)got;

    if(conn->want == 0)
    {
        if(conn->got < 2)
            return;

        conn->want = ((size_t)conn->buf[0] << 8) | conn->buf[1];

        if(conn->want == 0 || conn->want > CFG_TCP_MSG_BYTES)
        {
            CloseConnection(conn);
            return;
        }
    }

    if(conn->got < 2 + conn->want)
        return;

    uint8_t   reply[CFG_TCP_MSG_BYTES];
    size_t    replyLen = 0;
    ClientRef client;

    memset(&client, 0, sizeof client);
    client.bOverTcp       = true;
    client.connIndex      = index;
    client.connGeneration = conn->generation;

    Handled outcome = HandleQuery(server, conn->buf + 2, conn->want,
                                  reply, sizeof reply, &replyLen, &client);

    if(outcome == Handled_Deferred)
    {
        /* Stop reading until the answer arrives, so the request buffer is not
           overwritten by a second query on the same connection. */
        conn->bAwaiting = true;
        return;
    }

    if(outcome != Handled_Reply)
    {
        CloseConnection(conn);
        return;
    }

    Deliver(server, &client, reply, replyLen);
}

/* One probe measures one unselected upstream. It only goes out when clients
   have been asking, so an idle device is silent. */
static void ProbeTick(Server *server, uint32_t nowMs)
{
    UpstreamPoolProbeSweep(server->upstreams, nowMs);

    if(server->queries == server->queriesAtLastProbe)
        return;

    if(UpstreamPoolProbeBegin(server->upstreams, nowMs))
        server->queriesAtLastProbe = server->queries;
}

int ServerPoll(Server *server, int timeoutMs)
{
    struct pollfd waiting[5 + CFG_TCP_SLOTS + CFG_TX_SLOTS];
    int           listeners[4] = { server->fdUdp4, server->fdUdp6,
                                   server->fdTcp4, server->fdTcp6 };
    size_t        connIndex[CFG_TCP_SLOTS];
    size_t        txIndex[CFG_TX_SLOTS];
    nfds_t        count = 0;

    for(size_t i = 0; i < 4; i++)
    {
        if(listeners[i] < 0)
            continue;

        waiting[count].fd      = listeners[i];
        waiting[count].events  = POLLIN;
        waiting[count].revents = 0;
        count++;
    }

    nfds_t listenCount = count;
    nfds_t connCount   = 0;

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        Connection *conn = &server->conns[i];

        if(conn->fd < 0)
            continue;

        connIndex[connCount] = i;
        waiting[count].fd = conn->fd;

        /* A connection waiting on an upstream is not read from. POLLRDHUP
           still reports the client closing its side, so the slot is released
           then instead of at the end of the query. A plain FIN sets POLLIN
           rather than POLLHUP, so asking for no events would miss it. */
        waiting[count].events  = conn->bAwaiting ? POLLRDHUP
                               : (conn->bWriting ? POLLOUT : POLLIN);
        waiting[count].revents = 0;
        count++;
        connCount++;
    }

    nfds_t txCount = 0;

    for(size_t i = 0; i < CFG_TX_SLOTS; i++)
    {
        Transaction *tx = &server->transactions[i];

        if(!tx->bActive || tx->exchange.fd < 0)
            continue;

        txIndex[txCount] = i;
        waiting[count].fd      = tx->exchange.fd;
        waiting[count].events  = UpstreamEvents(&tx->exchange);
        waiting[count].revents = 0;
        count++;
        txCount++;
    }

    bool bProbing = server->upstreams->bProbing;

    if(bProbing)
    {
        waiting[count].fd      = server->upstreams->probe.fd;
        waiting[count].events  = UpstreamEvents(&server->upstreams->probe);
        waiting[count].revents = 0;
        count++;
    }

    /* Never sleep past the nearest deadline, or a timeout is only noticed when
       the next packet happens to arrive. */
    int wait = timeoutMs;
    if((txCount > 0 || bProbing) && (wait < 0 || wait > CFG_UPSTREAM_TIMEOUT_MS))
        wait = CFG_UPSTREAM_TIMEOUT_MS;

    int ready = poll(waiting, count, wait);
    if(ready < 0)
        return (errno == EINTR) ? 0 : -1;

    uint32_t nowMs = ServerNowMilliseconds();

    for(nfds_t i = 0; i < count; i++)
    {
        if(waiting[i].revents == 0)
            continue;

        if(i < listenCount)
        {
            if(waiting[i].fd == server->fdUdp4 || waiting[i].fd == server->fdUdp6)
                ServiceUdp(server, waiting[i].fd);
            else
                AcceptConnection(server, waiting[i].fd);

            continue;
        }

        if(i < listenCount + connCount)
        {
            size_t      index = connIndex[i - listenCount];
            Connection *conn  = &server->conns[index];

            if(conn->fd < 0)
                continue;

            if((waiting[i].revents & (POLLERR | POLLHUP | POLLNVAL | POLLRDHUP)) != 0
               && (waiting[i].revents & (POLLIN | POLLOUT)) == 0)
            {
                CloseConnection(conn);
                continue;
            }

            /* Still waiting on an upstream, so there is nothing to read yet.
               The answer arrives through Deliver. */
            if(conn->bAwaiting)
                continue;

            ServiceConnection(server, conn, index);
            continue;
        }

        size_t after = i - listenCount - connCount;

        if(after < txCount)
        {
            Transaction *tx = &server->transactions[txIndex[after]];

            if(tx->bActive)
                TxReadable(server, tx, nowMs);

            continue;
        }

        UpstreamPoolProbeReadable(server->upstreams, nowMs);
    }

    TxSweep(server, nowMs);
    ProbeTick(server, nowMs);

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        Connection *conn = &server->conns[i];

        /* A connection waiting on an upstream is not idle. */
        if(conn->fd >= 0 && !conn->bAwaiting && Elapsed(nowMs, conn->idleDeadlineMs))
            CloseConnection(conn);
    }

    return ready;
}
