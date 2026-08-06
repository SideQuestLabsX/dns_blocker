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

static uint32_t NowMilliseconds(void)
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

bool ServerOpen(Server *server, Cache *cache, Upstream *upstream,
                const Blocklist *blocklist, Arena *connArena, Arena *txArena,
                uint16_t port)
{
    memset(server, 0, sizeof *server);

    server->cache          = cache;
    server->upstream       = upstream;
    server->blocklist      = blocklist;
    server->nextGeneration = 1;
    server->fdUdp4         = -1;
    server->fdUdp6         = -1;
    server->fdTcp4         = -1;
    server->fdTcp6         = -1;

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

static bool TxSend(Server *server, Transaction *tx)
{
    if(!UpstreamBegin(server->upstream, tx->query, tx->queryLen, &tx->exchange))
        return false;

    tx->deadlineMs = NowMilliseconds() + CFG_UPSTREAM_TIMEOUT_MS;
    return true;
}

static bool TxStart(Server *server, const uint8_t *query, size_t queryLen,
                    const ClientRef *client, uint16_t clientId,
                    uint16_t advertised)
{
    if(queryLen > CFG_TX_QUERY_BYTES)
        return false;

    Transaction *tx = TxAcquire(server);

    memcpy(tx->query, query, queryLen);
    tx->queryLen   = (uint16_t)queryLen;
    tx->client     = *client;
    tx->clientId   = clientId;
    tx->advertised = advertised;
    tx->attempts   = 1;
    tx->bActive    = true;

    if(!TxSend(server, tx))
    {
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

static void TxReadable(Server *server, Transaction *tx)
{
    uint8_t reply[CFG_TCP_MSG_BYTES];
    size_t  replyLen = 0;

    UpstreamRead got = UpstreamComplete(server->upstream, &tx->exchange,
                                        reply, sizeof reply, &replyLen);

    /* Again means the datagram failed a check while the exchange stays open,
       so a forged packet loses the race instead of ending it. */
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

        server->upstream->timeouts++;

        if(tx->attempts <= CFG_UPSTREAM_RETRIES)
        {
            /* A retry gets a new socket, so it also gets a new source port and
               a new transaction ID. */
            UpstreamEnd(&tx->exchange);
            tx->attempts++;
            server->retries++;

            if(TxSend(server, tx))
                continue;
        }

        server->upstream->failures++;
        Fail(server, tx, MSG_RCODE_SERVFAIL);
    }
}

typedef enum
{
    Handled_Reply,
    Handled_Deferred,
    Handled_Drop
} Handled;

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

    if(TxStart(server, query, queryLen, client, clientId, advertised))
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
        conn->idleDeadlineMs = NowMilliseconds() + CFG_TCP_IDLE_MS;
        return;
    }

    /* At capacity, close the connection immediately. The client gets a
       defined result, and the backlog stays bounded. */
    server->refusedConnections++;
    close(fd);
}

static void ServiceConnection(Server *server, Connection *conn, size_t index)
{
    conn->idleDeadlineMs = NowMilliseconds() + CFG_TCP_IDLE_MS;

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

int ServerPoll(Server *server, int timeoutMs)
{
    struct pollfd waiting[4 + CFG_TCP_SLOTS + CFG_TX_SLOTS];
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
        waiting[count].events  = POLLIN;
        waiting[count].revents = 0;
        count++;
        txCount++;
    }

    /* Never sleep past the nearest deadline, or a timeout is only noticed when
       the next packet happens to arrive. */
    int wait = timeoutMs;
    if(txCount > 0 && (wait < 0 || wait > CFG_UPSTREAM_TIMEOUT_MS))
        wait = CFG_UPSTREAM_TIMEOUT_MS;

    int ready = poll(waiting, count, wait);
    if(ready < 0)
        return (errno == EINTR) ? 0 : -1;

    uint32_t nowMs = NowMilliseconds();

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

        Transaction *tx = &server->transactions[txIndex[i - listenCount - connCount]];
        if(tx->bActive)
            TxReadable(server, tx);
    }

    TxSweep(server, nowMs);

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        Connection *conn = &server->conns[i];

        /* A connection waiting on an upstream is not idle. */
        if(conn->fd >= 0 && !conn->bAwaiting && Elapsed(nowMs, conn->idleDeadlineMs))
            CloseConnection(conn);
    }

    return ready;
}
