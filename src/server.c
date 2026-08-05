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

bool ServerOpen(Server *server, Cache *cache, Upstream *upstream, Arena *arena,
                uint16_t port)
{
    memset(server, 0, sizeof *server);

    server->cache    = cache;
    server->upstream = upstream;
    server->fdUdp4   = -1;
    server->fdUdp6   = -1;
    server->fdTcp4   = -1;
    server->fdTcp6   = -1;

    server->conns = ARENA_ARRAY(arena, Connection, CFG_TCP_SLOTS);
    if(server->conns == NULL)
        return false;

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
        server->conns[i].fd = -1;

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

    if(server->conns == NULL)
        return;

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        if(server->conns[i].fd >= 0)
            close(server->conns[i].fd);

        server->conns[i].fd = -1;
    }
}

/* Produces the bytes to send back, or 0 to answer nothing at all. */
static size_t HandleQuery(Server *server, const uint8_t *query, size_t queryLen,
                          uint8_t *out, size_t cap, bool bOverTcp)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion question;
    WireEdns     edns;
    size_t       replyLen = 0;

    server->queries++;

    ReaderInit(&reader, query, queryLen);
    if(!WireParseHeader(&reader, &header))
    {
        server->malformed++;
        return 0;
    }

    /* The listen socket accepts queries. A message with QR set is a
       response. Two resolvers that point at each other trade one forever. */
    if((header.flags & MSG_FLAG_QR) != 0)
    {
        server->malformed++;
        return 0;
    }

    if(header.qdCount != 1 || !WireParseQuestion(&reader, &question))
    {
        server->malformed++;
        if(MsgBuildReply(out, cap, query, queryLen, MSG_RCODE_FORMERR, &replyLen))
            return replyLen;
        return 0;
    }

    uint16_t clientId  = MsgId(query, queryLen);
    uint16_t advertised = CFG_EDNS_PAYLOAD_BYTES;

    if(WireFindEdns(query, queryLen, &edns) && edns.bPresent)
        advertised = (edns.payloadSize < 512) ? 512 : edns.payloadSize;
    else
        advertised = 512;

    uint32_t now = ServerNowSeconds();

    if(CacheLookup(server->cache, &question.name, question.type, question.klass,
                   now, out, cap, &replyLen))
    {
        server->hits++;
    }
    else if(UpstreamQuery(server->upstream, query, queryLen, out, cap, &replyLen))
    {
        server->forwarded++;
        (void)CacheInsert(server->cache, out, replyLen, now);
    }
    else
    {
        server->failures++;
        if(MsgBuildReply(out, cap, query, queryLen, MSG_RCODE_SERVFAIL, &replyLen))
            return replyLen;
        return 0;
    }

    /* Both paths above may have produced bytes carrying a foreign transaction
       ID: the cache stores whatever arrived, and the forwarder used its own
       random ID upstream. */
    MsgSetId(out, replyLen, clientId);

    if(!bOverTcp && replyLen > advertised)
    {
        server->truncated++;
        if(MsgBuildTruncated(out, cap, query, queryLen, &replyLen))
            return replyLen;
        return 0;
    }

    return replyLen;
}

static void ServiceUdp(Server *server, int fd)
{
    uint8_t                 query[CFG_UDP_MSG_BYTES];
    uint8_t                 reply[CFG_TCP_MSG_BYTES];
    struct sockaddr_storage from;
    socklen_t               fromLen = sizeof from;

    ssize_t got = recvfrom(fd, query, sizeof query, 0,
                           (struct sockaddr *)&from, &fromLen);
    if(got < 0)
        return;

    size_t replyLen = HandleQuery(server, query, (size_t)got,
                                  reply, sizeof reply, false);
    if(replyLen == 0)
        return;

    sendto(fd, reply, replyLen, 0, (struct sockaddr *)&from, fromLen);
}

static void CloseConnection(Connection *conn)
{
    if(conn->fd >= 0)
        close(conn->fd);

    conn->fd       = -1;
    conn->want     = 0;
    conn->got      = 0;
    conn->sent     = 0;
    conn->replyLen = 0;
    conn->bWriting = false;
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
        conn->want           = 0;
        conn->got            = 0;
        conn->sent           = 0;
        conn->replyLen       = 0;
        conn->bWriting       = false;
        conn->idleDeadlineMs = NowMilliseconds() + CFG_TCP_IDLE_MS;
        return;
    }

    /* At capacity, close the connection immediately. The client gets a
       defined result, and the backlog stays bounded. */
    server->refusedConnections++;
    close(fd);
}

static void ServiceConnection(Server *server, Connection *conn)
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

    size_t target = (conn->want == 0) ? 2 : 2 + conn->want;
    ssize_t got = recv(conn->fd, conn->buf + conn->got, target - conn->got, 0);

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

    uint8_t reply[CFG_TCP_MSG_BYTES];
    size_t  replyLen = HandleQuery(server, conn->buf + 2, conn->want,
                                   reply, sizeof reply, true);
    if(replyLen == 0)
    {
        CloseConnection(conn);
        return;
    }

    conn->buf[0]   = (uint8_t)(replyLen >> 8);
    conn->buf[1]   = (uint8_t)replyLen;
    memcpy(conn->buf + 2, reply, replyLen);
    conn->replyLen = replyLen + 2;
    conn->sent     = 0;
    conn->bWriting = true;
}

int ServerPoll(Server *server, int timeoutMs)
{
    struct pollfd waiting[4 + CFG_TCP_SLOTS];
    int           listeners[4] = { server->fdUdp4, server->fdUdp6,
                                   server->fdTcp4, server->fdTcp6 };
    nfds_t        count = 0;
    size_t        connIndex[CFG_TCP_SLOTS];

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

    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        Connection *conn = &server->conns[i];

        if(conn->fd < 0)
            continue;

        connIndex[count - listenCount] = i;
        waiting[count].fd      = conn->fd;
        waiting[count].events  = conn->bWriting ? POLLOUT : POLLIN;
        waiting[count].revents = 0;
        count++;
    }

    int ready = poll(waiting, count, timeoutMs);
    if(ready < 0)
        return (errno == EINTR) ? 0 : -1;

    uint32_t nowMs = NowMilliseconds();
    for(size_t i = 0; i < CFG_TCP_SLOTS; i++)
    {
        Connection *conn = &server->conns[i];

        if(conn->fd >= 0 && (int32_t)(nowMs - conn->idleDeadlineMs) >= 0)
            CloseConnection(conn);
    }

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

        Connection *conn = &server->conns[connIndex[i - listenCount]];
        if(conn->fd < 0)
            continue;

        if((waiting[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0
           && (waiting[i].revents & (POLLIN | POLLOUT)) == 0)
        {
            CloseConnection(conn);
            continue;
        }

        ServiceConnection(server, conn);
    }

    return ready;
}
