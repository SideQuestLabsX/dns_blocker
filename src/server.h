#ifndef DNS_BLOCKER_SERVER_H
#define DNS_BLOCKER_SERVER_H

#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "hosts.h"
#include "upstream.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct
{
    int      fd;
    uint32_t generation;
    uint32_t idleDeadlineMs;
    size_t   want;
    size_t   got;
    size_t   sent;
    size_t   replyLen;
    bool     bWriting;
    bool     bAwaiting;
    uint8_t  buf[2 + CFG_TCP_MSG_BYTES];
} Connection;

/* Where an answer goes once it arrives. A TCP slot is identified by index and
   generation, because the client may hang up while the query is in flight and
   the slot may already belong to somebody else. */
typedef struct
{
    bool                    bOverTcp;
    int                     listenFd;
    struct sockaddr_storage from;
    socklen_t               fromLen;
    size_t                  connIndex;
    uint32_t                connGeneration;
} ClientRef;

typedef struct
{
    UpstreamExchange exchange;
    UpstreamPool    *pool;
    ClientRef        client;
    uint32_t         deadlineMs;
    uint32_t         attemptedMask;
    uint16_t         clientId;
    uint16_t         advertised;
    uint8_t          attempts;
    bool             bActive;
    /* The daemon's own lookup rather than a client's. Its answer goes to the
       internal buffer, and no reply is ever written to a socket. */
    bool             bInternal;
    uint16_t         queryLen;
    uint8_t          query[CFG_TX_QUERY_BYTES];
} Transaction;

typedef enum
{
    ServerResolve_Idle,
    ServerResolve_Waiting,
    ServerResolve_Ready,
    ServerResolve_Failed
} ServerResolveState;

typedef struct
{
    Cache           *cache;
    UpstreamPool    *upstreams;
    UpstreamPool    *ptrRouter;
    const Blocklist *blocklist;
    const HostMap   *hosts;
    Connection  *conns;
    Transaction *transactions;

    uint8_t ptrPrefix[4];
    uint8_t ptrPrefixBits;
    bool    bPtrRoute;

    int fdUdp4;
    int fdUdp6;
    int fdTcp4;
    int fdTcp6;

    uint32_t nextGeneration;

    /* One descriptor the caller wants polled alongside the listeners, so a
       background transfer shares this loop instead of running its own. The
       server never reads, writes or closes it. */
    int   watchFd;
    short watchEvents;
    bool  bWatchReady;

    /* The reserved slot's answer lands here rather than on a socket */
    ServerResolveState resolveState;
    uint16_t           resolveType;
    size_t             resolveLen;
    uint8_t            resolveReply[CFG_UDP_MSG_BYTES];

    /* Probing is skipped while this equals queries, so a device nobody is
       using sends nothing. */
    uint64_t queriesAtLastProbe;

    uint64_t queries;
    uint64_t hits;
    uint64_t forwarded;
    uint64_t failures;
    uint64_t malformed;
    uint64_t truncated;
    uint64_t refusedConnections;
    uint64_t evictedTransactions;
    uint64_t retries;
    uint64_t blocked;
    uint64_t local;
} Server;

/* Binds UDP and TCP on the port, for IPv4 and IPv6. IPv4 is required. The
   daemon reports a failed IPv6 bind and continues, so it still starts on an
   IPv4-only host. The report matters, because a client that reaches an ISP
   resolver over IPv6 bypasses this daemon. */
bool ServerOpen(Server *server, Cache *cache, UpstreamPool *upstreams,
                const Blocklist *blocklist, const HostMap *hosts,
                UpstreamPool *ptrRouter, const uint8_t *ptrPrefix,
                uint8_t ptrPrefixBits,
                Arena *connArena, Arena *txArena, uint16_t port);

void ServerClose(Server *server);

/* One poll and dispatch pass. Waiting for an upstream never blocks this, so a
   slow resolver delays only the client that asked. Returns the number of
   descriptors serviced, or -1 on a poll failure that is not an interruption. */
int ServerPoll(Server *server, int timeoutMs);

/* Starts one lookup of the daemon's own, on the slot reserved for it. Returns
   false when that slot is busy or the pool refuses the query, which is a
   fail-soft: the caller retries later rather than displacing client traffic to
   make room. */
bool ServerResolveBegin(Server *server, const char *hostname, uint16_t type);

ServerResolveState ServerResolveCheck(const Server *server);

/* Copies out the address the lookup found and returns the slot to idle. The
   answer was checked by VerifyAnswer before it reached here. */
bool ServerResolveTake(Server *server, uint8_t *addr, uint8_t *addrLen);

void ServerResolveCancel(Server *server);

/* Adds one descriptor to the next poll. Pass -1 to stop watching. The server
   reports readiness and nothing else: the owner does the reading. */
void ServerWatch(Server *server, int fd, short events);

/* True when the watched descriptor was ready during the last poll. */
bool ServerWatchReady(const Server *server);

uint32_t ServerNowSeconds(void);
uint32_t ServerNowMilliseconds(void);

#endif
