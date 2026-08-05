#ifndef DNS_BLOCKER_SERVER_H
#define DNS_BLOCKER_SERVER_H

#include "arena.h"
#include "cache.h"
#include "config.h"
#include "upstream.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    int      fd;
    uint32_t idleDeadlineMs;
    size_t   want;
    size_t   got;
    size_t   sent;
    size_t   replyLen;
    bool     bWriting;
    uint8_t  buf[2 + CFG_TCP_MSG_BYTES];
} Connection;

typedef struct
{
    Cache      *cache;
    Upstream   *upstream;
    Connection *conns;

    int fdUdp4;
    int fdUdp6;
    int fdTcp4;
    int fdTcp6;

    uint64_t queries;
    uint64_t hits;
    uint64_t forwarded;
    uint64_t failures;
    uint64_t malformed;
    uint64_t truncated;
    uint64_t refusedConnections;
} Server;

/* Binds UDP and TCP on the port, for IPv4 and IPv6. IPv4 is required. The
   daemon reports a failed IPv6 bind and continues, so it still starts on an
   IPv4-only host. The report matters, because a client that reaches an ISP
   resolver over IPv6 bypasses this daemon. */
bool ServerOpen(Server *server, Cache *cache, Upstream *upstream, Arena *arena,
                uint16_t port);

void ServerClose(Server *server);

/* One poll and dispatch pass. Returns the number of descriptors serviced, or
   -1 on a poll failure that is not an interruption. */
int ServerPoll(Server *server, int timeoutMs);

uint32_t ServerNowSeconds(void);

#endif
