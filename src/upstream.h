#ifndef DNS_BLOCKER_UPSTREAM_H
#define DNS_BLOCKER_UPSTREAM_H

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
    uint64_t failures;
} Upstream;

/* Accepts a literal IPv4 or IPv6 address only. Resolving a name here would
   need the resolver this daemon is trying to be. */
bool UpstreamInit(Upstream *upstream, const char *address, uint16_t port);

/* Forwards the query and returns the upstream response without change.

   Each query gets a new socket, so the kernel picks a new ephemeral source
   port. The transaction ID comes from the CSPRNG. An attacker off the path
   can predict neither. The code discards and counts a response whose ID does
   not match.

   WARNING: this path has no bailiwick check. Add one before the daemon faces
   a hostile network. */
bool UpstreamQuery(Upstream *upstream, const uint8_t *query, size_t queryLen,
                   uint8_t *out, size_t cap, size_t *outLen);

#endif
