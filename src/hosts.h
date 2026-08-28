#ifndef DNS_BLOCKER_HOSTS_H
#define DNS_BLOCKER_HOSTS_H

#include "arena.h"
#include "config.h"
#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The static host map, which replaces the device naming a bundled DHCP server
   would have provided. Parsed once at boot into an arena slice, then read only,
   so nothing here allocates after start-up.

   The file is local and trusted, unlike a blocklist or a packet. It is still
   parsed defensively, because a typo should cost one line rather than the
   daemon. */

typedef struct
{
    WireName name;
    uint8_t  addr[16];
    uint8_t  addrLen;    /* 4 for IPv4, 16 for IPv6 */
} HostEntry;

typedef struct
{
    HostEntry *entries;
    size_t     count;
    size_t     capacity;
    size_t     rejected;

    WireName   domain;
    bool       bHasDomain;
} HostMap;

/* Carves CFG_HOSTS_MAX entries and fills them from path. A missing file is not
   an error: the map is simply empty and every lookup says no. Returns false
   only when the slice cannot hold the table. */
bool HostsLoad(HostMap *map, Arena *arena, const char *path);

/* Parses one line into an address and the names on it, so the file format is
   testable without a file. Returns the number of names, 0 for a comment, a
   blank line or anything malformed. */
size_t HostsParseLine(char *line, uint8_t *addr, uint8_t *addrLen,
                      WireName *names, size_t maxNames);

/* Answers a forward query. Reports whether the name exists at all through
   bNameExists, because a name that exists without the type asked for is NODATA
   rather than NXDOMAIN, and the two are different answers. */
bool HostsLookup(const HostMap *map, const WireName *name, uint16_t type,
                 const HostEntry **out, bool *bNameExists);

/* True for CFG_LOCAL_DOMAIN and everything under it. A name in that zone is
   this network's business: answering it here keeps device names off a public
   resolver, which would return NXDOMAIN for them anyway. */
bool HostsNameIsLocal(const HostMap *map, const WireName *name);

/* Decodes the address a reverse name asks about. Handles in-addr.arpa and
   ip6.arpa, and rejects anything that is not exactly one address. */
bool HostsReverseAddress(const WireName *name, uint8_t *addr, uint8_t *addrLen);

const HostEntry *HostsByAddress(const HostMap *map, const uint8_t *addr,
                                uint8_t addrLen);

/* True when an IPv4 address falls within a configured network prefix */
bool HostsAddressInPrefix(const uint8_t *addr, uint8_t addrLen,
                          const uint8_t *prefix, uint8_t prefixBits);

#endif
