#ifndef DNS_BLOCKER_CACHE_H
#define DNS_BLOCKER_CACHE_H

#include "arena.h"
#include "config.h"
#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Stores each upstream response whole. A hit is a copy, a transaction ID
   patch and a TTL rewrite.

   A slot keeps a 64-bit hash to select the bucket. To confirm a candidate, the
   code compares the question inside the stored message. This comparison is
   exact, so a hash collision cannot give a wrong answer. */

typedef struct
{
    uint64_t hash;
    uint32_t insertedAt;
    uint32_t expiresAt;
    uint16_t msgLen;
    uint8_t  ttlCount;
    bool     bReferenced;
    uint16_t ttlOffset[CFG_CACHE_MAX_TTLS];
    uint32_t ttlValue[CFG_CACHE_MAX_TTLS];
    uint8_t  msg[CFG_CACHE_ENTRY_BYTES];
} CacheEntry;

typedef struct
{
    CacheEntry *entries;
    size_t      bucketCount;
    size_t      bucketMask;

    uint64_t hits;
    uint64_t misses;
    uint64_t inserts;
    uint64_t evictions;
    uint64_t rejects;
} Cache;

/* Carves as many buckets as the arena slice allows, rounded down to a power of
   two. Fails when the slice cannot hold even one bucket. */
bool CacheInit(Cache *cache, Arena *arena);

/* Copies the stored response into out with every TTL decremented by the time
   elapsed since insertion. The caller patches the transaction ID: the stored
   copy keeps the one it arrived with, which must never be replayed. */
bool CacheLookup(Cache *cache, const WireName *name, uint16_t type,
                 uint16_t klass, uint32_t nowSec,
                 uint8_t *out, size_t outCap, size_t *outLen);

/* Derives the lifetime from the response: the smallest answer TTL, or the SOA
   minimum for NXDOMAIN and NODATA per RFC 2308. Clamped to
   [CFG_CACHE_MIN_TTL_SEC, CFG_CACHE_MAX_TTL_SEC]. Returns false when the
   response is not cacheable, which is not an error. */
bool CacheInsert(Cache *cache, const uint8_t *msg, size_t len, uint32_t nowSec);

void CacheClear(Cache *cache);

#endif
