#include "cache.h"

#include <string.h>

static CacheEntry *BucketOf(const Cache *cache, uint64_t hash)
{
    size_t index = (size_t)(hash & (uint64_t)cache->bucketMask);
    return cache->entries + index * CFG_CACHE_WAYS;
}

/* Wrap-safe: a signed difference stays correct across a uint32 rollover of the
   clock, which a plain `now >= expires` does not. */
static bool HasExpired(uint32_t nowSec, uint32_t expiresAt)
{
    return (int32_t)(nowSec - expiresAt) >= 0;
}

static bool EntryMatches(const CacheEntry *entry, const WireName *name,
                         uint16_t type, uint16_t klass)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion question;

    ReaderInit(&reader, entry->msg, entry->msgLen);

    if(!WireParseHeader(&reader, &header) || header.qdCount == 0)
        return false;
    if(!WireParseQuestion(&reader, &question))
        return false;

    return question.type == type
        && question.klass == klass
        && WireNameEqual(&question.name, name);
}

bool CacheInit(Cache *cache, Arena *arena)
{
    memset(cache, 0, sizeof *cache);

    size_t perBucket = CFG_CACHE_WAYS * sizeof(CacheEntry);
    size_t affordable = ArenaRemaining(arena) / perBucket;
    size_t buckets = 1;

    if(affordable == 0)
        return false;

    while(buckets * 2 <= affordable)
        buckets *= 2;

    /* Alignment padding can cost the last bucket, and a failed carve consumes
       nothing, so stepping down is safe. */
    while(buckets >= 1)
    {
        cache->entries = ARENA_ARRAY(arena, CacheEntry, buckets * CFG_CACHE_WAYS);
        if(cache->entries != NULL)
            break;

        buckets /= 2;
        if(buckets == 0)
            return false;
    }

    cache->bucketCount = buckets;
    cache->bucketMask  = buckets - 1;
    return true;
}

void CacheClear(Cache *cache)
{
    for(size_t i = 0; i < cache->bucketCount * CFG_CACHE_WAYS; i++)
        cache->entries[i].msgLen = 0;
}

bool CacheLookup(Cache *cache, const WireName *name, uint16_t type,
                 uint16_t klass, uint32_t nowSec,
                 uint8_t *out, size_t outCap, size_t *outLen)
{
    uint64_t    hash   = WireNameHash(name, type, klass);
    CacheEntry *bucket = BucketOf(cache, hash);

    for(size_t w = 0; w < CFG_CACHE_WAYS; w++)
    {
        CacheEntry *entry = &bucket[w];

        if(entry->msgLen == 0 || entry->hash != hash)
            continue;

        if(HasExpired(nowSec, entry->expiresAt))
        {
            entry->msgLen = 0;
            continue;
        }

        if(!EntryMatches(entry, name, type, klass))
            continue;

        if(entry->msgLen > outCap)
            break;

        memcpy(out, entry->msg, entry->msgLen);

        uint32_t elapsed = nowSec - entry->insertedAt;
        for(size_t i = 0; i < entry->ttlCount; i++)
        {
            uint32_t stored    = entry->ttlValue[i];
            uint32_t remaining = (stored > elapsed) ? stored - elapsed : 0;
            size_t   at        = entry->ttlOffset[i];

            out[at]     = (uint8_t)(remaining >> 24);
            out[at + 1] = (uint8_t)(remaining >> 16);
            out[at + 2] = (uint8_t)(remaining >> 8);
            out[at + 3] = (uint8_t)remaining;
        }

        entry->bReferenced = true;
        *outLen = entry->msgLen;
        cache->hits++;
        return true;
    }

    cache->misses++;
    return false;
}

static uint32_t ClampTtl(uint32_t ttl)
{
    if(ttl < CFG_CACHE_MIN_TTL_SEC)
        return CFG_CACHE_MIN_TTL_SEC;
    if(ttl > CFG_CACHE_MAX_TTL_SEC)
        return CFG_CACHE_MAX_TTL_SEC;
    return ttl;
}

static CacheEntry *SelectVictim(Cache *cache, CacheEntry *bucket, uint64_t hash,
                                const WireName *name, uint16_t type,
                                uint16_t klass, uint32_t nowSec)
{
    /* Replacing the same key wins over taking a free slot, otherwise a refresh
       leaves a stale duplicate behind that later lookups may reach first. */
    for(size_t w = 0; w < CFG_CACHE_WAYS; w++)
    {
        CacheEntry *entry = &bucket[w];
        if(entry->msgLen != 0 && entry->hash == hash
           && EntryMatches(entry, name, type, klass))
            return entry;
    }

    for(size_t w = 0; w < CFG_CACHE_WAYS; w++)
    {
        CacheEntry *entry = &bucket[w];
        if(entry->msgLen == 0 || HasExpired(nowSec, entry->expiresAt))
            return entry;
    }

    /* CLOCK, confined to the bucket. Sweeping only these ways keeps the work
       bounded and needs no tombstones, since nothing outside the bucket can be
       probing through it. */
    for(size_t w = 0; w < CFG_CACHE_WAYS; w++)
    {
        CacheEntry *entry = &bucket[w];
        if(!entry->bReferenced)
        {
            cache->evictions++;
            return entry;
        }

        entry->bReferenced = false;
    }

    cache->evictions++;
    return &bucket[0];
}

bool CacheInsert(Cache *cache, const uint8_t *msg, size_t len, uint32_t nowSec)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion question;
    uint16_t     offsets[CFG_CACHE_MAX_TTLS];
    uint32_t     values[CFG_CACHE_MAX_TTLS];
    size_t       count         = 0;
    uint32_t     minAnswerTtl  = UINT32_MAX;
    uint32_t     negativeTtl   = 0;
    bool         bHaveAnswer   = false;
    bool         bHaveNegative = false;

    if(len < WIRE_HEADER_BYTES || len > CFG_CACHE_ENTRY_BYTES)
    {
        cache->rejects++;
        return false;
    }

    ReaderInit(&reader, msg, len);

    if(!WireParseHeader(&reader, &header) || header.qdCount != 1
       || !WireParseQuestion(&reader, &question))
    {
        cache->rejects++;
        return false;
    }

    uint16_t rcode = WireRcode(&header);
    if(rcode != 0 && rcode != 3)
    {
        cache->rejects++;
        return false;
    }

    uint32_t total = (uint32_t)header.anCount + header.nsCount + header.arCount;
    for(uint32_t i = 0; i < total; i++)
    {
        WireRecord record;

        if(!WireReadRecord(&reader, &record))
        {
            cache->rejects++;
            return false;
        }

        /* An OPT record uses its TTL field for the extended rcode, the
           version and the DO bit. A decrement corrupts all three. */
        if(record.type == WIRE_TYPE_OPT)
            continue;

        /* ReaderU32 already guarantees this bound, because it succeeds only
           with four bytes left. The check stays because the offset outlives
           the parse, and CacheLookup writes four bytes at it later. */
        if(count >= CFG_CACHE_MAX_TTLS || record.ttlOffset + 4 > len)
        {
            cache->rejects++;
            return false;
        }

        offsets[count] = (uint16_t)record.ttlOffset;
        values[count]  = record.ttl;
        count++;

        if(i < header.anCount)
        {
            bHaveAnswer = true;
            if(record.ttl < minAnswerTtl)
                minAnswerTtl = record.ttl;
        }
        else if(record.type == WIRE_TYPE_SOA && !bHaveNegative)
        {
            uint32_t minimum;
            if(WireSoaMinimum(msg, len, &record, &minimum))
            {
                negativeTtl   = (minimum < record.ttl) ? minimum : record.ttl;
                bHaveNegative = true;
            }
        }
    }

    uint32_t lifetime;
    if(rcode == 0 && bHaveAnswer)
    {
        lifetime = minAnswerTtl;
    }
    else if(bHaveNegative)
    {
        /* RFC 2308: NXDOMAIN and NODATA live for the SOA minimum, bounded by
           the SOA record's own TTL. Without this every typo and every dead
           tracker domain re-queries upstream forever. */
        lifetime = negativeTtl;
    }
    else
    {
        cache->rejects++;
        return false;
    }

    /* A zero TTL means do not cache, so it is honoured before the clamp raises
       it to the floor. */
    if(lifetime == 0)
    {
        cache->rejects++;
        return false;
    }

    lifetime = ClampTtl(lifetime);

    uint64_t    hash   = WireNameHash(&question.name, question.type, question.klass);
    CacheEntry *bucket = BucketOf(cache, hash);
    CacheEntry *entry  = SelectVictim(cache, bucket, hash, &question.name,
                                      question.type, question.klass, nowSec);

    entry->hash        = hash;
    entry->insertedAt  = nowSec;
    entry->expiresAt   = nowSec + lifetime;
    entry->msgLen      = (uint16_t)len;
    entry->ttlCount    = (uint8_t)count;
    entry->bReferenced = false;

    memcpy(entry->ttlOffset, offsets, count * sizeof offsets[0]);
    memcpy(entry->ttlValue, values, count * sizeof values[0]);
    memcpy(entry->msg, msg, len);

    cache->inserts++;
    return true;
}
