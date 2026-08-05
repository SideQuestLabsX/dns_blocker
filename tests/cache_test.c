#include "arena.h"
#include "cache.h"
#include "wire.h"

#include "dnsbuild.h"

#include <stdio.h>
#include <string.h>

static int G_FAILURES;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if(!(cond))                                                        \
        {                                                                  \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

/* TTL of the first non-OPT record in a served message. */
static bool FirstTtl(const uint8_t *msg, size_t len, uint32_t *out)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion question;

    ReaderInit(&reader, msg, len);
    if(!WireParseHeader(&reader, &header) || !WireParseQuestion(&reader, &question))
        return false;

    uint32_t total = (uint32_t)header.anCount + header.nsCount + header.arCount;
    for(uint32_t i = 0; i < total; i++)
    {
        WireRecord record;
        if(!WireReadRecord(&reader, &record))
            return false;

        if(record.type == WIRE_TYPE_OPT)
            continue;

        *out = record.ttl;
        return true;
    }

    return false;
}

static bool OptTtlField(const uint8_t *msg, size_t len, uint32_t *out)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion question;

    ReaderInit(&reader, msg, len);
    if(!WireParseHeader(&reader, &header) || !WireParseQuestion(&reader, &question))
        return false;

    uint32_t total = (uint32_t)header.anCount + header.nsCount + header.arCount;
    for(uint32_t i = 0; i < total; i++)
    {
        WireRecord record;
        if(!WireReadRecord(&reader, &record))
            return false;

        if(record.type == WIRE_TYPE_OPT)
        {
            *out = record.ttl;
            return true;
        }
    }

    return false;
}

/* Arena sized so bucketMask is 0 and every key lands in one bucket, which
   makes eviction deterministic instead of dependent on the hash. */
static bool MakeCache(Arena *arena, Cache *cache, size_t buckets)
{
    size_t bytes = buckets * CFG_CACHE_WAYS * sizeof(CacheEntry) + 4096;
    return ArenaInit(arena, bytes) && CacheInit(cache, arena);
}

static void TestRoundTrip(void)
{
    Arena   arena;
    Cache   cache;
    uint8_t msg[512];
    uint8_t out[512];
    size_t  outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "www.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("www.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                      out, sizeof out, &outLen));
    CHECK(outLen == len);
    CHECK(memcmp(out, msg, len) == 0);
    CHECK(cache.hits == 1);

    ArenaRelease(&arena);
}

static void TestTtlDecrementsWithElapsedTime(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    uint32_t ttl = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "a.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("a.example.com", &name));

    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                      out, sizeof out, &outLen));
    CHECK(FirstTtl(out, outLen, &ttl));
    CHECK(ttl == 300);

    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1120,
                      out, sizeof out, &outLen));
    CHECK(FirstTtl(out, outLen, &ttl));
    CHECK(ttl == 180);

    /* The stored copy keeps its original TTL, so a later hit is not
       double-decremented. */
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1060,
                      out, sizeof out, &outLen));
    CHECK(FirstTtl(out, outLen, &ttl));
    CHECK(ttl == 240);

    ArenaRelease(&arena);
}

static void TestExpiry(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "b.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("b.example.com", &name));

    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1299,
                      out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1300,
                       out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 5000,
                       out, sizeof out, &outLen));

    ArenaRelease(&arena);
}

static void TestTtlClamps(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));

    /* Below the floor. The entry lives for CFG_CACHE_MIN_TTL_SEC. */
    size_t len = BuildPositive(msg, sizeof msg, "short.example.com", 5);
    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("short.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN,
                      1000 + CFG_CACHE_MIN_TTL_SEC - 1, out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN,
                       1000 + CFG_CACHE_MIN_TTL_SEC, out, sizeof out, &outLen));

    /* Above the ceiling: capped. */
    len = BuildPositive(msg, sizeof msg, "long.example.com", 999999);
    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("long.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN,
                      1000 + CFG_CACHE_MAX_TTL_SEC - 1, out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN,
                       1000 + CFG_CACHE_MAX_TTL_SEC, out, sizeof out, &outLen));

    ArenaRelease(&arena);
}

static void TestZeroTtlNotCached(void)
{
    Arena   arena;
    Cache   cache;
    uint8_t msg[512];

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "zero.example.com", 0);

    CHECK(!CacheInsert(&cache, msg, len, 1000));
    CHECK(cache.rejects == 1);

    ArenaRelease(&arena);
}

static void TestNegativeCaching(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));

    /* NXDOMAIN: lifetime is the SOA minimum, bounded by the SOA record TTL. */
    size_t len = BuildNegative(msg, sizeof msg, "nope.example.com", 3, 3600, 900);
    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("nope.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1899,
                      out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1900,
                       out, sizeof out, &outLen));

    /* NODATA: NOERROR with no answers, same rule. */
    len = BuildNegative(msg, sizeof msg, "nodata.example.com", 0, 3600, 600);
    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("nodata.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1599,
                      out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1600,
                       out, sizeof out, &outLen));

    /* The SOA's own TTL bounds a larger minimum. */
    len = BuildNegative(msg, sizeof msg, "bounded.example.com", 3, 300, 86400);
    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("bounded.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1299,
                      out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1300,
                       out, sizeof out, &outLen));

    ArenaRelease(&arena);
}

static void TestNegativeWithoutSoaNotCached(void)
{
    Arena   arena;
    Cache   cache;
    uint8_t buf[512];

    CHECK(MakeCache(&arena, &cache, 4));

    Builder b = { buf, sizeof buf, 0 };
    PutResponseHeader(&b, 3, 0, 0, 0);
    PutQuestion(&b, "bare.example.com", WIRE_TYPE_A);

    CHECK(!CacheInsert(&cache, buf, b.len, 1000));

    ArenaRelease(&arena);
}

static void TestServfailNotCached(void)
{
    Arena   arena;
    Cache   cache;
    uint8_t buf[512];

    CHECK(MakeCache(&arena, &cache, 4));

    Builder b = { buf, sizeof buf, 0 };
    PutResponseHeader(&b, 2, 0, 1, 0);
    PutQuestion(&b, "fail.example.com", WIRE_TYPE_A);
    PutSoa(&b, "example.com", 3600, 900);

    CHECK(!CacheInsert(&cache, buf, b.len, 1000));

    ArenaRelease(&arena);
}

/* An OPT record's TTL field carries the extended rcode, the version and the DO
   bit. Treating it as a TTL and decrementing it corrupts all three. */
static void TestOptTtlFieldIsNotDecremented(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  buf[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    uint32_t optTtl = 0;
    uint32_t answerTtl = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));

    Builder b = { buf, sizeof buf, 0 };
    PutResponseHeader(&b, 0, 1, 0, 1);
    PutQuestion(&b, "edns.example.com", WIRE_TYPE_A);
    PutARecord(&b, "edns.example.com", 300);
    PutOpt(&b, 1232, 0x00008000u);

    CHECK(CacheInsert(&cache, buf, b.len, 1000));
    CHECK(NameOf("edns.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1200,
                      out, sizeof out, &outLen));

    CHECK(OptTtlField(out, outLen, &optTtl));
    CHECK(optTtl == 0x00008000u);

    CHECK(FirstTtl(out, outLen, &answerTtl));
    CHECK(answerTtl == 100);

    ArenaRelease(&arena);
}

static void TestLookupIsCaseInsensitive(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "MiXeD.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("mixed.EXAMPLE.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                      out, sizeof out, &outLen));

    ArenaRelease(&arena);
}

static void TestTypeIsPartOfTheKey(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "dual.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("dual.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                      out, sizeof out, &outLen));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_AAAA, WIRE_CLASS_IN, 1000,
                       out, sizeof out, &outLen));

    ArenaRelease(&arena);
}

static void TestRefreshReplacesRatherThanDuplicates(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    uint32_t ttl = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 1));
    size_t len = BuildPositive(msg, sizeof msg, "same.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    len = BuildPositive(msg, sizeof msg, "same.example.com", 900);
    CHECK(CacheInsert(&cache, msg, len, 1000));

    CHECK(NameOf("same.example.com", &name));
    CHECK(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                      out, sizeof out, &outLen));
    CHECK(FirstTtl(out, outLen, &ttl));
    CHECK(ttl == 900);
    CHECK(cache.evictions == 0);

    ArenaRelease(&arena);
}

static void TestBucketOverflowEvicts(void)
{
    Arena   arena;
    Cache   cache;
    uint8_t msg[512];
    uint8_t out[512];
    size_t  outLen = 0;
    size_t  present = 0;

    /* One bucket, so every key collides and eviction is deterministic. */
    CHECK(MakeCache(&arena, &cache, 1));
    CHECK(cache.bucketCount == 1);

    for(size_t i = 0; i < CFG_CACHE_WAYS + 4; i++)
    {
        char host[32];
        snprintf(host, sizeof host, "h%zu.example.com", i);
        size_t len = BuildPositive(msg, sizeof msg, host, 300);
        CHECK(CacheInsert(&cache, msg, len, 1000));
    }

    for(size_t i = 0; i < CFG_CACHE_WAYS + 4; i++)
    {
        char     host[32];
        WireName name;

        snprintf(host, sizeof host, "h%zu.example.com", i);
        CHECK(NameOf(host, &name));
        if(CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                       out, sizeof out, &outLen))
            present++;
    }

    CHECK(present <= CFG_CACHE_WAYS);
    CHECK(present > 0);
    CHECK(cache.evictions > 0);

    ArenaRelease(&arena);
}

static void TestOversizedResponseNotCached(void)
{
    Arena   arena;
    Cache   cache;
    uint8_t msg[CFG_CACHE_ENTRY_BYTES + 64];

    CHECK(MakeCache(&arena, &cache, 4));
    memset(msg, 0, sizeof msg);

    CHECK(!CacheInsert(&cache, msg, sizeof msg, 1000));

    ArenaRelease(&arena);
}

static void TestUndersizedOutputBufferIsRefused(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  msg[512];
    uint8_t  out[8];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    size_t len = BuildPositive(msg, sizeof msg, "small.example.com", 300);

    CHECK(CacheInsert(&cache, msg, len, 1000));
    CHECK(NameOf("small.example.com", &name));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                       out, sizeof out, &outLen));

    ArenaRelease(&arena);
}

static void TestInitRefusesATinyArena(void)
{
    Arena arena;
    Cache cache;

    CHECK(ArenaInit(&arena, 64));
    CHECK(!CacheInit(&cache, &arena));

    ArenaRelease(&arena);
}

static void TestMissOnEmptyCache(void)
{
    Arena    arena;
    Cache    cache;
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName name;

    CHECK(MakeCache(&arena, &cache, 4));
    CHECK(NameOf("absent.example.com", &name));
    CHECK(!CacheLookup(&cache, &name, WIRE_TYPE_A, WIRE_CLASS_IN, 1000,
                       out, sizeof out, &outLen));
    CHECK(cache.misses == 1);
    CHECK(cache.hits == 0);

    ArenaRelease(&arena);
}

int main(void)
{
    TestRoundTrip();
    TestTtlDecrementsWithElapsedTime();
    TestExpiry();
    TestTtlClamps();
    TestZeroTtlNotCached();
    TestNegativeCaching();
    TestNegativeWithoutSoaNotCached();
    TestServfailNotCached();
    TestOptTtlFieldIsNotDecremented();
    TestLookupIsCaseInsensitive();
    TestTypeIsPartOfTheKey();
    TestRefreshReplacesRatherThanDuplicates();
    TestBucketOverflowEvicts();
    TestOversizedResponseNotCached();
    TestUndersizedOutputBufferIsRefused();
    TestInitRefusesATinyArena();
    TestMissOnEmptyCache();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("cache: all checks passed\n");
    return 0;
}
