#include "arena.h"
#include "cache.h"
#include "verify.h"
#include "wire.h"

#include "fuzzseed.h"

#include <stdint.h>
#include <stddef.h>

/* The parser must never read out of bounds or fail to terminate, whatever the
   input. Correctness of the parse is the unit test's job; this only asserts
   that no input crashes or hangs. Build with -fsanitize=fuzzer,address. */

static Arena    G_FUZZ_ARENA;
static Cache    G_FUZZ_CACHE;
static bool     G_FUZZ_READY;
static uint32_t G_FUZZ_CLOCK;

/* CacheInsert records TTL field offsets from untrusted input and CacheLookup
   later writes four bytes at each one, so a bad offset is memory corruption
   rather than a wrong answer. */
static void FuzzCache(const uint8_t *data, size_t size)
{
    uint8_t      out[CFG_CACHE_ENTRY_BYTES];
    size_t       outLen = 0;
    Reader       reader;
    WireHeader   header;
    WireQuestion question;

    if(!G_FUZZ_READY)
    {
        if(!ArenaInit(&G_FUZZ_ARENA, 256u * 1024u)
           || !CacheInit(&G_FUZZ_CACHE, &G_FUZZ_ARENA))
            return;

        G_FUZZ_READY = true;
    }

    G_FUZZ_CLOCK += 7;
    (void)CacheInsert(&G_FUZZ_CACHE, data, size, G_FUZZ_CLOCK);

    ReaderInit(&reader, data, size);
    if(WireParseHeader(&reader, &header) && WireParseQuestion(&reader, &question))
    {
        (void)CacheLookup(&G_FUZZ_CACHE, &question.name, question.type,
                          question.klass, G_FUZZ_CLOCK, out, sizeof out, &outLen);

        /* Also probe far in the future, so expiry and lazy reclaim run. */
        (void)CacheLookup(&G_FUZZ_CACHE, &question.name, question.type,
                          question.klass, G_FUZZ_CLOCK + 100000u,
                          out, sizeof out, &outLen);
    }
}

/* A valid query and a valid response with an OPT record. */
static const uint8_t G_SEED_QUERY[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t G_SEED_RESPONSE[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01,
    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C,
    0x00, 0x04, 0x5D, 0xB8, 0xD8, 0x22
};

const char *FuzzTargetName(void)
{
    return "fuzz-wire";
}

/* 0xC0 is the byte that turns a length prefix into a jump. */
uint8_t FuzzSpliceByte(void)
{
    return 0xC0u;
}

size_t FuzzSeedCount(void)
{
    return 2;
}

FuzzSeed FuzzSeedAt(size_t index)
{
    FuzzSeed seed;

    if(index == 0)
    {
        seed.data = G_SEED_QUERY;
        seed.size = sizeof G_SEED_QUERY;
    }
    else
    {
        seed.data = G_SEED_RESPONSE;
        seed.size = sizeof G_SEED_RESPONSE;
    }

    return seed;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Reader     reader;
    WireHeader header;
    WireEdns   edns;

    FuzzCache(data, size);

    /* VerifyResponse walks an untrusted response against an untrusted query,
       and follows CNAME rdata as a name, so it needs the same coverage as the
       parser it sits on. */
    (void)VerifyResponse(data, size, data, size);
    if(size > 16)
    {
        (void)VerifyResponse(data, 16, data + 16, size - 16);
        (void)VerifyResponse(data + 16, size - 16, data, 16);
    }

    (void)WireFindEdns(data, size, &edns);

    ReaderInit(&reader, data, size);
    if(WireParseHeader(&reader, &header))
    {
        WireQuestion question;
        while(WireParseQuestion(&reader, &question))
            ;

        ReaderInit(&reader, data, size);
        (void)ReaderSkip(&reader, WIRE_HEADER_BYTES);
        while(WireSkipRecord(&reader))
            ;
    }

    /* Names are also read from arbitrary offsets, since a hostile message can
       place a pointer anywhere in the payload. */
    for(size_t at = 0; at < size && at < 64; at++)
    {
        Reader   nameReader;
        WireName name;

        ReaderInit(&nameReader, data, size);
        if(ReaderSkip(&nameReader, at))
            (void)WireReadName(&nameReader, &name);
    }

    return 0;
}
