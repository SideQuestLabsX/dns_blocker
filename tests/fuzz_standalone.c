/* Driver for LLVMFuzzerTestOneInput on toolchains without libFuzzer. Coverage
   blind, so it is a smoke test rather than a replacement for `make fuzz`. It
   exists so the fuzz entry point is exercised everywhere gcc and ASan are
   available, instead of only where clang is. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 600

static uint32_t G_RANDOM_STATE = 0x9E3779B9u;

static uint32_t NextRandom(void)
{
    uint32_t x = G_RANDOM_STATE;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    G_RANDOM_STATE = x;
    return x;
}

static size_t RandomBelow(size_t bound)
{
    return (size_t)(NextRandom() % (uint32_t)bound);
}

/* A valid query and a valid response with an OPT record. Mutating real
   messages reaches parser states uniform random bytes almost never hit. */
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

int main(int argc, char **argv)
{
    unsigned long iterations = (argc > 1) ? strtoul(argv[1], NULL, 10) : 200000ul;
    uint8_t       buffer[MAX_INPUT];

    if(argc > 2)
        G_RANDOM_STATE = (uint32_t)strtoul(argv[2], NULL, 10) | 1u;

    LLVMFuzzerTestOneInput(G_SEED_QUERY, sizeof G_SEED_QUERY);
    LLVMFuzzerTestOneInput(G_SEED_RESPONSE, sizeof G_SEED_RESPONSE);

    for(unsigned long i = 0; i < iterations; i++)
    {
        size_t size;

        switch(NextRandom() % 3u)
        {
            case 0:
                size = RandomBelow(MAX_INPUT);
                for(size_t k = 0; k < size; k++)
                    buffer[k] = (uint8_t)NextRandom();
                break;

            case 1:
                size = sizeof G_SEED_QUERY;
                memcpy(buffer, G_SEED_QUERY, size);
                break;

            default:
                size = sizeof G_SEED_RESPONSE;
                memcpy(buffer, G_SEED_RESPONSE, size);
                break;
        }

        /* Splice in pointer bytes deliberately: 0xC0 is the byte that turns a
           length prefix into a jump, and random bytes hit it rarely. */
        size_t edits = RandomBelow(6);
        for(size_t e = 0; e < edits && size > 0; e++)
        {
            size_t at = RandomBelow(size);
            buffer[at] = (NextRandom() % 4u == 0) ? 0xC0u : (uint8_t)NextRandom();
        }

        if(size > 0 && NextRandom() % 8u == 0)
            size = RandomBelow(size);

        LLVMFuzzerTestOneInput(buffer, size);
    }

    printf("fuzz-standalone: %lu iterations, no crash\n", iterations);
    return 0;
}
