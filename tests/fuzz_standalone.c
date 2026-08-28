/* Driver for LLVMFuzzerTestOneInput on toolchains without libFuzzer. Coverage
   blind, so it is a smoke test rather than a replacement for `make fuzz`. It
   exists so the fuzz entry points are exercised everywhere gcc and ASan are
   available, instead of only where clang is. The entry point supplies its own
   name and corpus through fuzzseed.h. */

#include "fuzzseed.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Exactly sized, so a read one byte past the input lands in a redzone. */
static void RunExact(const uint8_t *data, size_t size)
{
    uint8_t *exact = malloc((size == 0) ? 1u : size);

    if(exact == NULL)
        return;

    memcpy(exact, data, size);
    LLVMFuzzerTestOneInput(exact, size);
    free(exact);
}

int main(int argc, char **argv)
{
    unsigned long iterations = (argc > 1) ? strtoul(argv[1], NULL, 10) : 200000ul;
    size_t        seedCount  = FuzzSeedCount();
    uint8_t       buffer[MAX_INPUT];

    if(argc > 2)
        G_RANDOM_STATE = (uint32_t)strtoul(argv[2], NULL, 10) | 1u;

    for(size_t i = 0; i < seedCount; i++)
    {
        FuzzSeed seed = FuzzSeedAt(i);

        RunExact(seed.data, seed.size);
    }

    for(unsigned long i = 0; i < iterations; i++)
    {
        size_t size;

        if(seedCount == 0 || NextRandom() % 3u == 0)
        {
            size = RandomBelow(MAX_INPUT);
            for(size_t k = 0; k < size; k++)
                buffer[k] = (uint8_t)NextRandom();
        }
        else
        {
            FuzzSeed seed = FuzzSeedAt(RandomBelow(seedCount));

            size = (seed.size < MAX_INPUT) ? seed.size : MAX_INPUT;
            memcpy(buffer, seed.data, size);
        }

        size_t edits = RandomBelow(6);
        for(size_t e = 0; e < edits && size > 0; e++)
        {
            size_t at = RandomBelow(size);

            buffer[at] = (NextRandom() % 4u == 0) ? FuzzSpliceByte()
                                                  : (uint8_t)NextRandom();
        }

        if(size > 0 && NextRandom() % 8u == 0)
            size = RandomBelow(size);

        RunExact(buffer, size);
    }

    printf("%s: %lu iterations, no crash\n", FuzzTargetName(), iterations);
    return 0;
}
