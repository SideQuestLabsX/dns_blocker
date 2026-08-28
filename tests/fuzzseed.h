#ifndef DNS_BLOCKER_FUZZSEED_H
#define DNS_BLOCKER_FUZZSEED_H

#include <stddef.h>
#include <stdint.h>

/* What an entry point tells the standalone driver about itself, so one driver
   runs any of them. Mutating a valid input reaches states uniform random bytes
   almost never hit, and only the entry point knows what a valid input is. */

typedef struct
{
    const uint8_t *data;
    size_t         size;
} FuzzSeed;

const char *FuzzTargetName(void);

/* The byte the target's format treats specially, spliced in deliberately
   because random bytes hit one rarely. */
uint8_t FuzzSpliceByte(void);

size_t   FuzzSeedCount(void);
FuzzSeed FuzzSeedAt(size_t index);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif
