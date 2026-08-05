#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>

_Static_assert(ARENA_CACHE_BYTES + ARENA_TXTABLE_BYTES + ARENA_TLS_BYTES +
               ARENA_SPARE_BYTES == ARENA_TOTAL_BYTES,
               "arena slices must sum to ARENA_TOTAL_BYTES");

typedef struct
{
    Arena root;
    Arena cache;
    Arena txTable;
    Arena tls;
} Memory;

static bool MemoryInit(Memory *mem)
{
    if(!ArenaInit(&mem->root, ARENA_TOTAL_BYTES))
        return false;

    return ArenaCarve(&mem->root, &mem->cache,   ARENA_CACHE_BYTES)
        && ArenaCarve(&mem->root, &mem->txTable, ARENA_TXTABLE_BYTES)
        && ArenaCarve(&mem->root, &mem->tls,     ARENA_TLS_BYTES);
}

static void Report(const Memory *mem, const Blocklist *list, const Cache *cache)
{
    printf("arena     %zu bytes\n", mem->root.size);
    printf("cache     %zu (%zu entries)\n", mem->cache.size,
           cache->bucketCount * CFG_CACHE_WAYS);
    printf("txtable   %zu\n", mem->txTable.size);
    printf("tls       %zu\n", mem->tls.size);
    printf("spare     %zu\n", ArenaRemaining(&mem->root));
    printf("blocklist %zu (%s)\n", list->size, BlocklistSourceName(list->source));
}

int main(void)
{
    Memory    mem;
    Blocklist list;
    Cache     cache;

    if(!MemoryInit(&mem))
    {
        fputs("dns_blocker: arena reservation failed\n", stderr);
        return EXIT_FAILURE;
    }

    if(!CacheInit(&cache, &mem.cache))
    {
        fputs("dns_blocker: cache slice too small\n", stderr);
        return EXIT_FAILURE;
    }

    if(!BlocklistLoad(&list, CFG_BLOCKLIST_PATH))
        fputs("dns_blocker: no blocklist available, filtering is disabled\n", stderr);

    Report(&mem, &list, &cache);

    fputs("dns_blocker: no resolver implemented yet\n", stderr);
    BlocklistUnload(&list);
    ArenaRelease(&mem.root);
    return EXIT_FAILURE;
}
