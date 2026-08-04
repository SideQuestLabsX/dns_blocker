#include "arena.h"
#include "blocklist.h"
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

static void Report(const Memory *mem, const Blocklist *list)
{
    printf("arena     %zu bytes\n", mem->root.size);
    printf("cache     %zu\n", mem->cache.size);
    printf("txtable   %zu\n", mem->txTable.size);
    printf("tls       %zu\n", mem->tls.size);
    printf("spare     %zu\n", ArenaRemaining(&mem->root));
    printf("blocklist %zu (%s)\n", list->size, BlocklistSourceName(list->source));
}

int main(void)
{
    Memory    mem;
    Blocklist list;

    if(!MemoryInit(&mem))
    {
        fputs("dns_blocker: arena reservation failed\n", stderr);
        return EXIT_FAILURE;
    }

    if(!BlocklistLoad(&list, CFG_BLOCKLIST_PATH))
        fputs("dns_blocker: no blocklist available, filtering is disabled\n", stderr);

    Report(&mem, &list);

    fputs("dns_blocker: no resolver implemented yet\n", stderr);
    BlocklistUnload(&list);
    ArenaRelease(&mem.root);
    return EXIT_FAILURE;
}
