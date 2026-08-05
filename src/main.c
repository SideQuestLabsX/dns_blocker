#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "server.h"
#include "upstream.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

_Static_assert(ARENA_CACHE_BYTES + ARENA_TXTABLE_BYTES + ARENA_CONN_BYTES +
               ARENA_TLS_BYTES + ARENA_SPARE_BYTES == ARENA_TOTAL_BYTES,
               "arena slices must sum to ARENA_TOTAL_BYTES");

typedef struct
{
    Arena root;
    Arena cache;
    Arena txTable;
    Arena conn;
    Arena tls;
} Memory;

static volatile sig_atomic_t G_STOP;

static void OnSignal(int signum)
{
    (void)signum;
    G_STOP = 1;
}

static bool MemoryInit(Memory *mem)
{
    if(!ArenaInit(&mem->root, ARENA_TOTAL_BYTES))
        return false;

    return ArenaCarve(&mem->root, &mem->cache,   ARENA_CACHE_BYTES)
        && ArenaCarve(&mem->root, &mem->txTable, ARENA_TXTABLE_BYTES)
        && ArenaCarve(&mem->root, &mem->conn,    ARENA_CONN_BYTES)
        && ArenaCarve(&mem->root, &mem->tls,     ARENA_TLS_BYTES);
}

static void Report(const Memory *mem, const Blocklist *list, const Cache *cache)
{
    printf("arena     %zu bytes\n", mem->root.size);
    printf("cache     %zu (%zu entries)\n", mem->cache.size,
           cache->bucketCount * CFG_CACHE_WAYS);
    printf("txtable   %zu\n", mem->txTable.size);
    printf("conn      %zu (%d slots)\n", mem->conn.size, CFG_TCP_SLOTS);
    printf("tls       %zu\n", mem->tls.size);
    printf("spare     %zu\n", ArenaRemaining(&mem->root));
    printf("blocklist %zu (%s)\n", list->size, BlocklistSourceName(list->source));
    printf("upstream  %s:%d\n", CFG_UPSTREAM_ADDR, CFG_UPSTREAM_PORT);
}

int main(void)
{
    Memory    mem;
    Blocklist list;
    Cache     cache;
    Upstream  upstream;
    Server    server;

    signal(SIGTERM, OnSignal);
    signal(SIGINT, OnSignal);
    signal(SIGPIPE, SIG_IGN);

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

    if(!UpstreamInit(&upstream, CFG_UPSTREAM_ADDR, CFG_UPSTREAM_PORT))
    {
        fputs("dns_blocker: upstream address is not a literal IP\n", stderr);
        return EXIT_FAILURE;
    }

    if(!BlocklistLoad(&list, CFG_BLOCKLIST_PATH))
        fputs("dns_blocker: no blocklist available, filtering is disabled\n", stderr);

    Report(&mem, &list, &cache);

    if(!ServerOpen(&server, &cache, &upstream, &mem.conn, CFG_DNS_PORT))
    {
        fprintf(stderr, "dns_blocker: cannot bind port %d\n", CFG_DNS_PORT);
        BlocklistUnload(&list);
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    printf("listening on port %d\n", CFG_DNS_PORT);
    fflush(stdout);

    while(!G_STOP)
    {
        if(ServerPoll(&server, 1000) < 0)
        {
            fputs("dns_blocker: poll failed\n", stderr);
            break;
        }
    }

    fprintf(stderr, "dns_blocker: stopping after %llu queries, %llu hits\n",
            (unsigned long long)server.queries, (unsigned long long)server.hits);

    ServerClose(&server);
    BlocklistUnload(&list);
    ArenaRelease(&mem.root);
    return EXIT_SUCCESS;
}
