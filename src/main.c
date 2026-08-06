#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "hosts.h"
#include "server.h"
#include "upstream.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(ARENA_CACHE_BYTES + ARENA_TXTABLE_BYTES + ARENA_CONN_BYTES +
               ARENA_HOSTS_BYTES + ARENA_TLS_BYTES + ARENA_SPARE_BYTES
               == ARENA_TOTAL_BYTES,
               "arena slices must sum to ARENA_TOTAL_BYTES");

typedef struct
{
    Arena root;
    Arena cache;
    Arena txTable;
    Arena conn;
    Arena hosts;
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
        && ArenaCarve(&mem->root, &mem->hosts,   ARENA_HOSTS_BYTES)
        && ArenaCarve(&mem->root, &mem->tls,     ARENA_TLS_BYTES);
}

static const char *const G_UPSTREAM_ADDRS[] = CFG_UPSTREAM_ADDRS;

static bool ConfigurePtrRoute(UpstreamPool *router, uint8_t prefix[4])
{
    UpstreamPoolInit(router, ServerNowMilliseconds());

    if(CFG_PTR_ROUTER_ADDR == NULL)
        return false;

    if(CFG_PTR_LOCAL_PREFIX_BITS > 32)
    {
        fputs("dns_blocker: conditional PTR prefix is wider than IPv4\n", stderr);
        return false;
    }

    struct in_addr network;
    if(inet_pton(AF_INET, CFG_PTR_LOCAL_PREFIX_ADDR, &network) != 1)
    {
        fputs("dns_blocker: conditional PTR prefix is not an IPv4 address\n",
              stderr);
        return false;
    }

    if(!UpstreamPoolAdd(router, CFG_PTR_ROUTER_ADDR, CFG_PTR_ROUTER_PORT))
    {
        fputs("dns_blocker: PTR router refused, not a literal IP\n", stderr);
        return false;
    }

    memcpy(prefix, &network.s_addr, sizeof network.s_addr);
    return true;
}

static void Report(const Memory *mem, const Blocklist *list, const Cache *cache,
                   const HostMap *hosts)
{
    printf("arena     %zu bytes\n", mem->root.size);
    printf("cache     %zu (%zu entries)\n", mem->cache.size,
           cache->bucketCount * CFG_CACHE_WAYS);
    printf("txtable   %zu\n", mem->txTable.size);
    printf("conn      %zu (%d slots)\n", mem->conn.size, CFG_TCP_SLOTS);
    printf("hosts     %zu (%zu names)\n", mem->hosts.size, hosts->count);
    printf("tls       %zu\n", mem->tls.size);
    printf("spare     %zu\n", ArenaRemaining(&mem->root));
    printf("blocklist %zu (%s)\n", list->size, BlocklistSourceName(list->source));
    printf("upstream ");
    for(size_t i = 0; i < sizeof G_UPSTREAM_ADDRS / sizeof *G_UPSTREAM_ADDRS; i++)
        printf(" %s:%d", G_UPSTREAM_ADDRS[i], CFG_UPSTREAM_PORT);
    printf("\n");
}

int main(void)
{
    Memory    mem;
    Blocklist list;
    HostMap   hosts;
    Cache        cache;
    UpstreamPool upstreams;
    UpstreamPool ptrRouter;
    Server       server;
    uint8_t      ptrPrefix[4];
    bool         bPtrRoute;

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

    UpstreamPoolInit(&upstreams, ServerNowMilliseconds());

    bPtrRoute = ConfigurePtrRoute(&ptrRouter, ptrPrefix);
    if(CFG_PTR_ROUTER_ADDR != NULL && !bPtrRoute)
        return EXIT_FAILURE;

    for(size_t i = 0; i < sizeof G_UPSTREAM_ADDRS / sizeof *G_UPSTREAM_ADDRS; i++)
    {
        if(!UpstreamPoolAdd(&upstreams, G_UPSTREAM_ADDRS[i], CFG_UPSTREAM_PORT))
            fprintf(stderr, "dns_blocker: upstream %s refused, not a literal IP\n",
                    G_UPSTREAM_ADDRS[i]);
    }

    if(upstreams.count == 0)
    {
        fputs("dns_blocker: no usable upstream address\n", stderr);
        return EXIT_FAILURE;
    }

    if(!BlocklistLoad(&list, CFG_BLOCKLIST_PATH))
        fputs("dns_blocker: no blocklist available, filtering is disabled\n", stderr);

    if(!HostsLoad(&hosts, &mem.hosts, CFG_HOSTS_PATH))
    {
        fputs("dns_blocker: hosts slice too small\n", stderr);
        return EXIT_FAILURE;
    }

    Report(&mem, &list, &cache, &hosts);

    if(!ServerOpen(&server, &cache, &upstreams, &list, &hosts,
                   bPtrRoute ? &ptrRouter : NULL,
                   bPtrRoute ? ptrPrefix : NULL, CFG_PTR_LOCAL_PREFIX_BITS,
                   &mem.conn, &mem.txTable, CFG_DNS_PORT))
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

    uint64_t rejected = 0;
    for(size_t i = 0; i < upstreams.count; i++)
        rejected += upstreams.members[i].rejected;

    fprintf(stderr,
            "dns_blocker: stopping. queries %llu, hits %llu, blocked %llu, "
            "local %llu, forwarded %llu, failed %llu, rejected %llu\n",
            (unsigned long long)server.queries,
            (unsigned long long)server.hits,
            (unsigned long long)server.blocked,
            (unsigned long long)server.local,
            (unsigned long long)server.forwarded,
            (unsigned long long)server.failures,
            (unsigned long long)rejected);

    ServerClose(&server);
    BlocklistUnload(&list);
    ArenaRelease(&mem.root);
    return EXIT_SUCCESS;
}
