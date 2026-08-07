#define _GNU_SOURCE

#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "hosts.h"
#include "server.h"
#include "sync.h"
#include "tls.h"
#include "upstream.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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

#if defined(PROFILE_ENCRYPTED)
static const char *const G_UPSTREAM_TLS_NAMES[] = CFG_UPSTREAM_TLS_NAMES;
static const char *const G_UPSTREAM_DOH_PATHS[] = CFG_UPSTREAM_DOH_PATHS;

_Static_assert(sizeof G_UPSTREAM_ADDRS / sizeof *G_UPSTREAM_ADDRS
               == sizeof G_UPSTREAM_TLS_NAMES / sizeof *G_UPSTREAM_TLS_NAMES,
               "each encrypted upstream needs a TLS hostname");
_Static_assert(sizeof G_UPSTREAM_ADDRS / sizeof *G_UPSTREAM_ADDRS
               == sizeof G_UPSTREAM_DOH_PATHS / sizeof *G_UPSTREAM_DOH_PATHS,
               "each encrypted upstream needs a DoH path");

typedef struct
{
    const uint8_t *base;
    size_t         size;
} TrustMap;

static bool TrustLoad(TrustMap *trust)
{
    memset(trust, 0, sizeof *trust);

    int fd = open(CFG_TLS_CA_DER_PATH, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return false;

    struct stat info;
    if(fstat(fd, &info) != 0 || info.st_size <= 0
       || info.st_size > (off_t)CFG_TLS_CA_MAX_BYTES)
    {
        close(fd);
        return false;
    }

    void *base = mmap(NULL, (size_t)info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if(base == MAP_FAILED)
        return false;

    trust->base = base;
    trust->size = (size_t)info.st_size;
    return true;
}

static void TrustUnload(TrustMap *trust)
{
    if(trust->base != NULL)
        munmap((void *)trust->base, trust->size);

    trust->base = NULL;
    trust->size = 0;
}
#endif

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
                   const HostMap *hosts, const UpstreamPool *upstreams)
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
    for(size_t i = 0; i < upstreams->count; i++)
    {
        const Upstream *member = &upstreams->members[i];
        const void     *raw;
        if(member->addr.ss_family == AF_INET)
            raw = &((const struct sockaddr_in *)&member->addr)->sin_addr;
        else
            raw = &((const struct sockaddr_in6 *)&member->addr)->sin6_addr;

        char address[INET6_ADDRSTRLEN];
        const char *display = inet_ntop(member->addr.ss_family, raw, address,
                                       sizeof address);
        const char *transport = "udp";
        if(member->transport == UpstreamTransport_Dot)
            transport = "dot";
        else if(member->transport == UpstreamTransport_Doh)
            transport = "doh";
        printf(" %s:%s", display != NULL ? display : "?", transport);
    }
    printf("\n");
}

#if defined(PROFILE_ENCRYPTED)

/* Wiring only. Every branch below hands off to something tested on its own:
   the driver sequences the transfers, the server resolves on its reserved slot
   and the blocklist performs the swap. */
typedef struct
{
    SyncJob     *job;
    TlsBackend  *tls;
    Server      *server;
    Blocklist   *list;
    const char  *path;
    uint32_t     dueMs;
    bool         bActive;
} SyncRun;

static bool SyncDue(uint32_t nowMs, uint32_t dueMs)
{
    return (int32_t)(nowMs - dueMs) >= 0;
}

static void SyncStop(SyncRun *run, uint32_t nowMs, uint32_t delayMs)
{
    SyncEnd(run->job);
    ServerResolveCancel(run->server);
    run->bActive = false;
    run->dueMs   = nowMs + delayMs;
}

static void SyncTick(SyncRun *run, uint32_t nowMs)
{
    if(!run->bActive)
    {
        if(!SyncDue(nowMs, run->dueMs))
            return;

        if(!SyncBegin(run->job, run->tls, run->path))
        {
            run->dueMs = nowMs + CFG_SYNC_RETRY_MS;
            return;
        }

        run->bActive = true;
    }

    SyncStep step = SyncProgress(run->job);

    if(step == SyncStep_NeedAddress)
    {
        switch(ServerResolveCheck(run->server))
        {
            case ServerResolve_Idle:
                if(!ServerResolveBegin(run->server, SyncHost(run->job),
                                       WIRE_TYPE_A))
                    SyncStop(run, nowMs, CFG_SYNC_RETRY_MS);
                break;

            case ServerResolve_Ready:
            {
                uint8_t   addr[16];
                uint8_t   addrLen = 0;
                struct sockaddr_in v4;
                struct sockaddr_storage peer;

                if(!ServerResolveTake(run->server, addr, &addrLen)
                   || addrLen != 4)
                {
                    SyncStop(run, nowMs, CFG_SYNC_RETRY_MS);
                    break;
                }

                memset(&v4, 0, sizeof v4);
                v4.sin_family = AF_INET;
                v4.sin_port   = htons(443);
                memcpy(&v4.sin_addr, addr, 4);

                memset(&peer, 0, sizeof peer);
                memcpy(&peer, &v4, sizeof v4);

                if(!SyncProvideAddress(run->job, &peer, sizeof v4))
                    SyncStop(run, nowMs, CFG_SYNC_RETRY_MS);
                break;
            }

            case ServerResolve_Failed:
                ServerResolveCancel(run->server);
                SyncStop(run, nowMs, CFG_SYNC_RETRY_MS);
                break;

            case ServerResolve_Waiting:
                break;
        }

        return;
    }

    if(step == SyncStep_Done)
    {
        if(BlocklistReload(run->list, run->path))
            fprintf(stderr, "sync: installed %zu bytes\n", run->list->size);
        else
            fputs("sync: the installed list did not map, keeping the old one\n",
                  stderr);

        SyncStop(run, nowMs, CFG_SYNC_PERIOD_MS);
        return;
    }

    if(step == SyncStep_Failed)
        SyncStop(run, nowMs, CFG_SYNC_RETRY_MS);
}

#endif

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

#if defined(PROFILE_ENCRYPTED)
    TlsBackend tls;
    TrustMap   trust;
#endif

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

#if defined(PROFILE_ENCRYPTED)
    if(!TrustLoad(&trust))
    {
        fprintf(stderr, "dns_blocker: cannot map TLS trust anchor %s\n",
                CFG_TLS_CA_DER_PATH);
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    if(!TlsBackendInit(&tls, &mem.tls, trust.base, trust.size))
    {
        fputs("dns_blocker: TLS initialization failed\n", stderr);
        TrustUnload(&trust);
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    UpstreamPoolSetTlsBackend(&upstreams, &tls);
#endif

    bPtrRoute = ConfigurePtrRoute(&ptrRouter, ptrPrefix);
    if(CFG_PTR_ROUTER_ADDR != NULL && !bPtrRoute)
    {
#if defined(PROFILE_ENCRYPTED)
        TlsBackendFree(&tls);
        TrustUnload(&trust);
#endif
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    for(size_t i = 0; i < sizeof G_UPSTREAM_ADDRS / sizeof *G_UPSTREAM_ADDRS; i++)
    {
#if defined(PROFILE_ENCRYPTED)
#if CFG_ENCRYPTED_USE_DOH
        bool bAdded = UpstreamPoolAddDoh(&upstreams, G_UPSTREAM_ADDRS[i],
                                         CFG_DOH_PORT, G_UPSTREAM_TLS_NAMES[i],
                                         G_UPSTREAM_DOH_PATHS[i]);
#else
        bool bAdded = UpstreamPoolAddDot(&upstreams, G_UPSTREAM_ADDRS[i],
                                         CFG_DOT_PORT, G_UPSTREAM_TLS_NAMES[i]);
#endif
#else
        bool bAdded = UpstreamPoolAdd(&upstreams, G_UPSTREAM_ADDRS[i],
                                      CFG_UPSTREAM_PORT);
#endif
        if(!bAdded)
            fprintf(stderr, "dns_blocker: upstream %s refused, not a literal IP\n",
                    G_UPSTREAM_ADDRS[i]);
    }

    if(upstreams.count == 0)
    {
        fputs("dns_blocker: no usable upstream address\n", stderr);
#if defined(PROFILE_ENCRYPTED)
        TlsBackendFree(&tls);
        TrustUnload(&trust);
#endif
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    if(!BlocklistLoad(&list, CFG_BLOCKLIST_PATH))
        fputs("dns_blocker: no blocklist available, filtering is disabled\n", stderr);

    if(!HostsLoad(&hosts, &mem.hosts, CFG_HOSTS_PATH))
    {
        fputs("dns_blocker: hosts slice too small\n", stderr);
        BlocklistUnload(&list);
#if defined(PROFILE_ENCRYPTED)
        TlsBackendFree(&tls);
        TrustUnload(&trust);
#endif
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    Report(&mem, &list, &cache, &hosts, &upstreams);

    if(!ServerOpen(&server, &cache, &upstreams, &list, &hosts,
                   bPtrRoute ? &ptrRouter : NULL,
                   bPtrRoute ? ptrPrefix : NULL, CFG_PTR_LOCAL_PREFIX_BITS,
                   &mem.conn, &mem.txTable, CFG_DNS_PORT))
    {
        fprintf(stderr, "dns_blocker: cannot bind port %d\n", CFG_DNS_PORT);
        BlocklistUnload(&list);
#if defined(PROFILE_ENCRYPTED)
        TlsBackendFree(&tls);
        TrustUnload(&trust);
#endif
        ArenaRelease(&mem.root);
        return EXIT_FAILURE;
    }

    printf("listening on port %d\n", CFG_DNS_PORT);
    fflush(stdout);

#if defined(PROFILE_ENCRYPTED)
    SyncJob  sync;
    SyncRun  run = { &sync, &tls, &server, &list, CFG_BLOCKLIST_PATH,
                     ServerNowMilliseconds() + CFG_SYNC_FIRST_MS, false };
#endif

    while(!G_STOP)
    {
#if defined(PROFILE_ENCRYPTED)
        SyncTick(&run, ServerNowMilliseconds());
        ServerWatch(&server, run.bActive ? SyncFd(&sync) : -1,
                    run.bActive ? SyncEvents(&sync) : 0);
#endif

        if(ServerPoll(&server, 1000) < 0)
        {
            fputs("dns_blocker: poll failed\n", stderr);
            break;
        }
    }

#if defined(PROFILE_ENCRYPTED)
    if(run.bActive)
        SyncEnd(&sync);
#endif

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
#if defined(PROFILE_ENCRYPTED)
    TlsBackendFree(&tls);
    TrustUnload(&trust);
#endif
    ArenaRelease(&mem.root);
    return EXIT_SUCCESS;
}
