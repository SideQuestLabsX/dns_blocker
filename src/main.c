#define _GNU_SOURCE

#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "hosts.h"
#include "server.h"
#include "status.h"
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

#define ARENA_CARVE_ALIGN _Alignof(max_align_t)

#define ARENA_REM_AFTER_CACHE   (ARENA_TOTAL_BYTES - ARENA_CACHE_BYTES)
#define ARENA_REM_AFTER_TXTABLE (ARENA_REM_AFTER_CACHE - ARENA_TXTABLE_BYTES)
#define ARENA_REM_AFTER_CONN    (ARENA_REM_AFTER_TXTABLE - ARENA_CONN_BYTES)
#define ARENA_REM_AFTER_HOSTS   (ARENA_REM_AFTER_CONN - ARENA_HOSTS_BYTES)
#define ARENA_REM_AFTER_TLS     (ARENA_REM_AFTER_HOSTS - ARENA_TLS_BYTES)

_Static_assert(ARENA_CACHE_BYTES <= ARENA_TOTAL_BYTES &&
               ARENA_TXTABLE_BYTES <= ARENA_REM_AFTER_CACHE &&
               ARENA_CONN_BYTES <= ARENA_REM_AFTER_TXTABLE &&
               ARENA_HOSTS_BYTES <= ARENA_REM_AFTER_CONN &&
               ARENA_TLS_BYTES <= ARENA_REM_AFTER_HOSTS &&
               ARENA_SPARE_BYTES == ARENA_REM_AFTER_TLS,
               "arena slices must sum to ARENA_TOTAL_BYTES");
_Static_assert(ARENA_CACHE_BYTES % ARENA_CARVE_ALIGN == 0 &&
               ARENA_TXTABLE_BYTES % ARENA_CARVE_ALIGN == 0 &&
               ARENA_CONN_BYTES % ARENA_CARVE_ALIGN == 0 &&
               ARENA_HOSTS_BYTES % ARENA_CARVE_ALIGN == 0 &&
               ARENA_TLS_BYTES % ARENA_CARVE_ALIGN == 0 &&
               ARENA_SPARE_BYTES % ARENA_CARVE_ALIGN == 0 &&
               ARENA_TOTAL_BYTES % ARENA_CARVE_ALIGN == 0,
               "arena slices must preserve carve alignment");

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
    const char  *tier;
    uint32_t     dueMs;
    bool         bActive;
} SyncRun;

static bool SyncDue(uint32_t nowMs, uint32_t dueMs)
{
    return (int32_t)(nowMs - dueMs) >= 0;
}

/* A run that stops without saying why leaves a permanent defect looking like a
   flaky network, because the only other symptom is another attempt later */
static void SyncStop(SyncRun *run, uint32_t nowMs, uint32_t delayMs,
                     const char *why)
{
    if(why != NULL)
        fprintf(stderr, "sync: %s, retrying in %us\n", why, delayMs / 1000u);

    SyncEnd(run->job);
    ServerResolveCancel(run->server);
    run->bActive = false;
    run->dueMs   = nowMs + delayMs;
}

static void SyncStopOnFailure(SyncRun *run, uint32_t nowMs)
{
    char why[160];
    snprintf(why, sizeof why, "the %s transfer failed, %s",
             SyncPhaseText(run->job), SyncFailText(run->job));
    SyncStop(run, nowMs, CFG_SYNC_RETRY_MS, why);
}

static void SyncTick(SyncRun *run, uint32_t nowMs)
{
    if(!run->bActive)
    {
        if(!SyncDue(nowMs, run->dueMs))
            return;

        if(!SyncBegin(run->job, run->tls, run->path, run->tier))
        {
            if(run->job->fail == SyncFail_None)
            {
                fprintf(stderr,
                        "sync: cannot start against %s, retrying in %us\n",
                        run->path, CFG_SYNC_RETRY_MS / 1000u);
            }
            else
            {
                fprintf(stderr, "sync: cannot start, %s, retrying in %us\n",
                        SyncFailText(run->job), CFG_SYNC_RETRY_MS / 1000u);
            }
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
                    SyncStop(run, nowMs, CFG_SYNC_RETRY_MS,
                             "the reserved lookup slot is busy");
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
                    SyncStop(run, nowMs, CFG_SYNC_RETRY_MS,
                             "the answer carried no IPv4 address");
                    break;
                }

                memset(&v4, 0, sizeof v4);
                v4.sin_family = AF_INET;
                v4.sin_port   = htons(443);
                memcpy(&v4.sin_addr, addr, 4);

                memset(&peer, 0, sizeof peer);
                memcpy(&peer, &v4, sizeof v4);

                if(!SyncProvideAddress(run->job, &peer, sizeof v4))
                    SyncStopOnFailure(run, nowMs);
                break;
            }

            case ServerResolve_Failed:
            {
                char why[CFG_FETCH_HOST_BYTES + 32];
                snprintf(why, sizeof why, "%s did not resolve",
                         SyncHost(run->job));
                ServerResolveCancel(run->server);
                SyncStop(run, nowMs, CFG_SYNC_RETRY_MS, why);
                break;
            }

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

        SyncStop(run, nowMs, CFG_SYNC_PERIOD_MS, NULL);
        return;
    }

    if(step == SyncStep_Failed)
        SyncStopOnFailure(run, nowMs);
}

#endif

/* The only argument the daemon takes. Reading the segment is the same binary
   because the layout lives in one place, and a reader that maps it read-only
   and exits cannot disturb the daemon that wrote it. */
static int ReportStatus(int argc, char **argv)
{
    const char *path = (argc > 2) ? argv[2] : CFG_STATUS_PATH;

    if(path == NULL)
    {
        fputs("dns_blocker: no status path in this build\n", stderr);
        return EXIT_FAILURE;
    }

    if(!StatusReport(path, stdout))
    {
        fprintf(stderr, "dns_blocker: cannot read %s\n", path);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if(argc > 1)
    {
        if(strcmp(argv[1], "--status") == 0)
            return ReportStatus(argc, argv);

        fputs("usage: dns_blocker [--status [path]]\n", stderr);
        return EXIT_FAILURE;
    }

    Memory    mem;
    Blocklist list;
    HostMap   hosts;
    char        tierText[CFG_BLOCKLIST_TIER_BYTES];
    const char *tier = SyncLoadTier(CFG_BLOCKLIST_TIER_PATH, tierText,
                                   sizeof tierText);
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

    /* stdio blocks output whenever stdout is not a terminal, which is every
       supervised deployment. A query stream that arrives 4KB at a time is late,
       and whatever is still buffered dies with the process */
    setvbuf(stdout, NULL, _IOLBF, 0);

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

    /* The list lives on a tmpfs that starts empty, and no supervisor here makes
       the directory. Filtering fails open, so a refusal is reported and the
       daemon serves anyway */
    if(CFG_BLOCKLIST_PATH != NULL && !SyncPrepareDirectory(CFG_BLOCKLIST_PATH))
        fprintf(stderr, "dns_blocker: cannot make the directory for %s\n",
                CFG_BLOCKLIST_PATH);

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
    SyncRun  run = { &sync, &tls, &server, &list, CFG_BLOCKLIST_PATH, tier,
                     ServerNowMilliseconds() + CFG_SYNC_FIRST_MS, false };
#endif

    Status   status      = { NULL, 0 };
    uint32_t statusDueMs = ServerNowMilliseconds();

    if(CFG_STATUS_PATH != NULL
       && !StatusOpen(&status, CFG_STATUS_PATH, statusDueMs))
        fprintf(stderr, "dns_blocker: no status segment at %s\n",
                CFG_STATUS_PATH);

    while(!G_STOP)
    {
        uint32_t nowMs = ServerNowMilliseconds();

#if defined(PROFILE_ENCRYPTED)
        SyncTick(&run, nowMs);
        ServerWatch(&server, run.bActive ? SyncFd(&sync) : -1,
                    run.bActive ? SyncEvents(&sync) : 0);
#endif

        if((int32_t)(nowMs - statusDueMs) >= 0)
        {
            StatusSync syncState = { 0, 0, 0, 0 };
#if defined(PROFILE_ENCRYPTED)
            syncState.bActive        = run.bActive ? 1u : 0u;
            syncState.fail           = (uint32_t)sync.fail;
            syncState.installedBytes = (list.source == BlocklistSource_Mapped)
                                     ? list.size : 0;
            syncState.nextDueMs      = run.bActive
                                     ? 0 : (uint64_t)(run.dueMs - nowMs);
#endif
            StatusPublish(&status, &server, &cache, &upstreams, &list,
                          &syncState, tier, nowMs);
            statusDueMs = nowMs + CFG_STATUS_PERIOD_MS;
        }

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

    /* The last snapshot stays on the tmpfs, so a reader can still see how a
       stopped daemon left things */
    StatusPublish(&status, &server, &cache, &upstreams, &list, NULL, tier,
                  ServerNowMilliseconds());
    StatusClose(&status);

    ServerClose(&server);
    BlocklistUnload(&list);
#if defined(PROFILE_ENCRYPTED)
    TlsBackendFree(&tls);
    TrustUnload(&trust);
#endif
    ArenaRelease(&mem.root);
    return EXIT_SUCCESS;
}
