#define _POSIX_C_SOURCE 200809L

#include "status.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Fixed size, so a reader built against this version knows the layout before
   it maps anything */
_Static_assert(sizeof(StatusBlock) < 4096,
               "the status block must stay within one page");

#define STATUS_READ_TRIES 64

static void StoreSequence(uint32_t *at, uint32_t value)
{
    __atomic_store_n(at, value, __ATOMIC_RELEASE);
}

static uint32_t LoadSequence(const uint32_t *at)
{
    return __atomic_load_n(at, __ATOMIC_ACQUIRE);
}

bool StatusOpen(Status *status, const char *path, uint32_t nowMs)
{
    if(status == NULL || path == NULL)
        return false;

    status->block     = NULL;
    status->startedMs = nowMs;

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if(fd < 0)
        return false;

    if(ftruncate(fd, (off_t)sizeof(StatusBlock)) != 0)
    {
        close(fd);
        return false;
    }

    void *at = mmap(NULL, sizeof(StatusBlock), PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);
    close(fd);

    if(at == MAP_FAILED)
        return false;

    StatusBlock *block = at;

    /* An earlier run may have left a snapshot here, and a reader must not take
       it for this one. The sequence goes odd before anything else changes */
    StoreSequence(&block->sequence, LoadSequence(&block->sequence) | 1u);
    /* Even is settled, so the zeroed block reads as a real snapshot of a daemon
       that has answered nothing yet */
    memset(block, 0, sizeof *block);
    memcpy(block->magic, STATUS_MAGIC, sizeof block->magic);
    block->version = STATUS_VERSION;
    block->bytes   = (uint32_t)sizeof(StatusBlock);

    status->block = block;
    return true;
}

void StatusClose(Status *status)
{
    if(status == NULL || status->block == NULL)
        return;

    munmap(status->block, sizeof(StatusBlock));
    status->block = NULL;
}

static void PublishLatency(StatusLatency *to, const LatencyHist *from)
{
    memset(to, 0, sizeof *to);

    if(from == NULL || from->count == 0)
        return;

    to->count  = from->count;
    to->minUs  = from->minUs;
    to->meanUs = LatencyMean(from);
    to->p50Us  = LatencyPercentile(from, 500);
    to->p90Us  = LatencyPercentile(from, 900);
    to->p99Us  = LatencyPercentile(from, 990);
    to->maxUs  = from->maxUs;
}

static void PublishUpstreams(StatusBlock *block, const UpstreamPool *pool,
                             uint32_t nowMs)
{
    size_t count = (pool != NULL) ? pool->count : 0;
    if(count > CFG_MAX_UPSTREAMS)
        count = CFG_MAX_UPSTREAMS;

    block->upstreamCount = (uint32_t)count;

    for(size_t i = 0; i < count; i++)
    {
        const Upstream *from = &pool->members[i];
        StatusUpstream *to   = &block->upstreams[i];

        /* Selection lets a member back the moment its hold expires, so an
           expired flag here would name a resolver that is already in use */
        bool bHeld = from->bDown && (int32_t)(from->downUntilMs - nowMs) > 0;

        memset(to, 0, sizeof *to);
        to->transport           = (uint8_t)from->transport;
        to->bDown               = bHeld ? 1u : 0u;
        to->bUnusable           = from->bUnusable ? 1u : 0u;
        to->srttMs              = from->srttMs;
        to->consecutiveFailures = from->consecutiveFailures;
        to->queries             = from->queries;
        to->failures            = from->failures;
        to->rejected            = from->rejected;
        to->probes              = from->probes;
        PublishLatency(&to->latency, &from->latency);

        if(bHeld)
            to->downForMs = from->downUntilMs - nowMs;

        if(from->addr.ss_family == AF_INET)
        {
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)&from->addr;
            memcpy(to->address, &v4->sin_addr, 4);
            to->addressLen = 4;
            to->port       = ntohs(v4->sin_port);
        }
        else if(from->addr.ss_family == AF_INET6)
        {
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&from->addr;
            memcpy(to->address, &v6->sin6_addr, 16);
            to->addressLen = 16;
            to->port       = ntohs(v6->sin6_port);
        }
    }
}

void StatusPublish(Status *status, const Server *server, const Cache *cache,
                   const UpstreamPool *pool, const Blocklist *list,
                   const StatusSync *sync, const char *tier, uint32_t nowMs)
{
    if(status == NULL || status->block == NULL)
        return;

    StatusBlock *block = status->block;

    StoreSequence(&block->sequence, block->sequence + 1);

    block->pid      = (uint32_t)getpid();
    block->uptimeMs = nowMs - status->startedMs;

    if(server != NULL)
    {
        block->queries             = server->queries;
        block->hits                = server->hits;
        block->blocked             = server->blocked;
        block->local               = server->local;
        block->forwarded           = server->forwarded;
        block->failures            = server->failures;
        block->malformed           = server->malformed;
        block->truncated           = server->truncated;
        block->refusedConnections  = server->refusedConnections;
        block->evictedTransactions = server->evictedTransactions;
        block->retries             = server->retries;
        block->deferred            = server->deferred;
    }

    if(pool != NULL)
    {
        block->channelOpens  = pool->channelOpens;
        block->channelReuses = pool->channelReuses;
        block->channelStale  = pool->channelStale;
    }

    if(cache != NULL)
    {
        block->cacheHits      = cache->hits;
        block->cacheMisses    = cache->misses;
        block->cacheInserts   = cache->inserts;
        block->cacheEvictions = cache->evictions;
        block->cacheRejects   = cache->rejects;
    }

    if(list != NULL)
    {
        block->blocklistSource = (uint32_t)list->source;
        block->blocklistBytes  = list->size;
    }

    snprintf(block->blocklistTier, sizeof block->blocklistTier, "%s",
             (tier != NULL) ? tier : CFG_BLOCKLIST_TIER);

    if(server != NULL)
        PublishLatency(&block->service, &server->serviceLatency);

    /* Retaining the last live values would leave the final snapshot of a
       stopped daemon reporting a sync that is still running */
    if(sync != NULL)
        block->sync = *sync;
    else
        memset(&block->sync, 0, sizeof block->sync);

    PublishUpstreams(block, pool, nowMs);

    StoreSequence(&block->sequence, block->sequence + 1);
}

bool StatusRead(const char *path, StatusBlock *out)
{
    if(path == NULL || out == NULL)
        return false;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return false;

    struct stat info;
    if(fstat(fd, &info) != 0 || (size_t)info.st_size < sizeof(StatusBlock))
    {
        close(fd);
        return false;
    }

    void *at = mmap(NULL, sizeof(StatusBlock), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);

    if(at == MAP_FAILED)
        return false;

    const StatusBlock *block = at;
    bool               bRead = false;

    for(unsigned i = 0; i < STATUS_READ_TRIES; i++)
    {
        uint32_t before = LoadSequence(&block->sequence);
        if((before & 1u) != 0)
            continue;

        memcpy(out, block, sizeof *out);

        if(LoadSequence(&block->sequence) == before)
        {
            bRead = true;
            break;
        }
    }

    munmap(at, sizeof(StatusBlock));

    if(!bRead)
        return false;

    return memcmp(out->magic, STATUS_MAGIC, sizeof out->magic) == 0
        && out->version == STATUS_VERSION
        && out->bytes == sizeof(StatusBlock)
        && out->upstreamCount <= CFG_MAX_UPSTREAMS;
}

static const char *AddressText(const StatusUpstream *upstream, char *out,
                               size_t cap)
{
    int family = (upstream->addressLen == 16) ? AF_INET6 : AF_INET;

    if(upstream->addressLen == 0
       || inet_ntop(family, upstream->address, out, (socklen_t)cap) == NULL)
        snprintf(out, cap, "?");

    return out;
}

/* Choose units by magnitude without floating point */
static const char *DurationText(uint32_t us, char *out, size_t cap)
{
    if(us < 1000u)
        snprintf(out, cap, "%u us", us);
    else if(us < 1000000u)
        snprintf(out, cap, "%u.%02u ms", us / 1000u, (us % 1000u) / 10u);
    else
        snprintf(out, cap, "%u.%03u s", us / 1000000u, (us % 1000000u) / 1000u);

    return out;
}

static void PrintLatency(FILE *out, const char *label,
                         const StatusLatency *latency)
{
    if(latency->count == 0)
    {
        fprintf(out, "latency     %s, no samples\n", label);
        return;
    }

    char min[24];
    char mean[24];
    char p50[24];
    char p90[24];
    char p99[24];
    char max[24];

    fprintf(out, "latency     %s, n %llu, min %s, mean %s, p50 %s, p90 %s, "
                 "p99 %s, max %s\n",
            label, (unsigned long long)latency->count,
            DurationText(latency->minUs, min, sizeof min),
            DurationText(latency->meanUs, mean, sizeof mean),
            DurationText(latency->p50Us, p50, sizeof p50),
            DurationText(latency->p90Us, p90, sizeof p90),
            DurationText(latency->p99Us, p99, sizeof p99),
            DurationText(latency->maxUs, max, sizeof max));
}

void StatusPrint(const StatusBlock *block, FILE *out)
{
    if(block == NULL || out == NULL)
        return;

    fprintf(out, "pid         %u\n", block->pid);
    fprintf(out, "uptime      %llu s\n",
            (unsigned long long)(block->uptimeMs / 1000u));
    fprintf(out, "queries     %llu, hits %llu, blocked %llu, local %llu, "
                 "forwarded %llu, failed %llu\n",
            (unsigned long long)block->queries,
            (unsigned long long)block->hits,
            (unsigned long long)block->blocked,
            (unsigned long long)block->local,
            (unsigned long long)block->forwarded,
            (unsigned long long)block->failures);
    fprintf(out, "refused     malformed %llu, truncated %llu, connections %llu, "
                 "evicted %llu, retries %llu\n",
            (unsigned long long)block->malformed,
            (unsigned long long)block->truncated,
            (unsigned long long)block->refusedConnections,
            (unsigned long long)block->evictedTransactions,
            (unsigned long long)block->retries);
    fprintf(out, "deferred    %llu, waited for a free encrypted channel\n",
            (unsigned long long)block->deferred);
    fprintf(out, "channels    opened %llu, reused %llu, stale %llu\n",
            (unsigned long long)block->channelOpens,
            (unsigned long long)block->channelReuses,
            (unsigned long long)block->channelStale);
    fprintf(out, "cache       hits %llu, misses %llu, inserts %llu, "
                 "evictions %llu, refused %llu\n",
            (unsigned long long)block->cacheHits,
            (unsigned long long)block->cacheMisses,
            (unsigned long long)block->cacheInserts,
            (unsigned long long)block->cacheEvictions,
            (unsigned long long)block->cacheRejects);
    fprintf(out, "blocklist   %s, %llu bytes, tier %s\n",
            BlocklistSourceName((BlocklistSource)block->blocklistSource),
            (unsigned long long)block->blocklistBytes,
            (block->blocklistTier[0] != '\0') ? block->blocklistTier
                                              : "unnamed");
    fprintf(out, "sync        %s, next in %llu s, installed %llu bytes",
            (block->sync.bActive != 0) ? "running" : "idle",
            (unsigned long long)(block->sync.nextDueMs / 1000u),
            (unsigned long long)block->sync.installedBytes);

    /* A sync that keeps failing retries on a timer and is otherwise silent
       here, which is how two fetch buffer defects survived a green suite */
    if(block->sync.fail != 0)
        fprintf(out, ", %s", StatusSyncFailName(block->sync.fail));

    fprintf(out, "\n");
    PrintLatency(out, "service", &block->service);

    for(uint32_t i = 0; i < block->upstreamCount; i++)
    {
        const StatusUpstream *upstream = &block->upstreams[i];
        char                  address[64];
        char                  rtt[32];

        if(upstream->srttMs == UINT32_MAX)
            snprintf(rtt, sizeof rtt, "unmeasured");
        else
            snprintf(rtt, sizeof rtt, "%u ms", upstream->srttMs);

        fprintf(out, "upstream    %s:%u %s, %s, queries %llu, failures %llu, "
                     "rejected %llu, probes %llu",
                AddressText(upstream, address, sizeof address), upstream->port,
                StatusTransportName(upstream->transport), rtt,
                (unsigned long long)upstream->queries,
                (unsigned long long)upstream->failures,
                (unsigned long long)upstream->rejected,
                (unsigned long long)upstream->probes);

        if(upstream->bDown != 0)
            fprintf(out, ", held down for %u ms", upstream->downForMs);
        if(upstream->bUnusable != 0)
            fprintf(out, ", REFUSED THE PROTOCOL");

        fprintf(out, "\n");
        PrintLatency(out, "  round trip", &upstream->latency);
    }
}

bool StatusReport(const char *path, FILE *out)
{
    StatusBlock block;

    if(!StatusRead(path, &block))
        return false;

    StatusPrint(&block, out);
    return true;
}

const char *StatusSyncFailName(uint32_t fail)
{
    switch(fail)
    {
        case 0: return "no failure";
        case 1: return "the transfer failed";
        case 2: return "the staging file could not be opened";
        case 3: return "the listing names no such asset";
        case 4: return "the digest did not match";
        case 5: return "the install failed";
        case 6: return "the locator names no valid release";
        case 7: return "the release URL is invalid";
        case 8: return "the configured tier is not a valid name";
        case 9: return "no TLS channel was free";
        default: return "unknown";
    }
}

const char *StatusTransportName(uint8_t transport)
{
    switch(transport)
    {
        case UpstreamTransport_Plaintext: return "plain";
        case UpstreamTransport_Dot:       return "dot";
        case UpstreamTransport_Doh:       return "doh";
        default:                          return "unknown";
    }
}
