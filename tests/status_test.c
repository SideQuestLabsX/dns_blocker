#define _POSIX_C_SOURCE 200809L

#include "status.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int G_FAILURES;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if(!(cond))                                                        \
        {                                                                  \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

static void FillServer(Server *server)
{
    memset(server, 0, sizeof *server);
    server->queries             = 100;
    server->hits                = 40;
    server->blocked             = 7;
    server->local               = 3;
    server->forwarded           = 50;
    server->failures            = 2;
    server->malformed           = 1;
    server->truncated           = 4;
    server->refusedConnections  = 5;
    server->evictedTransactions = 6;
    server->retries             = 8;

    /* Exercise both printed duration units */
    LatencyAdd(&server->serviceLatency, 40);
    LatencyAdd(&server->serviceLatency, 200);
    LatencyAdd(&server->serviceLatency, 30000);
}

static void FillCache(Cache *cache)
{
    memset(cache, 0, sizeof *cache);
    cache->hits      = 40;
    cache->misses    = 60;
    cache->inserts   = 55;
    cache->evictions = 9;
    cache->rejects   = 2;
}

static void FillPool(UpstreamPool *pool)
{
    struct sockaddr_in address;

    memset(pool, 0, sizeof *pool);
    pool->count = 2;

    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port   = htons(853);
    CHECK(inet_pton(AF_INET, "1.1.1.1", &address.sin_addr) == 1);
    memcpy(&pool->members[0].addr, &address, sizeof address);
    pool->members[0].addrLen   = sizeof address;
    pool->members[0].transport = UpstreamTransport_Dot;
    pool->members[0].srttMs    = 23;
    pool->members[0].queries   = 90;
    LatencyAdd(&pool->members[0].latency, 20000);
    LatencyAdd(&pool->members[0].latency, 24000);
    LatencyAdd(&pool->members[0].latency, 28000);

    CHECK(inet_pton(AF_INET, "9.9.9.9", &address.sin_addr) == 1);
    memcpy(&pool->members[1].addr, &address, sizeof address);
    pool->members[1].addrLen             = sizeof address;
    pool->members[1].transport           = UpstreamTransport_Doh;
    pool->members[1].srttMs              = UINT32_MAX;
    pool->members[1].bDown               = true;
    pool->members[1].downUntilMs         = 5000;
    pool->members[1].consecutiveFailures = 3;
    pool->members[1].failures            = 3;
}

static void TestPublishAndRead(const char *path)
{
    Status       status;
    Server       server;
    Cache        cache;
    UpstreamPool pool;
    Blocklist    list;
    StatusBlock  block;
    StatusSync   sync = { 0, 0, 6543894, 900000 };

    FillServer(&server);
    FillCache(&cache);
    FillPool(&pool);

    memset(&list, 0, sizeof list);
    list.source = BlocklistSource_Mapped;
    list.size   = 6543894;

    CHECK(StatusOpen(&status, path, 1000));
    StatusPublish(&status, &server, &cache, &pool, &list, &sync, NULL, 4000);

    CHECK(StatusRead(path, &block));
    CHECK(block.version == STATUS_VERSION);
    CHECK(block.bytes == sizeof(StatusBlock));
    CHECK(block.uptimeMs == 3000);
    CHECK(block.pid == (uint32_t)getpid());

    CHECK(block.queries == 100);
    CHECK(block.hits == 40);
    CHECK(block.blocked == 7);
    CHECK(block.retries == 8);
    CHECK(block.cacheEvictions == 9);
    CHECK(block.blocklistBytes == 6543894);
    CHECK(block.blocklistSource == (uint32_t)BlocklistSource_Mapped);
    CHECK(strcmp(block.blocklistTier, CFG_BLOCKLIST_TIER) == 0);
    CHECK(block.sync.installedBytes == 6543894);

    CHECK(block.service.count == 3);
    CHECK(block.service.minUs == 40);
    CHECK(block.service.maxUs == 30000);
    CHECK(block.service.meanUs == (40 + 200 + 30000) / 3);
    CHECK(block.service.p50Us >= block.service.minUs);
    CHECK(block.service.p99Us <= block.service.maxUs);

    CHECK(block.upstreamCount == 2);
    CHECK(block.upstreams[0].addressLen == 4);
    CHECK(block.upstreams[0].port == 853);
    CHECK(block.upstreams[0].srttMs == 23);
    CHECK(block.upstreams[0].bDown == 0);
    CHECK(block.upstreams[0].latency.count == 3);
    CHECK(block.upstreams[0].latency.minUs == 20000);
    CHECK(block.upstreams[0].latency.maxUs == 28000);
    CHECK(block.upstreams[1].latency.count == 0);
    CHECK(strcmp(StatusTransportName(block.upstreams[0].transport), "dot") == 0);

    /* Held down until 5000 and the snapshot was taken at 4000 */
    CHECK(block.upstreams[1].bDown == 1);
    CHECK(block.upstreams[1].downForMs == 1000);
    CHECK(block.upstreams[1].srttMs == UINT32_MAX);
    CHECK(strcmp(StatusTransportName(block.upstreams[1].transport), "doh") == 0);

    /* A second snapshot moves the counter by two and leaves it even */
    uint32_t before = status.block->sequence;
    StatusPublish(&status, &server, &cache, &pool, &list, &sync, NULL, 5000);
    CHECK(status.block->sequence == before + 2);
    CHECK((status.block->sequence & 1u) == 0);

    StatusClose(&status);
    CHECK(status.block == NULL);
}

/* Status text is part of the operator interface */
static void TestPrintRenders(const char *path)
{
    Status       status;
    Server       server;
    Cache        cache;
    UpstreamPool pool;
    Blocklist    list;
    StatusBlock  block;
    StatusSync   sync = { 0, 0, 6543894, 900000 };

    FillServer(&server);
    FillCache(&cache);
    FillPool(&pool);

    memset(&list, 0, sizeof list);
    list.source = BlocklistSource_Mapped;
    list.size   = 6543894;

    CHECK(StatusOpen(&status, path, 1000));
    StatusPublish(&status, &server, &cache, &pool, &list, &sync, NULL, 4000);
    StatusClose(&status);

    CHECK(StatusRead(path, &block));

    char  *text = NULL;
    size_t len  = 0;
    FILE  *out  = open_memstream(&text, &len);

    CHECK(out != NULL);
    if(out == NULL)
        return;

    StatusPrint(&block, out);
    fclose(out);

    CHECK(strstr(text, "tier " CFG_BLOCKLIST_TIER) != NULL);
    CHECK(strstr(text, "latency     service, n 3,") != NULL);
    CHECK(strstr(text, "round trip, n 3,") != NULL);
    CHECK(strstr(text, "round trip, no samples") != NULL);

    CHECK(strstr(text, "min 40 us") != NULL);
    CHECK(strstr(text, "max 30.00 ms") != NULL);
    CHECK(strstr(text, "min 20.00 ms") != NULL);

    /* Catch format and argument mismatches */
    CHECK(strstr(text, "(null)") == NULL);
    CHECK(strstr(text, "%") == NULL);

    free(text);
    unlink(path);
}

/* A reader that copies while the writer is inside a snapshot has to notice and
   try again, rather than reporting a half-written mixture. */
static void TestTornReadIsRefused(const char *path)
{
    Status      status;
    Server      server;
    StatusBlock block;

    FillServer(&server);

    CHECK(StatusOpen(&status, path, 0));
    StatusPublish(&status, &server, NULL, NULL, NULL, NULL, NULL, 0);
    CHECK(StatusRead(path, &block));

    /* Leave the counter odd, which is what a writer part-way through looks
       like */
    status.block->sequence |= 1u;
    CHECK(!StatusRead(path, &block));

    status.block->sequence += 1u;
    CHECK(StatusRead(path, &block));

    StatusClose(&status);
}

static void TestForeignSegmentIsRefused(const char *path)
{
    Status      status;
    StatusBlock block;

    CHECK(StatusOpen(&status, path, 0));
    CHECK(StatusRead(path, &block));

    status.block->version = STATUS_VERSION + 1;
    CHECK(!StatusRead(path, &block));
    status.block->version = STATUS_VERSION;

    memcpy(status.block->magic, "XXXX", 4);
    CHECK(!StatusRead(path, &block));
    memcpy(status.block->magic, STATUS_MAGIC, 4);

    status.block->upstreamCount = CFG_MAX_UPSTREAMS + 1;
    CHECK(!StatusRead(path, &block));

    StatusClose(&status);
}

static void TestRefusals(const char *dir)
{
    Status      status;
    StatusBlock block;
    char        missing[256];

    snprintf(missing, sizeof missing, "%s/absent/status", dir);

    CHECK(!StatusOpen(NULL, "/tmp/x", 0));
    CHECK(!StatusOpen(&status, NULL, 0));
    CHECK(!StatusOpen(&status, missing, 0));

    CHECK(!StatusRead(missing, &block));
    CHECK(!StatusRead(NULL, &block));

    /* Every entry point tolerates a segment that was never opened */
    status.block = NULL;
    StatusPublish(&status, NULL, NULL, NULL, NULL, NULL, NULL, 0);
    StatusClose(&status);
    StatusPublish(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
    StatusClose(NULL);

    CHECK(strcmp(StatusTransportName(200), "unknown") == 0);
}

/* A file left by an older run must not read as this one's state before the
   first snapshot lands. */
static void TestStaleSegmentIsReset(const char *path)
{
    Status      status;
    Server      server;
    StatusBlock block;

    FillServer(&server);

    CHECK(StatusOpen(&status, path, 0));
    StatusPublish(&status, &server, NULL, NULL, NULL, NULL, NULL, 0);
    StatusClose(&status);

    CHECK(StatusRead(path, &block));
    CHECK(block.queries == 100);

    CHECK(StatusOpen(&status, path, 0));
    CHECK(StatusRead(path, &block));
    CHECK(block.queries == 0);

    StatusClose(&status);
}

int main(void)
{
    char dir[] = "/tmp/dns_blocker_status_XXXXXX";
    char path[256];

    if(mkdtemp(dir) == NULL)
    {
        printf("status: cannot create a temporary directory\n");
        return 1;
    }

    snprintf(path, sizeof path, "%s/status", dir);

    TestPublishAndRead(path);
    TestPrintRenders(path);
    TestTornReadIsRefused(path);
    TestForeignSegmentIsRefused(path);
    TestStaleSegmentIsReset(path);
    TestRefusals(dir);

    unlink(path);
    rmdir(dir);

    if(G_FAILURES != 0)
    {
        printf("status: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("status: all checks passed\n");
    return 0;
}
