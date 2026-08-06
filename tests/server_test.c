#define _GNU_SOURCE

#include "arena.h"
#include "blocklist.h"
#include "cache.h"
#include "msg.h"
#include "server.h"
#include "upstream.h"
#include "wire.h"

#include "dnsbuild.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
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

#define SERVER_PORT    15353
#define UPSTREAM_PORT  15354
#define UPSTREAM_PORT2 15355

static const uint8_t G_PTR_PREFIX[4] = { 192, 168, 1, 0 };

/* A stand-in resolver. It echoes the question and answers with one A record,
   keeping whatever transaction ID the daemon chose, which is what lets the
   test prove the daemon rewrites it before replying to the client. */
typedef struct
{
    int         fd;
    uint32_t    answerTtl;
    int         padding;
    bool        bSilent;
    const char *silentName;
    int         delayMs;
    volatile bool bStop;
    volatile int  served;
} FakeUpstream;

/* The answer has to be owned by the name that was asked, or the daemon's
   bailiwick check rejects it, which is exactly what that check is for. */
static void PutAnswerFor(Builder *b, const WireQuestion *question, uint32_t ttl)
{
    PutBytes(b, question->name.wire, question->name.len);
    PutU16(b, WIRE_TYPE_A);
    PutU16(b, WIRE_CLASS_IN);
    PutU32(b, ttl);
    PutU16(b, 4);
    PutU8(b, 93);
    PutU8(b, 184);
    PutU8(b, 216);
    PutU8(b, 34);
}

static void *FakeUpstreamMain(void *arg)
{
    FakeUpstream *fake = arg;

    while(!fake->bStop)
    {
        uint8_t                 query[4096];
        uint8_t                 reply[8192];
        struct sockaddr_storage from;
        socklen_t               fromLen = sizeof from;

        ssize_t got = recvfrom(fake->fd, query, sizeof query, 0,
                               (struct sockaddr *)&from, &fromLen);
        if(got < (ssize_t)WIRE_HEADER_BYTES)
            continue;

        if(fake->bSilent)
        {
            fake->served++;
            continue;
        }

        Reader       reader;
        WireHeader   header;
        WireQuestion question;

        ReaderInit(&reader, query, (size_t)got);
        if(!WireParseHeader(&reader, &header)
           || !WireParseQuestion(&reader, &question))
            continue;

        /* One name the resolver never answers, so a test can hold a query open
           while other clients keep being served. */
        if(fake->silentName != NULL)
        {
            WireName quiet;
            if(NameOf(fake->silentName, &quiet)
               && WireNameEqual(&question.name, &quiet))
            {
                fake->served++;
                continue;
            }
        }

        if(fake->delayMs > 0)
        {
            struct timespec nap = {
                .tv_sec  = fake->delayMs / 1000,
                .tv_nsec = (long)(fake->delayMs % 1000) * 1000000L
            };
            nanosleep(&nap, NULL);
        }

        Builder b = { reply, sizeof reply, 0 };
        PutHeader(&b, header.id, 0x8180u, 1, 1, 0, 0);
        PutBytes(&b, query + WIRE_HEADER_BYTES,
                 reader.pos - WIRE_HEADER_BYTES);
        PutAnswerFor(&b, &question, fake->answerTtl);

        /* Optional filler so the reply crosses the 512-byte UDP limit. */
        for(int i = 0; i < fake->padding; i++)
            PutAnswerFor(&b, &question, fake->answerTtl);

        if(fake->padding > 0)
        {
            reply[6] = (uint8_t)((1 + fake->padding) >> 8);
            reply[7] = (uint8_t)(1 + fake->padding);
        }

        sendto(fake->fd, reply, b.len, 0, (struct sockaddr *)&from, fromLen);
        fake->served++;
    }

    return NULL;
}

static int OpenLoopbackUdp(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if(fd >= 0 && bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static int ConnectLoopback(uint16_t port, int type)
{
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if(fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

/* A trie holding one name, so the server fixture can exercise the blocked
   path. Built by hand in the on-disk layout, the same as blocklist_test. */
static uint8_t G_TRIE[256];

static void TriePut32(uint8_t *at, uint32_t v)
{
    at[0] = (uint8_t)v;
    at[1] = (uint8_t)(v >> 8);
    at[2] = (uint8_t)(v >> 16);
    at[3] = (uint8_t)(v >> 24);
}

/* com -> example -> blocked(terminal) */
static void TrieBuild(Blocklist *list)
{
    static const char *labels[] = { "com", "example", "blocked" };

    uint8_t *nodes = G_TRIE + BLOCKLIST_HEADER_BYTES;
    uint32_t offsets[3];
    uint32_t at = 0;

    for(size_t i = 0; i < 3; i++)
    {
        offsets[i] = at;
        TriePut32(nodes + at, 1);
        at += 4 + BLOCKLIST_CHILD_BYTES;
    }

    uint32_t poolAt   = 0;
    uint8_t *poolStart = nodes + at;

    for(size_t i = 0; i < 3; i++)
    {
        uint8_t *entry = nodes + offsets[i] + 4;
        size_t   len   = strlen(labels[i]);
        bool     bLast = (i == 2);

        memcpy(poolStart + poolAt, labels[i], len);
        TriePut32(entry, poolAt);
        TriePut32(entry + 4, bLast ? 0u : offsets[i + 1]);
        entry[8]  = (uint8_t)len;
        entry[9]  = bLast ? BLOCKLIST_FLAG_TERMINAL : 0u;
        entry[10] = 0;
        entry[11] = 0;
        poolAt += (uint32_t)len;
    }

    memcpy(G_TRIE, BLOCKLIST_MAGIC, 4);
    TriePut32(G_TRIE + 4, at);
    TriePut32(G_TRIE + 8, poolAt);
    TriePut32(G_TRIE + 12, 0);

    memset(list, 0, sizeof *list);
    list->base   = G_TRIE;
    list->size   = BLOCKLIST_HEADER_BYTES + at + poolAt;
    list->source = BlocklistSource_Mapped;
    BlocklistParseHeader(list, list->base, list->size);
}

typedef struct
{
    Arena        arena;
    Arena        connArena;
    Arena        txArena;
    Arena        hostsArena;
    Cache        cache;
    Blocklist    blocklist;
    HostMap      hosts;
    UpstreamPool upstreams;
    UpstreamPool ptrRouter;
    Server       server;
    FakeUpstream fake;
    pthread_t    thread;
    bool         bThread;
    bool         bArenaReady;
    bool         bServerReady;

    /* Only the failover test needs a second resolver, and only then is it in
       the pool. */
    FakeUpstream fake2;
    pthread_t    thread2;
    bool         bThread2;
} Fixture;

static void FixtureDown(Fixture *fix);

static bool FixtureStart(Fixture *fix, uint32_t ttl, int padding, bool bSilent,
                         bool bPtrRoute)
{
    memset(fix, 0, sizeof *fix);
    fix->fake.fd  = -1;
    fix->fake2.fd = -1;

    fix->fake.fd        = OpenLoopbackUdp(UPSTREAM_PORT);
    fix->fake.answerTtl = ttl;
    fix->fake.padding   = padding;
    fix->fake.bSilent   = bSilent;

    if(fix->fake.fd < 0)
        goto fail;

    if(pthread_create(&fix->thread, NULL, FakeUpstreamMain, &fix->fake) != 0)
        goto fail;
    fix->bThread = true;

    UpstreamPoolInit(&fix->upstreams, ServerNowMilliseconds());

    if(bPtrRoute)
        UpstreamPoolInit(&fix->ptrRouter, ServerNowMilliseconds());

    if(!ArenaInit(&fix->arena, 2048u * 1024u))
        goto fail;
    fix->bArenaReady = true;

    if(!CacheInit(&fix->cache, &fix->arena)
       || !ArenaCarve(&fix->arena, &fix->connArena, ARENA_CONN_BYTES)
       || !ArenaCarve(&fix->arena, &fix->txArena, ARENA_TXTABLE_BYTES)
       || !ArenaCarve(&fix->arena, &fix->hostsArena, ARENA_HOSTS_BYTES)
       || !HostsLoad(&fix->hosts, &fix->hostsArena, NULL)
       || !UpstreamPoolAdd(&fix->upstreams, "127.0.0.1", UPSTREAM_PORT)
       || (bPtrRoute
           && !UpstreamPoolAdd(&fix->ptrRouter, "127.0.0.1", UPSTREAM_PORT)))
        goto fail;

    if(!ServerOpen(&fix->server, &fix->cache, &fix->upstreams,
                   &fix->blocklist, &fix->hosts,
                   bPtrRoute ? &fix->ptrRouter : NULL,
                   bPtrRoute ? G_PTR_PREFIX : NULL,
                   bPtrRoute ? 24 : 0,
                   &fix->connArena, &fix->txArena, SERVER_PORT))
        goto fail;

    fix->bServerReady = true;
    return true;

fail:
    FixtureDown(fix);
    return false;
}

static bool FixtureUp(Fixture *fix, uint32_t ttl, int padding, bool bSilent)
{
    return FixtureStart(fix, ttl, padding, bSilent, false);
}

static bool FixturePtrRouteUp(Fixture *fix, uint32_t ttl)
{
    return FixtureStart(fix, ttl, 0, false, true);
}

/* A second resolver that always answers, behind a first one that never does,
   so a retry has somewhere to go. */
static bool FixturePairUp(Fixture *fix, uint32_t ttl)
{
    if(!FixtureUp(fix, ttl, 0, true))
        return false;

    fix->fake2.fd        = OpenLoopbackUdp(UPSTREAM_PORT2);
    fix->fake2.answerTtl = ttl;

    if(fix->fake2.fd < 0)
    {
        FixtureDown(fix);
        return false;
    }

    if(pthread_create(&fix->thread2, NULL, FakeUpstreamMain, &fix->fake2) != 0)
    {
        FixtureDown(fix);
        return false;
    }

    fix->bThread2 = true;
    if(!UpstreamPoolAdd(&fix->upstreams, "127.0.0.1", UPSTREAM_PORT2))
    {
        FixtureDown(fix);
        return false;
    }

    return true;
}

/* The thread is parked in recvfrom, so it only sees bStop after a datagram. */
static void StopFake(FakeUpstream *fake, pthread_t thread, uint16_t port)
{
    uint8_t poke = 0;
    struct sockaddr_in addr;

    fake->bStop = true;

    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int poker = socket(AF_INET, SOCK_DGRAM, 0);
    if(poker >= 0)
    {
        sendto(poker, &poke, 1, 0, (struct sockaddr *)&addr, sizeof addr);
        close(poker);
    }

    pthread_join(thread, NULL);
    close(fake->fd);
}

static void FixtureDown(Fixture *fix)
{
    if(fix->bThread)
    {
        StopFake(&fix->fake, fix->thread, UPSTREAM_PORT);
        fix->bThread = false;
        fix->fake.fd = -1;
    }
    else if(fix->fake.fd >= 0)
    {
        close(fix->fake.fd);
        fix->fake.fd = -1;
    }

    if(fix->bThread2)
    {
        StopFake(&fix->fake2, fix->thread2, UPSTREAM_PORT2);
        fix->bThread2 = false;
        fix->fake2.fd = -1;
    }
    else if(fix->fake2.fd >= 0)
    {
        close(fix->fake2.fd);
        fix->fake2.fd = -1;
    }

    if(fix->bServerReady)
    {
        ServerClose(&fix->server);
        fix->bServerReady = false;
    }

    if(fix->bArenaReady)
    {
        ArenaRelease(&fix->arena);
        fix->bArenaReady = false;
    }
}

static void Pump(Server *server, int times)
{
    for(int i = 0; i < times; i++)
        ServerPoll(server, 200);
}

/* Short waits, so a whole sequence finishes inside one upstream timeout. */
static void PumpBriefly(Server *server, int times)
{
    for(int i = 0; i < times; i++)
        ServerPoll(server, 10);
}

static void TestUdpQueryIsForwardedAndAnswered(void)
{
    Fixture  fix;
    uint8_t  query[512];
    uint8_t  reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP udp: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t queryLen = BuildQuery(query, sizeof query, 0xBEEF,
                                 "a.example.com", WIRE_TYPE_A);
    CHECK(send(client, query, queryLen, 0) == (ssize_t)queryLen);

    Pump(&fix.server, 6);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);

    if(got > 0)
    {
        /* The daemon sent its own random ID upstream, so this passing is the
           evidence that the reply was rewritten for this client. */
        CHECK(MsgId(reply, (size_t)got) == 0xBEEF);
        CHECK((MsgFlags(reply, (size_t)got) & MSG_FLAG_QR) != 0);
        CHECK(fix.server.forwarded == 1);
        CHECK(fix.server.hits == 0);
    }

    close(client);
    FixtureDown(&fix);
}

static void TestSecondQueryIsACacheHit(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP cache hit: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t queryLen = BuildQuery(query, sizeof query, 0x1111,
                                 "a.example.com", WIRE_TYPE_A);
    send(client, query, queryLen, 0);
    Pump(&fix.server, 6);
    recv(client, reply, sizeof reply, MSG_DONTWAIT);

    queryLen = BuildQuery(query, sizeof query, 0x2222,
                          "a.example.com", WIRE_TYPE_A);
    send(client, query, queryLen, 0);
    Pump(&fix.server, 6);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);

    if(got > 0)
    {
        /* A hit replays stored bytes whose ID belongs to the first exchange. */
        CHECK(MsgId(reply, (size_t)got) == 0x2222);
        CHECK(fix.server.hits == 1);
        CHECK(fix.server.forwarded == 1);
        CHECK(fix.fake.served == 1);
    }

    close(client);
    FixtureDown(&fix);
}

static void TestTcpQuery(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t framed[514];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP tcp: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_STREAM);
    CHECK(client >= 0);

    Pump(&fix.server, 2);

    size_t queryLen = BuildQuery(query, sizeof query, 0x7A7A,
                                 "a.example.com", WIRE_TYPE_A);
    framed[0] = (uint8_t)(queryLen >> 8);
    framed[1] = (uint8_t)queryLen;
    memcpy(framed + 2, query, queryLen);

    CHECK(send(client, framed, queryLen + 2, 0) == (ssize_t)(queryLen + 2));

    Pump(&fix.server, 8);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)(2 + WIRE_HEADER_BYTES));

    if(got > 2)
    {
        size_t declared = ((size_t)reply[0] << 8) | reply[1];
        CHECK(declared == (size_t)got - 2);
        CHECK(MsgId(reply + 2, declared) == 0x7A7A);
    }

    close(client);
    FixtureDown(&fix);
}

static void TestOversizedUdpAnswerSetsTruncated(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    /* No EDNS in the query, so the client's limit is 512 bytes and a padded
       answer must come back with TC rather than as a large datagram. */
    if(!FixtureUp(&fix, 300, 24, false))
    {
        printf("SKIP truncation: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t queryLen = BuildQuery(query, sizeof query, 0x0F0F,
                                 "a.example.com", WIRE_TYPE_A);
    send(client, query, queryLen, 0);
    Pump(&fix.server, 6);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > 0);

    if(got > 0)
    {
        CHECK((MsgFlags(reply, (size_t)got) & MSG_FLAG_TC) != 0);
        CHECK(got <= 512);
        CHECK(MsgId(reply, (size_t)got) == 0x0F0F);
        CHECK(fix.server.truncated == 1);
    }

    close(client);
    FixtureDown(&fix);
}

static void TestUpstreamSilenceBecomesServfail(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, true))
    {
        printf("SKIP servfail: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t queryLen = BuildQuery(query, sizeof query, 0x4242,
                                 "a.example.com", WIRE_TYPE_A);
    send(client, query, queryLen, 0);

    /* Three attempts at the two-second timeout. */
    Pump(&fix.server, 6);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);

    if(got > 0)
    {
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_SERVFAIL);
        CHECK(MsgId(reply, (size_t)got) == 0x4242);
        CHECK(fix.server.failures == 1);
    }

    close(client);
    FixtureDown(&fix);
}

/* A silent resolver must not become the client's problem while another one is
   configured. The retry has to change resolver, not repeat the question to the
   one that already ignored it. */
static void TestRetryMovesToTheSecondUpstream(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    if(!FixturePairUp(&fix, 300))
    {
        printf("SKIP failover: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t queryLen = BuildQuery(query, sizeof query, 0x5151,
                                 "a.example.com", WIRE_TYPE_A);
    send(client, query, queryLen, 0);

    Pump(&fix.server, 6);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);

    if(got > 0)
    {
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NOERROR);
        CHECK(MsgId(reply, (size_t)got) == 0x5151);
    }

    CHECK(fix.server.failures == 0);
    CHECK(fix.server.retries >= 1);
    CHECK(fix.fake.served >= 1);
    CHECK(fix.fake2.served >= 1);

    /* The failure is recorded against the resolver that earned it. */
    CHECK(fix.upstreams.members[0].failures >= 1);
    CHECK(fix.upstreams.members[1].failures == 0);

    /* And the answer is a measurement of the one that sent it. */
    CHECK(fix.upstreams.members[1].srttMs != UPSTREAM_RTT_NONE);
    CHECK(fix.upstreams.members[0].srttMs == UPSTREAM_RTT_NONE);

    close(client);
    FixtureDown(&fix);
}

static void TestStartFailureMovesToTheSecondUpstream(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    if(!FixturePairUp(&fix, 300))
    {
        printf("SKIP start failover: cannot bind test ports\n");
        return;
    }

    fix.upstreams.members[0].addrLen = 0;
    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t queryLen = BuildQuery(query, sizeof query, 0x4545,
                                 "a.example.com", WIRE_TYPE_A);
    CHECK(send(client, query, queryLen, 0) == (ssize_t)queryLen);
    Pump(&fix.server, 6);

    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT)
          > (ssize_t)WIRE_HEADER_BYTES);
    CHECK(fix.server.retries == 1);
    CHECK(fix.upstreams.members[0].failures == 1);
    CHECK(fix.fake2.served >= 1);

    close(client);
    FixtureDown(&fix);
}

/* The probe is the only reason an upstream nobody is using ever gets a
   reading. It has to complete through the poll loop and leave a measurement,
   without going near a client query. */
static void TestProbeMeasuresAnUnselectedUpstream(void)
{
    Fixture fix;

    if(!FixturePairUp(&fix, 300))
    {
        printf("SKIP probe: cannot bind test ports\n");
        return;
    }

    fix.upstreams.probeDeadlineMs = ServerNowMilliseconds();
    CHECK(UpstreamPoolProbeBegin(&fix.upstreams, ServerNowMilliseconds()));

    /* Nothing is measured yet, so the first address is selected and the probe
       goes to the other one. */
    CHECK(fix.upstreams.bProbing);
    CHECK(fix.upstreams.probe.index == 1);

    PumpBriefly(&fix.server, 8);

    CHECK(!fix.upstreams.bProbing);
    CHECK(fix.upstreams.probeFailures == 0);
    CHECK(fix.upstreams.members[1].srttMs != UPSTREAM_RTT_NONE);
    CHECK(fix.fake2.served >= 1);

    /* No client asked for any of this. */
    CHECK(fix.server.queries == 0);
    CHECK(fix.server.forwarded == 0);

    FixtureDown(&fix);
}

static void TestResponseSentToListenerIsIgnored(void)
{
    Fixture fix;
    uint8_t response[512];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP loop guard: cannot bind test ports\n");
        return;
    }

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    /* Two resolvers pointed at each other would trade this forever. */
    size_t len = BuildPositive(response, sizeof response, "a.example.com", 300);
    send(client, response, len, 0);
    Pump(&fix.server, 6);

    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT) < 0);
    CHECK(fix.server.malformed == 1);
    CHECK(fix.server.forwarded == 0);

    close(client);
    FixtureDown(&fix);
}


/* The reason the in-flight table exists. Before it, HandleQuery waited inside
   the poll loop, so one unanswered query stalled every other client for the
   whole timeout and retry budget. */
static void TestOneStalledQueryDoesNotBlockOthers(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP head of line: cannot bind test ports\n");
        return;
    }

    fix.fake.silentName = "slow.example.com";

    int stalled = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    int prompt  = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(stalled >= 0 && prompt >= 0);

    size_t slowLen = BuildQuery(query, sizeof query, 0xAAAA,
                                "slow.example.com", WIRE_TYPE_A);
    CHECK(send(stalled, query, slowLen, 0) == (ssize_t)slowLen);
    PumpBriefly(&fix.server, 2);

    size_t fastLen = BuildQuery(query, sizeof query, 0xBBBB,
                                "a.example.com", WIRE_TYPE_A);
    CHECK(send(prompt, query, fastLen, 0) == (ssize_t)fastLen);
    PumpBriefly(&fix.server, 6);

    /* The whole sequence fits inside one upstream timeout, so the first query
       is still waiting. The synchronous path would not have read the second
       query at all until the first gave up. */
    ssize_t served = recv(prompt, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(served > (ssize_t)WIRE_HEADER_BYTES);
    if(served > 0)
        CHECK(MsgId(reply, (size_t)served) == 0xBBBB);

    CHECK(recv(stalled, reply, sizeof reply, MSG_DONTWAIT) < 0);

    /* And it does eventually give up rather than leaking the slot. */
    Pump(&fix.server, 6);
    ssize_t late = recv(stalled, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(late > (ssize_t)WIRE_HEADER_BYTES);
    if(late > 0)
    {
        CHECK(MsgId(reply, (size_t)late) == 0xAAAA);
        CHECK((MsgFlags(reply, (size_t)late) & 0x000Fu) == MSG_RCODE_SERVFAIL);
    }

    close(stalled);
    close(prompt);
    FixtureDown(&fix);
}

/* At capacity the oldest slot is taken. The client that loses it gets an
   answer, so nothing is left waiting for a reply that never comes. */
static void TestTableFullEvictsOldest(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];
    int     clients[CFG_TX_SLOTS + 4];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP eviction: cannot bind test ports\n");
        return;
    }

    fix.fake.silentName = "slow.example.com";

    for(size_t i = 0; i < CFG_TX_SLOTS + 4; i++)
    {
        clients[i] = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
        size_t len = BuildQuery(query, sizeof query, (uint16_t)(0x100 + i),
                                "slow.example.com", WIRE_TYPE_A);
        send(clients[i], query, len, 0);
        PumpBriefly(&fix.server, 1);
    }

    PumpBriefly(&fix.server, 3);
    CHECK(fix.server.evictedTransactions >= 4);

    /* Counted before any upstream timeout can fire, so these answers can only
       have come from eviction. A table that silently reuses a slot leaves the
       displaced client waiting instead. */
    size_t answered = 0;
    for(size_t i = 0; i < CFG_TX_SLOTS + 4; i++)
    {
        if(recv(clients[i], reply, sizeof reply, MSG_DONTWAIT) > 0)
            answered++;

        close(clients[i]);
    }

    CHECK(answered >= 4);
    FixtureDown(&fix);
}

/* A client that hangs up while its query is in flight must not have the answer
   written into whatever now owns that connection slot. */
static void TestTcpClientVanishingMidQuery(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t framed[514];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP tcp vanish: cannot bind test ports\n");
        return;
    }

    /* The answer arrives after the first client has gone, which is what puts
       a stale reply and a reused connection slot in the same moment. */
    fix.fake.delayMs = 40;

    int first = ConnectLoopback(SERVER_PORT, SOCK_STREAM);
    CHECK(first >= 0);
    PumpBriefly(&fix.server, 2);

    size_t len = BuildQuery(query, sizeof query, 0xCCCC,
                            "a.example.com", WIRE_TYPE_A);
    framed[0] = (uint8_t)(len >> 8);
    framed[1] = (uint8_t)len;
    memcpy(framed + 2, query, len);
    send(first, framed, len + 2, 0);
    PumpBriefly(&fix.server, 1);
    close(first);

    /* The server has to notice the hang-up and free the slot, or the second
       connection lands somewhere else and the reuse is never exercised. */
    PumpBriefly(&fix.server, 3);
    CHECK(fix.server.conns[0].fd < 0);

    /* A new connection takes the slot the first one just released. */
    int second = ConnectLoopback(SERVER_PORT, SOCK_STREAM);
    CHECK(second >= 0);
    PumpBriefly(&fix.server, 2);

    CHECK(fix.server.conns[0].fd >= 0);
    len = BuildQuery(query, sizeof query, 0xDDDD, "b.example.com", WIRE_TYPE_A);
    framed[0] = (uint8_t)(len >> 8);
    framed[1] = (uint8_t)len;
    memcpy(framed + 2, query, len);
    send(second, framed, len + 2, 0);

    Pump(&fix.server, 10);

    ssize_t got = recv(second, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)(2 + WIRE_HEADER_BYTES));

    if(got > 2)
    {
        /* The first client's answer must not land here. */
        size_t declared = ((size_t)reply[0] << 8) | reply[1];
        CHECK(MsgId(reply + 2, declared) == 0xDDDD);
    }

    close(second);
    FixtureDown(&fix);
}


/* A blocked name is answered here. It must never reach the upstream, and it
   must never take a cache slot. */
static void AddHost(HostMap *map, const char *dotted, const uint8_t *addr,
                    uint8_t addrLen)
{
    WireName name;

    if(!NameOf(dotted, &name) || map->count == map->capacity)
        return;

    map->entries[map->count].name    = name;
    map->entries[map->count].addrLen = addrLen;
    memcpy(map->entries[map->count].addr, addr, addrLen);
    map->count++;
}

/* The map answers before the blocklist, before the cache and without the
   upstream, in both directions. */
static void TestLocalNamesAreAnsweredHere(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];
    static const uint8_t phone[4] = { 192, 168, 1, 47 };

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP local: cannot bind test ports\n");
        return;
    }

    AddHost(&fix.hosts, "iphone.lan", phone, 4);

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t len = BuildQuery(query, sizeof query, 0x6161, "iphone.lan",
                            WIRE_TYPE_A);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);

    if(got > 0)
    {
        CHECK(MsgId(reply, (size_t)got) == 0x6161);
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NOERROR);

        /* One answer, and the address the file gave. */
        CHECK(reply[7] == 1);
        CHECK(memcmp(reply + (size_t)got - 4, phone, 4) == 0);
    }

    /* The name exists without an AAAA, which is NODATA rather than NXDOMAIN. */
    len = BuildQuery(query, sizeof query, 0x6262, "iphone.lan", WIRE_TYPE_AAAA);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);
    if(got > 0)
    {
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NOERROR);
        CHECK(reply[7] == 0);
    }

    len = BuildQuery(query, sizeof query, 0x6363, "47.1.168.192.in-addr.arpa",
                     WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);
    if(got > 0)
    {
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NOERROR);
        CHECK(reply[7] == 1);
    }

    /* An address on the LAN that nothing claims is answered here as well, so
       the internal addressing never reaches the upstream. */
    len = BuildQuery(query, sizeof query, 0x6464, "99.1.168.192.in-addr.arpa",
                     WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);
    if(got > 0)
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NXDOMAIN);

    CHECK(fix.server.local == 4);
    CHECK(fix.server.forwarded == 0);
    CHECK(fix.fake.served == 0);

    /* A name in the local domain that the map does not have stops here too,
       rather than handing a device name to a public resolver. */
    len = BuildQuery(query, sizeof query, 0x6666, "unknown.lan", WIRE_TYPE_A);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);
    if(got > 0)
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NXDOMAIN);

    CHECK(fix.server.local == 5);
    CHECK(fix.server.forwarded == 0);

    /* A public reverse name is none of our business and goes upstream. */
    len = BuildQuery(query, sizeof query, 0x6565, "9.113.0.203.in-addr.arpa",
                     WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 6);
    CHECK(fix.server.local == 5);
    CHECK(fix.server.forwarded == 1);

    close(client);
    FixtureDown(&fix);
}

static void TestUnknownLocalPtrGoesToRouter(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];
    static const uint8_t phone[4] = { 192, 168, 1, 47 };

    if(!FixturePtrRouteUp(&fix, 300))
    {
        printf("SKIP conditional PTR: cannot bind test ports\n");
        FixtureDown(&fix);
        return;
    }

    AddHost(&fix.hosts, "iphone.lan", phone, 4);

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t len = BuildQuery(query, sizeof query, 0x7171,
                            "47.1.168.192.in-addr.arpa", WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);
    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT) > 0);
    CHECK(fix.server.local == 1);
    CHECK(fix.server.forwarded == 0);
    CHECK(fix.ptrRouter.members[0].queries == 0);

    len = BuildQuery(query, sizeof query, 0x7272,
                     "99.1.168.192.in-addr.arpa", WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 6);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);
    if(got > 0)
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NOERROR);

    CHECK(fix.server.local == 1);
    CHECK(fix.server.forwarded == 1);
    CHECK(fix.ptrRouter.members[0].queries == 1);
    CHECK(fix.upstreams.members[0].queries == 0);

    len = BuildQuery(query, sizeof query, 0x7273,
                     "99.1.168.192.in-addr.arpa", WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);
    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT) > 0);
    CHECK(fix.server.hits == 1);
    CHECK(fix.ptrRouter.members[0].queries == 1);
    CHECK(fix.upstreams.members[0].queries == 0);

    /* A private reverse name outside the configured LAN prefix stays local */
    len = BuildQuery(query, sizeof query, 0x7373,
                     "99.2.168.192.in-addr.arpa", WIRE_TYPE_PTR);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);
    if(got > 0)
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NXDOMAIN);

    CHECK(fix.server.local == 2);
    CHECK(fix.ptrRouter.members[0].queries == 1);
    CHECK(fix.upstreams.members[0].queries == 0);

    close(client);
    FixtureDown(&fix);
}

static void TestBlockedNameIsRefusedLocally(void)
{
    Fixture fix;
    uint8_t query[512];
    uint8_t reply[2048];

    if(!FixtureUp(&fix, 300, 0, false))
    {
        printf("SKIP blocked: cannot bind test ports\n");
        return;
    }

    TrieBuild(&fix.blocklist);

    int client = ConnectLoopback(SERVER_PORT, SOCK_DGRAM);
    CHECK(client >= 0);

    size_t len = BuildQuery(query, sizeof query, 0x5151,
                            "blocked.example.com", WIRE_TYPE_A);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);

    ssize_t got = recv(client, reply, sizeof reply, MSG_DONTWAIT);
    CHECK(got > (ssize_t)WIRE_HEADER_BYTES);

    if(got > 0)
    {
        CHECK(MsgId(reply, (size_t)got) == 0x5151);
        CHECK((MsgFlags(reply, (size_t)got) & 0x000Fu) == MSG_RCODE_NXDOMAIN);
    }

    CHECK(fix.server.blocked == 1);
    CHECK(fix.server.forwarded == 0);
    CHECK(fix.fake.served == 0);

    /* A subdomain of a blocked name goes the same way. */
    len = BuildQuery(query, sizeof query, 0x5252,
                     "ads.blocked.example.com", WIRE_TYPE_A);
    send(client, query, len, 0);
    PumpBriefly(&fix.server, 4);
    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT) > 0);
    CHECK(fix.server.blocked == 2);
    CHECK(fix.server.forwarded == 0);

    /* A name outside the list is still forwarded. */
    len = BuildQuery(query, sizeof query, 0x5353, "a.example.com", WIRE_TYPE_A);
    send(client, query, len, 0);
    Pump(&fix.server, 6);
    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT) > 0);
    CHECK(fix.server.blocked == 2);
    CHECK(fix.server.forwarded == 1);

    close(client);
    FixtureDown(&fix);
}

static void TestCloseCancelsActiveProbe(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool pool;
    UpstreamPoolInit(&pool, 0);
    pool.bProbing = true;
    pool.probe.fd = fds[0];
    pool.probe.transport = UpstreamTransport_Plaintext;

    Server server;
    memset(&server, 0, sizeof server);
    server.fdUdp4    = -1;
    server.fdUdp6    = -1;
    server.fdTcp4    = -1;
    server.fdTcp6    = -1;
    server.upstreams = &pool;

    ServerClose(&server);

    CHECK(!pool.bProbing);
    CHECK(pool.probe.fd == -1);
    CHECK(close(fds[0]) < 0);
    close(fds[1]);
}

int main(void)
{
    TestUdpQueryIsForwardedAndAnswered();
    TestSecondQueryIsACacheHit();
    TestTcpQuery();
    TestOversizedUdpAnswerSetsTruncated();
    TestUpstreamSilenceBecomesServfail();
    TestRetryMovesToTheSecondUpstream();
    TestStartFailureMovesToTheSecondUpstream();
    TestProbeMeasuresAnUnselectedUpstream();
    TestResponseSentToListenerIsIgnored();
    TestOneStalledQueryDoesNotBlockOthers();
    TestTableFullEvictsOldest();
    TestTcpClientVanishingMidQuery();
    TestBlockedNameIsRefusedLocally();
    TestLocalNamesAreAnsweredHere();
    TestUnknownLocalPtrGoesToRouter();
    TestCloseCancelsActiveProbe();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("server: all checks passed\n");
    return 0;
}
