#define _GNU_SOURCE

#include "arena.h"
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

#define SERVER_PORT   15353
#define UPSTREAM_PORT 15354

/* A stand-in resolver. It echoes the question and answers with one A record,
   keeping whatever transaction ID the daemon chose, which is what lets the
   test prove the daemon rewrites it before replying to the client. */
typedef struct
{
    int      fd;
    uint32_t answerTtl;
    int      padding;
    bool     bSilent;
    volatile bool bStop;
    volatile int  served;
} FakeUpstream;

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

        Builder b = { reply, sizeof reply, 0 };
        PutHeader(&b, header.id, 0x8180u, 1, 1, 0, 0);
        PutBytes(&b, query + WIRE_HEADER_BYTES,
                 reader.pos - WIRE_HEADER_BYTES);
        PutARecord(&b, "a.example.com", fake->answerTtl);

        /* Optional filler so the reply crosses the 512-byte UDP limit. */
        for(int i = 0; i < fake->padding; i++)
            PutARecord(&b, "a.example.com", fake->answerTtl);

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

typedef struct
{
    Arena        arena;
    Cache        cache;
    Upstream     upstream;
    Server       server;
    FakeUpstream fake;
    pthread_t    thread;
} Fixture;

static bool FixtureUp(Fixture *fix, uint32_t ttl, int padding, bool bSilent)
{
    memset(fix, 0, sizeof *fix);

    fix->fake.fd        = OpenLoopbackUdp(UPSTREAM_PORT);
    fix->fake.answerTtl = ttl;
    fix->fake.padding   = padding;
    fix->fake.bSilent   = bSilent;

    if(fix->fake.fd < 0)
        return false;

    if(pthread_create(&fix->thread, NULL, FakeUpstreamMain, &fix->fake) != 0)
        return false;

    return ArenaInit(&fix->arena, 512u * 1024u)
        && CacheInit(&fix->cache, &fix->arena)
        && UpstreamInit(&fix->upstream, "127.0.0.1", UPSTREAM_PORT)
        && ServerOpen(&fix->server, &fix->cache, &fix->upstream,
                      &fix->arena, SERVER_PORT);
}

static void FixtureDown(Fixture *fix)
{
    uint8_t poke = 0;
    struct sockaddr_in addr;

    fix->fake.bStop = true;

    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(UPSTREAM_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int poker = socket(AF_INET, SOCK_DGRAM, 0);
    if(poker >= 0)
    {
        sendto(poker, &poke, 1, 0, (struct sockaddr *)&addr, sizeof addr);
        close(poker);
    }

    pthread_join(fix->thread, NULL);
    close(fix->fake.fd);
    ServerClose(&fix->server);
    ArenaRelease(&fix->arena);
}

static void Pump(Server *server, int times)
{
    for(int i = 0; i < times; i++)
        ServerPoll(server, 200);
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

    Pump(&fix.server, 2);

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
    Pump(&fix.server, 2);
    recv(client, reply, sizeof reply, MSG_DONTWAIT);

    queryLen = BuildQuery(query, sizeof query, 0x2222,
                          "a.example.com", WIRE_TYPE_A);
    send(client, query, queryLen, 0);
    Pump(&fix.server, 2);

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

    Pump(&fix.server, 1);

    size_t queryLen = BuildQuery(query, sizeof query, 0x7A7A,
                                 "a.example.com", WIRE_TYPE_A);
    framed[0] = (uint8_t)(queryLen >> 8);
    framed[1] = (uint8_t)queryLen;
    memcpy(framed + 2, query, queryLen);

    CHECK(send(client, framed, queryLen + 2, 0) == (ssize_t)(queryLen + 2));

    Pump(&fix.server, 4);

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
    Pump(&fix.server, 2);

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
    Pump(&fix.server, 2);

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
    Pump(&fix.server, 2);

    CHECK(recv(client, reply, sizeof reply, MSG_DONTWAIT) < 0);
    CHECK(fix.server.malformed == 1);
    CHECK(fix.server.forwarded == 0);

    close(client);
    FixtureDown(&fix);
}

int main(void)
{
    TestUdpQueryIsForwardedAndAnswered();
    TestSecondQueryIsACacheHit();
    TestTcpQuery();
    TestOversizedUdpAnswerSetsTruncated();
    TestUpstreamSilenceBecomesServfail();
    TestResponseSentToListenerIsIgnored();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("server: all checks passed\n");
    return 0;
}
