#define _POSIX_C_SOURCE 200809L

#include "fetch.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
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

/* The shim is replaced so the state machine runs against scripted bytes. A
   real handshake would make every case below depend on a live peer. */
static ssize_t  G_READ_RESULT;
static ssize_t  G_WRITE_RESULT;
static size_t   G_READ_CHUNK;
static size_t   G_READ_AT;
static size_t   G_READ_LEN;
static uint8_t  G_READ_DATA[CFG_FETCH_HEADER_BYTES * 4];
static uint32_t G_NOW_MS;

static void FakeReset(void)
{
    G_READ_RESULT  = 0;
    G_WRITE_RESULT = 0;
    G_READ_CHUNK   = SIZE_MAX;
    G_READ_AT      = 0;
    G_READ_LEN     = 0;
}

static void Script(const char *head, const char *body, size_t bodyLen)
{
    size_t headLen = strlen(head);
    memcpy(G_READ_DATA, head, headLen);
    if(bodyLen != 0)
        memcpy(G_READ_DATA + headLen, body, bodyLen);
    G_READ_LEN = headLen + bodyLen;
    G_READ_AT  = 0;
}

TlsIo TlsChannelStart(TlsBackend *backend, TlsChannel *channel, int fd,
                      const char *hostname)
{
    (void)backend;
    (void)hostname;
    memset(channel, 0, sizeof *channel);
    channel->fd     = fd;
    channel->want   = TlsIo_WantRead;
    channel->bReady = true;
    return TlsIo_Ok;
}

TlsIo TlsChannelHandshake(TlsChannel *channel)
{
    channel->want = TlsIo_Ok;
    return TlsIo_Ok;
}

ssize_t TlsChannelRead(TlsChannel *channel, uint8_t *out, size_t cap)
{
    if(G_READ_RESULT != 0)
    {
        ssize_t result = G_READ_RESULT;
        G_READ_RESULT = 0;
        channel->want = (TlsIo)result;
        return result;
    }

    if(G_READ_AT >= G_READ_LEN)
        return TlsIo_Closed;

    size_t count = G_READ_LEN - G_READ_AT;
    if(count > cap)
        count = cap;
    if(count > G_READ_CHUNK)
        count = G_READ_CHUNK;

    memcpy(out, G_READ_DATA + G_READ_AT, count);
    G_READ_AT += count;
    channel->want = TlsIo_WantRead;
    return (ssize_t)count;
}

ssize_t TlsChannelWrite(TlsChannel *channel, const uint8_t *data, size_t len)
{
    (void)data;

    if(G_WRITE_RESULT != 0)
    {
        ssize_t result = G_WRITE_RESULT;
        G_WRITE_RESULT = 0;
        channel->want = (TlsIo)result;
        return result;
    }

    channel->want = TlsIo_WantWrite;
    return (ssize_t)len;
}

short TlsChannelEvents(const TlsChannel *channel)
{
    return (channel->want == TlsIo_WantWrite) ? POLLOUT : POLLIN;
}

void TlsChannelClose(TlsChannel *channel)
{
    if(channel != NULL && channel->fd >= 0)
        channel->fd = -1;
}

/* A listener on an ephemeral port, so the nonblocking connect completes and
   the SO_ERROR check passes without reaching the network */
static int OpenListener(uint16_t *port)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return -1;

    socklen_t addressLen = sizeof address;
    if(bind(fd, (struct sockaddr *)&address, addressLen) != 0
       || listen(fd, 4) != 0
       || getsockname(fd, (struct sockaddr *)&address, &addressLen) != 0)
    {
        close(fd);
        return -1;
    }

    *port = ntohs(address.sin_port);
    return fd;
}

static void LoopbackAddress(struct sockaddr_storage *out, socklen_t *outLen,
                            uint16_t port)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port        = htons(port);

    memset(out, 0, sizeof *out);
    memcpy(out, &address, sizeof address);
    *outLen = sizeof address;
}

static FetchStep Drive(FetchJob *job, unsigned budget)
{
    for(unsigned i = 0; i < budget; i++)
    {
        FetchStep step = FetchProgress(job, G_NOW_MS);
        if(step != FetchStep_Again)
            return step;
    }

    return FetchStep_Again;
}

static bool DigestIs(FetchJob *job, const char *hex)
{
    uint8_t got[FETCH_DIGEST_BYTES];
    char    text[FETCH_DIGEST_BYTES * 2 + 1];

    if(!FetchDigest(job, got))
        return false;

    for(size_t i = 0; i < FETCH_DIGEST_BYTES; i++)
        snprintf(text + i * 2, 3, "%02x", got[i]);

    return strcmp(text, hex) == 0;
}

static int OpenSink(void)
{
    char path[] = "/tmp/dns_blocker_fetch_XXXXXX";
    int  fd     = mkstemp(path);
    if(fd >= 0)
        unlink(path);
    return fd;
}

#define HELLO_SHA "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
#define TEN_SHA   "72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0"

static TlsBackend G_BACKEND;

static bool Start(FetchJob *job, const char *url, uint16_t port, int sink,
                  size_t maxBody)
{
    struct sockaddr_storage addr;
    socklen_t               addrLen = 0;

    LoopbackAddress(&addr, &addrLen, port);
    return FetchBegin(job, &G_BACKEND, url, &addr, addrLen, sink, maxBody,
                      G_NOW_MS);
}

static bool Follow(FetchJob *job, uint16_t port)
{
    struct sockaddr_storage addr;
    socklen_t               addrLen = 0;

    LoopbackAddress(&addr, &addrLen, port);
    return FetchFollow(job, &G_BACKEND, &addr, addrLen);
}

static bool Retry(FetchJob *job, uint16_t port)
{
    struct sockaddr_storage addr;
    socklen_t               addrLen = 0;

    LoopbackAddress(&addr, &addrLen, port);
    return FetchRetry(job, &G_BACKEND, &addr, addrLen);
}

static void TestBody(uint16_t port)
{
    FetchJob job;
    int      sink = OpenSink();
    CHECK(sink >= 0);

    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n", "hello\n", 6);
    CHECK(Start(&job, "https://a.example/x", port, sink, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Done);
    CHECK(job.bodyGot == 6);
    CHECK(DigestIs(&job, HELLO_SHA));

    /* The sink holds exactly the body, so header bytes never leaked into it */
    char check[16];
    CHECK(lseek(sink, 0, SEEK_SET) == 0);
    CHECK(read(sink, check, sizeof check) == 6);
    CHECK(memcmp(check, "hello\n", 6) == 0);
    FetchEnd(&job);
    close(sink);

    /* One byte at a time, so the body arrives split across many reads and the
       leftover in the header buffer is still accounted once */
    FakeReset();
    G_READ_CHUNK = 1;
    Script("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", "abcdefghij", 10);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 512) == FetchStep_Done);
    CHECK(job.bodyGot == 10);
    CHECK(DigestIs(&job, TEN_SHA));
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Done);
    CHECK(job.bodyGot == 0);
    FetchEnd(&job);
}

/* The digest listing is read, not stored, so it lands in memory. The real one
   is 382 bytes across four asset lines. */
static void TestMemorySink(uint16_t port)
{
    static const char listing[] =
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  a.trie\n";

    FetchJob job;
    uint8_t  body[256];
    uint8_t  digest[FETCH_DIGEST_BYTES];
    struct sockaddr_storage addr;
    socklen_t               addrLen = 0;

    LoopbackAddress(&addr, &addrLen, port);

    char head[64];
    snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n",
             strlen(listing));

    FakeReset();
    G_READ_CHUNK = 7;
    Script(head, listing, strlen(listing));
    CHECK(FetchBeginToMemory(&job, &G_BACKEND, "https://a.example/d", &addr,
                             addrLen, body, sizeof body, G_NOW_MS));
    CHECK(Drive(&job, 256) == FetchStep_Done);
    CHECK(FetchBodyLength(&job) == strlen(listing));
    CHECK(memcmp(body, listing, strlen(listing)) == 0);

    /* The point of keeping it: the digest for the asset comes straight out */
    CHECK(FetchFindDigest(body, FetchBodyLength(&job), "a.trie", digest));
    CHECK(digest[0] == 0x58 && digest[31] == 0x03);
    FetchEnd(&job);

    /* A listing larger than the buffer is refused at the header, before any
       byte is copied */
    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 300\r\n\r\n", NULL, 0);
    CHECK(FetchBeginToMemory(&job, &G_BACKEND, "https://a.example/d", &addr,
                             addrLen, body, sizeof body, G_NOW_MS));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    CHECK(FetchBodyLength(&job) == 0);
    FetchEnd(&job);

    CHECK(!FetchBeginToMemory(&job, &G_BACKEND, "https://a.example/d", &addr,
                              addrLen, NULL, sizeof body, G_NOW_MS));
    CHECK(!FetchBeginToMemory(&job, &G_BACKEND, "https://a.example/d", &addr,
                              addrLen, body, 0, G_NOW_MS));
}

static void TestRefusals(uint16_t port)
{
    FetchJob job;

    FakeReset();
    G_READ_RESULT = TlsIo_Closed;
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Read);
    CHECK(strcmp(FetchFailText(&job),
                 "the response connection failed before the header completed") == 0);
    FetchEnd(&job);

    /* Closed before the declared length. A short trie must never reach the
       rename, so this is a failure and not a short read */
    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n", "hello\n", 6);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "hello\n", 6);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 4096));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 200 OK\r\n\r\n", "hello\n", 6);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    FakeReset();
    Script("HTTP/1.1 302 Found\r\nLocation: http://a.example/x\r\n"
           "Content-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    FetchEnd(&job);

    CHECK(!Start(&job, "https://a.example/x", port, -1, 0));
    CHECK(!Start(&job, "ftp://a.example/x", port, -1, 1024));
}

static void TestRedirects(uint16_t port)
{
    FetchJob job;

    /* The live release answers with two hops before the body, so this is the
       shape the daemon actually meets */
    FakeReset();
    Script("HTTP/1.1 302 Found\r\n"
           "Location: https://b.example/second\r\n"
           "Content-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Redirect);
    CHECK(strcmp(FetchRedirectHost(&job), "b.example") == 0);

    FakeReset();
    Script("HTTP/1.1 302 Found\r\n"
           "Location: https://c.example/third?sig=x%2By\r\n"
           "Content-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Follow(&job, port));
    CHECK(Drive(&job, 32) == FetchStep_Redirect);
    CHECK(strcmp(FetchRedirectHost(&job), "c.example") == 0);

    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n", "hello\n", 6);
    CHECK(Follow(&job, port));
    CHECK(Drive(&job, 32) == FetchStep_Done);
    CHECK(DigestIs(&job, HELLO_SHA));
    CHECK(job.redirects == 2);
    FetchEnd(&job);

    /* The hop budget is spent, so the next follow is refused rather than
       chasing a loop */
    FakeReset();
    Script("HTTP/1.1 302 Found\r\nLocation: https://a.example/loop\r\n"
           "Content-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    for(unsigned i = 0; i < CFG_FETCH_MAX_REDIRECTS; i++)
    {
        CHECK(Drive(&job, 32) == FetchStep_Redirect);
        G_READ_AT = 0;
        CHECK(Follow(&job, port));
    }
    CHECK(Drive(&job, 32) == FetchStep_Redirect);
    CHECK(!Follow(&job, port));
    FetchEnd(&job);
}

static void TestDigestGuard(uint16_t port)
{
    FetchJob job;
    uint8_t  digest[FETCH_DIGEST_BYTES];

    FakeReset();
    Script("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n", "hello\n", 6);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));

    /* Nothing has been hashed yet, so a digest here would verify an empty
       file against a real listing */
    CHECK(!FetchDigest(&job, digest));
    CHECK(FetchEvents(&job) != 0);

    CHECK(Drive(&job, 32) == FetchStep_Done);
    CHECK(FetchDigest(&job, digest));

    FetchEnd(&job);
    CHECK(FetchEvents(&job) == 0);
}

static void TestPermanentWantReadTimesOut(uint16_t port)
{
    FetchJob job;

    G_NOW_MS = 1000;
    FakeReset();
    G_READ_RESULT = TlsIo_WantRead;
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 1) == FetchStep_Again);
    CHECK(job.state == FetchState_ReadHeaders);

    G_NOW_MS = job.deadlineMs;
    G_READ_RESULT = TlsIo_WantRead;
    CHECK(Drive(&job, 1) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Timeout);
    CHECK(job.fd == -1);
    CHECK(job.channel.fd == -1);
    FetchEnd(&job);
}

static void TestPermanentWantWriteTimesOut(uint16_t port)
{
    FetchJob job;

    G_NOW_MS = 1000;
    FakeReset();
    G_WRITE_RESULT = TlsIo_WantWrite;
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 1) == FetchStep_Again);
    CHECK(job.state == FetchState_Write);

    G_NOW_MS = job.deadlineMs;
    G_WRITE_RESULT = TlsIo_WantWrite;
    CHECK(Drive(&job, 1) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Timeout);
    FetchEnd(&job);
}

static void TestPartialHeadersDoNotResetDeadline(uint16_t port)
{
    FetchJob job;

    G_NOW_MS = 1000;
    FakeReset();
    G_READ_CHUNK = 1;
    Script("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n", "hello\n", 6);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));

    G_NOW_MS = job.deadlineMs - 1;
    CHECK(Drive(&job, 1) == FetchStep_Again);
    CHECK(job.held == 1);

    G_NOW_MS++;
    CHECK(Drive(&job, 1) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Timeout);
    FetchEnd(&job);
}

static void TestRedirectSharesDeadline(uint16_t port)
{
    FetchJob job;

    G_NOW_MS = 1000;
    FakeReset();
    Script("HTTP/1.1 302 Found\r\nLocation: https://b.example/x\r\n"
           "Content-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Redirect);

    uint32_t deadlineMs = job.deadlineMs;
    G_NOW_MS = deadlineMs - 1;
    FakeReset();
    G_READ_RESULT = TlsIo_WantRead;
    CHECK(Follow(&job, port));
    CHECK(job.deadlineMs == deadlineMs);
    CHECK(Drive(&job, 1) == FetchStep_Again);

    G_NOW_MS++;
    CHECK(Drive(&job, 1) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Timeout);
    FetchEnd(&job);
}

static void TestReadRetrySharesDeadline(uint16_t port)
{
    FetchJob job;

    G_NOW_MS = 1000;
    FakeReset();
    CHECK(Start(&job, "https://a.example/x", port, -1, 1024));
    CHECK(Drive(&job, 32) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Read);

    uint32_t deadlineMs = job.deadlineMs;
    FetchEnd(&job);
    G_NOW_MS = deadlineMs - 1;
    FakeReset();
    G_READ_RESULT = TlsIo_WantRead;
    CHECK(Retry(&job, port));
    CHECK(job.deadlineMs == deadlineMs);
    CHECK(Drive(&job, 1) == FetchStep_Again);

    G_NOW_MS++;
    CHECK(Drive(&job, 1) == FetchStep_Failed);
    CHECK(job.fail == FetchFail_Timeout);
    FetchEnd(&job);
}

int main(void)
{
    uint16_t port     = 0;
    int      listener = OpenListener(&port);

    CHECK(listener >= 0);
    if(listener < 0)
        return 1;

    G_BACKEND.bReady = true;

    TestBody(port);
    TestMemorySink(port);
    TestRefusals(port);
    TestRedirects(port);
    TestDigestGuard(port);
    TestPermanentWantReadTimesOut(port);
    TestPermanentWantWriteTimesOut(port);
    TestPartialHeadersDoNotResetDeadline(port);
    TestRedirectSharesDeadline(port);
    TestReadRetrySharesDeadline(port);

    close(listener);

    if(G_FAILURES != 0)
    {
        printf("fetch tls: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("fetch tls: all checks passed\n");
    return 0;
}
