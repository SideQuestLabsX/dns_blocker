#define _POSIX_C_SOURCE 200809L

#include "sync.h"

#include "dnsbuild.h"
#include "trieimage.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

/* The shim is replaced, so the driver runs against scripted responses. Each
   entry is one server reply, consumed in order as the driver reconnects. */
#define MAX_REPLIES 8

_Static_assert(CFG_FETCH_READ_RETRIES > 0,
               "the sync must retry a transient response close");
_Static_assert(CFG_FETCH_READ_RETRIES <= MAX_REPLIES - 2,
               "the scripted reply table must hold every read retry");

static uint8_t  G_REPLY[MAX_REPLIES][4096];
static size_t   G_REPLY_LEN[MAX_REPLIES];
static size_t   G_REPLIES;
static size_t   G_REPLY_AT;
static size_t   G_READ_AT;
static size_t   G_STALL_REPLY;
static size_t   G_STALL_AFTER;
static uint32_t G_NOW_MS;
static char     G_REQUEST[MAX_REPLIES][CFG_FETCH_REQUEST_BYTES];
static size_t   G_REQUESTS;

static void ScriptReset(void)
{
    G_REPLIES     = 0;
    G_REPLY_AT    = 0;
    G_READ_AT     = 0;
    G_STALL_REPLY = SIZE_MAX;
    G_STALL_AFTER = SIZE_MAX;
    G_REQUESTS    = 0;
}

static void Reply(const char *head, const void *body, size_t bodyLen)
{
    size_t headLen = strlen(head);
    memcpy(G_REPLY[G_REPLIES], head, headLen);
    if(bodyLen != 0)
        memcpy(G_REPLY[G_REPLIES] + headLen, body, bodyLen);
    G_REPLY_LEN[G_REPLIES] = headLen + bodyLen;
    G_REPLIES++;
}

static void ReplyBody(const void *body, size_t bodyLen)
{
    char head[64];
    snprintf(head, sizeof head,
             "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", bodyLen);
    Reply(head, body, bodyLen);
}

static void ReplyClose(void)
{
    G_REPLY_LEN[G_REPLIES] = 0;
    G_REPLIES++;
}

static void ReplyRedirect(const char *location)
{
    char head[256];
    snprintf(head, sizeof head,
             "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n",
             location);
    Reply(head, NULL, 0);
}

static void StallLastReplyAfter(size_t bytes)
{
    G_STALL_REPLY = G_REPLIES - 1;
    G_STALL_AFTER = bytes;
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

    /* Each connection serves the next scripted reply from its first byte */
    G_READ_AT = 0;
    return TlsIo_Ok;
}

TlsIo TlsChannelHandshake(TlsChannel *channel)
{
    channel->want = TlsIo_Ok;
    return TlsIo_Ok;
}

ssize_t TlsChannelRead(TlsChannel *channel, uint8_t *out, size_t cap)
{
    if(G_REPLY_AT >= G_REPLIES)
        return TlsIo_Closed;

    size_t len = G_REPLY_LEN[G_REPLY_AT];
    if(G_REPLY_AT == G_STALL_REPLY && G_READ_AT >= G_STALL_AFTER)
    {
        channel->want = TlsIo_WantRead;
        return TlsIo_WantRead;
    }
    if(G_READ_AT >= len)
        return TlsIo_Closed;

    size_t count = len - G_READ_AT;
    if(count > cap)
        count = cap;
    if(G_REPLY_AT == G_STALL_REPLY
       && count > G_STALL_AFTER - G_READ_AT)
        count = G_STALL_AFTER - G_READ_AT;

    memcpy(out, G_REPLY[G_REPLY_AT] + G_READ_AT, count);
    G_READ_AT += count;
    channel->want = TlsIo_WantRead;
    return (ssize_t)count;
}

ssize_t TlsChannelWrite(TlsChannel *channel, const uint8_t *data, size_t len)
{
    if(G_REQUESTS < MAX_REPLIES)
    {
        size_t copy = (len < sizeof G_REQUEST[0] - 1)
                    ? len : sizeof G_REQUEST[0] - 1;
        memcpy(G_REQUEST[G_REQUESTS], data, copy);
        G_REQUEST[G_REQUESTS][copy] = '\0';
        G_REQUESTS++;
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
    {
        channel->fd = -1;
        if(G_REPLY_AT < G_REPLIES)
            G_REPLY_AT++;
        G_READ_AT = 0;
    }
}

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

static uint16_t G_PORT;
static TlsBackend G_BACKEND;
static UpstreamPool G_POOL;

static bool Begin(SyncJob *job, const char *path, const char *tier)
{
    UpstreamPoolInit(&G_POOL, G_NOW_MS);
    UpstreamPoolSetTlsBackend(&G_POOL, &G_BACKEND);
    return SyncBegin(job, &G_POOL, path, tier, NULL);
}

static bool BeginWithList(SyncJob *job, const char *path,
                          const Blocklist *list)
{
    UpstreamPoolInit(&G_POOL, G_NOW_MS);
    UpstreamPoolSetTlsBackend(&G_POOL, &G_BACKEND);
    return SyncBegin(job, &G_POOL, path, NULL, list);
}

static bool Answer(SyncJob *job)
{
    struct sockaddr_in address;
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof address;

    memset(&address, 0, sizeof address);
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port        = htons(G_PORT);

    memset(&addr, 0, sizeof addr);
    memcpy(&addr, &address, sizeof address);

    return SyncProvideAddress(job, &addr, addrLen, G_NOW_MS);
}

/* Runs the driver to a terminal step, answering every address request. */
static SyncStep Run(SyncJob *job, unsigned budget, unsigned *resolves)
{
    unsigned count = 0;

    for(unsigned i = 0; i < budget; i++)
    {
        SyncStep step = SyncProgress(job, G_NOW_MS);

        if(step == SyncStep_NeedAddress)
        {
            count++;
            if(!Answer(job))
            {
                if(resolves != NULL)
                    *resolves = count;
                return SyncStep_Failed;
            }
            continue;
        }

        if(step != SyncStep_Again)
        {
            if(resolves != NULL)
                *resolves = count;
            return step;
        }
    }

    if(resolves != NULL)
        *resolves = count;
    return SyncStep_Again;
}

/* The listing covers every tier in the release, and the driver has to take the
   line for the asset this build asks for */
static const char G_LISTING[] =
    "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  " CFG_BLOCKLIST_ASSET "\n"
    "8d4a70100bf861ea3f9dcd701938a183e89c300932ad6ac6b35fa5c8fe4979f9  dns_blocker-blocklist-other.trie\n";
static const char G_LOCATOR[] = "blocklist-2026-08-09-31286198180-1\n";

static bool Exists(const char *path)
{
    struct stat info;
    return stat(path, &info) == 0;
}

static size_t SizeOf(const char *path)
{
    struct stat info;
    return (stat(path, &info) == 0) ? (size_t)info.st_size : 0;
}

static size_t UsedTlsSlots(const UpstreamPool *pool)
{
    size_t used = 0;
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        if(pool->tlsSlots[i].bUsed)
            used++;
    }
    return used;
}

static bool WriteBytes(const char *path, const uint8_t *data, size_t len)
{
    FILE *file = fopen(path, "wb");
    if(file == NULL)
        return false;

    bool bOk = fwrite(data, 1, len, file) == len;
    return fclose(file) == 0 && bOk;
}

static uint8_t *BuildTrie(const char *name, size_t *size)
{
    TrieImage build;
    char     *reversed = TrieReverse(name);

    TrieImageInit(&build, CFG_MAX_NAME_BYTES);
    CHECK(TrieImageAdd(&build, reversed, ""));
    uint8_t *image = TrieImageFinish(&build, size);
    TrieImageRelease(&build);
    free(reversed);
    return image;
}

static bool BuildListing(const uint8_t *data, size_t len,
                         char *out, size_t cap)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[FETCH_DIGEST_BYTES];

    if(mbedtls_sha256(data, len, digest, 0) != 0
       || cap < FETCH_DIGEST_BYTES * 2 + 3 + sizeof CFG_BLOCKLIST_ASSET)
        return false;

    for(size_t i = 0; i < sizeof digest; i++)
    {
        out[i * 2]     = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0Fu];
    }

    snprintf(out + FETCH_DIGEST_BYTES * 2,
             cap - FETCH_DIGEST_BYTES * 2, "  %s\n", CFG_BLOCKLIST_ASSET);
    return true;
}

static bool RequestContains(const char *text)
{
    for(size_t i = 0; i < G_REQUESTS; i++)
    {
        if(strstr(G_REQUEST[i], text) != NULL)
            return true;
    }

    return false;
}

static void TestUnchangedListSkipsTheAsset(const char *dir)
{
    SyncJob job;
    Blocklist list;
    char target[256];
    char staging[256];
    char listing[160];
    size_t imageLen = 0;
    uint8_t *image = BuildTrie("old.example", &imageLen);
    struct stat before;
    struct stat after;
    struct timespec times[2] = {
        { .tv_sec = 1700000000, .tv_nsec = 123456789 },
        { .tv_sec = 1700000000, .tv_nsec = 123456789 }
    };
    unsigned resolves = 0;

    snprintf(target, sizeof target, "%s/unchanged.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));
    CHECK(image != NULL && WriteBytes(target, image, imageLen));
    CHECK(utimensat(AT_FDCWD, target, times, 0) == 0);
    CHECK(BlocklistLoad(&list, target));
    CHECK(stat(target, &before) == 0);
    const uint8_t *mapped = list.base;

    CHECK(BuildListing(image, imageLen, listing, sizeof listing));
    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(listing, strlen(listing));

    CHECK(BeginWithList(&job, target, &list));
    CHECK(Run(&job, 512, &resolves) == SyncStep_Done);
    CHECK(!SyncInstalled(&job));
    CHECK(resolves == 2);
    CHECK(G_REQUESTS == 2);
    CHECK(!RequestContains(CFG_BLOCKLIST_ASSET));
    CHECK(!Exists(staging));
    CHECK(stat(target, &after) == 0);
    CHECK(before.st_ino == after.st_ino);
    CHECK(before.st_mtim.tv_sec == after.st_mtim.tv_sec);
    CHECK(before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
    CHECK(list.base == mapped);
    CHECK(list.size == imageLen);

    SyncEnd(&job);
    BlocklistUnload(&list);
    free(image);
    unlink(target);
}

static void TestChangedListInstallsAndReloads(const char *dir)
{
    SyncJob job;
    Blocklist list;
    char target[256];
    char listing[160];
    size_t oldLen = 0;
    size_t newLen = 0;
    uint8_t *oldImage = BuildTrie("old.example", &oldLen);
    uint8_t *newImage = BuildTrie("new.example", &newLen);
    WireName oldName;
    WireName newName;
    unsigned resolves = 0;

    snprintf(target, sizeof target, "%s/changed.trie", dir);
    CHECK(oldImage != NULL && newImage != NULL);
    CHECK(WriteBytes(target, oldImage, oldLen));
    CHECK(BlocklistLoad(&list, target));
    const uint8_t *mapped = list.base;
    CHECK(NameOf("old.example", &oldName));
    CHECK(NameOf("new.example", &newName));
    CHECK(BlocklistContains(&list, &oldName));
    CHECK(!BlocklistContains(&list, &newName));

    CHECK(BuildListing(newImage, newLen, listing, sizeof listing));
    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(listing, strlen(listing));
    ReplyBody(newImage, newLen);

    CHECK(BeginWithList(&job, target, &list));
    CHECK(Run(&job, 512, &resolves) == SyncStep_Done);
    CHECK(SyncInstalled(&job));
    CHECK(resolves == 3);
    CHECK(G_REQUESTS == 3);
    CHECK(RequestContains(CFG_BLOCKLIST_ASSET));
    CHECK(list.base == mapped);
    CHECK(BlocklistReload(&list, target));
    CHECK(list.base != mapped);
    CHECK(!BlocklistContains(&list, &oldName));
    CHECK(BlocklistContains(&list, &newName));

    SyncEnd(&job);
    BlocklistUnload(&list);
    free(oldImage);
    free(newImage);
    unlink(target);
}

static void TestActiveHashYieldsBetweenChunks(const char *dir)
{
    SyncJob job;
    char target[256];
    char listing[160];
    size_t size = 128u * 1024u;
    uint8_t *data = malloc(size);
    Blocklist list = {
        .base = data,
        .size = size,
        .source = BlocklistSource_Mapped
    };

    snprintf(target, sizeof target, "%s/chunked.trie", dir);
    CHECK(data != NULL);
    if(data == NULL)
        return;

    memset(data, 'x', size);
    CHECK(BuildListing(data, size, listing, sizeof listing));
    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(listing, strlen(listing));
    CHECK(BeginWithList(&job, target, &list));

    for(unsigned i = 0; i < 64 && !SyncNeedsProgress(&job); i++)
    {
        SyncStep step = SyncProgress(&job, G_NOW_MS);
        if(step == SyncStep_NeedAddress)
            CHECK(Answer(&job));
        else
            CHECK(step == SyncStep_Again);
    }

    CHECK(SyncNeedsProgress(&job));
    CHECK(SyncProgress(&job, G_NOW_MS) == SyncStep_Again);
    CHECK(SyncNeedsProgress(&job));
    CHECK(job.activeAt > 0 && job.activeAt < size);
    CHECK(SyncProgress(&job, G_NOW_MS) == SyncStep_Done);
    CHECK(!SyncInstalled(&job));

    SyncEnd(&job);
    free(data);
}

static void TestHappyPath(const char *dir)
{
    SyncJob  job;
    char     target[256];
    char     staging[256];
    unsigned resolves = 0;

    snprintf(target, sizeof target, "%s/blocklist.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(G_LISTING, strlen(G_LISTING));
    ReplyBody("hello\n", 6);

    CHECK(Begin(&job, target, NULL));
    CHECK(strcmp(SyncHost(&job), "raw.githubusercontent.com") == 0);
    CHECK(Run(&job, 512, &resolves) == SyncStep_Done);

    CHECK(resolves == 3);
    CHECK(Exists(target));
    CHECK(SizeOf(target) == 6);
    CHECK(!Exists(staging));

    SyncEnd(&job);
    unlink(target);
}

static void TestSyncCompletesWithTwoFreeSlots(const char *dir)
{
    UpstreamPool pool;
    SyncJob      job;
    char         target[256];
    int          fds[2];

    snprintf(target, sizeof target, "%s/shared-slot.trie", dir);
    UpstreamPoolInit(&pool, G_NOW_MS);
    UpstreamPoolSetTlsBackend(&pool, &G_BACKEND);
    for(size_t i = 0; i < CFG_TLS_SLOTS - 2; i++)
    {
        pool.tlsSlots[i].bUsed  = true;
        pool.tlsSlots[i].member = 0;
    }

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(G_LISTING, strlen(G_LISTING));
    ReplyBody("hello\n", 6);

    CHECK(SyncBegin(&job, &pool, target, NULL, NULL));
    CHECK(UsedTlsSlots(&pool) == CFG_TLS_SLOTS - 1);
    CHECK(Run(&job, 512, NULL) == SyncStep_Done);
    CHECK(SizeOf(target) == 6);

    TlsChannel *released = job.channel;
    SyncEnd(&job);
    CHECK(UsedTlsSlots(&pool) == CFG_TLS_SLOTS - 2);
    CHECK(job.job.channel == NULL);

    size_t      slotIndex = UPSTREAM_NONE;
    TlsChannel *next = NULL;
    if(!UpstreamPoolAcquireFetchChannel(&pool, &slotIndex, &next))
    {
        CHECK(false);
        unlink(target);
        return;
    }
    CHECK(next == released);
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    {
        CHECK(false);
        UpstreamPoolReleaseFetchChannel(&pool, slotIndex);
        unlink(target);
        return;
    }
    next->fd = fds[0];

    SyncEnd(&job);
    CHECK(next->fd == fds[0]);

    UpstreamPoolReleaseFetchChannel(&pool, slotIndex);
    close(fds[0]);
    close(fds[1]);
    unlink(target);
}

static void TestRefusedSyncKeepsResolverHealthy(const char *dir)
{
    UpstreamPool pool;
    SyncJob      job;
    char         target[256];

    snprintf(target, sizeof target, "%s/capacity.trie", dir);
    UpstreamPoolInit(&pool, G_NOW_MS);
    UpstreamPoolSetTlsBackend(&pool, &G_BACKEND);
    CHECK(UpstreamPoolAddDoh(&pool, "127.0.0.1", 443, "resolver.example",
                             "/dns-query"));
    for(size_t i = 0; i < CFG_TLS_SLOTS - 1; i++)
    {
        pool.tlsSlots[i].bUsed  = true;
        pool.tlsSlots[i].member = 0;
    }

    uint64_t failures = pool.members[0].failures;
    CHECK(!SyncBegin(&job, &pool, target, NULL, NULL));
    CHECK(job.fail == SyncFail_Capacity);
    CHECK(job.state == SyncState_Failed);
    CHECK(strcmp(SyncFailText(&job),
                 "TLS capacity is reserved for client queries") == 0);
    CHECK(UsedTlsSlots(&pool) == CFG_TLS_SLOTS - 1);
    CHECK(pool.members[0].failures == failures);
    CHECK(!pool.members[0].bDown);
    CHECK(!Exists(target));
}

/* The live release answers each asset with two hops, so the driver has to ask
   for an address again per hop. */
static void TestRedirects(const char *dir)
{
    SyncJob  job;
    char     target[256];
    unsigned resolves = 0;

    snprintf(target, sizeof target, "%s/redirected.trie", dir);

    ScriptReset();
    ReplyRedirect("https://objects.example/locator");
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyRedirect("https://objects.example/listing");
    ReplyBody(G_LISTING, strlen(G_LISTING));
    ReplyRedirect("https://objects.example/asset");
    ReplyBody("hello\n", 6);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, &resolves) == SyncStep_Done);
    CHECK(resolves == 6);
    CHECK(SizeOf(target) == 6);

    SyncEnd(&job);
    unlink(target);
}

static void TestResponseCloseIsRetried(const char *dir)
{
    SyncJob  job;
    char     target[256];
    unsigned resolves = 0;

    snprintf(target, sizeof target, "%s/retried.trie", dir);

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyClose();
    ReplyBody(G_LISTING, strlen(G_LISTING));
    ReplyBody("hello\n", 6);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, &resolves) == SyncStep_Done);
    CHECK(resolves == 4);
    CHECK(SizeOf(target) == 6);

    SyncEnd(&job);
    unlink(target);
}

static void TestResponseCloseRetryIsBounded(const char *dir)
{
    SyncJob job;
    char    target[256];

    snprintf(target, sizeof target, "%s/retry-limit.trie", dir);

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    for(unsigned i = 0; i <= CFG_FETCH_READ_RETRIES; i++)
        ReplyClose();

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(job.phase == SyncPhase_Digest);
    CHECK(job.job.fail == FetchFail_Read);
    CHECK(!Exists(target));

    SyncEnd(&job);
}

static void TestDigestMismatchKeepsTheOldList(const char *dir)
{
    SyncJob job;
    char    target[256];
    char    staging[256];

    snprintf(target, sizeof target, "%s/kept.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    FILE *old = fopen(target, "wb");
    CHECK(old != NULL);
    fwrite("old list", 1, 8, old);
    fclose(old);

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(G_LISTING, strlen(G_LISTING));
    ReplyBody("tampered\n", 9);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);

    /* The list the daemon is serving has to survive a bad download */
    CHECK(SizeOf(target) == 8);
    CHECK(!Exists(staging));
    CHECK(job.fail == SyncFail_Digest);
    CHECK(strcmp(SyncPhaseText(&job), "trie") == 0);
    CHECK(strcmp(SyncFailText(&job), "the digest did not match") == 0);

    SyncEnd(&job);
    unlink(target);
}

static void TestListingWithoutTheAsset(const char *dir)
{
    SyncJob job;
    char    target[256];
    char    staging[256];

    snprintf(target, sizeof target, "%s/absent.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    static const char other[] =
        "8d4a70100bf861ea3f9dcd701938a183e89c300932ad6ac6b35fa5c8fe4979f9  something-else.txt\n";

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(other, strlen(other));

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);

    /* Nothing was downloaded, so no staging file was ever opened */
    CHECK(!Exists(target));
    CHECK(!Exists(staging));
    CHECK(job.fail == SyncFail_Listing);
    CHECK(strstr(SyncFailText(&job), CFG_BLOCKLIST_ASSET) != NULL);

    SyncEnd(&job);
}

static void TestTransferFailureCleansUp(const char *dir)
{
    SyncJob job;
    char    target[256];
    char    staging[256];

    snprintf(target, sizeof target, "%s/truncated.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(G_LISTING, strlen(G_LISTING));
    Reply("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n", "short", 5);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);

    /* A partial download must not be left behind for the next run to find */
    CHECK(!Exists(staging));
    CHECK(!Exists(target));
    CHECK(job.fail == SyncFail_Transfer);
    CHECK(job.job.fail == FetchFail_Body);

    SyncEnd(&job);
    CHECK(UsedTlsSlots(&G_POOL) == 0);
}

static void TestPartialBodyTimeoutCleansUp(const char *dir)
{
    static const char head[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n";
    SyncJob job;
    char    target[256];
    char    staging[256];

    snprintf(target, sizeof target, "%s/timeout.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    G_NOW_MS = 1000;
    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(G_LISTING, strlen(G_LISTING));
    Reply(head, "hello\n", 6);
    StallLastReplyAfter(sizeof head);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 64, NULL) == SyncStep_Again);
    CHECK(job.phase == SyncPhase_Asset);
    CHECK(job.job.bodyGot == 1);
    CHECK(SizeOf(staging) == 1);

    G_NOW_MS = job.job.deadlineMs;
    CHECK(SyncProgress(&job, G_NOW_MS) == SyncStep_Failed);
    CHECK(job.fail == SyncFail_Transfer);
    CHECK(job.job.fail == FetchFail_Timeout);
    CHECK(strcmp(SyncFailText(&job), "the transfer deadline expired") == 0);
    CHECK(job.job.fd == -1);
    CHECK(!Exists(staging));
    CHECK(!Exists(target));

    SyncEnd(&job);
    G_NOW_MS = 1000;
}

static void TestServerError(const char *dir)
{
    SyncJob job;
    char    target[256];

    snprintf(target, sizeof target, "%s/error.trie", dir);

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    Reply("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n", NULL, 0);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(!Exists(target));
    CHECK(job.fail == SyncFail_Transfer);
    CHECK(job.job.fail == FetchFail_Status);
    CHECK(strcmp(SyncPhaseText(&job), "digest listing") == 0);

    SyncEnd(&job);
}

/* Each of these stops the run for a different reason, and the daemon only
   retries on a timer, so the reason is the whole diagnosis. */
static void TestFailuresNameThemselves(const char *dir)
{
    SyncJob job;
    char    target[256];

    snprintf(target, sizeof target, "%s/named.trie", dir);

    ScriptReset();
    Reply("HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n", NULL, 0);
    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(job.job.fail == FetchFail_Header);
    CHECK(strcmp(SyncFailText(&job), "the response header was refused") == 0);
    SyncEnd(&job);

    ScriptReset();
    for(unsigned i = 0; i < CFG_FETCH_MAX_REDIRECTS + 1; i++)
        ReplyRedirect("https://cdn.example/asset");
    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(job.job.fail == FetchFail_Redirects);
    SyncEnd(&job);

    /* A directory that does not exist cannot hold a staging file */
    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(G_LISTING, strlen(G_LISTING));
    ReplyBody("hello\n", 6);
    CHECK(Begin(&job, "/nonexistent/dns_blocker/blocklist.trie", NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(job.fail == SyncFail_Staging);
    SyncEnd(&job);

    CHECK(strcmp(SyncFailText(NULL), "no run") == 0);
    CHECK(strcmp(SyncPhaseText(NULL), "no run") == 0);
    CHECK(strcmp(FetchFailText(NULL), "no transfer") == 0);

    ScriptReset();
    CHECK(Begin(&job, target, NULL));
    job.phase = SyncPhase_Digest;
    memcpy(job.releaseTag, "bad/tag", sizeof "bad/tag");
    CHECK(!Answer(&job));
    CHECK(job.fail == SyncFail_Url);
    CHECK(strcmp(SyncFailText(&job), "the release URL is invalid") == 0);
    SyncEnd(&job);
}

/* Runtime tier selects both digest and asset */
static void TestRuntimeTierSelectsTheAsset(const char *dir)
{
    SyncJob job;
    char    target[256];

    static const char listing[] =
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  "
        "dns_blocker-blocklist-aggressive-nsfw.trie\n"
        "8d4a70100bf861ea3f9dcd701938a183e89c300932ad6ac6b35fa5c8fe4979f9  "
        CFG_BLOCKLIST_ASSET "\n";

    snprintf(target, sizeof target, "%s/runtime-tier.trie", dir);

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(listing, strlen(listing));
    ReplyBody("hello\n", 6);

    CHECK(Begin(&job, target, "aggressive-nsfw"));
    CHECK(Run(&job, 512, NULL) == SyncStep_Done);
    CHECK(SizeOf(target) == 6);

    SyncEnd(&job);
    unlink(target);

    /* The compiled tier selects the other digest */
    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    ReplyBody(listing, strlen(listing));
    ReplyBody("hello\n", 6);

    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(job.fail == SyncFail_Digest);
    CHECK(!Exists(target));

    SyncEnd(&job);
}

static void TestInvalidTierIsRefused(const char *dir)
{
    SyncJob job;
    char    target[256];

    snprintf(target, sizeof target, "%s/bad-tier.trie", dir);

    ScriptReset();
    CHECK(!Begin(&job, target, "bad/tier"));
    CHECK(job.fail == SyncFail_Tier);
    CHECK(strcmp(SyncFailText(&job), "the configured tier is not a valid name")
          == 0);

    CHECK(!Begin(&job, target, ""));
    CHECK(job.fail == SyncFail_Tier);

    CHECK(!Exists(target));
}

static void TestInvalidLocator(const char *dir)
{
    SyncJob job;
    char    target[256];

    snprintf(target, sizeof target, "%s/invalid-locator.trie", dir);

    ScriptReset();
    ReplyBody("blocklist-latest\n", strlen("blocklist-latest\n"));
    CHECK(Begin(&job, target, NULL));
    CHECK(Run(&job, 512, NULL) == SyncStep_Failed);
    CHECK(job.fail == SyncFail_Locator);
    CHECK(strcmp(SyncPhaseText(&job), "release locator") == 0);
    CHECK(strcmp(SyncFailText(&job), "the locator names no valid release") == 0);
    CHECK(!Exists(target));

    SyncEnd(&job);
}

static void TestRefusals(const char *dir)
{
    SyncJob job;
    char    target[256];

    snprintf(target, sizeof target, "%s/guard.trie", dir);

    CHECK(!SyncBegin(NULL, &G_POOL, target, NULL, NULL));

    /* A refused start still has to leave a defined job. The daemon reads
       job->fail to report why the run did not begin, and an immutable build
       passes a null path on every retry, so reading uninitialised bytes here is
       undefined behaviour on a schedule. 0xA5 stands in for whatever the stack
       held. */
    memset(&job, 0xA5, sizeof job);
    CHECK(!SyncBegin(&job, NULL, target, NULL, NULL));
    CHECK(job.fail == SyncFail_None);
    CHECK(job.state == SyncState_Idle);
    CHECK(strcmp(SyncFailText(&job), "no failure") == 0);

    memset(&job, 0xA5, sizeof job);
    CHECK(!SyncBegin(&job, &G_POOL, NULL, NULL, NULL));
    CHECK(job.fail == SyncFail_None);
    CHECK(job.state == SyncState_Idle);
    CHECK(strcmp(SyncFailText(&job), "no failure") == 0);

    char oversize[CFG_SYNC_PATH_BYTES + 16];
    memset(oversize, 'a', sizeof oversize);
    oversize[sizeof oversize - 1] = '\0';
    memset(&job, 0xA5, sizeof job);
    CHECK(!Begin(&job, oversize, NULL));
    CHECK(job.fail == SyncFail_None);
    CHECK(job.state == SyncState_Idle);

    ScriptReset();
    ReplyBody(G_LOCATOR, strlen(G_LOCATOR));
    CHECK(Begin(&job, target, NULL));

    /* An address is only meaningful while the driver is waiting for one */
    CHECK(SyncEvents(&job) == 0);
    CHECK(SyncProgress(&job, G_NOW_MS) == SyncStep_NeedAddress);
    CHECK(Answer(&job));
    CHECK(!Answer(&job));
    CHECK(SyncEvents(&job) != 0);

    SyncEnd(&job);
    CHECK(SyncProgress(&job, G_NOW_MS) == SyncStep_Failed);
    CHECK(SyncProgress(NULL, G_NOW_MS) == SyncStep_Failed);
    CHECK(SyncHost(NULL) == NULL);
    CHECK(!SyncNeedsProgress(NULL));
}

int main(void)
{
    char dir[] = "/tmp/dns_blocker_driver_XXXXXX";
    int  listener;

    if(mkdtemp(dir) == NULL)
    {
        printf("sync driver: cannot create a temporary directory\n");
        return 1;
    }

    listener = OpenListener(&G_PORT);
    CHECK(listener >= 0);
    if(listener < 0)
        return 1;

    G_BACKEND.bReady = true;
    G_NOW_MS = 1000;

    TestUnchangedListSkipsTheAsset(dir);
    TestChangedListInstallsAndReloads(dir);
    TestActiveHashYieldsBetweenChunks(dir);
    TestHappyPath(dir);
    TestSyncCompletesWithTwoFreeSlots(dir);
    TestRefusedSyncKeepsResolverHealthy(dir);
    TestRedirects(dir);
    TestResponseCloseIsRetried(dir);
    TestResponseCloseRetryIsBounded(dir);
    TestDigestMismatchKeepsTheOldList(dir);
    TestListingWithoutTheAsset(dir);
    TestTransferFailureCleansUp(dir);
    TestPartialBodyTimeoutCleansUp(dir);
    TestServerError(dir);
    TestFailuresNameThemselves(dir);
    TestInvalidLocator(dir);
    TestRuntimeTierSelectsTheAsset(dir);
    TestInvalidTierIsRefused(dir);
    TestRefusals(dir);

    close(listener);
    rmdir(dir);

    if(G_FAILURES != 0)
    {
        printf("sync driver: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("sync driver: all checks passed\n");
    return 0;
}
