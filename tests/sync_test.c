#define _POSIX_C_SOURCE 200809L

#include "sync.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static const uint8_t G_WANT[FETCH_DIGEST_BYTES] = {
    0x25, 0xb9, 0x3f, 0x9c, 0x8b, 0x85, 0x5b, 0x0e,
    0x99, 0x57, 0x41, 0x20, 0x7a, 0xec, 0x6a, 0xb9,
    0x79, 0xec, 0xe3, 0x17, 0xd5, 0xbe, 0xd1, 0x32,
    0x79, 0x91, 0xda, 0x54, 0xa4, 0x38, 0x2f, 0x4c
};

static bool Exists(const char *path)
{
    struct stat info;
    return stat(path, &info) == 0;
}

static bool Contents(const char *path, char *out, size_t cap, size_t *outLen)
{
    FILE *file = fopen(path, "rb");
    if(file == NULL)
        return false;

    *outLen = fread(out, 1, cap, file);
    fclose(file);
    return true;
}

static void WriteFile(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if(file == NULL)
        return;
    fwrite(text, 1, strlen(text), file);
    fclose(file);
}

static void TestLocator(void)
{
    static const char valid[] = "blocklist-2026-08-09-31286198180-1";
    char tag[CFG_SYNC_RELEASE_TAG_BYTES];
    char url[CFG_FETCH_URL_BYTES];

    CHECK(SyncParseLocator((const uint8_t *)valid, strlen(valid), tag,
                           sizeof tag));
    CHECK(strcmp(tag, valid) == 0);

    static const char lf[] = "blocklist-2026-08-09-31286198180-1\n";
    CHECK(SyncParseLocator((const uint8_t *)lf, strlen(lf), tag, sizeof tag));

    static const char crlf[] = "blocklist-2024-02-29-1-2\r\n";
    CHECK(SyncParseLocator((const uint8_t *)crlf, strlen(crlf), tag,
                           sizeof tag));

    static const char *invalid[] = {
        "",
        "release-2026-08-09-1-1",
        "blocklist-0000-08-09-1-1",
        "blocklist-2026-00-09-1-1",
        "blocklist-2026-13-09-1-1",
        "blocklist-2026-02-29-1-1",
        "blocklist-2026-08-32-1-1",
        "blocklist-2026-08-09-0-1",
        "blocklist-2026-08-09-01-1",
        "blocklist-2026-08-09-1-0",
        "blocklist-2026-08-09-1-01",
        "blocklist-2026-08-09-1-1/asset",
        "blocklist-2026-08-09-1-1\nextra",
        "blocklist-2026-08-09-1-1\n\n"
    };

    for(size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++)
    {
        memset(tag, 'x', sizeof tag);
        CHECK(!SyncParseLocator((const uint8_t *)invalid[i], strlen(invalid[i]),
                                tag, sizeof tag));
        CHECK(tag[0] == '\0');
    }

    static const uint8_t embeddedNul[] = {
        'b','l','o','c','k','l','i','s','t','-',
        '2','0','2','6','-','0','8','-','0','9','-',
        '1','\0','-','1'
    };
    CHECK(!SyncParseLocator(embeddedNul, sizeof embeddedNul, tag, sizeof tag));
    CHECK(!SyncParseLocator(NULL, 0, tag, sizeof tag));
    CHECK(!SyncParseLocator((const uint8_t *)valid, strlen(valid), NULL,
                            sizeof tag));
    CHECK(!SyncParseLocator((const uint8_t *)valid, strlen(valid), tag, 0));
    CHECK(!SyncParseLocator((const uint8_t *)valid, strlen(valid), tag,
                            strlen(valid)));

    CHECK(SyncBuildReleaseUrl(url, sizeof url, valid,
                              CFG_BLOCKLIST_DIGEST_ASSET));
    CHECK(strcmp(url,
                 CFG_BLOCKLIST_RELEASE_BASE_URL
                 "blocklist-2026-08-09-31286198180-1/"
                 CFG_BLOCKLIST_DIGEST_ASSET) == 0);
    CHECK(!SyncBuildReleaseUrl(url, 8, valid, CFG_BLOCKLIST_ASSET));
    CHECK(!SyncBuildReleaseUrl(url, sizeof url, "bad/tag", CFG_BLOCKLIST_ASSET));
    CHECK(!SyncBuildReleaseUrl(NULL, sizeof url, valid, CFG_BLOCKLIST_ASSET));
}

static void TestStagingPath(void)
{
    char path[64];

    CHECK(SyncStagingPath(path, sizeof path, "/run/dns_blocker/blocklist.trie"));
    CHECK(strcmp(path, "/run/dns_blocker/blocklist.trie.new") == 0);

    /* Same directory, so rename(2) stays within one filesystem */
    CHECK(strncmp(path, "/run/dns_blocker/", 17) == 0);

    CHECK(SyncStagingPath(path, sizeof path, "a"));
    CHECK(strcmp(path, "a.new") == 0);

    char tight[6];
    CHECK(SyncStagingPath(tight, sizeof tight, "a"));
    CHECK(!SyncStagingPath(tight, sizeof tight, "ab"));

    CHECK(!SyncStagingPath(path, sizeof path, ""));
    CHECK(!SyncStagingPath(path, 0, "a"));
    CHECK(!SyncStagingPath(NULL, sizeof path, "a"));
    CHECK(!SyncStagingPath(path, sizeof path, NULL));

    char small[8];
    CHECK(!SyncStagingPath(small, sizeof small,
                           "/run/dns_blocker/blocklist.trie"));
}

/* Under `init` nothing else makes this directory, and a tmpfs loses it at every
   boot, so the daemon has to make it and has to tolerate finding it. */
static void TestPrepareDirectory(const char *dir)
{
    char made[256];
    char nested[256];
    struct stat info;

    snprintf(made, sizeof made, "%s/made/blocklist.trie", dir);
    CHECK(SyncPrepareDirectory(made));
    CHECK(SyncPrepareDirectory(made));

    snprintf(nested, sizeof nested, "%s/made", dir);
    CHECK(stat(nested, &info) == 0);
    CHECK(S_ISDIR(info.st_mode));
    CHECK(rmdir(nested) == 0);

    /* One level only, so a missing parent is a refusal rather than a walk */
    snprintf(nested, sizeof nested, "%s/absent/deeper/blocklist.trie", dir);
    CHECK(!SyncPrepareDirectory(nested));

    /* Nothing to make */
    CHECK(SyncPrepareDirectory("blocklist.trie"));
    CHECK(SyncPrepareDirectory("/blocklist.trie"));

    CHECK(!SyncPrepareDirectory(NULL));

    char oversize[CFG_SYNC_PATH_BYTES + 16];
    memset(oversize, 'a', sizeof oversize);
    oversize[0]                    = '/';
    oversize[sizeof oversize - 8]  = '/';
    oversize[sizeof oversize - 1]  = '\0';
    CHECK(!SyncPrepareDirectory(oversize));
}

static void TestCommitPromotes(const char *dir)
{
    char target[256];
    char staging[256];
    char body[64];
    size_t bodyLen = 0;

    snprintf(target, sizeof target, "%s/blocklist.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    WriteFile(target, "old");

    int fd = SyncOpenStaging(staging);
    CHECK(fd >= 0);
    CHECK(write(fd, "new", 3) == 3);

    CHECK(SyncCommit(fd, staging, target, G_WANT, G_WANT) == SyncInstall_Ok);
    CHECK(!Exists(staging));
    CHECK(Contents(target, body, sizeof body, &bodyLen));
    CHECK(bodyLen == 3 && memcmp(body, "new", 3) == 0);

    unlink(target);
}

static void TestCommitRefusesMismatch(const char *dir)
{
    char target[256];
    char staging[256];
    char body[64];
    size_t bodyLen = 0;
    uint8_t wrong[FETCH_DIGEST_BYTES];

    memcpy(wrong, G_WANT, sizeof wrong);
    wrong[FETCH_DIGEST_BYTES - 1] ^= 0x01;

    snprintf(target, sizeof target, "%s/blocklist.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    WriteFile(target, "old");

    int fd = SyncOpenStaging(staging);
    CHECK(fd >= 0);
    CHECK(write(fd, "poisoned", 8) == 8);

    CHECK(SyncCommit(fd, staging, target, wrong, G_WANT)
          == SyncInstall_Mismatch);

    /* The old list is still the one on disk, and the rejected bytes are gone */
    CHECK(!Exists(staging));
    CHECK(Contents(target, body, sizeof body, &bodyLen));
    CHECK(bodyLen == 3 && memcmp(body, "old", 3) == 0);

    /* A single differing byte anywhere in the digest has to be caught */
    for(size_t i = 0; i < FETCH_DIGEST_BYTES; i++)
    {
        memcpy(wrong, G_WANT, sizeof wrong);
        wrong[i] ^= 0x80;

        fd = SyncOpenStaging(staging);
        CHECK(fd >= 0);
        CHECK(SyncCommit(fd, staging, target, wrong, G_WANT)
              == SyncInstall_Mismatch);
    }

    CHECK(Contents(target, body, sizeof body, &bodyLen));
    CHECK(bodyLen == 3 && memcmp(body, "old", 3) == 0);

    unlink(target);
}

static void TestCommitWithNoTarget(const char *dir)
{
    char target[256];
    char staging[256];

    snprintf(target, sizeof target, "%s/first.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    int fd = SyncOpenStaging(staging);
    CHECK(fd >= 0);
    CHECK(write(fd, "first", 5) == 5);
    CHECK(SyncCommit(fd, staging, target, G_WANT, G_WANT) == SyncInstall_Ok);
    CHECK(Exists(target));

    unlink(target);
}

static void TestStagingTruncatesLeftovers(const char *dir)
{
    char target[256];
    char staging[256];
    char body[64];
    size_t bodyLen = 0;

    snprintf(target, sizeof target, "%s/resumed.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    /* An interrupted run leaves a partial file. The next attempt must not
       append to it, or the digest covers bytes from two downloads */
    WriteFile(staging, "leftover garbage");

    int fd = SyncOpenStaging(staging);
    CHECK(fd >= 0);
    CHECK(write(fd, "clean", 5) == 5);
    CHECK(SyncCommit(fd, staging, target, G_WANT, G_WANT) == SyncInstall_Ok);
    CHECK(Contents(target, body, sizeof body, &bodyLen));
    CHECK(bodyLen == 5 && memcmp(body, "clean", 5) == 0);

    unlink(target);
}

static void TestAbandon(const char *dir)
{
    char target[256];
    char staging[256];

    snprintf(target, sizeof target, "%s/dropped.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    int fd = SyncOpenStaging(staging);
    CHECK(fd >= 0);
    CHECK(write(fd, "partial", 7) == 7);

    SyncAbandon(fd, staging);
    CHECK(!Exists(staging));
    CHECK(!Exists(target));

    SyncAbandon(-1, staging);
    SyncAbandon(-1, NULL);
}

static void TestRefusals(const char *dir)
{
    char target[256];
    char staging[256];

    snprintf(target, sizeof target, "%s/guard.trie", dir);
    CHECK(SyncStagingPath(staging, sizeof staging, target));

    CHECK(SyncCommit(-1, staging, target, G_WANT, G_WANT)
          == SyncInstall_Failed);
    CHECK(!Exists(target));

    int fd = SyncOpenStaging(staging);
    CHECK(fd >= 0);
    CHECK(SyncCommit(fd, staging, target, NULL, G_WANT) == SyncInstall_Failed);
    CHECK(!Exists(staging));

    CHECK(SyncOpenStaging(NULL) < 0);
    CHECK(SyncOpenStaging("/nonexistent-directory/x.new") < 0);
}

int main(void)
{
    char dir[] = "/tmp/dns_blocker_sync_XXXXXX";

    if(mkdtemp(dir) == NULL)
    {
        printf("sync: cannot create a temporary directory\n");
        return 1;
    }

    TestStagingPath();
    TestLocator();
    TestPrepareDirectory(dir);
    TestCommitPromotes(dir);
    TestCommitRefusesMismatch(dir);
    TestCommitWithNoTarget(dir);
    TestStagingTruncatesLeftovers(dir);
    TestAbandon(dir);
    TestRefusals(dir);

    rmdir(dir);

    if(G_FAILURES != 0)
    {
        printf("sync: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("sync: all checks passed\n");
    return 0;
}
