#define _POSIX_C_SOURCE 200809L

#include "blocklist.h"
#include "wire.h"

#include "dnsbuild.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define CHECK_BLOCKED(list, dotted, want)                                  \
    do {                                                                   \
        WireName n_;                                                       \
        if(!NameOf((dotted), &n_))                                         \
        {                                                                  \
            printf("FAIL %s:%d  cannot encode %s\n",                       \
                   __FILE__, __LINE__, (dotted));                          \
            G_FAILURES++;                                                  \
        }                                                                  \
        else if(BlocklistContains((list), &n_) != (want))                  \
        {                                                                  \
            printf("FAIL %s:%d  %s: got %d, want %d\n", __FILE__, __LINE__,\
                   (dotted), (int)BlocklistContains((list), &n_),          \
                   (int)(want));                                           \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

/* Builds a trie by hand, in the layout the generator produces. Keeping this
   independent of the generator means a change to either one that breaks the
   agreement shows up here. */
typedef struct
{
    uint8_t  buf[4096];
    uint32_t nodeBytes;
    uint8_t  pool[512];
    uint32_t poolUsed;
} Builder2;

static void Put32(uint8_t *at, uint32_t v)
{
    at[0] = (uint8_t)v;
    at[1] = (uint8_t)(v >> 8);
    at[2] = (uint8_t)(v >> 16);
    at[3] = (uint8_t)(v >> 24);
}

static uint32_t PoolPut(Builder2 *b, const char *label)
{
    uint32_t at = b->poolUsed;
    size_t   n  = strlen(label);

    memcpy(b->pool + at, label, n);
    b->poolUsed += (uint32_t)n;
    return at;
}

/* One node with count children. Children must be given in the order the
   daemon searches: by length, then bytes. */
static uint32_t NodePut(Builder2 *b, size_t count)
{
    uint32_t at = b->nodeBytes;

    Put32(b->buf + at, (uint32_t)count);
    b->nodeBytes += 4 + (uint32_t)count * BLOCKLIST_CHILD_BYTES;
    return at;
}

static void ChildPut(Builder2 *b, uint32_t node, size_t index,
                     const char *label, uint32_t childOffset, bool bTerminal)
{
    uint8_t *entry = b->buf + node + 4 + index * BLOCKLIST_CHILD_BYTES;

    Put32(entry, PoolPut(b, label));
    Put32(entry + 4, childOffset);
    entry[8]  = (uint8_t)strlen(label);
    entry[9]  = bTerminal ? BLOCKLIST_FLAG_TERMINAL : 0u;
    entry[10] = 0;
    entry[11] = 0;
}

static uint8_t *Finish(Builder2 *b, Blocklist *list, size_t *sizeOut)
{
    size_t   total = BLOCKLIST_HEADER_BYTES + b->nodeBytes + b->poolUsed;
    uint8_t *file  = malloc(total);

    memcpy(file, BLOCKLIST_MAGIC, 4);
    Put32(file + 4, b->nodeBytes);
    Put32(file + 8, b->poolUsed);
    Put32(file + 12, 0);
    memcpy(file + BLOCKLIST_HEADER_BYTES, b->buf, b->nodeBytes);
    memcpy(file + BLOCKLIST_HEADER_BYTES + b->nodeBytes, b->pool, b->poolUsed);

    memset(list, 0, sizeof *list);
    list->base   = file;
    list->size   = total;
    list->source = BlocklistSource_Mapped;

    CHECK(BlocklistParseHeader(list, file, total));
    *sizeOut = total;
    return file;
}

/* com -> { doubleclick(terminal), example -> ads(terminal) } */
static uint8_t *BuildSample(Blocklist *list, size_t *sizeOut)
{
    static Builder2 b;
    memset(&b, 0, sizeof b);

    uint32_t root    = NodePut(&b, 1);
    uint32_t com     = NodePut(&b, 2);
    uint32_t example = NodePut(&b, 1);

    ChildPut(&b, root, 0, "com", com, false);

    /* "example" is longer than "doubleclick"? No: sorted by length first. */
    ChildPut(&b, com, 0, "example", example, false);
    ChildPut(&b, com, 1, "doubleclick", 0, true);

    ChildPut(&b, example, 0, "ads", 0, true);

    return Finish(&b, list, sizeOut);
}

static void TestExactAndSuffix(void)
{
    Blocklist list;
    size_t    size = 0;
    uint8_t  *file = BuildSample(&list, &size);

    /* The terminal mark covers the name and everything below it. */
    CHECK_BLOCKED(&list, "doubleclick.net", false);
    CHECK_BLOCKED(&list, "doubleclick.com", true);
    CHECK_BLOCKED(&list, "ad.doubleclick.com", true);
    CHECK_BLOCKED(&list, "a.b.c.doubleclick.com", true);

    CHECK_BLOCKED(&list, "ads.example.com", true);
    CHECK_BLOCKED(&list, "img.ads.example.com", true);

    /* A parent of a blocked name is not itself blocked. */
    CHECK_BLOCKED(&list, "example.com", false);
    CHECK_BLOCKED(&list, "com", false);

    /* A sibling that merely starts with the same bytes is not blocked. */
    CHECK_BLOCKED(&list, "notads.example.com", false);
    CHECK_BLOCKED(&list, "example.org", false);

    free(file);
}

static void TestCaseIsIgnored(void)
{
    Blocklist list;
    size_t    size = 0;
    uint8_t  *file = BuildSample(&list, &size);

    CHECK_BLOCKED(&list, "ADS.EXAMPLE.COM", true);
    CHECK_BLOCKED(&list, "Ads.Example.Com", true);
    CHECK_BLOCKED(&list, "DoubleClick.COM", true);

    free(file);
}

static void TestEmptyAndAbsentList(void)
{
    Blocklist list;
    WireName  name;

    memset(&list, 0, sizeof list);
    CHECK(NameOf("ads.example.com", &name));
    CHECK(!BlocklistContains(&list, &name));
}

/* The list linked into .rodata, reached two ways: a path that maps nothing, and
   the NULL path of an air-gapped build, which reads no file at all. The build
   decides whether a list is there, so both outcomes are checked. */
static void TestEmbeddedList(void)
{
    static const char *const paths[] = { "/nonexistent/blocklist.trie", NULL };

    for(size_t i = 0; i < sizeof paths / sizeof paths[0]; i++)
    {
        Blocklist list;
        bool      bLoaded = BlocklistLoad(&list, paths[i]);

        if(G_EMBEDDED_SIZE == 0)
        {
            CHECK(!bLoaded);
            CHECK(list.source == BlocklistSource_None);
        }
        else
        {
            CHECK(bLoaded);
            CHECK(list.source == BlocklistSource_Embedded);
            CHECK(list.nodeBytes > 0);
            CHECK_BLOCKED(&list, "definitely-not-in-any-list-12345.example",
                          false);
        }

        BlocklistUnload(&list);
    }
}

/* The file arrives over the network, so a corrupt one has to be refused
   rather than followed. */
static void TestCorruptHeaderRefused(void)
{
    Blocklist list;
    size_t    size = 0;
    uint8_t  *file = BuildSample(&list, &size);

    uint8_t *copy = malloc(size);

    memcpy(copy, file, size);
    copy[0] = 'X';
    CHECK(!BlocklistParseHeader(&list, copy, size));

    memcpy(copy, file, size);
    Put32(copy + 4, 0xFFFFFFFFu);
    CHECK(!BlocklistParseHeader(&list, copy, size));

    memcpy(copy, file, size);
    Put32(copy + 8, 0xFFFFFFFFu);
    CHECK(!BlocklistParseHeader(&list, copy, size));

    memcpy(copy, file, size);
    Put32(copy + 12, 0xFFFFFFFFu);
    CHECK(!BlocklistParseHeader(&list, copy, size));

    for(size_t n = 0; n < BLOCKLIST_HEADER_BYTES; n++)
        CHECK(!BlocklistParseHeader(&list, file, n));

    free(copy);
    free(file);
}

/* Every single-byte corruption of the body must leave the lookup bounded. A
   crash or a sanitizer report here is the failure. */
static void TestCorruptBodyIsBounded(void)
{
    Blocklist list;
    size_t    size = 0;
    uint8_t  *file = BuildSample(&list, &size);
    uint8_t  *copy = malloc(size);
    WireName  name;

    CHECK(NameOf("ads.example.com", &name));

    for(size_t at = 0; at < size; at++)
    {
        for(unsigned bit = 0; bit < 8; bit++)
        {
            Blocklist probe;

            memcpy(copy, file, size);
            copy[at] ^= (uint8_t)(1u << bit);

            memset(&probe, 0, sizeof probe);
            probe.base   = copy;
            probe.size   = size;
            probe.source = BlocklistSource_Mapped;

            if(BlocklistParseHeader(&probe, copy, size))
                (void)BlocklistContains(&probe, &name);
        }
    }

    /* Truncation as well. */
    for(size_t n = 0; n < size; n++)
    {
        Blocklist probe;

        memset(&probe, 0, sizeof probe);
        probe.base   = file;
        probe.size   = n;
        probe.source = BlocklistSource_Mapped;

        if(BlocklistParseHeader(&probe, file, n))
            (void)BlocklistContains(&probe, &name);
    }

    free(copy);
    free(file);
}

/* net -> tracker(terminal). Distinguishable from BuildSample, so a swap that
   did not happen shows up as the wrong name being blocked. */
static uint8_t *BuildOther(Blocklist *list, size_t *sizeOut)
{
    static Builder2 b;
    memset(&b, 0, sizeof b);

    uint32_t root = NodePut(&b, 1);
    uint32_t net  = NodePut(&b, 1);

    ChildPut(&b, root, 0, "net", net, false);
    ChildPut(&b, net, 0, "tracker", 0, true);

    return Finish(&b, list, sizeOut);
}

static bool WriteTrie(const char *path, const uint8_t *file, size_t size)
{
    FILE *out = fopen(path, "wb");
    if(out == NULL)
        return false;

    size_t wrote = fwrite(file, 1, size, out);
    fclose(out);
    return wrote == size;
}

/* A reload happens while the daemon is serving, so a bad replacement must
   never cost it the list it already has. */
static void TestReload(void)
{
    char dir[] = "/tmp/dns_blocker_reload_XXXXXX";
    if(mkdtemp(dir) == NULL)
    {
        printf("FAIL %s:%d  cannot create a temporary directory\n",
               __FILE__, __LINE__);
        G_FAILURES++;
        return;
    }

    char first[256];
    char second[256];
    char broken[256];
    snprintf(first, sizeof first, "%s/first.trie", dir);
    snprintf(second, sizeof second, "%s/second.trie", dir);
    snprintf(broken, sizeof broken, "%s/broken.trie", dir);

    Blocklist built;
    size_t    size = 0;

    uint8_t *sample = BuildSample(&built, &size);
    CHECK(WriteTrie(first, sample, size));

    size_t   otherSize = 0;
    uint8_t *other     = BuildOther(&built, &otherSize);
    CHECK(WriteTrie(second, other, otherSize));

    uint8_t *corrupt = malloc(otherSize);
    memcpy(corrupt, other, otherSize);
    corrupt[0] = 'X';
    CHECK(WriteTrie(broken, corrupt, otherSize));

    Blocklist list;
    CHECK(BlocklistLoad(&list, first));
    CHECK(list.source == BlocklistSource_Mapped);
    CHECK_BLOCKED(&list, "doubleclick.com", true);
    CHECK_BLOCKED(&list, "tracker.net", false);

    /* The lookups below read through the new mapping. Reading the old one
       after it is unmapped is what this proves does not happen. */
    CHECK(BlocklistReload(&list, second));
    CHECK(list.source == BlocklistSource_Mapped);
    CHECK_BLOCKED(&list, "tracker.net", true);
    CHECK_BLOCKED(&list, "sub.tracker.net", true);
    CHECK_BLOCKED(&list, "doubleclick.com", false);

    CHECK(!BlocklistReload(&list, broken));
    CHECK_BLOCKED(&list, "tracker.net", true);

    char absent[256];
    snprintf(absent, sizeof absent, "%s/absent.trie", dir);
    CHECK(!BlocklistReload(&list, absent));
    CHECK_BLOCKED(&list, "tracker.net", true);

    CHECK(WriteTrie(broken, corrupt, 3));
    CHECK(!BlocklistReload(&list, broken));
    CHECK_BLOCKED(&list, "tracker.net", true);

    CHECK(!BlocklistReload(&list, NULL));
    CHECK(!BlocklistReload(NULL, second));
    CHECK_BLOCKED(&list, "tracker.net", true);

    BlocklistUnload(&list);

    /* An embedded list lives in .rodata, so a swap away from it must not try
       to unmap it */
    Blocklist embedded;
    if(BlocklistLoad(&embedded, "/nonexistent/blocklist.trie")
       && embedded.source == BlocklistSource_Embedded)
    {
        CHECK(BlocklistReload(&embedded, second));
        CHECK(embedded.source == BlocklistSource_Mapped);
        CHECK_BLOCKED(&embedded, "tracker.net", true);
    }
    BlocklistUnload(&embedded);

    free(corrupt);
    free(other);
    free(sample);

    unlink(first);
    unlink(second);
    unlink(broken);
    rmdir(dir);
}

int main(void)
{
    TestExactAndSuffix();
    TestCaseIsIgnored();
    TestEmptyAndAbsentList();
    TestEmbeddedList();
    TestCorruptHeaderRefused();
    TestCorruptBodyIsBounded();
    TestReload();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("blocklist: all checks passed\n");
    return 0;
}
