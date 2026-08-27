#define _POSIX_C_SOURCE 200809L

#include "trust.h"

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

static bool WriteBytes(const char *path, size_t count, uint8_t fill)
{
    FILE *f = fopen(path, "wb");
    if(f == NULL)
        return false;

    for(size_t i = 0; i < count; i++)
    {
        if(fputc(fill, f) == EOF)
        {
            fclose(f);
            return false;
        }
    }

    return fclose(f) == 0;
}

/* The cap is what keeps a whole system store off a device with a fixed arena,
   so the boundary is tested from both sides rather than only over it. */
static void TestSizeBoundary(const char *dir)
{
    TrustMap map;
    char     path[256];

    snprintf(path, sizeof path, "%s/bundle.der", dir);

    CHECK(WriteBytes(path, 64, 0xAB));
    CHECK(TrustLoad(&map, path, 128) == TrustLoad_Ok);
    CHECK(map.size == 64);
    CHECK(map.base != NULL && map.base[0] == 0xAB);
    TrustUnload(&map);
    CHECK(map.base == NULL);

    /* Exactly at the cap is usable, or a bundle that just fits is refused */
    CHECK(WriteBytes(path, 128, 0xCD));
    CHECK(TrustLoad(&map, path, 128) == TrustLoad_Ok);
    CHECK(map.size == 128);
    TrustUnload(&map);

    CHECK(WriteBytes(path, 129, 0xEF));
    CHECK(TrustLoad(&map, path, 128) == TrustLoad_TooLarge);
    CHECK(map.base == NULL);
    /* The measured size survives the refusal, so the operator is told what to cut */
    CHECK(map.fileSize == 129);

    unlink(path);
}

/* A missing file and an empty one need different fixes, and reporting both as
   one failure sent an earlier deployment looking for the wrong thing. */
static void TestRefusalsAreDistinct(const char *dir)
{
    TrustMap map;
    char     path[256];

    snprintf(path, sizeof path, "%s/absent.der", dir);
    CHECK(TrustLoad(&map, path, 4096) == TrustLoad_Missing);
    CHECK(map.base == NULL);

    snprintf(path, sizeof path, "%s/empty.der", dir);
    CHECK(WriteBytes(path, 0, 0));
    CHECK(TrustLoad(&map, path, 4096) == TrustLoad_Empty);
    CHECK(map.base == NULL);
    unlink(path);

    /* A directory opens but is not a bundle */
    CHECK(TrustLoad(&map, dir, 4096) == TrustLoad_Unreadable);

    CHECK(TrustLoad(&map, NULL, 4096) == TrustLoad_Missing);
    CHECK(TrustLoad(NULL, "x", 4096) == TrustLoad_Unreadable);

    /* A zero cap cannot be satisfied and must not read the file */
    snprintf(path, sizeof path, "%s/some.der", dir);
    CHECK(WriteBytes(path, 8, 1));
    CHECK(TrustLoad(&map, path, 0) == TrustLoad_Missing);
    unlink(path);
}

static void TestEveryResultIsNamed(void)
{
    const TrustResult all[] = {
        TrustLoad_Ok, TrustLoad_Missing, TrustLoad_Empty,
        TrustLoad_TooLarge, TrustLoad_Unreadable
    };

    for(size_t i = 0; i < sizeof all / sizeof *all; i++)
    {
        const char *text = TrustResultText(all[i]);
        CHECK(text != NULL && text[0] != '\0');
        CHECK(strcmp(text, "unknown") != 0);
    }
}

/* Unloading twice, or unloading something that never loaded, must not fault:
   every startup failure path calls it on the way out */
static void TestUnloadIsSafe(void)
{
    TrustMap map;

    memset(&map, 0, sizeof map);
    TrustUnload(&map);
    TrustUnload(&map);
    TrustUnload(NULL);
    CHECK(map.base == NULL);
}

int main(void)
{
    char dir[] = "/tmp/dns_blocker_trust_XXXXXX";

    if(mkdtemp(dir) == NULL)
    {
        printf("trust: cannot create a temporary directory\n");
        return 1;
    }

    TestSizeBoundary(dir);
    TestRefusalsAreDistinct(dir);
    TestEveryResultIsNamed();
    TestUnloadIsSafe();

    rmdir(dir);

    if(G_FAILURES != 0)
    {
        printf("trust: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("trust: all checks passed\n");
    return 0;
}
