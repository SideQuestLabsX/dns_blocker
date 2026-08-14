#include "arena.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int G_FAILURES;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if(!(cond))                                                        \
        {                                                                  \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

static void TestInitRejectsBadArgs(void)
{
    CHECK(!ArenaInit(NULL, 4096));
    CHECK(!ArenaInit((&(Arena){0}), 0));
}

static void TestAllocReturnsAlignedZeroedMemory(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    char *probe = ArenaAlloc(&arena, 64, _Alignof(max_align_t));
    CHECK(probe != NULL);
    CHECK(((uintptr_t)probe % _Alignof(max_align_t)) == 0);
    for(int i = 0; i < 64; i++)
        CHECK(probe[i] == 0);

    ArenaRelease(&arena);
}

static void TestAllocRejectsBadArgs(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    CHECK(ArenaAlloc(NULL, 64, _Alignof(max_align_t)) == NULL);
    CHECK(ArenaAlloc(&arena, 0, _Alignof(max_align_t)) == NULL);
    CHECK(ArenaAlloc(&arena, 64, 0) == NULL);
    CHECK(ArenaAlloc(&arena, 64, 3) == NULL);
    CHECK(ArenaAlloc(&arena, 64, 6) == NULL);

    Arena empty = {0};
    CHECK(ArenaAlloc(&empty, 64, _Alignof(max_align_t)) == NULL);

    ArenaRelease(&arena);
}

static void TestAllocAdvancesUsedMonotonically(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    size_t before = ArenaRemaining(&arena);
    CHECK(ArenaAlloc(&arena, 100, _Alignof(max_align_t)) != NULL);
    size_t after = ArenaRemaining(&arena);
    CHECK(after < before);
    CHECK(ArenaRemaining(&arena) == arena.size - arena.used);

    ArenaRelease(&arena);
}

static void TestAllocRefusesOversize(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 256));

    CHECK(ArenaAlloc(&arena, 200, _Alignof(max_align_t)) != NULL);
    CHECK(ArenaAlloc(&arena, 200, _Alignof(max_align_t)) == NULL);

    ArenaRelease(&arena);
}

static void TestAllocHonorsLargeAlignment(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    void *a = ArenaAlloc(&arena, 1, 256);
    CHECK(a != NULL);
    CHECK(((uintptr_t)a % 256) == 0);

    void *b = ArenaAlloc(&arena, 1, 256);
    CHECK(b != NULL);
    CHECK(((uintptr_t)b % 256) == 0);
    CHECK((unsigned char *)b >= (unsigned char *)a + 256);

    ArenaRelease(&arena);
}

static void TestCarvePartitionsParent(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    Arena child;
    CHECK(ArenaCarve(&arena, &child, 512));
    CHECK(child.base != NULL);
    CHECK(child.size == 512);
    CHECK(child.used == 0);
    CHECK((unsigned char *)child.base >= arena.base);
    CHECK((unsigned char *)child.base + child.size <= arena.base + arena.size);
    CHECK(((uintptr_t)child.base % _Alignof(max_align_t)) == 0);

    size_t remaining = ArenaRemaining(&arena);
    CHECK(ArenaAlloc(&child, 512, 1) != NULL);
    CHECK(ArenaRemaining(&child) == 0);
    CHECK(ArenaAlloc(&child, 1, 1) == NULL);
    CHECK(ArenaRemaining(&arena) == remaining);

    ArenaRelease(&arena);
}

static void TestCarveRejectsBadArgs(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    CHECK(!ArenaCarve(&arena, NULL, 64));

    Arena child;
    CHECK(ArenaCarve(&arena, &child, 0));
    CHECK(child.base == NULL);
    CHECK(child.size == 0);
    CHECK(child.used == 0);

    CHECK(!ArenaCarve(&arena, &child, 8192));

    ArenaRelease(&arena);
}

static void TestCarveChainSumsToParent(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 1024));

    Arena slices[4];
    const size_t sizes[4] = {256, 256, 256, 256};
    for(int i = 0; i < 4; i++)
        CHECK(ArenaCarve(&arena, &slices[i], sizes[i]));

    CHECK(ArenaRemaining(&arena) == 0);

    Arena overflow;
    CHECK(ArenaCarve(&arena, &overflow, 1) == false);

    for(int i = 0; i < 4; i++)
    {
        CHECK(slices[i].base != slices[(i + 1) % 4].base);
        CHECK(slices[i].size == 256);
    }

    ArenaRelease(&arena);
}

static void TestAllocArrayGuardsOverflow(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 4096));

    CHECK(ArenaAllocArray(&arena, 16, 64, _Alignof(max_align_t)) != NULL);

    CHECK(ArenaAllocArray(&arena, (size_t)-1, 2, _Alignof(max_align_t)) == NULL);
    CHECK(ArenaAllocArray(&arena, 2, (size_t)-1, _Alignof(max_align_t)) == NULL);

    ArenaRelease(&arena);
}

static void TestRemainingMatchesState(void)
{
    Arena arena;
    CHECK(ArenaInit(&arena, 512));
    CHECK(ArenaRemaining(&arena) == 512);

    ArenaAlloc(&arena, 100, _Alignof(max_align_t));
    CHECK(ArenaRemaining(&arena) == arena.size - arena.used);

    ArenaRelease(&arena);
    CHECK(ArenaRemaining(&arena) == 0);
    CHECK(ArenaRemaining(NULL) == 0);
}

int main(void)
{
    TestInitRejectsBadArgs();
    TestAllocReturnsAlignedZeroedMemory();
    TestAllocRejectsBadArgs();
    TestAllocAdvancesUsedMonotonically();
    TestAllocRefusesOversize();
    TestAllocHonorsLargeAlignment();
    TestCarvePartitionsParent();
    TestCarveRejectsBadArgs();
    TestCarveChainSumsToParent();
    TestAllocArrayGuardsOverflow();
    TestRemainingMatchesState();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("arena: all checks passed\n");
    return 0;
}
