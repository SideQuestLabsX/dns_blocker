#include "arena.h"
#include "tls.h"

#include <stdio.h>

static int G_FAILURES;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if(!(cond))                                                        \
        {                                                                  \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);       \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

static void TestMinimalContract(void)
{
    Arena      arena;
    TlsBackend backend;
    TlsChannel channel;

    CHECK(ArenaInit(&arena, 4096));
    CHECK(TlsBackendInit(&backend, &arena, NULL, 0));
    CHECK(backend.bReady);
    CHECK(TlsChannelStart(&backend, &channel, -1, "example.com") == TlsIo_Error);

    TlsBackendFree(&backend);
    ArenaRelease(&arena);
}

int main(void)
{
    TestMinimalContract();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("tls: all checks passed\n");
    return 0;
}
