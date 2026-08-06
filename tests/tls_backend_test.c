#include "arena.h"
#include "config.h"
#include "tls.h"

#include <mbedtls/base64.h>

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

/* ISRG Root X1 DER fixture encoded as base64 */
static const unsigned char G_CA_BASE64[] =
    "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";

static bool DecodeRoot(uint8_t *der, size_t cap, size_t *derLen)
{
    return mbedtls_base64_decode(der, cap, derLen, G_CA_BASE64,
                                 sizeof G_CA_BASE64 - 1) == 0;
}

static void TestBackendUsesDerBundleAndResetsAllocator(void)
{
    Arena      arena;
    TlsBackend backend;
    TlsChannel channels[CFG_TLS_SLOTS];
    uint8_t    root[2048];
    uint8_t    bundle[4096];
    size_t     rootLen = 0;
    int        fds[CFG_TLS_SLOTS][2];

    CHECK(DecodeRoot(root, sizeof root, &rootLen));
    CHECK(rootLen != 0 && rootLen * 2 <= sizeof bundle);
    memcpy(bundle, root, rootLen);
    memcpy(bundle + rootLen, root, rootLen);

    CHECK(ArenaInit(&arena, ARENA_TLS_BYTES));
    CHECK(TlsBackendInit(&backend, &arena, bundle, rootLen * 2));
    CHECK(backend.bReady);
    size_t started = 0;
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
    {
        if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds[i]) != 0)
        {
            CHECK(false);
            break;
        }

        if(TlsChannelStart(&backend, &channels[i], fds[i][0], "example.com")
           != TlsIo_Ok)
        {
            CHECK(false);
            close(fds[i][1]);
            break;
        }

        CHECK(channels[i].bReady);
        started++;
    }

    CHECK(started == CFG_TLS_SLOTS);
    for(size_t i = 0; i < started; i++)
    {
        TlsChannelClose(&channels[i]);
        close(fds[i][1]);
    }
    TlsBackendFree(&backend);

    bundle[rootLen] = 0;
    CHECK(!TlsBackendInit(&backend, &arena, bundle, rootLen + 1));
    CHECK(TlsBackendInit(&backend, &arena, root, rootLen));
    TlsBackendFree(&backend);
    ArenaRelease(&arena);
}

int main(void)
{
    TestBackendUsesDerBundleAndResetsAllocator();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("tls backend: all checks passed\n");
    return 0;
}
