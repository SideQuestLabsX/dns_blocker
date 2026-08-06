#define _POSIX_C_SOURCE 200809L

#include "arena.h"
#include "hosts.h"
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

/* HostsParseLine rewrites its argument, so every case gets its own buffer. */
static size_t ParseOf(const char *text, uint8_t *addr, uint8_t *addrLen,
                      WireName *names, size_t maxNames)
{
    char line[512];

    snprintf(line, sizeof line, "%s", text);
    return HostsParseLine(line, addr, addrLen, names, maxNames);
}

static void TestParsesAddressesAndNames(void)
{
    uint8_t  addr[16];
    uint8_t  addrLen = 0;
    WireName names[8];
    WireName want;

    CHECK(ParseOf("192.168.1.47 iPhone", addr, &addrLen, names, 8) == 1);
    CHECK(addrLen == 4);
    CHECK(addr[0] == 192 && addr[1] == 168 && addr[2] == 1 && addr[3] == 47);

    /* A name with no dot takes the local domain, and case is folded. */
    CHECK(NameOf("iphone.lan", &want));
    CHECK(WireNameEqual(&names[0], &want));

    CHECK(ParseOf("10.0.0.5\tnas.example.org", addr, &addrLen, names, 8) == 1);
    CHECK(NameOf("nas.example.org", &want));
    CHECK(WireNameEqual(&names[0], &want));

    /* Several names on one address, the way /etc/hosts allows. */
    CHECK(ParseOf("10.0.0.6  printer scanner", addr, &addrLen, names, 8) == 2);
    CHECK(NameOf("printer.lan", &want));
    CHECK(WireNameEqual(&names[0], &want));
    CHECK(NameOf("scanner.lan", &want));
    CHECK(WireNameEqual(&names[1], &want));

    CHECK(ParseOf("fd00::1 router", addr, &addrLen, names, 8) == 1);
    CHECK(addrLen == 16);
    CHECK(addr[0] == 0xFD && addr[15] == 1);
}

static void TestRejectsRubbish(void)
{
    uint8_t  addr[16];
    uint8_t  addrLen = 0;
    WireName names[8];

    CHECK(ParseOf("# a comment", addr, &addrLen, names, 8) == 0);
    CHECK(ParseOf("", addr, &addrLen, names, 8) == 0);
    CHECK(ParseOf("   \t  ", addr, &addrLen, names, 8) == 0);
    CHECK(ParseOf("192.168.1.47", addr, &addrLen, names, 8) == 0);
    CHECK(ParseOf("notanaddress name", addr, &addrLen, names, 8) == 0);
    CHECK(ParseOf("999.1.1.1 name", addr, &addrLen, names, 8) == 0);
    CHECK(ParseOf("192.168.1.47 iPhone # trailing", addr, &addrLen, names, 8) == 1);

    /* An empty label cannot be encoded, so the name is dropped and the line
       keeps whatever else it carried. */
    CHECK(ParseOf("192.168.1.47 .. good", addr, &addrLen, names, 8) == 1);
}

static void Load(HostMap *map, Arena *arena, const char *text)
{
    char path[] = "/tmp/dns_blocker_hosts_XXXXXX";
    int  fd = mkstemp(path);

    CHECK(fd >= 0);
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    close(fd);

    CHECK(HostsLoad(map, arena, path));
    unlink(path);
}

static const char *G_FILE =
    "# devices\n"
    "192.168.1.47  iPhone\n"
    "192.168.1.10  nas printer\n"
    "fd00::1       router\n"
    "\n"
    "203.0.113.9   public.example.org\n";

static void TestForwardLookup(void)
{
    Arena    arena;
    HostMap  map;
    WireName name;
    const HostEntry *entry = NULL;
    bool     bExists = false;

    CHECK(ArenaInit(&arena, ARENA_HOSTS_BYTES));
    Load(&map, &arena, G_FILE);
    CHECK(map.count == 5);

    CHECK(NameOf("iphone.lan", &name));
    CHECK(HostsLookup(&map, &name, WIRE_TYPE_A, &entry, &bExists));
    CHECK(bExists);
    if(entry != NULL)
        CHECK(entry->addrLen == 4 && entry->addr[3] == 47);

    /* Case folds, because a query may arrive in any case at all. */
    CHECK(NameOf("iPhone.LAN", &name));
    CHECK(HostsLookup(&map, &name, WIRE_TYPE_A, &entry, &bExists));

    /* The name is ours but has no AAAA, which is NODATA and not NXDOMAIN. */
    CHECK(!HostsLookup(&map, &name, WIRE_TYPE_AAAA, &entry, &bExists));
    CHECK(bExists);

    CHECK(NameOf("router.lan", &name));
    CHECK(HostsLookup(&map, &name, WIRE_TYPE_AAAA, &entry, &bExists));
    if(entry != NULL)
        CHECK(entry->addrLen == 16);
    CHECK(!HostsLookup(&map, &name, WIRE_TYPE_A, &entry, &bExists));
    CHECK(bExists);

    /* Two names on one line both resolve. */
    CHECK(NameOf("printer.lan", &name));
    CHECK(HostsLookup(&map, &name, WIRE_TYPE_A, &entry, &bExists));
    if(entry != NULL)
        CHECK(entry->addr[3] == 10);

    CHECK(NameOf("elsewhere.lan", &name));
    CHECK(!HostsLookup(&map, &name, WIRE_TYPE_A, &entry, &bExists));
    CHECK(!bExists);

    ArenaRelease(&arena);
}

static void TestLocalZone(void)
{
    Arena    arena;
    HostMap  map;
    WireName name;

    CHECK(ArenaInit(&arena, ARENA_HOSTS_BYTES));
    Load(&map, &arena, G_FILE);

    CHECK(NameOf("iphone.lan", &name));
    CHECK(HostsNameIsLocal(&map, &name));

    /* A name that is not in the map is still this network's business. */
    CHECK(NameOf("unknown.lan", &name));
    CHECK(HostsNameIsLocal(&map, &name));

    CHECK(NameOf("deep.sub.lan", &name));
    CHECK(HostsNameIsLocal(&map, &name));

    CHECK(NameOf("lan", &name));
    CHECK(HostsNameIsLocal(&map, &name));

    CHECK(NameOf("example.com", &name));
    CHECK(!HostsNameIsLocal(&map, &name));

    /* The zone match lands on a label boundary, so this is not below it. */
    CHECK(NameOf("notlan", &name));
    CHECK(!HostsNameIsLocal(&map, &name));

    ArenaRelease(&arena);
}

static void TestReverseLookup(void)
{
    Arena    arena;
    HostMap  map;
    WireName name;
    uint8_t  addr[16];
    uint8_t  addrLen = 0;

    CHECK(ArenaInit(&arena, ARENA_HOSTS_BYTES));
    Load(&map, &arena, G_FILE);

    CHECK(NameOf("47.1.168.192.in-addr.arpa", &name));
    CHECK(HostsReverseAddress(&name, addr, &addrLen));
    CHECK(addrLen == 4);
    CHECK(addr[0] == 192 && addr[3] == 47);

    const HostEntry *entry = HostsByAddress(&map, addr, addrLen);
    WireName want;
    CHECK(entry != NULL);
    CHECK(NameOf("iphone.lan", &want));
    if(entry != NULL)
        CHECK(WireNameEqual(&entry->name, &want));

    /* fd00::1, nibble reversed. */
    CHECK(NameOf("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
                 "0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", &name));
    CHECK(HostsReverseAddress(&name, addr, &addrLen));
    CHECK(addrLen == 16);
    CHECK(addr[0] == 0xFD && addr[15] == 1);
    CHECK(HostsByAddress(&map, addr, addrLen) != NULL);

    ArenaRelease(&arena);
}

static void TestReverseRejectsMalformed(void)
{
    WireName name;
    uint8_t  addr[16];
    uint8_t  addrLen = 0;

    CHECK(NameOf("example.com", &name));
    CHECK(!HostsReverseAddress(&name, addr, &addrLen));

    /* Too few labels for an address. */
    CHECK(NameOf("1.168.192.in-addr.arpa", &name));
    CHECK(!HostsReverseAddress(&name, addr, &addrLen));

    /* A label that is not a number. */
    CHECK(NameOf("x.1.168.192.in-addr.arpa", &name));
    CHECK(!HostsReverseAddress(&name, addr, &addrLen));

    /* Out of range. */
    CHECK(NameOf("300.1.168.192.in-addr.arpa", &name));
    CHECK(!HostsReverseAddress(&name, addr, &addrLen));

    /* An ip6.arpa name of the wrong length. */
    CHECK(NameOf("1.0.d.f.ip6.arpa", &name));
    CHECK(!HostsReverseAddress(&name, addr, &addrLen));

    CHECK(NameOf("arpa", &name));
    CHECK(!HostsReverseAddress(&name, addr, &addrLen));
}

static void TestPrivateRanges(void)
{
    static const struct { uint8_t a[4]; bool bPrivate; } v4[] = {
        { { 10, 0, 0, 1 },      true },
        { { 127, 0, 0, 1 },     true },
        { { 172, 16, 0, 1 },    true },
        { { 172, 31, 255, 1 },  true },
        { { 172, 32, 0, 1 },    false },
        { { 172, 15, 0, 1 },    false },
        { { 192, 168, 1, 1 },   true },
        { { 169, 254, 0, 1 },   true },
        { { 8, 8, 8, 8 },       false },
        { { 203, 0, 113, 9 },   false }
    };

    for(size_t i = 0; i < sizeof v4 / sizeof v4[0]; i++)
        CHECK(HostsAddressIsPrivate(v4[i].a, 4) == v4[i].bPrivate);

    uint8_t ula[16]  = { 0xFD };
    uint8_t link[16] = { 0xFE, 0x80 };
    uint8_t loop[16] = { 0 };
    uint8_t global[16] = { 0x20, 0x01, 0x0D, 0xB8 };

    loop[15] = 1;

    CHECK(HostsAddressIsPrivate(ula, 16));
    CHECK(HostsAddressIsPrivate(link, 16));
    CHECK(HostsAddressIsPrivate(loop, 16));
    CHECK(!HostsAddressIsPrivate(global, 16));
}

static void TestAddressPrefixes(void)
{
    static const uint8_t prefix[4] = { 192, 168, 1, 0 };
    static const uint8_t same[4]   = { 192, 168, 1, 47 };
    static const uint8_t next[4]   = { 192, 168, 2, 1 };
    static const uint8_t lower[4]  = { 192, 168, 1, 127 };
    static const uint8_t upper[4]  = { 192, 168, 1, 128 };

    CHECK(HostsAddressInPrefix(same, 4, prefix, 24));
    CHECK(!HostsAddressInPrefix(next, 4, prefix, 24));
    CHECK(HostsAddressInPrefix(lower, 4, prefix, 25));
    CHECK(!HostsAddressInPrefix(upper, 4, prefix, 25));
    CHECK(HostsAddressInPrefix(next, 4, prefix, 0));
    CHECK(HostsAddressInPrefix(prefix, 4, prefix, 32));
    CHECK(!HostsAddressInPrefix(same, 16, prefix, 24));
    CHECK(!HostsAddressInPrefix(same, 4, prefix, 33));
}

/* At capacity the map keeps what it has and counts the rest, rather than
   growing or refusing to start. */
static void TestCapacity(void)
{
    Arena arena;
    HostMap map;
    char  text[64 * 1024];
    size_t at = 0;

    for(size_t i = 0; i < CFG_HOSTS_MAX + 20; i++)
    {
        int written = snprintf(text + at, sizeof text - at,
                               "10.0.%zu.%zu host%zu\n",
                               i / 256, i % 256, i);
        if(written < 0)
            break;
        at += (size_t)written;
    }

    CHECK(ArenaInit(&arena, ARENA_HOSTS_BYTES));
    Load(&map, &arena, text);
    CHECK(map.count == CFG_HOSTS_MAX);
    CHECK(map.rejected == 20);

    ArenaRelease(&arena);
}

static void TestMissingFileIsNotAnError(void)
{
    Arena   arena;
    HostMap map;

    CHECK(ArenaInit(&arena, ARENA_HOSTS_BYTES));
    CHECK(HostsLoad(&map, &arena, "/nonexistent/hosts"));
    CHECK(map.count == 0);
    ArenaRelease(&arena);

    CHECK(ArenaInit(&arena, ARENA_HOSTS_BYTES));
    CHECK(HostsLoad(&map, &arena, NULL));
    CHECK(map.count == 0);
    ArenaRelease(&arena);
}

/* The slice holds exactly one table, so a second load into the same arena has
   nowhere to go and says so rather than overrunning. */
static void TestSliceTooSmall(void)
{
    Arena   arena;
    HostMap map;

    CHECK(ArenaInit(&arena, 128));
    CHECK(!HostsLoad(&map, &arena, NULL));
    ArenaRelease(&arena);
}

int main(void)
{
    TestParsesAddressesAndNames();
    TestRejectsRubbish();
    TestForwardLookup();
    TestLocalZone();
    TestReverseLookup();
    TestReverseRejectsMalformed();
    TestPrivateRanges();
    TestAddressPrefixes();
    TestCapacity();
    TestMissingFileIsNotAnError();
    TestSliceTooSmall();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("hosts: all checks passed\n");
    return 0;
}
