#include "blocklist.h"
#include "wire.h"

#include "fuzzseed.h"
#include "trieimage.h"

#include <stdint.h>
#include <stddef.h>

/* The compiled list arrives over the network, so an arbitrary file has to be
   refused or read entirely inside its own mapping, and a file that survives the
   header check has to keep every lookup inside it too. Build with
   -fsanitize=fuzzer,address.

   Two passes. The first hands the bytes over as they are. The header
   cross-checks its counts against each other and against the mapping, so almost
   nothing arbitrary gets past it, which is what the second pass is for: it
   rebuilds a consistent header over the same bytes, and the walk beneath it
   then runs on positions the file itself states. */

#define FUZZ_MAX_NODES       512u
#define FUZZ_MAX_IMAGE_BYTES 4096u

static const uint8_t G_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz0123456789-._";
#define ALPHABET_LEN (sizeof G_ALPHABET - 1u)

static void RawName(const uint8_t *data, size_t size, WireName *out)
{
    size_t len = (size < sizeof out->wire) ? size : sizeof out->wire;

    memset(out, 0, sizeof *out);
    memcpy(out->wire, data, len);
    out->len = len;
}

/* Arbitrary bytes are a name too, but almost never one that descends. This
   builds a well-formed name over the alphabet a repaired code table holds. */
static void ShapedName(const uint8_t *data, size_t size, WireName *out)
{
    unsigned labels = 1u + (data[0] % 4u);
    size_t   taken  = 1;
    size_t   at     = 0;

    memset(out, 0, sizeof *out);

    for(unsigned label = 0; label < labels; label++)
    {
        unsigned len = 1u + (data[taken++ % size] % 8u);

        if(at + 1u + len + 1u > sizeof out->wire)
            break;

        out->wire[at] = (uint8_t)len;

        for(unsigned c = 0; c < len; c++)
            out->wire[at + 1u + c] =
                G_ALPHABET[data[taken++ % size] % ALPHABET_LEN];

        at += 1u + len;
    }

    out->len = at + 1u;
}

static void Lookups(Blocklist *list, const uint8_t *data, size_t size)
{
    WireName name;

    RawName(data, size, &name);
    (void)BlocklistContains(list, &name);

    ShapedName(data, size, &name);
    (void)BlocklistContains(list, &name);
}

/* Counts that agree with each other and a code table the header accepts, over
   body bytes that are still the fuzzer's. */
static void FuzzRepaired(const uint8_t *data, size_t size)
{
    if(size < 8)
        return;

    uint32_t nodeCount  = 1u + ((((uint32_t)data[0] << 8) | data[1])
                                % FUZZ_MAX_NODES);
    uint32_t edgeCount  = nodeCount - 1u;
    unsigned symbolBits = 1u + (data[2] % BLOCKLIST_MAX_SYMBOL_BITS);
    unsigned span       = (1u << symbolBits) < ALPHABET_LEN
                        ? (1u << symbolBits) : (unsigned)ALPHABET_LEN;
    unsigned alphabet   = 1u + (data[3] % span);

    size_t loudsBytes    = ((size_t)nodeCount * 2u - 1u + 7u) / 8u;
    size_t samples       = ((size_t)nodeCount + BLOCKLIST_SELECT_SAMPLE - 1u)
                         / BLOCKLIST_SELECT_SAMPLE;
    size_t selectBytes   = samples * 4u;
    size_t symbolBytes   = ((size_t)edgeCount * symbolBits + 7u) / 8u;
    size_t terminalBytes = ((size_t)edgeCount + 7u) / 8u;
    size_t total         = BLOCKLIST_HEADER_BYTES + loudsBytes + selectBytes
                         + symbolBytes + terminalBytes + alphabet;

    if(total > FUZZ_MAX_IMAGE_BYTES)
        return;

    /* Exactly sized: every position in a trie is derived from the file, so a
       read past the last region has to land in a redzone */
    uint8_t *image = malloc(total);
    if(image == NULL)
        return;

    memcpy(image, BLOCKLIST_MAGIC, 4);
    TriePutU32(image + 4, nodeCount);
    TriePutU32(image + 8, edgeCount);
    TriePutU32(image + 12, (uint32_t)loudsBytes);
    TriePutU32(image + 16, (uint32_t)selectBytes);
    TriePutU32(image + 20, (uint32_t)symbolBytes);
    TriePutU32(image + 24, (uint32_t)terminalBytes);
    image[28] = (uint8_t)symbolBits;
    image[29] = (uint8_t)alphabet;
    image[30] = 0;
    image[31] = 0;

    for(size_t i = BLOCKLIST_HEADER_BYTES; i < total; i++)
        image[i] = data[i % size];

    /* Distinct characters a name may hold, or the header refuses the file
       before the walk is reached. Consecutive entries of a 39 character
       alphabet cannot repeat */
    uint8_t *codes = image + total - alphabet;
    unsigned first = data[4] % ALPHABET_LEN;

    for(unsigned i = 0; i < alphabet; i++)
        codes[i] = G_ALPHABET[(first + i) % ALPHABET_LEN];

    Blocklist list;
    memset(&list, 0, sizeof list);
    list.base   = image;
    list.size   = total;
    list.source = BlocklistSource_Mapped;

    if(BlocklistParseHeader(&list, image, total))
        Lookups(&list, data, size);

    free(image);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Blocklist list;

    if(size == 0)
        return 0;

    memset(&list, 0, sizeof list);
    list.base   = data;
    list.size   = size;
    list.source = BlocklistSource_Mapped;

    if(BlocklistParseHeader(&list, data, size))
        Lookups(&list, data, size);

    FuzzRepaired(data, size);
    return 0;
}

const char *FuzzTargetName(void)
{
    return "fuzz-blocklist";
}

/* 0xFF saturates a count field, and every count in the header is checked
   against the mapping. */
uint8_t FuzzSpliceByte(void)
{
    return 0xFFu;
}

/* A root and nothing below it. The generator never writes this, the format
   allows it, and it is the shortest file the header accepts: one louds byte,
   one select sample and a single character code. */
static const uint8_t *EmptyImage(size_t *sizeOut)
{
    static uint8_t image[BLOCKLIST_HEADER_BYTES + 1 + 4 + 1];

    memcpy(image, BLOCKLIST_MAGIC, 4);
    TriePutU32(image + 4, 1);
    TriePutU32(image + 8, 0);
    TriePutU32(image + 12, 1);
    TriePutU32(image + 16, 4);
    TriePutU32(image + 20, 0);
    TriePutU32(image + 24, 0);
    image[28] = 1;
    image[29] = 1;
    image[sizeof image - 1] = 'a';

    *sizeOut = sizeof image;
    return image;
}

/* The encoder the generator uses, so a seed cannot drift from the format the
   shipped tool writes. This runs once, before the first iteration. */
static FuzzSeed BuildSeed(const char *const *names, size_t count)
{
    TrieImage    build;
    FuzzSeed     seed     = { NULL, 0 };
    const char  *previous = "";
    char       **reversed = TrieAlloc(count * sizeof(char *));

    TrieImageInit(&build, CFG_MAX_NAME_BYTES);

    for(size_t i = 0; i < count; i++)
        reversed[i] = TrieReverse(names[i]);

    qsort(reversed, count, sizeof(char *), TrieCompareString);

    for(size_t i = 0; i < count; i++)
    {
        if(!TrieImageAdd(&build, reversed[i], previous))
        {
            fprintf(stderr, "fuzz-blocklist: seed rejected, %s\n", build.reason);
            exit(1);
        }

        previous = reversed[i];
    }

    seed.data = TrieImageFinish(&build, &seed.size);
    if(seed.data == NULL)
    {
        fprintf(stderr, "fuzz-blocklist: seed not encoded, %s\n", build.reason);
        exit(1);
    }

    TrieImageRelease(&build);

    for(size_t i = 0; i < count; i++)
        free(reversed[i]);

    free(reversed);
    return seed;
}

#define SEED_COUNT 4

static FuzzSeed G_SEEDS[SEED_COUNT];
static bool     G_SEEDS_READY;

static void BuildSeeds(void)
{
    static const char *const one[] = { "example.com" };
    static const char *const two[] = { "doubleclick.com", "ads.example.com" };
    static const char *const many[] = {
        "ads.example.com", "doubleclick.com", "tracker-1.net", "x_y.org",
        "0abc.io", "sub.deep.name.test", "q.co", "zzz.example"
    };

    G_SEEDS[0].data = EmptyImage(&G_SEEDS[0].size);
    G_SEEDS[1] = BuildSeed(one, sizeof one / sizeof one[0]);
    G_SEEDS[2] = BuildSeed(two, sizeof two / sizeof two[0]);
    G_SEEDS[3] = BuildSeed(many, sizeof many / sizeof many[0]);

    G_SEEDS_READY = true;
}

size_t FuzzSeedCount(void)
{
    return SEED_COUNT;
}

FuzzSeed FuzzSeedAt(size_t index)
{
    if(!G_SEEDS_READY)
        BuildSeeds();

    return G_SEEDS[index % SEED_COUNT];
}
