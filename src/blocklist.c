#define _DEFAULT_SOURCE

#include "blocklist.h"

#include "config.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool MapFile(Blocklist *list, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return false;

    struct stat st;
    if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
    {
        close(fd);
        return false;
    }

    /* Compared as off_t, which may be wider than size_t on 32-bit targets. */
    if(st.st_size > (off_t)CFG_BLOCKLIST_MAX_BYTES)
    {
        fprintf(stderr, "blocklist: %s exceeds the %zu byte cap, refusing\n",
                path, (size_t)CFG_BLOCKLIST_MAX_BYTES);
        close(fd);
        return false;
    }

    size_t size = (size_t)st.st_size;
    void  *mem  = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if(mem == MAP_FAILED)
        return false;

    list->base   = (const unsigned char *)mem;
    list->size   = size;
    list->source = BlocklistSource_Mapped;

    if(!BlocklistParseHeader(list, list->base, list->size))
    {
        fprintf(stderr, "blocklist: %s is not a usable trie, ignoring it\n", path);
        munmap(mem, size);
        list->base   = NULL;
        list->size   = 0;
        list->source = BlocklistSource_None;
        return false;
    }

    return true;
}

bool BlocklistLoad(Blocklist *list, const char *path)
{
    if(list == NULL)
        return false;

    list->base   = NULL;
    list->size   = 0;
    list->source = BlocklistSource_None;

    if(path != NULL && MapFile(list, path))
        return true;

    if(G_EMBEDDED_SIZE > 0 && BlocklistParseHeader(list, G_EMBEDDED_TRIE,
                                                   G_EMBEDDED_SIZE))
    {
        list->base   = G_EMBEDDED_TRIE;
        list->size   = G_EMBEDDED_SIZE;
        list->source = BlocklistSource_Embedded;
        return true;
    }

    return false;
}

bool BlocklistReload(Blocklist *list, const char *path)
{
    if(list == NULL || path == NULL)
        return false;

    /* Mapped into a separate record first. Writing into `list` before the new
       file is known good would leave a failed reload with no list at all */
    Blocklist fresh;
    memset(&fresh, 0, sizeof fresh);

    if(!MapFile(&fresh, path))
        return false;

    Blocklist old = *list;
    *list = fresh;

    if(old.source == BlocklistSource_Mapped && old.base != NULL)
    {
        void *mem = (void *)(uintptr_t)old.base;
        munmap(mem, old.size);
    }

    return true;
}

void BlocklistUnload(Blocklist *list)
{
    if(list == NULL)
        return;

    if(list->source == BlocklistSource_Mapped && list->base != NULL)
    {
        void *mem = (void *)(uintptr_t)list->base;
        munmap(mem, list->size);
    }

    list->base   = NULL;
    list->size   = 0;
    list->source = BlocklistSource_None;
}

const char *BlocklistSourceName(BlocklistSource source)
{
    switch(source)
    {
        case BlocklistSource_Embedded: return "embedded";
        case BlocklistSource_Mapped:   return "mapped";
        case BlocklistSource_None:     break;
    }

    return "none";
}

static uint32_t ReadU32(const uint8_t *base, size_t offset)
{
    return ((uint32_t)base[offset])
         | ((uint32_t)base[offset + 1] << 8)
         | ((uint32_t)base[offset + 2] << 16)
         | ((uint32_t)base[offset + 3] << 24);
}

/* ARM1176 has no popcount, so counting bits in a byte is a table lookup. */
static const uint8_t G_ONES[256] = {
    0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4, 1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5, 2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5, 2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6, 3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5, 2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6, 3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6, 3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7, 4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8
};

bool BlocklistSymbolCharacter(uint8_t ch)
{
    return (ch >= 'a' && ch <= 'z')
        || (ch >= '0' && ch <= '9')
        || ch == '-' || ch == '.' || ch == '_';
}

static size_t LoudsBits(const Blocklist *list)
{
    return (size_t)list->nodeCount * 2u - 1u;
}

static bool BitAt(const uint8_t *bits, size_t index)
{
    unsigned byte = bits[index >> 3];

    return ((byte >> (unsigned)(index & 7u)) & 1u) != 0;
}

bool BlocklistParseHeader(Blocklist *list, const uint8_t *base, size_t size)
{
    list->nodeCount    = 0;
    list->edgeCount    = 0;
    list->sampleCount  = 0;
    list->symbolBits   = 0;
    list->alphabetSize = 0;

    if(size < BLOCKLIST_HEADER_BYTES || memcmp(base, BLOCKLIST_MAGIC, 4) != 0)
        return false;

    uint32_t nodeCount     = ReadU32(base, 4);
    uint32_t edgeCount     = ReadU32(base, 8);
    uint32_t loudsBytes    = ReadU32(base, 12);
    uint32_t selectBytes   = ReadU32(base, 16);
    uint32_t symbolBytes   = ReadU32(base, 20);
    uint32_t terminalBytes = ReadU32(base, 24);
    uint8_t  symbolBits    = base[28];
    uint8_t  alphabetSize  = base[29];

    /* A tree, so the counts decide each other. Everything below is derived
       rather than trusted, and then compared against what the file claims */
    if(nodeCount == 0 || edgeCount != nodeCount - 1)
        return false;
    if(symbolBits == 0 || symbolBits > BLOCKLIST_MAX_SYMBOL_BITS)
        return false;
    if(alphabetSize == 0 || alphabetSize > (1u << symbolBits))
        return false;

    /* uint64_t throughout: nodeCount is bounded only by the mapping, and a
       32-bit product here would wrap on a large list */
    uint64_t bits    = (uint64_t)nodeCount * 2u - 1u;
    uint64_t samples = ((uint64_t)nodeCount + BLOCKLIST_SELECT_SAMPLE - 1)
                     / BLOCKLIST_SELECT_SAMPLE;

    if(loudsBytes != (bits + 7) / 8
       || selectBytes != samples * 4
       || symbolBytes != ((uint64_t)edgeCount * symbolBits + 7) / 8
       || terminalBytes != ((uint64_t)edgeCount + 7) / 8)
        return false;

    uint64_t total = (uint64_t)BLOCKLIST_HEADER_BYTES + loudsBytes + selectBytes
                   + symbolBytes + terminalBytes + alphabetSize;
    if(total > size)
        return false;

    const uint8_t *at = base + BLOCKLIST_HEADER_BYTES;

    list->louds = at;      at += loudsBytes;
    list->select = at;     at += selectBytes;
    list->symbols = at;    at += symbolBytes;
    list->terminals = at;  at += terminalBytes;
    list->codes = at;

    /* One character a code, each usable in a name and none of them twice. A
       duplicate would make two codes match the same query character, so the
       walk would depend on which one the generator happened to emit */
    memset(list->byChar, 0xFF, sizeof list->byChar);
    for(uint32_t i = 0; i < alphabetSize; i++)
    {
        uint8_t ch = list->codes[i];

        if(!BlocklistSymbolCharacter(ch) || list->byChar[ch] != 0xFF)
            return false;

        list->byChar[ch] = (uint8_t)i;
    }

    list->nodeCount    = nodeCount;
    list->edgeCount    = edgeCount;
    list->sampleCount  = (uint32_t)samples;
    list->symbolBits   = symbolBits;
    list->alphabetSize = alphabetSize;
    return true;
}

/* Position of zero number `index`, counting from zero. The sample lands on a
   zero and the scan walks forward over at most BLOCKLIST_SELECT_SAMPLE more,
   skipping whole bytes that hold none. */
static bool Select0(const Blocklist *list, uint32_t index, size_t *out)
{
    size_t   bits   = LoudsBits(list);
    uint32_t sample = index / BLOCKLIST_SELECT_SAMPLE;

    if(index >= list->nodeCount || sample >= list->sampleCount)
        return false;

    size_t at = ReadU32(list->select, (size_t)sample * 4);
    if(at >= bits || BitAt(list->louds, at))
        return false;

    uint32_t remaining = index - sample * BLOCKLIST_SELECT_SAMPLE;

    while(remaining > 0)
    {
        at++;

        if((at & 7u) == 0 && at + 8 <= bits)
        {
            uint32_t zeros = 8u - G_ONES[list->louds[at >> 3]];

            if(zeros < remaining)
            {
                remaining -= zeros;
                at += 7;
                continue;
            }
        }

        if(at >= bits)
            return false;

        if(!BitAt(list->louds, at))
            remaining--;
    }

    *out = at;
    return true;
}

/* The transitions of one node, as a half-open range of transition indices.
   end(k) is the k-th zero less k, because every zero before it ends a node and
   every one before it is a transition. start(k) is the same for k - 1, and the
   previous zero is found by walking back over this node's own transitions,
   which the alphabet bounds. */
static bool NodeRange(const Blocklist *list, uint32_t node,
                      uint32_t *start, uint32_t *end)
{
    size_t z;

    if(!Select0(list, node, &z) || z < node)
        return false;

    *end = (uint32_t)(z - node);

    if(node == 0)
    {
        *start = 0;
    }
    else
    {
        size_t back = z;

        while(back > 0 && BitAt(list->louds, back - 1))
            back--;

        if(back == 0 || back - 1 < node - 1)
            return false;

        *start = (uint32_t)((back - 1) - (node - 1));
    }

    return *start <= *end && *end <= list->edgeCount;
}

/* The symbol region is packed, so a code can straddle two bytes. The second
   byte is inside the region whenever it is read: the highest bit of the last
   symbol is the last bit of the region. */
static uint8_t SymbolAt(const Blocklist *list, uint32_t edge)
{
    size_t   bit   = (size_t)edge * list->symbolBits;
    size_t   byte  = bit >> 3;
    unsigned shift = (unsigned)(bit & 7u);
    uint32_t word  = list->symbols[byte];

    if(shift + list->symbolBits > 8)
        word |= (uint32_t)list->symbols[byte + 1] << 8;

    return (uint8_t)((word >> shift) & ((1u << list->symbolBits) - 1u));
}

/* One character of the reversed query. The child of transition t is node t + 1
   by construction, so the descent needs no index of its own. */
static bool Step(const Blocklist *list, uint32_t *node, uint8_t ch,
                 uint32_t *edge)
{
    uint32_t start;
    uint32_t end;
    uint8_t  code = list->byChar[ch];

    if(code == 0xFF || !NodeRange(list, *node, &start, &end))
        return false;

    for(uint32_t t = start; t < end; t++)
    {
        if(SymbolAt(list, t) == code)
        {
            *edge = t;
            *node = t + 1;
            return true;
        }
    }

    return false;
}

static bool TerminalAt(const Blocklist *list, uint32_t edge)
{
    return edge < list->edgeCount && BitAt(list->terminals, edge);
}

static uint8_t Lower(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (uint8_t)(ch + 32) : ch;
}

bool BlocklistContains(const Blocklist *list, const WireName *name)
{
    if(list->base == NULL || list->nodeCount == 0 || name->len == 0)
        return false;

    /* Label starts, so the walk can run from the last label back to the
       first. A name holds at most 128 labels, one byte of content each. */
    size_t starts[CFG_MAX_NAME_BYTES / 2 + 1];
    size_t count  = 0;
    size_t offset = 0;

    while(offset < name->len)
    {
        uint8_t labelLen = name->wire[offset];

        if(labelLen == 0)
            break;
        if(count >= sizeof starts / sizeof starts[0])
            return false;
        if(name->len - offset - 1 < labelLen)
            return false;

        starts[count] = offset;
        count++;
        offset += 1u + labelLen;
    }

    uint32_t node = 0;
    uint32_t edge = 0;

    for(size_t i = count; i > 0; i--)
    {
        size_t         at       = starts[i - 1];
        uint8_t        labelLen = name->wire[at];
        const uint8_t *label    = name->wire + at + 1;

        for(size_t c = labelLen; c > 0; c--)
        {
            if(!Step(list, &node, Lower(label[c - 1]), &edge))
                return false;
        }

        /* A stored name can only end where a label ends, so this is the one
           place a terminal mark counts. Checking it inside a label would block
           `notexample.com` on a rule for `example.com` */
        if(TerminalAt(list, edge))
            return true;

        if(i > 1 && !Step(list, &node, '.', &edge))
            return false;
    }

    return false;
}
