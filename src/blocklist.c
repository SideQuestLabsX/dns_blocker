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

bool BlocklistParseHeader(Blocklist *list, const uint8_t *base, size_t size)
{
    list->nodeBytes  = 0;
    list->poolBytes  = 0;
    list->rootOffset = 0;

    if(size < BLOCKLIST_HEADER_BYTES || memcmp(base, BLOCKLIST_MAGIC, 4) != 0)
        return false;

    uint32_t nodeBytes  = ReadU32(base, 4);
    uint32_t poolBytes  = ReadU32(base, 8);
    uint32_t rootOffset = ReadU32(base, 12);

    /* Compared against the mapping, and written so no sum can wrap. */
    size_t room = size - BLOCKLIST_HEADER_BYTES;
    if(nodeBytes > room || poolBytes > room - nodeBytes)
        return false;

    /* The root has to hold at least a child count. */
    if(nodeBytes < 4 || rootOffset > nodeBytes - 4)
        return false;

    list->nodeBytes  = nodeBytes;
    list->poolBytes  = poolBytes;
    list->rootOffset = rootOffset;
    return true;
}

/* Compares a query label against a pool label without regard to case. Returns
   <0, 0 or >0 in the same order the generator sorted the children. */
static int CompareLabel(const uint8_t *query, size_t queryLen,
                        const uint8_t *pool, size_t poolLen)
{
    if(queryLen != poolLen)
        return (queryLen < poolLen) ? -1 : 1;

    for(size_t i = 0; i < queryLen; i++)
    {
        uint8_t a = query[i];
        if(a >= 'A' && a <= 'Z')
            a = (uint8_t)(a + 32);

        if(a != pool[i])
            return (a < pool[i]) ? -1 : 1;
    }

    return 0;
}

typedef struct
{
    uint32_t childOffset;
    uint32_t flags;
} Descent;

/* Binary search of one node's children. Every offset read here is checked
   against the mapping before it is used. */
static bool FindChild(const Blocklist *list, uint32_t nodeOffset,
                      const uint8_t *label, size_t labelLen, Descent *out)
{
    const uint8_t *nodes = list->base + BLOCKLIST_HEADER_BYTES;
    const uint8_t *pool  = nodes + list->nodeBytes;

    if(nodeOffset > list->nodeBytes - 4)
        return false;

    uint32_t count = ReadU32(nodes, nodeOffset);
    uint32_t first = nodeOffset + 4;

    /* Refuse a count that claims more children than the region can hold. */
    if(count == 0 || count > (list->nodeBytes - first) / BLOCKLIST_CHILD_BYTES)
        return false;

    uint32_t low  = 0;
    uint32_t high = count;

    while(low < high)
    {
        uint32_t mid   = low + (high - low) / 2;
        uint32_t entry = first + mid * BLOCKLIST_CHILD_BYTES;

        uint32_t labelOffset = ReadU32(nodes, entry);
        uint32_t childOffset = ReadU32(nodes, entry + 4);
        uint8_t  poolLen     = nodes[entry + 8];
        uint8_t  flags       = nodes[entry + 9];

        if(labelOffset > list->poolBytes || poolLen > list->poolBytes - labelOffset)
            return false;

        int order = CompareLabel(label, labelLen, pool + labelOffset, poolLen);

        if(order == 0)
        {
            out->childOffset = childOffset;
            out->flags       = flags;
            return true;
        }

        if(order < 0)
            high = mid;
        else
            low = mid + 1;
    }

    return false;
}

bool BlocklistContains(const Blocklist *list, const WireName *name)
{
    if(list->base == NULL || list->nodeBytes == 0 || name->len == 0)
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

    uint32_t nodeOffset = list->rootOffset;

    for(size_t i = count; i > 0; i--)
    {
        size_t  at       = starts[i - 1];
        uint8_t labelLen = name->wire[at];
        Descent step;

        if(!FindChild(list, nodeOffset, name->wire + at + 1, labelLen, &step))
            return false;

        /* A terminal mark covers this name and every name below it, which is
           what makes one entry block a whole subtree. */
        if((step.flags & BLOCKLIST_FLAG_TERMINAL) != 0)
            return true;

        if(step.childOffset == 0)
            return false;

        nodeOffset = step.childOffset;
    }

    return false;
}
