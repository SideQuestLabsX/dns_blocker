#define _DEFAULT_SOURCE

#include "blocklist.h"
#include "config.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* The embedded list stays empty until the trie generator exists. A zero size
   means the fallback is unavailable. */
static const unsigned char G_EMBEDDED_TRIE[1] = { 0 };
static const size_t        G_EMBEDDED_SIZE    = 0;

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

    if(G_EMBEDDED_SIZE > 0)
    {
        list->base   = G_EMBEDDED_TRIE;
        list->size   = G_EMBEDDED_SIZE;
        list->source = BlocklistSource_Embedded;
        return true;
    }

    return false;
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
