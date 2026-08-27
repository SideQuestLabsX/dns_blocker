#define _POSIX_C_SOURCE 200809L

#include "trust.h"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

TrustResult TrustLoad(TrustMap *trust, const char *path, size_t cap)
{
    if(trust == NULL)
        return TrustLoad_Unreadable;

    memset(trust, 0, sizeof *trust);

    if(path == NULL || cap == 0)
        return TrustLoad_Missing;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return TrustLoad_Missing;

    struct stat info;
    if(fstat(fd, &info) != 0 || !S_ISREG(info.st_mode))
    {
        close(fd);
        return TrustLoad_Unreadable;
    }

    if(info.st_size <= 0)
    {
        close(fd);
        return TrustLoad_Empty;
    }

    /* Compared as off_t, before any narrowing. st_size is 64 bits and size_t is
       32 on the board, so a huge file would otherwise wrap into a small map */
    if(info.st_size > (off_t)cap)
    {
        trust->fileSize = (size_t)info.st_size;
        close(fd);
        return TrustLoad_TooLarge;
    }

    void *base = mmap(NULL, (size_t)info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if(base == MAP_FAILED)
        return TrustLoad_Unreadable;

    trust->base     = base;
    trust->size     = (size_t)info.st_size;
    trust->fileSize = trust->size;
    return TrustLoad_Ok;
}

void TrustUnload(TrustMap *trust)
{
    if(trust == NULL)
        return;

    if(trust->base != NULL)
        munmap((void *)trust->base, trust->size);

    trust->base = NULL;
    trust->size = 0;
}

const char *TrustResultText(TrustResult result)
{
    switch(result)
    {
        case TrustLoad_Ok:         return "loaded";
        case TrustLoad_Missing:    return "no such file";
        case TrustLoad_Empty:      return "the file is empty";
        case TrustLoad_TooLarge:   return "the file is above the cap";
        case TrustLoad_Unreadable: return "the file could not be read";
    }

    return "unknown";
}
