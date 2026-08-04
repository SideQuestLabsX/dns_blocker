#define _DEFAULT_SOURCE

#include "arena.h"

#include <string.h>
#include <sys/mman.h>

static bool IsPowerOfTwo(size_t value)
{
    return value != 0 && (value & (value - 1u)) == 0;
}

bool ArenaInit(Arena *arena, size_t size)
{
    if(arena == NULL || size == 0)
        return false;

    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(mem == MAP_FAILED)
        return false;

    arena->base = (unsigned char *)mem;
    arena->size = size;
    arena->used = 0;
    return true;
}

void ArenaRelease(Arena *arena)
{
    if(arena == NULL || arena->base == NULL)
        return;

    munmap(arena->base, arena->size);
    arena->base = NULL;
    arena->size = 0;
    arena->used = 0;
}

void *ArenaAlloc(Arena *arena, size_t size, size_t align)
{
    if(arena == NULL || arena->base == NULL || size == 0 || !IsPowerOfTwo(align))
        return NULL;

    size_t offset = arena->used;
    size_t pad    = (align - (((size_t)arena->base + offset) & (align - 1u))) & (align - 1u);

    if(pad > arena->size - offset)
        return NULL;
    offset += pad;

    if(size > arena->size - offset)
        return NULL;

    unsigned char *ptr = arena->base + offset;
    arena->used = offset + size;
    memset(ptr, 0, size);
    return ptr;
}

void *ArenaAllocArray(Arena *arena, size_t count, size_t size, size_t align)
{
    if(count != 0 && size > (size_t)-1 / count)
        return NULL;

    return ArenaAlloc(arena, count * size, align);
}

/* Child borrows a fixed slice of the parent and owns no mapping of its own, so
   it must not be passed to ArenaRelease. */
bool ArenaCarve(Arena *parent, Arena *child, size_t size)
{
    if(child == NULL)
        return false;

    child->base = NULL;
    child->size = 0;
    child->used = 0;

    if(size == 0)
        return true;

    void *slice = ArenaAlloc(parent, size, _Alignof(max_align_t));
    if(slice == NULL)
        return false;

    child->base = (unsigned char *)slice;
    child->size = size;
    return true;
}

size_t ArenaRemaining(const Arena *arena)
{
    if(arena == NULL || arena->base == NULL)
        return 0;

    return arena->size - arena->used;
}
