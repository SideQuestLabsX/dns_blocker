#ifndef DNS_BLOCKER_ARENA_H
#define DNS_BLOCKER_ARENA_H

#include <stdbool.h>
#include <stddef.h>

typedef struct
{
    unsigned char *base;
    size_t         size;
    size_t         used;
} Arena;

bool   ArenaInit(Arena *arena, size_t size);
void   ArenaRelease(Arena *arena);
void  *ArenaAlloc(Arena *arena, size_t size, size_t align);
void  *ArenaAllocArray(Arena *arena, size_t count, size_t size, size_t align);
bool   ArenaCarve(Arena *parent, Arena *child, size_t size);
size_t ArenaRemaining(const Arena *arena);

#define ARENA_NEW(a, T)      ((T *)ArenaAlloc((a), sizeof(T), _Alignof(T)))
#define ARENA_ARRAY(a, T, n) ((T *)ArenaAllocArray((a), (n), sizeof(T), _Alignof(T)))

#endif
