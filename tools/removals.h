#ifndef DNS_BLOCKER_REMOVALS_H
#define DNS_BLOCKER_REMOVALS_H

/* The reviewed allowlist, subtracted while a tier is compiled. Shared by the
   generator and its test.

   A removal takes the exact name and its `www.` form and nothing else. The trie
   matches by suffix, so dropping a name as a subtree would also drop every
   child, and a child is very often the entry the publisher meant: removing
   `example.com` must not remove `ads.example.com`.

   Names arrive through ListLineName, the same parser the sources use, so a
   removal written in any accepted list format still matches what it removes. */

#include "listline.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    char **names;
    size_t count;
    size_t cap;
} RemovalSet;

static inline int RemovalCompare(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static inline bool RemovalSetAdd(RemovalSet *set, const char *name)
{
    if(set->count == set->cap)
    {
        size_t cap   = (set->cap == 0) ? 32 : set->cap * 2;
        char **grown = realloc(set->names, cap * sizeof *grown);

        if(grown == NULL)
            return false;

        set->names = grown;
        set->cap   = cap;
    }

    /* Not strdup: it needs a feature-test macro this header cannot assume, and
       an implicit declaration returns int and truncates the pointer */
    size_t len  = strlen(name) + 1;
    char  *copy = malloc(len);
    if(copy == NULL)
        return false;

    memcpy(copy, name, len);

    set->names[set->count] = copy;
    set->count++;
    return true;
}

/* Reads one name a line. Everything after `#` is the reason it was removed and
   is not part of the name. */
static inline bool RemovalSetLoad(RemovalSet *set, FILE *in, size_t *skipped)
{
    char line[1024];

    while(fgets(line, sizeof line, in) != NULL)
    {
        char *name = ListLineName(line);

        if(name == NULL)
        {
            if(skipped != NULL)
                (*skipped)++;
            continue;
        }

        if(!RemovalSetAdd(set, name))
            return false;
    }

    if(set->count > 1)
        qsort(set->names, set->count, sizeof *set->names, RemovalCompare);

    return true;
}

static inline bool RemovalSetHas(const RemovalSet *set, const char *name)
{
    if(set->count == 0 || name == NULL)
        return false;

    if(bsearch(&name, set->names, set->count, sizeof *set->names,
               RemovalCompare) != NULL)
        return true;

    /* `www.example.com` goes with `example.com`, because the two are
       conventionally the same site and splitting them only makes paperwork */
    if(strncmp(name, "www.", 4) == 0)
    {
        const char *bare = name + 4;
        if(bsearch(&bare, set->names, set->count, sizeof *set->names,
                   RemovalCompare) != NULL)
            return true;
    }

    return false;
}

static inline void RemovalSetFree(RemovalSet *set)
{
    for(size_t i = 0; i < set->count; i++)
        free(set->names[i]);

    free(set->names);
    set->names = NULL;
    set->count = 0;
    set->cap   = 0;
}

#endif
