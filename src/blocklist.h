#ifndef DNS_BLOCKER_BLOCKLIST_H
#define DNS_BLOCKER_BLOCKLIST_H

#include <stdbool.h>
#include <stddef.h>

/* The compiled trie has its own mapping. An embedded list is already in
   .rodata. A synced list gets its size from the file at boot. Both mappings
   are complete before the serve loop starts, so the zero-allocation guarantee
   holds. */

typedef enum
{
    BlocklistSource_None,
    BlocklistSource_Embedded,
    BlocklistSource_Mapped
} BlocklistSource;

typedef struct
{
    const unsigned char *base;
    size_t               size;
    BlocklistSource      source;
} Blocklist;

/* Maps the compiled list at path. Falls back to the embedded list when the
   file is missing, empty, unreadable or above CFG_BLOCKLIST_MAX_BYTES.
   Returns false only when neither source yields a usable list, which leaves
   the daemon forwarding without filtering rather than refusing to start. */
bool BlocklistLoad(Blocklist *list, const char *path);
void BlocklistUnload(Blocklist *list);

const char *BlocklistSourceName(BlocklistSource source);

#endif
