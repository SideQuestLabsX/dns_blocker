#ifndef DNS_BLOCKER_BLOCKLIST_H
#define DNS_BLOCKER_BLOCKLIST_H

#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
    const uint8_t *base;
    size_t         size;
    BlocklistSource source;

    /* Filled by the header check at load. A zero nodeBytes means the mapping
       is present but unusable, and every lookup then says no. */
    uint32_t nodeBytes;
    uint32_t poolBytes;
    uint32_t rootOffset;
} Blocklist;

/* On-disk format, version 1. Labels are held in reverse order, so `net` is the
   root's child and `doubleclick` sits below it. That is what makes a suffix
   rule a single terminal mark rather than a scan.

     header    16 bytes   magic, nodeBytes, poolBytes, rootOffset
     nodes     nodeBytes  a child count followed by that many children
     pool      poolBytes  label bytes, lowercased, shared between children

   Every multi-byte field is little endian and read byte-wise, because ARM1176
   does not reliably load an unaligned word and nothing here is aligned.

   A child is 12 bytes: label offset, child offset, label length, flags. A
   terminal flag on a child blocks that name and everything below it, so a leaf
   needs no node of its own.

   The file arrives over the network, so every offset in it is untrusted and is
   checked against the mapping at the point of use. */

#define BLOCKLIST_MAGIC        "DBL1"
#define BLOCKLIST_HEADER_BYTES 16
#define BLOCKLIST_CHILD_BYTES  12
#define BLOCKLIST_FLAG_TERMINAL 1u

/* Maps the compiled list at path. Falls back to the embedded list when the
   file is missing, empty, unreadable or above CFG_BLOCKLIST_MAX_BYTES.
   Returns false only when neither source yields a usable list, which leaves
   the daemon forwarding without filtering rather than refusing to start. */
bool BlocklistLoad(Blocklist *list, const char *path);
void BlocklistUnload(Blocklist *list);

const char *BlocklistSourceName(BlocklistSource source);

/* True when the name itself, or a parent of it, carries a terminal mark. */
bool BlocklistContains(const Blocklist *list, const WireName *name);

/* Reads and checks a header that is already in memory. Used by the loader and
   by the generator's self-check. */
bool BlocklistParseHeader(Blocklist *list, const uint8_t *base, size_t size);

#endif
