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

/* On-disk format, version 2. A character trie over the reversed names, so
   `example.com` is stored as `moc.elpmaxe` and a suffix rule is still a single
   terminal mark. The structure is succinct: nothing in the file names an
   offset, and a node's children are found by counting bits rather than by
   following a pointer.

   A tree has one parent per node. Number the nodes breadth-first and emit each
   degree in unary, and the transitions land in the same order as the nodes they
   lead to, so **transition t always leads to node t + 1**. That identity is why
   nothing here needs a target. See DECISIONS D-040.

     header     32 bytes    magic, counts, symbol width, alphabet size
     louds      2n - 1 bits each node's degree in unary, a zero ending each run
     select     4 a sample  bit position of every 64th zero
     symbols    6 bits each one packed symbol code a transition
     terminals  1 bit each  set when a stored name ends on that transition
     codes      one a code  the character each symbol code stands for

   Every multi-byte field is little endian and read byte-wise, because ARM1176
   does not reliably load an unaligned word and nothing here is aligned. Bits
   are numbered from the least significant end of each byte.

   The file arrives over the network, so every count in it is checked against
   the mapping at load and every index derived from it is checked at the point
   of use. */

#define BLOCKLIST_MAGIC          "DBL2"
#define BLOCKLIST_HEADER_BYTES   32
/* One select sample every this many zeros. A character trie's degree is capped
   by the alphabet, so the scan between samples is bounded by
   BLOCKLIST_SELECT_SAMPLE zeros and the ones among them */
#define BLOCKLIST_SELECT_SAMPLE  64
#define BLOCKLIST_MAX_SYMBOL_BITS 8

typedef struct
{
    const uint8_t  *base;
    size_t          size;
    BlocklistSource source;

    /* Filled by the header check at load. A zero nodeCount means the mapping is
       present but unusable, and every lookup then says no. */
    uint32_t nodeCount;
    uint32_t edgeCount;
    uint32_t sampleCount;
    uint8_t  symbolBits;
    uint8_t  alphabetSize;

    const uint8_t *louds;
    const uint8_t *select;
    const uint8_t *symbols;
    const uint8_t *terminals;
    const uint8_t *codes;

    /* Character to symbol code, inverted from the code table at load. 0xFF for
       a character the list never uses, which ends a walk immediately. */
    uint8_t byChar[256];
} Blocklist;

/* The list compiled into .rodata, defined either by the stub in src/embedded.c
   or by the file `mkblocklist -c` writes. A zero size means there is none. */
extern const unsigned char G_EMBEDDED_TRIE[];
extern const size_t        G_EMBEDDED_SIZE;

/* Maps the compiled list at path. Falls back to the embedded list when the
   file is missing, empty, unreadable or above CFG_BLOCKLIST_MAX_BYTES.
   Returns false only when neither source yields a usable list, which leaves
   the daemon forwarding without filtering rather than refusing to start. */
bool BlocklistLoad(Blocklist *list, const char *path);
void BlocklistUnload(Blocklist *list);

/* Swaps in a freshly downloaded list while the daemon is serving. The new file
   is mapped and checked before the old mapping is released, so a corrupt or
   unreadable replacement leaves the running list exactly as it was and returns
   false.

   The daemon is single threaded and every lookup runs to completion inside one
   poll iteration, so a swap between iterations needs no locking. Calling this
   from a signal handler or a second thread would hand a reader a pointer into
   an unmapped page. */
bool BlocklistReload(Blocklist *list, const char *path);

const char *BlocklistSourceName(BlocklistSource source);

/* True when the name itself, or a parent of it, carries a terminal mark. */
bool BlocklistContains(const Blocklist *list, const WireName *name);

/* Reads and checks a header that is already in memory. Used by the loader and
   by the generator's self-check. */
bool BlocklistParseHeader(Blocklist *list, const uint8_t *base, size_t size);

/* The characters a name may contain, and therefore the only ones a code table
   may name. Shared with the generator so both sides agree on the alphabet. */
bool BlocklistSymbolCharacter(uint8_t ch);

#endif
