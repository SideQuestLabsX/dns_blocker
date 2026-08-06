#include <stddef.h>

/* Placeholder for the list the build compiles in. `mkblocklist -c` writes the
   same two symbols, and the Makefile links that file instead of this one when
   EMBED_LIST names a list. A zero size turns the fallback off. */
const unsigned char G_EMBEDDED_TRIE[1] = { 0 };
const size_t        G_EMBEDDED_SIZE    = 0;
