#ifndef DNS_BLOCKER_TRIEIMAGE_H
#define DNS_BLOCKER_TRIEIMAGE_H

/* The encoder for the on-disk trie, shared by the generator and the test that
   checks the daemon reads what the generator writes. Header-only for the same
   reason listline.h is: one copy of the format, so the two sides cannot drift.

   Input is the reversed names, sorted with strcmp. Sorted is what keeps the
   build linear, because a new character always belongs at the end of a node's
   child list and the path from the previous word is valid up to the common
   prefix.

   Allocates freely. This runs on the build host, never in the daemon. */

#include "blocklist.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct TrieNode TrieNode;

struct TrieNode
{
    TrieNode *next;
    TrieNode *children;
    TrieNode *lastChild;
    uint8_t   ch;
    bool      bTerminal;
};

typedef struct
{
    TrieNode  *root;
    TrieNode **path;
    size_t     nodes;
    size_t     pathLen;
    const char *reason;
} TrieImage;

static inline void *TrieAlloc(size_t n)
{
    void *p = calloc(1, n);
    if(p == NULL)
    {
        fprintf(stderr, "trieimage: out of memory\n");
        exit(1);
    }

    return p;
}

static inline size_t TrieCommonPrefix(const char *word, const char *previous)
{
    size_t i = 0;

    while(word[i] != '\0' && word[i] == previous[i])
        i++;

    return i;
}

static inline void TrieImageInit(TrieImage *build, size_t maxNameBytes)
{
    build->root    = TrieAlloc(sizeof(TrieNode));
    build->path    = TrieAlloc((maxNameBytes + 1) * sizeof(TrieNode *));
    build->nodes   = 0;
    build->pathLen = maxNameBytes;
    build->reason  = NULL;
}

static inline TrieNode *TrieAppend(TrieImage *build, TrieNode *parent, uint8_t ch)
{
    TrieNode *node = TrieAlloc(sizeof(TrieNode));

    node->ch = ch;

    if(parent->lastChild == NULL)
        parent->children = node;
    else
        parent->lastChild->next = node;

    parent->lastChild = node;
    build->nodes++;
    return node;
}

/* One reversed name. `previous` is the one before it in sorted order, or "". */
static inline bool TrieImageAdd(TrieImage *build, const char *word,
                         const char *previous)
{
    size_t length = strlen(word);

    if(length == 0 || length > build->pathLen)
    {
        build->reason = "a name is longer than a name may be";
        return false;
    }

    size_t    common = TrieCommonPrefix(word, previous);
    TrieNode *node   = (common == 0) ? build->root : build->path[common - 1];

    for(size_t i = common; word[i] != '\0'; i++)
    {
        if(!BlocklistSymbolCharacter((uint8_t)word[i]))
        {
            build->reason = "a name carries a character the format cannot encode";
            return false;
        }

        node          = TrieAppend(build, node, (uint8_t)word[i]);
        build->path[i] = node;
    }

    build->path[length - 1]->bTerminal = true;
    return true;
}

static inline void TrieBitSet(uint8_t *bits, size_t index)
{
    bits[index >> 3] |= (uint8_t)(1u << (index & 7u));
}

static inline void TrieSymbolPut(uint8_t *symbols, size_t edge, uint8_t code,
                          unsigned bits)
{
    size_t   bit   = edge * bits;
    size_t   byte  = bit >> 3;
    unsigned shift = (unsigned)(bit & 7u);

    symbols[byte] |= (uint8_t)((unsigned)code << shift);

    if(shift + bits > 8)
        symbols[byte + 1] |= (uint8_t)((unsigned)code >> (8 - shift));
}

static inline void TriePutU32(uint8_t *at, uint32_t value)
{
    at[0] = (uint8_t)(value & 0xFFu);
    at[1] = (uint8_t)((value >> 8) & 0xFFu);
    at[2] = (uint8_t)((value >> 16) & 0xFFu);
    at[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static inline size_t TrieBitsFor(size_t values)
{
    size_t bits = 1;

    while(((size_t)1 << bits) < values)
        bits++;

    return bits;
}

/* Breadth-first, because that is what makes transition t lead to node t + 1
   and lets the file carry no targets at all. The queue holds every node in the
   order the encoding numbers them. */
static inline uint8_t *TrieImageFinish(TrieImage *build, size_t *outSize)
{
    uint8_t codeOf[256];
    uint8_t codes[256];
    size_t  alphabet = 0;

    memset(codeOf, 0xFF, sizeof codeOf);

    /* The alphabet is a property of this list, so it is counted rather than
       assumed. Ascending, so the same input gives the same table */
    TrieNode **stack = TrieAlloc((build->nodes + 1) * sizeof(TrieNode *));
    size_t     top   = 0;

    stack[top++] = build->root;
    while(top > 0)
    {
        TrieNode *node = stack[--top];

        for(TrieNode *child = node->children; child != NULL; child = child->next)
        {
            codeOf[child->ch] = 1;
            stack[top++] = child;
        }
    }
    free(stack);

    for(size_t ch = 0; ch < 256; ch++)
    {
        if(codeOf[ch] != 0xFF)
        {
            codeOf[ch]      = (uint8_t)alphabet;
            codes[alphabet] = (uint8_t)ch;
            alphabet++;
        }
    }

    if(alphabet == 0)
    {
        build->reason = "no usable characters";
        return NULL;
    }

    unsigned symbolBits = (unsigned)TrieBitsFor(alphabet);

    size_t nodeCount = build->nodes + 1;
    size_t edgeCount = build->nodes;
    size_t bits      = nodeCount * 2 - 1;

    size_t loudsBytes    = (bits + 7) / 8;
    size_t samples       = (nodeCount + BLOCKLIST_SELECT_SAMPLE - 1)
                         / BLOCKLIST_SELECT_SAMPLE;
    size_t selectBytes   = samples * 4;
    size_t symbolBytes   = (edgeCount * symbolBits + 7) / 8;
    size_t terminalBytes = (edgeCount + 7) / 8;

    size_t size = BLOCKLIST_HEADER_BYTES + loudsBytes + selectBytes
                + symbolBytes + terminalBytes + alphabet;

    uint8_t *image = TrieAlloc(size);

    memcpy(image, BLOCKLIST_MAGIC, 4);
    TriePutU32(image + 4, (uint32_t)nodeCount);
    TriePutU32(image + 8, (uint32_t)edgeCount);
    TriePutU32(image + 12, (uint32_t)loudsBytes);
    TriePutU32(image + 16, (uint32_t)selectBytes);
    TriePutU32(image + 20, (uint32_t)symbolBytes);
    TriePutU32(image + 24, (uint32_t)terminalBytes);
    image[28] = (uint8_t)symbolBits;
    image[29] = (uint8_t)alphabet;

    uint8_t *louds     = image + BLOCKLIST_HEADER_BYTES;
    uint8_t *select    = louds + loudsBytes;
    uint8_t *symbols   = select + selectBytes;
    uint8_t *terminals = symbols + symbolBytes;
    memcpy(terminals + terminalBytes, codes, alphabet);

    TrieNode **queue = TrieAlloc(nodeCount * sizeof(TrieNode *));
    queue[0] = build->root;

    size_t tail = 1;
    size_t at   = 0;
    size_t edge = 0;

    for(size_t node = 0; node < nodeCount; node++)
    {
        for(TrieNode *child = queue[node]->children; child != NULL;
            child = child->next)
        {
            TrieBitSet(louds, at);
            at++;

            TrieSymbolPut(symbols, edge, codeOf[child->ch], symbolBits);
            if(child->bTerminal)
                TrieBitSet(terminals, edge);

            queue[tail] = child;
            tail++;
            edge++;
        }

        /* One zero ends every node, so the zeros are the nodes in order and the
           k-th of them is what locates node k */
        if(node % BLOCKLIST_SELECT_SAMPLE == 0)
            TriePutU32(select + (node / BLOCKLIST_SELECT_SAMPLE) * 4,
                       (uint32_t)at);

        at++;
    }

    free(queue);

    if(at != bits || edge != edgeCount || tail != nodeCount)
    {
        build->reason = "the encoded structure does not match what was counted";
        free(image);
        return NULL;
    }

    *outSize = size;
    return image;
}

/* The test builds a trie per case under a leak checker. The generator exits
   straight after writing and never calls this. */
static inline void TrieImageRelease(TrieImage *build)
{
    TrieNode **stack = TrieAlloc((build->nodes + 1) * sizeof(TrieNode *));
    size_t     top   = 0;

    stack[top++] = build->root;

    while(top > 0)
    {
        TrieNode *node = stack[--top];

        for(TrieNode *child = node->children; child != NULL; )
        {
            TrieNode *next = child->next;

            stack[top++] = child;
            child = next;
        }

        free(node);
    }

    free(stack);
    free(build->path);
    build->root = NULL;
    build->path = NULL;
}

/* Reverses a whole name rather than its label order, because the lookup walks
   the query backwards one character at a time. */
static inline char *TrieReverse(const char *name)
{
    size_t len = strlen(name);
    char  *out = TrieAlloc(len + 1);

    for(size_t i = 0; i < len; i++)
        out[i] = name[len - 1 - i];

    out[len] = '\0';
    return out;
}

static inline int TrieCompareString(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

#endif
