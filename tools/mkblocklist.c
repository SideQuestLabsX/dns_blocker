/* Compiles domain lists into the trie the daemon maps at boot.
 *
 * This runs on the build host, not on the device, so it allocates freely. The
 * zero-allocation rule applies to the daemon.
 *
 *   mkblocklist out.trie list1 list2 ...
 *   cat lists | mkblocklist out.trie
 *   mkblocklist -c embedded.c list1 list2 ...
 *
 * Accepts one domain per line, hosts-file lines such as
 * "0.0.0.0 ads.example.com", and wildcard rules such as "*.ads.example.com".
 * A leading address is dropped, a wildcard prefix is dropped because the entry
 * already covers the subtree, comments and blank lines are skipped, and names
 * are lowercased.
 *
 * With -c the same bytes are written as a C array the daemon links into
 * .rodata, which is the fallback for a cold boot with no network.
 */

#define _POSIX_C_SOURCE 200809L

#include "blocklist.h"
#include "listline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Node Node;

typedef struct
{
    char *label;
    Node *child;
    bool  bTerminal;
} Edge;

struct Node
{
    Edge    *edges;
    size_t   count;
    size_t   capacity;
    uint32_t offset;
};

static void Fatal(const char *what)
{
    fprintf(stderr, "mkblocklist: %s\n", what);
    exit(1);
}

static void *Alloc(size_t n)
{
    void *p = calloc(1, n);
    if(p == NULL)
        Fatal("out of memory");

    return p;
}

static Node *NodeNew(void)
{
    return Alloc(sizeof(Node));
}

/* Ordered by length then bytes, the same order the daemon's binary search
   assumes. Getting these two out of step makes lookups miss silently. */
static int CompareLabel(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);

    if(la != lb)
        return (la < lb) ? -1 : 1;

    return memcmp(a, b, la);
}

static int CompareEdge(const void *a, const void *b)
{
    return CompareLabel(((const Edge *)a)->label, ((const Edge *)b)->label);
}

static Edge *EdgeFind(Node *node, const char *label)
{
    for(size_t i = 0; i < node->count; i++)
    {
        if(CompareLabel(node->edges[i].label, label) == 0)
            return &node->edges[i];
    }

    return NULL;
}

static Edge *EdgeAdd(Node *node, const char *label)
{
    Edge *found = EdgeFind(node, label);
    if(found != NULL)
        return found;

    if(node->count == node->capacity)
    {
        node->capacity = (node->capacity == 0) ? 4 : node->capacity * 2;
        node->edges = realloc(node->edges, node->capacity * sizeof(Edge));
        if(node->edges == NULL)
            Fatal("out of memory");
    }

    Edge *edge = &node->edges[node->count];
    node->count++;

    edge->label     = strdup(label);
    edge->child     = NULL;
    edge->bTerminal = false;

    if(edge->label == NULL)
        Fatal("out of memory");

    return edge;
}

/* Splits on dots and inserts in reverse, so `ads.example.com` becomes
   com -> example -> ads and the terminal mark lands on the last edge. */
static bool Insert(Node *root, char *name)
{
    char  *labels[128];
    size_t count = 0;

    for(char *part = strtok(name, "."); part != NULL; part = strtok(NULL, "."))
    {
        if(*part == '\0' || strlen(part) > 63 || count == 128)
            return false;

        labels[count] = part;
        count++;
    }

    if(count == 0)
        return false;

    Node *node = root;
    for(size_t i = count; i > 0; i--)
    {
        Edge *edge = EdgeAdd(node, labels[i - 1]);

        /* Already blocked by a shorter rule, so the rest of this name adds
           nothing. Keeping it would only grow the file. */
        if(edge->bTerminal)
            return true;

        if(i == 1)
        {
            edge->bTerminal = true;

            /* Everything below is covered by the mark now. */
            edge->child = NULL;
            return true;
        }

        if(edge->child == NULL)
            edge->child = NodeNew();

        node = edge->child;
    }

    return true;
}

/* Offsets are assigned in the order Emit will walk, so the two cannot drift.
   Sorting happens here as well, in the order the daemon's binary search
   assumes. */
static void Assign(Node *node, uint32_t *cursor)
{
    qsort(node->edges, node->count, sizeof(Edge), CompareEdge);

    node->offset = *cursor;
    *cursor += 4 + (uint32_t)node->count * BLOCKLIST_CHILD_BYTES;

    for(size_t i = 0; i < node->count; i++)
    {
        if(node->edges[i].child != NULL)
            Assign(node->edges[i].child, cursor);
    }
}

typedef struct
{
    const char *label;
    uint32_t    offset;
    bool        bUsed;
} PoolSlot;

typedef struct
{
    uint8_t  *nodes;
    uint8_t  *pool;
    uint32_t  poolUsed;
    uint32_t  poolSize;

    /* Labels repeat heavily across a blocklist, so the pool is deduplicated.
       A scan of the whole pool for every label would be quadratic on a real
       list, so the offsets go in a hash table instead. */
    PoolSlot *slots;
    size_t    slotCount;
} Output;

static void PutU32(uint8_t *at, uint32_t value)
{
    at[0] = (uint8_t)(value & 0xFFu);
    at[1] = (uint8_t)((value >> 8) & 0xFFu);
    at[2] = (uint8_t)((value >> 16) & 0xFFu);
    at[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static size_t HashLabel(const char *label)
{
    size_t hash = 1469598103934665603u;

    for(const char *c = label; *c != '\0'; c++)
    {
        hash ^= (unsigned char)*c;
        hash *= 1099511628211u;
    }

    return hash;
}

static uint32_t PoolAdd(Output *out, const char *label)
{
    size_t mask = out->slotCount - 1;
    size_t at   = HashLabel(label) & mask;

    while(out->slots[at].bUsed)
    {
        if(strcmp(out->slots[at].label, label) == 0)
            return out->slots[at].offset;

        at = (at + 1) & mask;
    }

    size_t len = strlen(label);
    if(out->poolUsed + len > out->poolSize)
        Fatal("label pool overflow");

    uint32_t offset = out->poolUsed;
    memcpy(out->pool + offset, label, len);
    out->poolUsed += (uint32_t)len;

    out->slots[at].label  = label;
    out->slots[at].offset = offset;
    out->slots[at].bUsed  = true;
    return offset;
}

static void Emit(Node *node, Output *out)
{
    PutU32(out->nodes + node->offset, (uint32_t)node->count);

    for(size_t i = 0; i < node->count; i++)
    {
        Edge    *edge  = &node->edges[i];
        uint8_t *entry = out->nodes + node->offset + 4
                       + i * BLOCKLIST_CHILD_BYTES;

        PutU32(entry, PoolAdd(out, edge->label));
        PutU32(entry + 4, (edge->child != NULL) ? edge->child->offset : 0u);
        entry[8]  = (uint8_t)strlen(edge->label);
        entry[9]  = edge->bTerminal ? BLOCKLIST_FLAG_TERMINAL : 0u;
        entry[10] = 0;
        entry[11] = 0;
    }

    for(size_t i = 0; i < node->count; i++)
    {
        if(node->edges[i].child != NULL)
            Emit(node->edges[i].child, out);
    }
}

static size_t CountEdges(Node *node)
{
    size_t total = node->count;

    for(size_t i = 0; i < node->count; i++)
    {
        if(node->edges[i].child != NULL)
            total += CountEdges(node->edges[i].child);
    }

    return total;
}

/* Every accepted name, kept so the file can be checked against the daemon's
   own lookup before it ships. */
static char **g_names;
static size_t g_nameCount;
static size_t g_nameCapacity;

static void RememberName(const char *name)
{
    if(g_nameCount == g_nameCapacity)
    {
        g_nameCapacity = (g_nameCapacity == 0) ? 1024 : g_nameCapacity * 2;
        g_names = realloc(g_names, g_nameCapacity * sizeof(char *));
        if(g_names == NULL)
            Fatal("out of memory");
    }

    g_names[g_nameCount] = strdup(name);
    if(g_names[g_nameCount] == NULL)
        Fatal("out of memory");

    g_nameCount++;
}

static bool EncodeName(const char *dotted, WireName *out)
{
    size_t at = 0;

    for(const char *part = dotted; *part != '\0'; )
    {
        const char *dot = strchr(part, '.');
        size_t      len = (dot != NULL) ? (size_t)(dot - part) : strlen(part);

        if(len == 0 || len > 63 || at + 1 + len >= sizeof out->wire)
            return false;

        out->wire[at] = (uint8_t)len;
        memcpy(out->wire + at + 1, part, len);
        at += 1 + len;

        part = (dot != NULL) ? dot + 1 : part + len;
    }

    if(at + 1 > sizeof out->wire)
        return false;

    out->wire[at] = 0;
    out->len = at + 1;
    return true;
}

/* Reads the image back through the daemon's own code. The generator sorts and
   the daemon binary searches, and those are two implementations of one order.
   If they ever disagree the lookups miss without any other symptom. */
static void SelfCheck(const uint8_t *bytes, size_t size)
{
    Blocklist list;
    memset(&list, 0, sizeof list);
    list.base   = bytes;
    list.size   = size;
    list.source = BlocklistSource_Mapped;

    if(!BlocklistParseHeader(&list, bytes, size))
        Fatal("the image we just built has a bad header");

    size_t missed = 0;
    for(size_t i = 0; i < g_nameCount; i++)
    {
        WireName name;

        if(!EncodeName(g_names[i], &name))
            continue;

        if(!BlocklistContains(&list, &name))
        {
            if(missed < 5)
                fprintf(stderr, "mkblocklist: %s went in but does not match\n",
                        g_names[i]);
            missed++;
        }
    }

    if(missed != 0)
    {
        fprintf(stderr, "mkblocklist: %zu of %zu names do not match\n",
                missed, g_nameCount);
        exit(1);
    }

    /* A name that was never added must not match either, or the trie is
       blocking more than it was asked to. */
    static const char *absent[] = {
        "definitely-not-in-any-list-12345.example",
        "a.b.c.d.e.f.g.h.invalid"
    };

    for(size_t i = 0; i < sizeof absent / sizeof absent[0]; i++)
    {
        WireName name;

        if(EncodeName(absent[i], &name) && BlocklistContains(&list, &name))
            Fatal("a name that was never added matches");
    }
}

static void WriteTrie(const char *path, const uint8_t *image, size_t size)
{
    FILE *file = fopen(path, "wb");
    if(file == NULL)
        Fatal("cannot open the output");

    if(fwrite(image, 1, size, file) != size)
        Fatal("short write on the output");

    if(fclose(file) != 0)
        Fatal("cannot write the output");
}

/* The daemon links this instead of the stub in src/embedded.c, so the symbol
   names have to match the ones the stub defines. */
static void WriteCArray(const char *path, const uint8_t *image, size_t size)
{
    FILE *file = fopen(path, "w");
    if(file == NULL)
        Fatal("cannot open the output");

    fputs("/* Generated by mkblocklist. Do not edit. */\n\n", file);
    fputs("#include <stddef.h>\n\n", file);
    fputs("const unsigned char G_EMBEDDED_TRIE[] = {", file);

    for(size_t i = 0; i < size; i++)
        fprintf(file, "%s0x%02x,", (i % 12 == 0) ? "\n    " : " ", image[i]);

    fputs("\n};\n\nconst size_t G_EMBEDDED_SIZE = sizeof G_EMBEDDED_TRIE;\n", file);

    if(fclose(file) != 0)
        Fatal("cannot write the output");
}

static void ReadList(Node *root, FILE *in, size_t *accepted, size_t *skipped)
{
    char line[1024];

    while(fgets(line, sizeof line, in) != NULL)
    {
        char *name = ListLineName(line);

        if(name == NULL)
        {
            (*skipped)++;
            continue;
        }

        /* Insert consumes the buffer through strtok, so the name is kept
           first. */
        char kept[256];
        snprintf(kept, sizeof kept, "%s", name);

        if(Insert(root, name))
        {
            RememberName(kept);
            (*accepted)++;
        }
        else
        {
            (*skipped)++;
        }
    }
}

int main(int argc, char **argv)
{
    bool bCArray = (argc > 1 && strcmp(argv[1], "-c") == 0);
    int  first   = bCArray ? 2 : 1;

    if(argc <= first)
    {
        fprintf(stderr, "usage: mkblocklist [-c] out [list ...]\n");
        return 1;
    }

    const char *outPath   = argv[first];
    int         firstList = first + 1;

    Node  *root     = NodeNew();
    size_t accepted = 0;
    size_t skipped  = 0;

    if(argc == firstList)
    {
        ReadList(root, stdin, &accepted, &skipped);
    }
    else
    {
        for(int i = firstList; i < argc; i++)
        {
            FILE *in = fopen(argv[i], "r");
            if(in == NULL)
            {
                fprintf(stderr, "mkblocklist: cannot open %s\n", argv[i]);
                return 1;
            }

            ReadList(root, in, &accepted, &skipped);
            fclose(in);
        }
    }

    if(root->count == 0)
        Fatal("no usable domains");

    uint32_t nodeBytes = 0;
    Assign(root, &nodeBytes);

    size_t edges = CountEdges(root);
    size_t slots = 16;
    while(slots < edges * 2)
        slots *= 2;

    Output out;
    out.nodes     = Alloc(nodeBytes);
    out.poolSize  = (uint32_t)(edges * 64 + 64);
    out.pool      = Alloc(out.poolSize);
    out.poolUsed  = 0;
    out.slots     = Alloc(slots * sizeof(PoolSlot));
    out.slotCount = slots;

    Emit(root, &out);

    size_t   imageSize = BLOCKLIST_HEADER_BYTES + nodeBytes + out.poolUsed;
    uint8_t *image     = Alloc(imageSize);

    memcpy(image, BLOCKLIST_MAGIC, 4);
    PutU32(image + 4, nodeBytes);
    PutU32(image + 8, out.poolUsed);
    PutU32(image + 12, root->offset);
    memcpy(image + BLOCKLIST_HEADER_BYTES, out.nodes, nodeBytes);
    memcpy(image + BLOCKLIST_HEADER_BYTES + nodeBytes, out.pool, out.poolUsed);

    SelfCheck(image, imageSize);

    if(bCArray)
        WriteCArray(outPath, image, imageSize);
    else
        WriteTrie(outPath, image, imageSize);

    fprintf(stderr, "mkblocklist: %zu names, %zu skipped, %zu bytes, checked\n",
            accepted, skipped, imageSize);
    return 0;
}
