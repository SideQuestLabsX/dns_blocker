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
 * .rodata, for a device that never syncs.
 */

#define _POSIX_C_SOURCE 200809L

#include "blocklist.h"
#include "listline.h"
#include "trieimage.h"

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

    /* Built only once a node grows past EDGE_INDEX_MIN children. Most nodes
       never do, and scanning a handful of edges beats hashing them. Slots hold
       an edge index plus one, so zero is empty. Indices rather than pointers,
       because the edge array is reallocated as it grows */
    uint32_t *index;
    size_t    indexMask;
};

#define EDGE_INDEX_MIN 16

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

static int CompareLabel(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);

    if(la != lb)
        return (la < lb) ? -1 : 1;

    return memcmp(a, b, la);
}

/* Accumulates in uint64_t and narrows once. A size_t here is 32 bits on the
   board and silently truncates both constants, which has happened before. */
static uint64_t LabelHash(const char *label)
{
    uint64_t hash = 14695981039346656037ULL;

    for(const unsigned char *p = (const unsigned char *)label; *p != '\0'; p++)
    {
        hash ^= *p;
        hash *= 1099511628211ULL;
    }

    return hash;
}

static void IndexInsert(Node *node, uint32_t edgeIndex)
{
    size_t slot = (size_t)LabelHash(node->edges[edgeIndex].label) & node->indexMask;

    while(node->index[slot] != 0)
        slot = (slot + 1) & node->indexMask;

    node->index[slot] = edgeIndex + 1;
}

static void IndexRebuild(Node *node)
{
    size_t want = 32;

    while(want < node->count * 2)
        want *= 2;

    free(node->index);
    node->index     = Alloc(want * sizeof *node->index);
    node->indexMask = want - 1;

    for(size_t i = 0; i < node->count; i++)
        IndexInsert(node, (uint32_t)i);
}

/* Every insert calls this, so a linear scan is quadratic in the children of one
   node, and `com` alone holds 46350 of them at 105369 names. */
static Edge *EdgeFind(Node *node, const char *label)
{
    if(node->index == NULL)
    {
        for(size_t i = 0; i < node->count; i++)
        {
            if(CompareLabel(node->edges[i].label, label) == 0)
                return &node->edges[i];
        }

        return NULL;
    }

    size_t slot = (size_t)LabelHash(label) & node->indexMask;

    while(node->index[slot] != 0)
    {
        Edge *edge = &node->edges[node->index[slot] - 1];

        if(strcmp(edge->label, label) == 0)
            return edge;

        slot = (slot + 1) & node->indexMask;
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

    if(node->index != NULL)
    {
        if(node->count * 2 > node->indexMask + 1)
            IndexRebuild(node);
        else
            IndexInsert(node, (uint32_t)(node->count - 1));
    }
    else if(node->count >= EDGE_INDEX_MIN)
    {
        IndexRebuild(node);
    }

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

static int CompareString(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* The whole name, not its label order: the file is a character trie and the
   daemon walks a query backwards one character at a time. */
static char *ReverseName(const char *name)
{
    size_t len = strlen(name);
    char  *out = Alloc(len + 1);

    for(size_t i = 0; i < len; i++)
        out[i] = name[len - 1 - i];

    out[len] = '\0';
    return out;
}

static char **g_terminals;
static size_t g_terminalCount;
static size_t g_terminalCapacity;

static void RememberTerminal(char *reversed)
{
    if(g_terminalCount == g_terminalCapacity)
    {
        g_terminalCapacity = (g_terminalCapacity == 0)
                           ? 1024 : g_terminalCapacity * 2;
        g_terminals = realloc(g_terminals,
                              g_terminalCapacity * sizeof(char *));
        if(g_terminals == NULL)
            Fatal("out of memory");
    }

    g_terminals[g_terminalCount] = reversed;
    g_terminalCount++;
}

/* The names the trie actually marks, which is fewer than the file offered:
   a name already covered by a shorter rule is never stored. */
static void CollectTerminals(Node *node, char **labels, size_t depth)
{
    for(size_t i = 0; i < node->count; i++)
    {
        labels[depth] = node->edges[i].label;

        if(node->edges[i].bTerminal)
        {
            char   dotted[512];
            size_t at = 0;

            for(size_t back = depth + 1; back > 0; back--)
            {
                int wrote = snprintf(dotted + at, sizeof dotted - at, "%s%s",
                                     labels[back - 1], (back > 1) ? "." : "");
                if(wrote < 0 || (size_t)wrote >= sizeof dotted - at)
                    Fatal("name too long to measure");

                at += (size_t)wrote;
            }

            RememberTerminal(ReverseName(dotted));
        }
        else if(node->edges[i].child != NULL)
        {
            CollectTerminals(node->edges[i].child, labels, depth + 1);
        }
    }
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

static uint8_t *ReadWhole(const char *path, size_t *outSize)
{
    FILE *file = fopen(path, "rb");
    if(file == NULL)
        Fatal("cannot open the trie");

    if(fseek(file, 0, SEEK_END) != 0)
        Fatal("cannot measure the trie");

    long end = ftell(file);
    if(end <= 0 || fseek(file, 0, SEEK_SET) != 0)
        Fatal("cannot measure the trie");

    size_t   size  = (size_t)end;
    uint8_t *image = Alloc(size);

    if(fread(image, 1, size, file) != size)
        Fatal("cannot read the trie");

    fclose(file);
    *outSize = size;
    return image;
}

static void SelfCheckHeader(const uint8_t *bytes, size_t size)
{
    Blocklist list;

    memset(&list, 0, sizeof list);

    if(!BlocklistParseHeader(&list, bytes, size))
        Fatal("that file is not a trie this daemon can read");
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
    bool bCArray = false;
    bool bWrap   = false;
    int  first   = 1;

    while(first < argc && argv[first][0] == '-' && argv[first][1] != '\0')
    {
        if(strcmp(argv[first], "-c") == 0)
            bCArray = true;
        else if(strcmp(argv[first], "-t") == 0)
            bWrap = true;
        else
            break;

        first++;
    }

    if(argc <= first)
    {
        fprintf(stderr, "usage: mkblocklist [-c] out [list ...]\n"
                        "       mkblocklist -t out.c in.trie\n");
        return 1;
    }

    const char *outPath   = argv[first];
    int         firstList = first + 1;

    /* A published trie is already what .rodata wants, so an embedded build
       wraps the release asset rather than compiling the lists again. The header
       is checked here, because a download that arrived wrong should stop the
       build and not become a binary that filters nothing. */
    if(bWrap)
    {
        if(argc != firstList + 1)
            Fatal("-t takes one trie");

        size_t   size  = 0;
        uint8_t *image = ReadWhole(argv[firstList], &size);

        SelfCheckHeader(image, size);
        WriteCArray(outPath, image, size);
        fprintf(stderr, "mkblocklist: wrapped %s, %zu bytes\n",
                argv[firstList], size);
        return 0;
    }

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

    /* The label trie decided which names survive, so the reversed forms it
       yields are exactly what the file has to hold */
    char *labels[128];
    CollectTerminals(root, labels, 0);
    qsort(g_terminals, g_terminalCount, sizeof(char *), CompareString);

    TrieImage   build;
    const char *previous = "";

    TrieImageInit(&build, CFG_MAX_NAME_BYTES);

    for(size_t i = 0; i < g_terminalCount; i++)
    {
        if(!TrieImageAdd(&build, g_terminals[i], previous))
            Fatal(build.reason);

        previous = g_terminals[i];
    }

    size_t   imageSize = 0;
    uint8_t *image     = TrieImageFinish(&build, &imageSize);

    if(image == NULL)
        Fatal(build.reason);

    if(!bCArray && imageSize > CFG_BLOCKLIST_MAX_BYTES)
        Fatal("compiled list exceeds CFG_BLOCKLIST_MAX_BYTES");

    SelfCheck(image, imageSize);

    if(bCArray)
        WriteCArray(outPath, image, imageSize);
    else
        WriteTrie(outPath, image, imageSize);

    fprintf(stderr, "mkblocklist: %zu names, %zu skipped, %zu bytes, checked\n",
            accepted, skipped, imageSize);

    return 0;
}
