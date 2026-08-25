#include "wire.h"

#include <stdio.h>
#include <string.h>

static int G_FAILURES;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if(!(cond))                                                        \
        {                                                                  \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

/* Header for a single-question query: id 0x1234, RD set, QDCOUNT 1. */
#define HDR 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

static bool ParseName(const uint8_t *msg, size_t len, size_t at, WireName *out)
{
    Reader reader;
    ReaderInit(&reader, msg, len);
    return ReaderSkip(&reader, at) && WireReadName(&reader, out);
}

static void TestWellFormedQuery(void)
{
    static const uint8_t msg[] = {
        HDR,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0x00, 0x01,
        0x00, 0x01
    };

    Reader       reader;
    WireHeader   header;
    WireQuestion question;

    ReaderInit(&reader, msg, sizeof msg);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(header.id == 0x1234);
    CHECK(header.qdCount == 1);
    CHECK(header.anCount == 0);

    CHECK(WireParseQuestion(&reader, &question));
    CHECK(question.type == WIRE_TYPE_A);
    CHECK(question.klass == WIRE_CLASS_IN);
    CHECK(question.name.len == 17);
    CHECK(question.name.wire[0] == 3);
    CHECK(memcmp(question.name.wire + 1, "www", 3) == 0);
    CHECK(ReaderRemaining(&reader) == 0);
}

static void TestBackwardPointer(void)
{
    /* Question at 12, then a name at 33 that is a pointer back to offset 16
       ("example.com" inside the question). */
    static const uint8_t msg[] = {
        HDR,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0x00, 0x01,
        0x00, 0x01,
        0xC0, 0x10
    };

    WireName name;
    CHECK(ParseName(msg, sizeof msg, 33, &name));
    CHECK(name.len == 13);
    CHECK(name.wire[0] == 7);
    CHECK(memcmp(name.wire + 1, "example", 7) == 0);
}

static void TestCompressedTailResumesAfterPointer(void)
{
    /* "mail" plus a pointer to "example.com". The reader must resume at the
       byte after the two pointer bytes. */
    static const uint8_t msg[] = {
        HDR,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0x00, 0x01,
        0x00, 0x01,
        4, 'm', 'a', 'i', 'l', 0xC0, 0x10,
        0xAB
    };

    Reader   reader;
    WireName name;
    uint8_t  trailer = 0;

    ReaderInit(&reader, msg, sizeof msg);
    CHECK(ReaderSkip(&reader, 33));
    CHECK(WireReadName(&reader, &name));
    CHECK(name.len == 18);
    CHECK(name.wire[0] == 4);
    CHECK(ReaderU8(&reader, &trailer));
    CHECK(trailer == 0xAB);
}

static void TestSelfReferentialPointer(void)
{
    static const uint8_t msg[] = { HDR, 0xC0, 0x0C };

    WireName name;
    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

static void TestForwardPointer(void)
{
    static const uint8_t msg[] = { HDR, 0xC0, 0x10, 0x00, 0x00, 3, 'a', 'b', 'c', 0 };

    WireName name;
    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

static void TestBackwardChainThatRevisits(void)
{
    /* The case the strictly-backwards rule does not catch. Label "a" at 12,
       then a pointer at 14 back to 12. Every jump targets an offset lower than
       the pointer performing it, so each one is individually legal, yet the
       walk cycles 12 -> 14 -> 12 without end.

       The name-length cap ends the walk. Each cycle crosses a label, and the
       code appends that label to a fixed buffer. With CFG_MAX_PTR_JUMPS raised
       to 100000, this case still terminates. */
    static const uint8_t msg[] = { HDR, 1, 'a', 0xC0, 0x0C };

    WireName name;
    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

/* The chain below is indexed by the configured cap, so the buffer takes its
   size from the same constant. A fixed size lets the test read past its own
   array when the cap goes up. */
_Static_assert(CFG_MAX_PTR_JUMPS >= 1 && CFG_MAX_PTR_JUMPS <= 64,
               "TestJumpCap sizes a stack buffer from CFG_MAX_PTR_JUMPS");

static void TestJumpCap(void)
{
    /* Descending pointer chain: offset 2k points to 2k-2, terminator at 0.
       A pure pointer chain carries no labels, so nothing accumulates in the
       name buffer and the jump cap is the only thing that ends it. */
    enum { CHAIN = CFG_MAX_PTR_JUMPS + 2 };

    uint8_t  msg[2 * CHAIN + 2];
    WireName name;

    memset(msg, 0, sizeof msg);
    for(size_t k = 1; k <= CHAIN; k++)
    {
        msg[2 * k]     = 0xC0;
        msg[2 * k + 1] = (uint8_t)(2 * k - 2);
    }

    CHECK(ParseName(msg, sizeof msg, 2 * CFG_MAX_PTR_JUMPS, &name));
    CHECK(!ParseName(msg, sizeof msg, 2 * (CFG_MAX_PTR_JUMPS + 1), &name));
}

static void TestTruncatedPointer(void)
{
    static const uint8_t msg[] = { HDR, 0xC0 };

    WireName name;
    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

static void TestLabelOverrunsMessage(void)
{
    static const uint8_t msg[] = { HDR, 9, 'a', 'b', 'c' };

    WireName name;
    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

static void TestReservedLabelType(void)
{
    static const uint8_t msg40[] = { HDR, 0x40, 0x00 };
    static const uint8_t msg80[] = { HDR, 0x80, 0x00 };

    WireName name;
    CHECK(!ParseName(msg40, sizeof msg40, 12, &name));
    CHECK(!ParseName(msg80, sizeof msg80, 12, &name));
}

static void TestUnterminatedName(void)
{
    static const uint8_t msg[] = { HDR, 3, 'a', 'b', 'c' };

    WireName name;
    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

static void TestNameLengthCap(void)
{
    /* 63-byte labels repeated until the 255-byte name limit is passed. */
    uint8_t  msg[512];
    size_t   pos = 12;
    WireName name;

    memset(msg, 0, sizeof msg);
    for(int i = 0; i < 6; i++)
    {
        msg[pos] = 63;
        memset(msg + pos + 1, 'a', 63);
        pos += 64;
    }
    msg[pos] = 0;

    CHECK(!ParseName(msg, sizeof msg, 12, &name));
}

static void TestEmptyAndTruncatedHeader(void)
{
    static const uint8_t msg[] = { 0x12, 0x34, 0x01 };

    Reader     reader;
    WireHeader header;

    ReaderInit(&reader, NULL, 0);
    CHECK(!WireParseHeader(&reader, &header));

    ReaderInit(&reader, msg, sizeof msg);
    CHECK(!WireParseHeader(&reader, &header));
}

static void TestHeaderOnlyHasNoQuestion(void)
{
    static const uint8_t msg[] = { HDR };

    Reader       reader;
    WireHeader   header;
    WireQuestion question;

    ReaderInit(&reader, msg, sizeof msg);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(header.qdCount == 1);
    CHECK(!WireParseQuestion(&reader, &question));
}

static void TestEdnsPresent(void)
{
    /* One question, one OPT in the additional section, payload size 1232. */
    static const uint8_t msg[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3, 'a', 'b', 'c', 0,
        0x00, 0x01,
        0x00, 0x01,
        0x00,
        0x00, 0x29,
        0x04, 0xD0,
        0x00, 0x00, 0x80, 0x00,
        0x00, 0x00
    };

    WireEdns edns;
    CHECK(WireFindEdns(msg, sizeof msg, &edns));
    CHECK(edns.bPresent);
    CHECK(edns.payloadSize == 1232);
    CHECK(edns.version == 0);
    CHECK(edns.flags == 0x8000);
}

static void TestEdnsAbsentIsNotAnError(void)
{
    static const uint8_t msg[] = {
        HDR,
        3, 'a', 'b', 'c', 0,
        0x00, 0x01,
        0x00, 0x01
    };

    WireEdns edns;
    CHECK(WireFindEdns(msg, sizeof msg, &edns));
    CHECK(!edns.bPresent);
}

static void TestEdnsNotAtRootRejected(void)
{
    static const uint8_t msg[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3, 'a', 'b', 'c', 0,
        0x00, 0x01,
        0x00, 0x01,
        3, 'x', 'y', 'z', 0,
        0x00, 0x29,
        0x04, 0xD0,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };

    WireEdns edns;
    CHECK(!WireFindEdns(msg, sizeof msg, &edns));
}

static void TestRdLengthOverrun(void)
{
    static const uint8_t msg[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        3, 'a', 'b', 'c', 0,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        0xFF, 0xFF,
        0x01, 0x02
    };

    Reader     reader;
    WireHeader header;

    ReaderInit(&reader, msg, sizeof msg);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(!WireSkipRecord(&reader));
}

static void TestNameEqualIsCaseInsensitive(void)
{
    static const uint8_t upper[] = { HDR, 3, 'A', 'B', 'C', 0 };
    static const uint8_t lower[] = { HDR, 3, 'a', 'b', 'c', 0 };
    static const uint8_t other[] = { HDR, 3, 'a', 'b', 'd', 0 };

    WireName a;
    WireName b;
    WireName c;

    CHECK(ParseName(upper, sizeof upper, 12, &a));
    CHECK(ParseName(lower, sizeof lower, 12, &b));
    CHECK(ParseName(other, sizeof other, 12, &c));
    CHECK(WireNameEqual(&a, &b));
    CHECK(!WireNameEqual(&a, &c));
}

static void TestRestoreNameCaseLeavesPointerTargetsReadOnly(void)
{
    uint8_t msg[] = {
        0x12, 0x34, 1, 'A', 0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x02
    };
    WireName name = { .wire = { 1, 'a', 0 }, .len = 3 };

    CHECK(WireRestoreNameCase(msg, sizeof msg, WIRE_HEADER_BYTES, &name));
    CHECK(msg[3] == 'A');
}

static void TestRestoreNameCaseWithCompressedTail(void)
{
    uint8_t msg[] = {
        HDR,
        7, 'E', 'x', 'A', 'm', 'P', 'l', 'E', 3, 'C', 'o', 'M', 0,
        3, 'W', 'W', 'W', 0xC0, 0x0C
    };
    static const uint8_t desired[] = {
        HDR,
        3, 'w', 'W', 'w', 7, 'e', 'X', 'a', 'M', 'p', 'L', 'e',
        3, 'c', 'O', 'm', 0
    };
    WireName name;
    WireName restored;
    size_t ownerAt = 25;

    CHECK(ParseName(desired, sizeof desired, WIRE_HEADER_BYTES, &name));
    CHECK(WireRestoreNameCase(msg, sizeof msg, ownerAt, &name));
    CHECK(msg[ownerAt + 1] == 'w');
    CHECK(msg[ownerAt + 2] == 'W');
    CHECK(msg[ownerAt + 3] == 'w');
    CHECK(msg[ownerAt + 4] == 0xC0 && msg[ownerAt + 5] == 0x0C);
    CHECK(ParseName(msg, sizeof msg, ownerAt, &restored));
    CHECK(WireNameEqual(&restored, &name));
    CHECK(!WireNameEqualExact(&restored, &name));
}

/* The parser must reject every prefix of a valid message before it reads past
   the end. This catches off-by-one bounds errors that the shaped cases miss. */
static void TestAllPrefixesOfAValidMessage(void)
{
    static const uint8_t msg[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
        0x00, 0x01,
        0x00, 0x01,
        0x00,
        0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    for(size_t n = 0; n < sizeof msg; n++)
    {
        WireEdns edns;
        WireName name;

        (void)WireFindEdns(msg, n, &edns);
        (void)ParseName(msg, n, 12, &name);
    }

    WireEdns edns;
    CHECK(WireFindEdns(msg, sizeof msg, &edns));
    CHECK(edns.bPresent);
}

/* The log line is one record per query, so a name carrying a newline or a
   space would let a client forge entries in it. */
static void TestNameText(void)
{
    WireName name;
    char     text[512];
    char     scratch[8];

    CHECK(WireEncodeName("example.com", &name));
    CHECK(WireNameText(&name, text, sizeof text));
    CHECK(strcmp(text, "example.com") == 0);

    CHECK(WireEncodeName("a.b.c.example.com", &name));
    CHECK(WireNameText(&name, text, sizeof text));
    CHECK(strcmp(text, "a.b.c.example.com") == 0);

    /* The root, which is one zero byte */
    memset(&name, 0, sizeof name);
    name.wire[0] = 0;
    name.len     = 1;
    CHECK(WireNameText(&name, text, sizeof text));
    CHECK(strcmp(text, ".") == 0);

    /* A label holding a newline, a space and a quote. None may reach the line
       as itself. */
    memset(&name, 0, sizeof name);
    name.wire[0] = 5;
    name.wire[1] = 'a';
    name.wire[2] = '\n';
    name.wire[3] = ' ';
    name.wire[4] = '"';
    name.wire[5] = 'b';
    name.wire[6] = 0;
    name.len     = 7;
    CHECK(WireNameText(&name, text, sizeof text));
    /* A quote passes through: the format is space separated and unquoted, so
       only the field and record separators are load bearing */
    CHECK(strcmp(text, "a\\010\\032\"b") == 0);
    CHECK(strchr(text, '\n') == NULL);
    CHECK(strchr(text, ' ') == NULL);

    /* A dot inside a label is escaped, or the text reads as two labels */
    memset(&name, 0, sizeof name);
    name.wire[0] = 3;
    name.wire[1] = 'a';
    name.wire[2] = '.';
    name.wire[3] = 'b';
    name.wire[4] = 0;
    name.len     = 5;
    CHECK(WireNameText(&name, text, sizeof text));
    CHECK(strcmp(text, "a\\046b") == 0);

    /* A buffer too small refuses rather than writing a partial name */
    CHECK(WireEncodeName("example.com", &name));
    for(size_t cap = 1; cap <= strlen("example.com"); cap++)
    {
        char small[16];
        CHECK(!WireNameText(&name, small, cap));
        CHECK(small[0] == '\0');
    }

    CHECK(!WireNameText(NULL, text, sizeof text));
    CHECK(!WireNameText(&name, text, 0));

    CHECK(strcmp(WireTypeName(WIRE_TYPE_A, scratch, sizeof scratch), "A") == 0);
    CHECK(strcmp(WireTypeName(WIRE_TYPE_AAAA, scratch, sizeof scratch),
                 "AAAA") == 0);
    CHECK(strcmp(WireTypeName(WIRE_TYPE_HTTPS, scratch, sizeof scratch),
                 "HTTPS") == 0);
    CHECK(strcmp(WireTypeName(99, scratch, sizeof scratch), "99") == 0);
    CHECK(strcmp(WireTypeName(65535, scratch, sizeof scratch), "65535") == 0);
    CHECK(strcmp(WireTypeName(0, scratch, sizeof scratch), "0") == 0);
}

int main(void)
{
    TestWellFormedQuery();
    TestNameText();
    TestBackwardPointer();
    TestCompressedTailResumesAfterPointer();
    TestSelfReferentialPointer();
    TestForwardPointer();
    TestBackwardChainThatRevisits();
    TestJumpCap();
    TestTruncatedPointer();
    TestLabelOverrunsMessage();
    TestReservedLabelType();
    TestUnterminatedName();
    TestNameLengthCap();
    TestEmptyAndTruncatedHeader();
    TestHeaderOnlyHasNoQuestion();
    TestEdnsPresent();
    TestEdnsAbsentIsNotAnError();
    TestEdnsNotAtRootRejected();
    TestRdLengthOverrun();
    TestNameEqualIsCaseInsensitive();
    TestRestoreNameCaseLeavesPointerTargetsReadOnly();
    TestRestoreNameCaseWithCompressedTail();
    TestAllPrefixesOfAValidMessage();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("wire: all checks passed\n");
    return 0;
}
