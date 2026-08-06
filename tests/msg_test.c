#include "msg.h"
#include "wire.h"

#include "dnsbuild.h"

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

static void TestIdRoundTrip(void)
{
    uint8_t query[512];
    size_t  len = BuildQuery(query, sizeof query, 0xABCD, "a.example.com",
                             WIRE_TYPE_A);

    CHECK(MsgId(query, len) == 0xABCD);
    MsgSetId(query, len, 0x1234);
    CHECK(MsgId(query, len) == 0x1234);

    /* Short buffers must not be written through. */
    uint8_t tiny[1] = { 0x77 };
    MsgSetId(tiny, sizeof tiny, 0xFFFF);
    CHECK(tiny[0] == 0x77);
    CHECK(MsgId(tiny, sizeof tiny) == 0);
}

static void TestQuestionEnd(void)
{
    uint8_t query[512];
    size_t  len = BuildQuery(query, sizeof query, 1, "a.example.com",
                             WIRE_TYPE_A);

    CHECK(MsgQuestionEnd(query, len) == len);
    CHECK(MsgQuestionEnd(query, WIRE_HEADER_BYTES) == 0);
    CHECK(MsgQuestionEnd(query, 3) == 0);
}

static void TestBuildReplyEchoesTheQuestion(void)
{
    uint8_t query[512];
    uint8_t reply[512];
    size_t  replyLen = 0;

    size_t len = BuildQuery(query, sizeof query, 0x5A5A, "blocked.example.com",
                            WIRE_TYPE_A);

    CHECK(MsgBuildReply(reply, sizeof reply, query, len,
                        MSG_RCODE_NXDOMAIN, &replyLen));
    CHECK(replyLen == len);
    CHECK(MsgId(reply, replyLen) == 0x5A5A);

    uint16_t flags = MsgFlags(reply, replyLen);
    CHECK((flags & MSG_FLAG_QR) != 0);
    CHECK((flags & MSG_FLAG_RA) != 0);
    CHECK((flags & MSG_FLAG_RD) != 0);
    CHECK((flags & 0x000Fu) == MSG_RCODE_NXDOMAIN);

    /* The question is copied verbatim, and no record counts are inherited. */
    CHECK(memcmp(reply + WIRE_HEADER_BYTES, query + WIRE_HEADER_BYTES,
                 len - WIRE_HEADER_BYTES) == 0);

    Reader     reader;
    WireHeader header;
    ReaderInit(&reader, reply, replyLen);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(header.qdCount == 1);
    CHECK(header.anCount == 0);
    CHECK(header.nsCount == 0);
    CHECK(header.arCount == 0);
}

static void TestCountsFromTheQueryAreNotInherited(void)
{
    uint8_t buf[512];
    uint8_t reply[512];
    size_t  replyLen = 0;

    /* A query claiming records it does not carry must not produce a reply that
       claims them either. */
    Builder b = { buf, sizeof buf, 0 };
    PutHeader(&b, 0x0101, 0x0100u, 1, 5, 5, 5);
    PutQuestion(&b, "a.example.com", WIRE_TYPE_A);

    CHECK(MsgBuildReply(reply, sizeof reply, buf, b.len,
                        MSG_RCODE_SERVFAIL, &replyLen));

    Reader     reader;
    WireHeader header;
    ReaderInit(&reader, reply, replyLen);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(header.anCount == 0);
    CHECK(header.nsCount == 0);
    CHECK(header.arCount == 0);
}

static void TestTruncatedSetsTc(void)
{
    uint8_t query[512];
    uint8_t reply[512];
    size_t  replyLen = 0;

    size_t len = BuildQuery(query, sizeof query, 0x9999, "big.example.com",
                            WIRE_TYPE_A);

    CHECK(MsgBuildTruncated(reply, sizeof reply, query, len, &replyLen));
    CHECK((MsgFlags(reply, replyLen) & MSG_FLAG_TC) != 0);
    CHECK((MsgFlags(reply, replyLen) & 0x000Fu) == MSG_RCODE_NOERROR);
    CHECK(MsgId(reply, replyLen) == 0x9999);
}

/* The record name is a compression pointer at the question, so a parser has to
   follow it back rather than find the name repeated. */
static void TestBuildAnswerCarriesOneRecord(void)
{
    uint8_t query[512];
    uint8_t out[512];
    size_t  outLen = 0;
    static const uint8_t addr[4] = { 192, 168, 1, 47 };

    size_t len = BuildQuery(query, sizeof query, 0x0F0F, "iphone.lan",
                            WIRE_TYPE_A);

    CHECK(MsgBuildAnswer(out, sizeof out, query, len, WIRE_TYPE_A, 60,
                         addr, sizeof addr, &outLen));

    Reader       reader;
    WireHeader   header;
    WireQuestion question;
    WireRecord   record;

    ReaderInit(&reader, out, outLen);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(header.id == 0x0F0F);
    CHECK(header.qdCount == 1);
    CHECK(header.anCount == 1);
    CHECK(header.nsCount == 0 && header.arCount == 0);
    CHECK((header.flags & MSG_FLAG_QR) != 0);
    CHECK(WireRcode(&header) == MSG_RCODE_NOERROR);

    CHECK(WireParseQuestion(&reader, &question));
    CHECK(WireReadRecord(&reader, &record));
    CHECK(record.type == WIRE_TYPE_A);
    CHECK(record.klass == WIRE_CLASS_IN);
    CHECK(record.ttl == 60);
    CHECK(record.rdLength == 4);
    CHECK(memcmp(out + record.rdOffset, addr, 4) == 0);

    /* The pointer resolves to the question name. */
    CHECK(WireNameEqual(&record.name, &question.name));
    CHECK(ReaderRemaining(&reader) == 0);
}

static void TestBuildAnswerCarriesAName(void)
{
    uint8_t  query[512];
    uint8_t  out[512];
    size_t   outLen = 0;
    WireName ptr;

    CHECK(NameOf("iphone.lan", &ptr));

    size_t len = BuildQuery(query, sizeof query, 0x1010,
                            "47.1.168.192.in-addr.arpa", WIRE_TYPE_PTR);

    CHECK(MsgBuildAnswer(out, sizeof out, query, len, WIRE_TYPE_PTR, 60,
                         ptr.wire, ptr.len, &outLen));

    Reader       reader;
    WireHeader   header;
    WireQuestion question;
    WireRecord   record;

    ReaderInit(&reader, out, outLen);
    CHECK(WireParseHeader(&reader, &header));
    CHECK(WireParseQuestion(&reader, &question));
    CHECK(WireReadRecord(&reader, &record));
    CHECK(record.type == WIRE_TYPE_PTR);
    CHECK(record.rdLength == ptr.len);
    CHECK(memcmp(out + record.rdOffset, ptr.wire, ptr.len) == 0);
}

static void TestBuildAnswerRefusesTinyBuffers(void)
{
    uint8_t query[512];
    uint8_t out[512];
    size_t  outLen = 0;
    static const uint8_t addr[4] = { 10, 0, 0, 1 };

    size_t len = BuildQuery(query, sizeof query, 0x2020, "host.lan",
                            WIRE_TYPE_A);

    /* Room for the question but not for the record. */
    for(size_t cap = 0; cap < len + 12 + sizeof addr; cap++)
        CHECK(!MsgBuildAnswer(out, cap, query, len, WIRE_TYPE_A, 60,
                              addr, sizeof addr, &outLen));

    CHECK(MsgBuildAnswer(out, len + 12 + sizeof addr, query, len, WIRE_TYPE_A,
                         60, addr, sizeof addr, &outLen));
}

static void TestRefusesMalformedAndTinyBuffers(void)
{
    uint8_t query[512];
    uint8_t reply[8];
    size_t  replyLen = 0;

    size_t len = BuildQuery(query, sizeof query, 1, "a.example.com",
                            WIRE_TYPE_A);

    CHECK(!MsgBuildReply(reply, sizeof reply, query, len,
                         MSG_RCODE_SERVFAIL, &replyLen));

    uint8_t big[512];
    CHECK(!MsgBuildReply(big, sizeof big, query, 4, MSG_RCODE_SERVFAIL, &replyLen));
    CHECK(!MsgBuildReply(big, sizeof big, query, 0, MSG_RCODE_SERVFAIL, &replyLen));
}

int main(void)
{
    TestIdRoundTrip();
    TestQuestionEnd();
    TestBuildReplyEchoesTheQuestion();
    TestCountsFromTheQueryAreNotInherited();
    TestTruncatedSetsTc();
    TestBuildAnswerCarriesOneRecord();
    TestBuildAnswerCarriesAName();
    TestBuildAnswerRefusesTinyBuffers();
    TestRefusesMalformedAndTinyBuffers();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("msg: all checks passed\n");
    return 0;
}
