#include "verify.h"
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

#define CHECK_VERDICT(got, want)                                           \
    do {                                                                   \
        VerifyResult g_ = (got);                                           \
        if(g_ != (want))                                                   \
        {                                                                  \
            printf("FAIL %s:%d  got %s, want %s\n", __FILE__, __LINE__,    \
                   VerifyResultName(g_), VerifyResultName(want));          \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

static void PutCname(Builder *b, const char *owner, const char *target,
                     uint32_t ttl)
{
    PutName(b, owner);
    PutU16(b, WIRE_TYPE_CNAME);
    PutU16(b, WIRE_CLASS_IN);
    PutU32(b, ttl);

    size_t lengthAt = b->len;
    PutU16(b, 0);
    size_t rdStart = b->len;
    PutName(b, target);

    uint16_t rdLength = (uint16_t)(b->len - rdStart);
    b->buf[lengthAt]     = (uint8_t)(rdLength >> 8);
    b->buf[lengthAt + 1] = (uint8_t)rdLength;
}

static void TestZoneMatching(void)
{
    WireName a, b, c, d, root;

    CHECK(NameOf("www.example.com", &a));
    CHECK(NameOf("example.com", &b));
    CHECK(NameOf("evilexample.com", &c));
    CHECK(NameOf("com", &d));
    CHECK(NameOf("", &root));

    CHECK(WireNameInZone(&a, &b));
    CHECK(WireNameInZone(&b, &b));
    CHECK(WireNameInZone(&a, &d));
    CHECK(!WireNameInZone(&b, &a));

    /* The comparison must land on a label boundary. */
    CHECK(!WireNameInZone(&c, &b));
    CHECK(WireNameInZone(&c, &d));

    /* Every name is under the root. */
    CHECK(WireNameInZone(&a, &root));
}

/* A single label whose bytes spell out the wire form of example.com. A scan
   that compares tails without stopping on label boundaries matches this at
   offset 1 and treats the name as belonging to the zone. The evilexample.com
   case above does not catch that, because there the length byte differs and
   the compare fails for an unrelated reason. */
static void TestZoneMatchRequiresLabelBoundary(void)
{
    static const uint8_t crafted[] = {
        12, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0
    };

    WireName name;
    WireName zone;

    memcpy(name.wire, crafted, sizeof crafted);
    name.len = sizeof crafted;

    CHECK(NameOf("example.com", &zone));
    CHECK(name.len - 1 == zone.len);
    CHECK(memcmp(name.wire + 1, zone.wire, zone.len) == 0);
    CHECK(!WireNameInZone(&name, &zone));
}

static void TestPlainAnswerAccepted(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 0x1234,
                                 "www.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 0x1234, 0x8180u, 1, 1, 0, 0);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutARecord(&b, "www.example.com", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len), VerifyResult_Ok);
}

static void TestCnameChainAccepted(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    /* The chain leaves the queried zone, which is normal and must be allowed
       once the CNAME that authorises it has been seen. */
    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 2, 0, 0);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutCname(&b, "www.example.com", "cdn.other.net", 300);
    PutARecord(&b, "cdn.other.net", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len), VerifyResult_Ok);
}

static void TestOutOfBailiwickRecordRejected(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    /* The Kaminsky shape: a correct answer with a forged record attached. */
    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 2, 0, 0);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutARecord(&b, "www.example.com", 300);
    PutARecord(&b, "www.bank.com", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len),
                  VerifyResult_OutOfBailiwick);
}

static void TestForgedRecordInAdditionalRejected(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 1, 0, 1);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutARecord(&b, "www.example.com", 300);
    PutARecord(&b, "bank.com", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len),
                  VerifyResult_OutOfBailiwick);
}

/* A forged CNAME must not be able to authorise the record that follows it,
   so the owner check runs before the chain is extended. */
static void TestForgedCnameCannotAuthoriseItself(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 2, 0, 0);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutCname(&b, "bank.com", "evil.net", 300);
    PutARecord(&b, "evil.net", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len),
                  VerifyResult_OutOfBailiwick);
}

static void TestNegativeAnswerWithZoneSoaAccepted(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "nope.example.com", WIRE_TYPE_A);

    /* The SOA is owned by a parent of the queried name. */
    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8183u, 1, 0, 1, 0);
    PutQuestion(&b, "nope.example.com", WIRE_TYPE_A);
    PutSoa(&b, "example.com", 3600, 900);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len), VerifyResult_Ok);
}

static void TestSoaFromAnUnrelatedZoneRejected(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "nope.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8183u, 1, 0, 1, 0);
    PutQuestion(&b, "nope.example.com", WIRE_TYPE_A);
    PutSoa(&b, "attacker.net", 3600, 900);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len),
                  VerifyResult_OutOfBailiwick);
}

static void TestQuestionMustMatch(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 1, 0, 0);
    PutQuestion(&b, "other.example.com", WIRE_TYPE_A);
    PutARecord(&b, "other.example.com", 300);
    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len),
                  VerifyResult_QuestionMismatch);

    /* Same name, different type. */
    Builder c = { reply, sizeof reply, 0 };
    PutHeader(&c, 1, 0x8180u, 1, 0, 0, 0);
    PutQuestion(&c, "www.example.com", WIRE_TYPE_AAAA);
    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, c.len),
                  VerifyResult_QuestionMismatch);
}

/* The 0x20 defence is the case surviving the round trip. A resolver that
   answers with different case is indistinguishable from an attacker who
   guessed the transaction ID but not the case. */
static void TestCaseMustBeEchoed(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "WwW.eXaMpLe.CoM", WIRE_TYPE_A);

    Builder same = { reply, sizeof reply, 0 };
    PutHeader(&same, 1, 0x8180u, 1, 1, 0, 0);
    PutQuestion(&same, "WwW.eXaMpLe.CoM", WIRE_TYPE_A);
    PutARecord(&same, "WwW.eXaMpLe.CoM", 300);
    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, same.len),
                  VerifyResult_Ok);

    Builder flat = { reply, sizeof reply, 0 };
    PutHeader(&flat, 1, 0x8180u, 1, 1, 0, 0);
    PutQuestion(&flat, "www.example.com", WIRE_TYPE_A);
    PutARecord(&flat, "www.example.com", 300);
    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, flat.len),
                  VerifyResult_QuestionMismatch);
}

/* Owner names are still matched without regard to case, because only the
   question carries the 0x20 entropy. */
static void TestOwnerCaseIsIgnored(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 1, 0, 0);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutARecord(&b, "WWW.EXAMPLE.COM", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len), VerifyResult_Ok);
}

static void TestQueryEchoedBackIsNotAResponse(void)
{
    uint8_t query[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    CHECK_VERDICT(VerifyResponse(query, queryLen, query, queryLen),
                  VerifyResult_NotAResponse);
}

static void TestTruncatedAndEmptyInputs(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 1, 0, 0);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutARecord(&b, "www.example.com", 300);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, 0),
                  VerifyResult_Malformed);
    CHECK_VERDICT(VerifyResponse(query, 0, reply, b.len),
                  VerifyResult_Malformed);

    /* Every prefix must be refused rather than read past. */
    for(size_t n = 0; n < b.len; n++)
        (void)VerifyResponse(query, queryLen, reply, n);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len), VerifyResult_Ok);
}

static void TestOptRecordIsExempt(void)
{
    uint8_t query[512];
    uint8_t reply[512];

    size_t queryLen = BuildQuery(query, sizeof query, 1,
                                 "www.example.com", WIRE_TYPE_A);

    /* OPT is owned by the root, which is not below the queried name. */
    Builder b = { reply, sizeof reply, 0 };
    PutHeader(&b, 1, 0x8180u, 1, 1, 0, 1);
    PutQuestion(&b, "www.example.com", WIRE_TYPE_A);
    PutARecord(&b, "www.example.com", 300);
    PutOpt(&b, 1232, 0);

    CHECK_VERDICT(VerifyResponse(query, queryLen, reply, b.len), VerifyResult_Ok);
}

int main(void)
{
    TestZoneMatching();
    TestZoneMatchRequiresLabelBoundary();
    TestPlainAnswerAccepted();
    TestCnameChainAccepted();
    TestOutOfBailiwickRecordRejected();
    TestForgedRecordInAdditionalRejected();
    TestForgedCnameCannotAuthoriseItself();
    TestNegativeAnswerWithZoneSoaAccepted();
    TestSoaFromAnUnrelatedZoneRejected();
    TestQuestionMustMatch();
    TestCaseMustBeEchoed();
    TestOwnerCaseIsIgnored();
    TestQueryEchoedBackIsNotAResponse();
    TestTruncatedAndEmptyInputs();
    TestOptRecordIsExempt();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("verify: all checks passed\n");
    return 0;
}
