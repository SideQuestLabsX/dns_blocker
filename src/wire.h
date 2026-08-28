#ifndef DNS_BLOCKER_WIRE_H
#define DNS_BLOCKER_WIRE_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RFC 1035 message parsing. Every function here consumes untrusted network
   input. Nothing outside wire.c may index Reader.base directly: the bounds
   check belongs in the accessor, not in each call site. */

#define WIRE_HEADER_BYTES   12
#define WIRE_TYPE_A         1
#define WIRE_TYPE_CNAME     5
#define WIRE_TYPE_SOA       6
#define WIRE_TYPE_PTR       12
#define WIRE_TYPE_AAAA      28
#define WIRE_TYPE_DNAME     39
#define WIRE_TYPE_OPT       41
#define WIRE_TYPE_HTTPS     65
#define WIRE_CLASS_IN       1

typedef struct
{
    const uint8_t *base;
    size_t         len;
    size_t         pos;
} Reader;

/* Name in uncompressed wire form, length-prefixed labels ending in a zero
   byte. Never a C string: a DNS label may legitimately contain a dot or a NUL,
   so presentation format is a lossy view and is not what we match on. */
typedef struct
{
    uint8_t wire[CFG_MAX_NAME_BYTES];
    size_t  len;
} WireName;

typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
} WireHeader;

typedef struct
{
    WireName name;
    uint16_t type;
    uint16_t klass;
} WireQuestion;

typedef struct
{
    bool     bPresent;
    uint16_t payloadSize;
    uint8_t  extRcode;
    uint8_t  version;
    uint16_t flags;
} WireEdns;

/* Offsets are absolute within the message, so a cached copy can have its TTLs
   rewritten in place without reparsing. */
typedef struct
{
    WireName name;
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    size_t   ttlOffset;
    size_t   rdOffset;
    uint16_t rdLength;
} WireRecord;

void ReaderInit(Reader *reader, const uint8_t *msg, size_t len);
bool ReaderU8(Reader *reader, uint8_t *out);
bool ReaderU16(Reader *reader, uint16_t *out);
bool ReaderU32(Reader *reader, uint32_t *out);
bool ReaderSkip(Reader *reader, size_t count);
size_t ReaderRemaining(const Reader *reader);

/* Decompresses into out. Rejects forward and self-referential pointers, caps
   the jump count and enforces the 63-byte label and 255-byte name limits. */
bool WireReadName(Reader *reader, WireName *out);

bool WireParseHeader(Reader *reader, WireHeader *out);
bool WireParseQuestion(Reader *reader, WireQuestion *out);

/* Reads one resource record, leaving the cursor after its rdata. */
bool WireReadRecord(Reader *reader, WireRecord *out);

/* Skips one resource record including its rdata. */
bool WireSkipRecord(Reader *reader);

/* True for RFC 1918, loopback, link local and the v6 equivalents. */
bool WireAddressIsPrivate(const uint8_t *addr, uint8_t addrLen);

/* The address out of an `A` or `AAAA` record, bounds-checked against the
   message. False for any other type, or a length the type does not allow, so a
   caller cannot read rdata this file has not measured. */
bool WireRecordAddress(const uint8_t *msg, size_t len, const WireRecord *record,
                       uint8_t out[16], uint8_t *outLen);

/* MINIMUM field of an SOA record, which bounds negative cache lifetime per
   RFC 2308. Fails when the record is not an SOA or its rdata is malformed. */
bool WireSoaMinimum(const uint8_t *msg, size_t len, const WireRecord *soa,
                    uint32_t *out);

uint16_t WireRcode(const WireHeader *header);
uint64_t WireNameHash(const WireName *name, uint16_t type, uint16_t klass);

/* Walks the message and reports the OPT pseudo-record when the additional
   section carries one. Absence is not an error: out->bPresent says which. */
bool WireFindEdns(const uint8_t *msg, size_t len, WireEdns *out);

bool WireNameEqual(const WireName *a, const WireName *b);

/* True when name is zone itself, or a name below it. The comparison lands on a
   label boundary, so evilexample.com is not below example.com. */
bool WireNameInZone(const WireName *name, const WireName *zone);

/* Byte-exact, including letter case. 0x20 randomisation needs this, because
   the defence is the case surviving the round trip unchanged. */
bool WireNameEqualExact(const WireName *a, const WireName *b);

/* Rewrites literal label bytes at offset. Compression targets stay read-only,
   so callers that require exact case must check the expanded result */
bool WireRestoreNameCase(uint8_t *msg, size_t len, size_t offset,
                         const WireName *name);

/* Presentation name to wire form, lowercased, with a trailing dot accepted.
   Used for the names the daemon holds as text: the host map and the probe. */
bool WireEncodeName(const char *dotted, WireName *out);

/* Wire name back to dotted text, for the query log. The name came off the
   network, so a byte that would break a single-line record is written as
   \DDD rather than passed through. Always terminates `out`. */
bool WireNameText(const WireName *name, char *out, size_t cap);

/* Short mnemonic for the common types, or the decimal number in `scratch`
   for everything else. */
const char *WireTypeName(uint16_t type, char *scratch, size_t cap);

#endif
