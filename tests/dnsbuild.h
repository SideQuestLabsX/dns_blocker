#ifndef DNS_BLOCKER_TESTS_DNSBUILD_H
#define DNS_BLOCKER_TESTS_DNSBUILD_H

/* Message construction shared by the tests. Everything is static inline so
   each test binary gets its own copy without unused-function warnings. */

#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
    uint8_t *buf;
    size_t   cap;
    size_t   len;
} Builder;

static inline void PutBytes(Builder *b, const void *src, size_t n)
{
    if(b->len + n > b->cap)
        return;

    memcpy(b->buf + b->len, src, n);
    b->len += n;
}

static inline void PutU8(Builder *b, uint8_t v)
{
    PutBytes(b, &v, 1);
}

static inline void PutU16(Builder *b, uint16_t v)
{
    PutU8(b, (uint8_t)(v >> 8));
    PutU8(b, (uint8_t)v);
}

static inline void PutU32(Builder *b, uint32_t v)
{
    PutU16(b, (uint16_t)(v >> 16));
    PutU16(b, (uint16_t)v);
}

static inline void PutName(Builder *b, const char *dotted)
{
    const char *start = dotted;

    if(*dotted == '\0')
    {
        PutU8(b, 0);
        return;
    }

    for(const char *p = dotted; ; p++)
    {
        if(*p == '.' || *p == '\0')
        {
            size_t n = (size_t)(p - start);
            PutU8(b, (uint8_t)n);
            PutBytes(b, start, n);
            start = p + 1;

            if(*p == '\0')
                break;
        }
    }

    PutU8(b, 0);
}

static inline void PutHeader(Builder *b, uint16_t id, uint16_t flags,
                             uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
    PutU16(b, id);
    PutU16(b, flags);
    PutU16(b, qd);
    PutU16(b, an);
    PutU16(b, ns);
    PutU16(b, ar);
}

static inline void PutResponseHeader(Builder *b, uint16_t rcode, uint16_t an,
                                     uint16_t ns, uint16_t ar)
{
    PutHeader(b, 0x1234, (uint16_t)(0x8180u | rcode), 1, an, ns, ar);
}

static inline void PutQuestion(Builder *b, const char *name, uint16_t type)
{
    PutName(b, name);
    PutU16(b, type);
    PutU16(b, WIRE_CLASS_IN);
}

static inline void PutARecord(Builder *b, const char *name, uint32_t ttl)
{
    PutName(b, name);
    PutU16(b, WIRE_TYPE_A);
    PutU16(b, WIRE_CLASS_IN);
    PutU32(b, ttl);
    PutU16(b, 4);
    PutU8(b, 93);
    PutU8(b, 184);
    PutU8(b, 216);
    PutU8(b, 34);
}

/* An A record with a chosen address, for the rebind checks */
static inline void PutAddrRecord(Builder *b, const char *name, uint32_t ttl,
                                 uint8_t a, uint8_t c, uint8_t d, uint8_t e)
{
    PutName(b, name);
    PutU16(b, WIRE_TYPE_A);
    PutU16(b, WIRE_CLASS_IN);
    PutU32(b, ttl);
    PutU16(b, 4);
    PutU8(b, a);
    PutU8(b, c);
    PutU8(b, d);
    PutU8(b, e);
}

/* An AAAA record. `high` becomes the first byte, so fc00::/7 and a global
   2000::/3 address are both reachable from a test. */
static inline void PutAaaaRecord(Builder *b, const char *name, uint32_t ttl,
                                 uint8_t high, uint8_t last)
{
    PutName(b, name);
    PutU16(b, WIRE_TYPE_AAAA);
    PutU16(b, WIRE_CLASS_IN);
    PutU32(b, ttl);
    PutU16(b, 16);
    PutU8(b, high);
    for(int i = 0; i < 14; i++)
        PutU8(b, 0);
    PutU8(b, last);
}

static inline void PutSoa(Builder *b, const char *zone, uint32_t ttl,
                          uint32_t minimum)
{
    PutName(b, zone);
    PutU16(b, WIRE_TYPE_SOA);
    PutU16(b, WIRE_CLASS_IN);
    PutU32(b, ttl);

    size_t lengthAt = b->len;
    PutU16(b, 0);

    size_t rdStart = b->len;
    PutName(b, "ns.example.com");
    PutName(b, "hostmaster.example.com");
    PutU32(b, 1);
    PutU32(b, 7200);
    PutU32(b, 3600);
    PutU32(b, 1209600);
    PutU32(b, minimum);

    uint16_t rdLength = (uint16_t)(b->len - rdStart);
    b->buf[lengthAt]     = (uint8_t)(rdLength >> 8);
    b->buf[lengthAt + 1] = (uint8_t)rdLength;
}

static inline void PutOpt(Builder *b, uint16_t payload, uint32_t ttlField)
{
    PutName(b, "");
    PutU16(b, WIRE_TYPE_OPT);
    PutU16(b, payload);
    PutU32(b, ttlField);
    PutU16(b, 0);
}

static inline size_t BuildPositive(uint8_t *buf, size_t cap, const char *name,
                                   uint32_t ttl)
{
    Builder b = { buf, cap, 0 };
    PutResponseHeader(&b, 0, 1, 0, 0);
    PutQuestion(&b, name, WIRE_TYPE_A);
    PutARecord(&b, name, ttl);
    return b.len;
}

static inline size_t BuildNegative(uint8_t *buf, size_t cap, const char *name,
                                   uint16_t rcode, uint32_t soaTtl,
                                   uint32_t minimum)
{
    Builder b = { buf, cap, 0 };
    PutResponseHeader(&b, rcode, 0, 1, 0);
    PutQuestion(&b, name, WIRE_TYPE_A);
    PutSoa(&b, "example.com", soaTtl, minimum);
    return b.len;
}

static inline size_t BuildQuery(uint8_t *buf, size_t cap, uint16_t id,
                                const char *name, uint16_t type)
{
    Builder b = { buf, cap, 0 };
    PutHeader(&b, id, 0x0100u, 1, 0, 0, 0);
    PutQuestion(&b, name, type);
    return b.len;
}

static inline bool NameOf(const char *dotted, WireName *out)
{
    uint8_t buf[CFG_MAX_NAME_BYTES + 16];
    Builder b = { buf, sizeof buf, 0 };
    Reader  reader;

    PutName(&b, dotted);
    ReaderInit(&reader, buf, b.len);
    return WireReadName(&reader, out);
}

#endif
