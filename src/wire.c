#include "wire.h"

#include <string.h>

/* All multi-byte fields are read byte-wise. DNS names are variable-length, so
   QTYPE and QCLASS land at arbitrary alignment, and ARM1176 either faults or
   silently rotates an unaligned word. */

void ReaderInit(Reader *reader, const uint8_t *msg, size_t len)
{
    reader->base = msg;
    reader->len  = (msg != NULL) ? len : 0;
    reader->pos  = 0;
}

size_t ReaderRemaining(const Reader *reader)
{
    return reader->len - reader->pos;
}

bool ReaderSkip(Reader *reader, size_t count)
{
    if(count > ReaderRemaining(reader))
        return false;

    reader->pos += count;
    return true;
}

bool ReaderU8(Reader *reader, uint8_t *out)
{
    if(ReaderRemaining(reader) < 1)
        return false;

    *out = reader->base[reader->pos];
    reader->pos += 1;
    return true;
}

bool ReaderU16(Reader *reader, uint16_t *out)
{
    if(ReaderRemaining(reader) < 2)
        return false;

    *out = (uint16_t)(((uint16_t)reader->base[reader->pos] << 8) |
                       (uint16_t)reader->base[reader->pos + 1]);
    reader->pos += 2;
    return true;
}

bool ReaderU32(Reader *reader, uint32_t *out)
{
    if(ReaderRemaining(reader) < 4)
        return false;

    *out = ((uint32_t)reader->base[reader->pos]     << 24) |
           ((uint32_t)reader->base[reader->pos + 1] << 16) |
           ((uint32_t)reader->base[reader->pos + 2] <<  8) |
            (uint32_t)reader->base[reader->pos + 3];
    reader->pos += 4;
    return true;
}

bool WireReadName(Reader *reader, WireName *out)
{
    size_t pos     = reader->pos;
    size_t jumps   = 0;
    size_t resume  = 0;
    size_t written = 0;
    bool   bJumped = false;

    out->len = 0;

    for(;;)
    {
        if(pos >= reader->len)
            return false;

        uint8_t label = reader->base[pos];

        if((label & 0xC0u) == 0xC0u)
        {
            if(pos + 1 >= reader->len)
                return false;

            size_t target = ((size_t)(label & 0x3Fu) << 8) |
                             (size_t)reader->base[pos + 1];

            /* Backwards-only ends a pure pointer chain, because each jump
               decreases the offset. The name-length cap below ends a chain
               that crosses a label and returns to an earlier offset. */
            if(target >= pos)
                return false;

            jumps++;
            if(jumps > CFG_MAX_PTR_JUMPS)
                return false;

            if(!bJumped)
            {
                resume  = pos + 2;
                bJumped = true;
            }

            pos = target;
            continue;
        }

        /* 0x40 and 0x80 are reserved label types. */
        if((label & 0xC0u) != 0)
            return false;

        if(label == 0)
        {
            if(written + 1 > sizeof out->wire)
                return false;

            out->wire[written] = 0;
            written++;
            pos++;
            break;
        }

        if(label > CFG_MAX_LABEL_BYTES)
            return false;
        if(reader->len - pos - 1 < label)
            return false;
        if(written + 1u + label > sizeof out->wire)
            return false;

        out->wire[written] = label;
        written++;
        memcpy(out->wire + written, reader->base + pos + 1, label);
        written += label;
        pos += 1u + label;
    }

    out->len    = written;
    reader->pos = bJumped ? resume : pos;
    return true;
}

bool WireParseHeader(Reader *reader, WireHeader *out)
{
    return ReaderU16(reader, &out->id)
        && ReaderU16(reader, &out->flags)
        && ReaderU16(reader, &out->qdCount)
        && ReaderU16(reader, &out->anCount)
        && ReaderU16(reader, &out->nsCount)
        && ReaderU16(reader, &out->arCount);
}

bool WireParseQuestion(Reader *reader, WireQuestion *out)
{
    return WireReadName(reader, &out->name)
        && ReaderU16(reader, &out->type)
        && ReaderU16(reader, &out->klass);
}

bool WireReadRecord(Reader *reader, WireRecord *out)
{
    if(!WireReadName(reader, &out->name)
       || !ReaderU16(reader, &out->type)
       || !ReaderU16(reader, &out->klass))
        return false;

    out->ttlOffset = reader->pos;

    if(!ReaderU32(reader, &out->ttl)
       || !ReaderU16(reader, &out->rdLength))
        return false;

    out->rdOffset = reader->pos;
    return ReaderSkip(reader, out->rdLength);
}

bool WireSkipRecord(Reader *reader)
{
    WireRecord record;
    return WireReadRecord(reader, &record);
}

bool WireSoaMinimum(const uint8_t *msg, size_t len, const WireRecord *soa,
                    uint32_t *out)
{
    Reader   reader;
    WireName mname;
    WireName rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;

    if(soa->type != WIRE_TYPE_SOA)
        return false;

    /* Bounded to the record's own rdata. A malformed length must not let the
       walk read the bytes of the next record as SOA fields. */
    if(soa->rdOffset > len || len - soa->rdOffset < soa->rdLength)
        return false;

    ReaderInit(&reader, msg, soa->rdOffset + soa->rdLength);
    if(!ReaderSkip(&reader, soa->rdOffset))
        return false;

    return WireReadName(&reader, &mname)
        && WireReadName(&reader, &rname)
        && ReaderU32(&reader, &serial)
        && ReaderU32(&reader, &refresh)
        && ReaderU32(&reader, &retry)
        && ReaderU32(&reader, &expire)
        && ReaderU32(&reader, out);
}

uint16_t WireRcode(const WireHeader *header)
{
    return (uint16_t)(header->flags & 0x000Fu);
}

uint64_t WireNameHash(const WireName *name, uint16_t type, uint16_t klass)
{
    /* FNV-1a over the lowercased name, so the hash matches the
       case-insensitive comparison in WireNameEqual. */
    uint64_t hash = 0xCBF29CE484222325u;

    for(size_t i = 0; i < name->len; i++)
    {
        uint8_t c = name->wire[i];
        if(c >= 'A' && c <= 'Z')
            c = (uint8_t)(c + 32);

        hash ^= c;
        hash *= 0x100000001B3u;
    }

    hash ^= type;
    hash *= 0x100000001B3u;
    hash ^= klass;
    hash *= 0x100000001B3u;
    return hash;
}

bool WireFindEdns(const uint8_t *msg, size_t len, WireEdns *out)
{
    Reader     reader;
    WireHeader header;

    memset(out, 0, sizeof *out);
    ReaderInit(&reader, msg, len);

    if(!WireParseHeader(&reader, &header))
        return false;

    for(uint16_t i = 0; i < header.qdCount; i++)
    {
        WireQuestion question;
        if(!WireParseQuestion(&reader, &question))
            return false;
    }

    uint32_t before = (uint32_t)header.anCount + header.nsCount;
    for(uint32_t i = 0; i < before; i++)
    {
        if(!WireSkipRecord(&reader))
            return false;
    }

    for(uint16_t i = 0; i < header.arCount; i++)
    {
        WireRecord record;

        if(!WireReadRecord(&reader, &record))
            return false;

        if(record.type != WIRE_TYPE_OPT)
            continue;

        /* OPT must sit at the root name, and only one may appear. */
        if(record.name.len != 1 || record.name.wire[0] != 0 || out->bPresent)
            return false;

        out->bPresent    = true;
        out->payloadSize = record.klass;
        out->extRcode    = (uint8_t)((record.ttl >> 24) & 0xFFu);
        out->version     = (uint8_t)((record.ttl >> 16) & 0xFFu);
        out->flags       = (uint16_t)(record.ttl & 0xFFFFu);
    }

    return true;
}

bool WireNameInZone(const WireName *name, const WireName *zone)
{
    if(zone->len == 0 || name->len < zone->len)
        return false;

    /* The root zone is one zero byte, and every name ends with it. */
    if(zone->len == 1)
        return true;

    size_t offset = 0;
    while(offset < name->len)
    {
        if(name->len - offset == zone->len)
        {
            for(size_t i = 0; i < zone->len; i++)
            {
                uint8_t c = name->wire[offset + i];
                uint8_t z = zone->wire[i];

                if(c >= 'A' && c <= 'Z')
                    c = (uint8_t)(c + 32);
                if(z >= 'A' && z <= 'Z')
                    z = (uint8_t)(z + 32);

                if(c != z)
                    return false;
            }

            return true;
        }

        uint8_t label = name->wire[offset];
        if(label == 0)
            break;

        offset += 1u + label;
    }

    return false;
}

bool WireNameEqualExact(const WireName *a, const WireName *b)
{
    return a->len == b->len && memcmp(a->wire, b->wire, a->len) == 0;
}

bool WireEncodeName(const char *dotted, WireName *out)
{
    size_t len = strlen(dotted);

    if(len == 0)
        return false;

    if(dotted[len - 1] == '.')
        len--;

    size_t at    = 0;
    size_t start = 0;

    for(size_t i = 0; i <= len; i++)
    {
        if(i != len && dotted[i] != '.')
            continue;

        size_t labelLen = i - start;
        if(labelLen == 0 || labelLen > CFG_MAX_LABEL_BYTES)
            return false;
        if(at + 1 + labelLen + 1 > sizeof out->wire)
            return false;

        out->wire[at] = (uint8_t)labelLen;
        for(size_t k = 0; k < labelLen; k++)
        {
            char c = dotted[start + k];
            if(c >= 'A' && c <= 'Z')
                c = (char)(c + 32);
            out->wire[at + 1 + k] = (uint8_t)c;
        }

        at += 1 + labelLen;
        start = i + 1;
    }

    if(at + 1 > sizeof out->wire)
        return false;

    out->wire[at] = 0;
    out->len      = at + 1;
    return true;
}

bool WireNameEqual(const WireName *a, const WireName *b)
{
    if(a->len != b->len)
        return false;

    /* Label content is case-insensitive on the wire. */
    for(size_t i = 0; i < a->len; i++)
    {
        uint8_t ca = a->wire[i];
        uint8_t cb = b->wire[i];

        if(ca >= 'A' && ca <= 'Z')
            ca = (uint8_t)(ca + 32);
        if(cb >= 'A' && cb <= 'Z')
            cb = (uint8_t)(cb + 32);

        if(ca != cb)
            return false;
    }

    return true;
}
