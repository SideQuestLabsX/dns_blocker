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

bool WireSkipRecord(Reader *reader)
{
    WireName name;
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    uint16_t rdLength;

    return WireReadName(reader, &name)
        && ReaderU16(reader, &type)
        && ReaderU16(reader, &klass)
        && ReaderU32(reader, &ttl)
        && ReaderU16(reader, &rdLength)
        && ReaderSkip(reader, rdLength);
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
        WireName name;
        uint16_t type;
        uint16_t klass;
        uint32_t ttl;
        uint16_t rdLength;

        if(!WireReadName(&reader, &name)
           || !ReaderU16(&reader, &type)
           || !ReaderU16(&reader, &klass)
           || !ReaderU32(&reader, &ttl)
           || !ReaderU16(&reader, &rdLength))
            return false;

        if(type != WIRE_TYPE_OPT)
        {
            if(!ReaderSkip(&reader, rdLength))
                return false;
            continue;
        }

        /* OPT must sit at the root name, and only one may appear. */
        if(name.len != 1 || name.wire[0] != 0 || out->bPresent)
            return false;

        out->bPresent    = true;
        out->payloadSize = klass;
        out->extRcode    = (uint8_t)((ttl >> 24) & 0xFFu);
        out->version     = (uint8_t)((ttl >> 16) & 0xFFu);
        out->flags       = (uint16_t)(ttl & 0xFFFFu);

        if(!ReaderSkip(&reader, rdLength))
            return false;
    }

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
