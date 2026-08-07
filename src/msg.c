#include "msg.h"

#include <string.h>

uint16_t MsgId(const uint8_t *msg, size_t len)
{
    if(len < 2)
        return 0;

    return (uint16_t)(((uint16_t)msg[0] << 8) | msg[1]);
}

void MsgSetId(uint8_t *msg, size_t len, uint16_t id)
{
    if(len < 2)
        return;

    msg[0] = (uint8_t)(id >> 8);
    msg[1] = (uint8_t)id;
}

uint16_t MsgFlags(const uint8_t *msg, size_t len)
{
    if(len < 4)
        return 0;

    return (uint16_t)(((uint16_t)msg[2] << 8) | msg[3]);
}

size_t MsgQuestionEnd(const uint8_t *msg, size_t len)
{
    Reader     reader;
    WireHeader header;

    ReaderInit(&reader, msg, len);
    if(!WireParseHeader(&reader, &header))
        return 0;

    for(uint16_t i = 0; i < header.qdCount; i++)
    {
        WireQuestion question;
        if(!WireParseQuestion(&reader, &question))
            return 0;
    }

    return reader.pos;
}

bool MsgBuildQuery(uint8_t *out, size_t cap, const WireName *name,
                   uint16_t type, uint16_t id, size_t *outLen)
{
    size_t len = WIRE_HEADER_BYTES + name->len + 4;

    if(name->len == 0 || len > cap)
        return false;

    memset(out, 0, WIRE_HEADER_BYTES);
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = (uint8_t)(MSG_FLAG_RD >> 8);
    out[3] = (uint8_t)MSG_FLAG_RD;
    out[5] = 1;

    memcpy(out + WIRE_HEADER_BYTES, name->wire, name->len);

    size_t at = WIRE_HEADER_BYTES + name->len;
    out[at]     = (uint8_t)(type >> 8);
    out[at + 1] = (uint8_t)type;
    out[at + 2] = (uint8_t)(WIRE_CLASS_IN >> 8);
    out[at + 3] = (uint8_t)WIRE_CLASS_IN;

    *outLen = len;
    return true;
}

static bool BuildFromQuestion(uint8_t *out, size_t cap, const uint8_t *query,
                              size_t queryLen, uint16_t flags, uint16_t rcode,
                              size_t *outLen)
{
    size_t     end = MsgQuestionEnd(query, queryLen);
    Reader     reader;
    WireHeader header;

    if(end == 0 || end > cap)
        return false;

    ReaderInit(&reader, query, queryLen);
    if(!WireParseHeader(&reader, &header))
        return false;

    memcpy(out, query, end);

    /* RD is echoed because it describes what the client asked for, and RA is
       set because this daemon does perform recursion on the client's behalf. */
    uint16_t replyFlags = (uint16_t)(MSG_FLAG_QR | MSG_FLAG_RA | flags
                                     | (header.flags & MSG_FLAG_RD)
                                     | (rcode & 0x000Fu));

    out[2] = (uint8_t)(replyFlags >> 8);
    out[3] = (uint8_t)replyFlags;

    /* Counts other than QDCOUNT are cleared: the question is all that is
       copied, so any inherited count would describe records that are absent. */
    memset(out + 6, 0, 6);

    *outLen = end;
    return true;
}

bool MsgBuildReply(uint8_t *out, size_t cap, const uint8_t *query,
                   size_t queryLen, uint16_t rcode, size_t *outLen)
{
    return BuildFromQuestion(out, cap, query, queryLen, 0, rcode, outLen);
}

bool MsgBuildAnswer(uint8_t *out, size_t cap, const uint8_t *query,
                    size_t queryLen, uint16_t type, uint32_t ttl,
                    const uint8_t *rdata, size_t rdataLen, size_t *outLen)
{
    size_t at = 0;

    if(rdataLen > 0xFFFFu)
        return false;

    if(!BuildFromQuestion(out, cap, query, queryLen, 0, MSG_RCODE_NOERROR, &at))
        return false;

    if(at + 12 + rdataLen > cap)
        return false;

    /* The question name starts right after the header, so every answer here
       points at offset 12 instead of repeating it. */
    out[at++] = 0xC0;
    out[at++] = 0x0C;

    out[at++] = (uint8_t)(type >> 8);
    out[at++] = (uint8_t)type;
    out[at++] = (uint8_t)(WIRE_CLASS_IN >> 8);
    out[at++] = (uint8_t)WIRE_CLASS_IN;

    out[at++] = (uint8_t)(ttl >> 24);
    out[at++] = (uint8_t)(ttl >> 16);
    out[at++] = (uint8_t)(ttl >> 8);
    out[at++] = (uint8_t)ttl;

    out[at++] = (uint8_t)(rdataLen >> 8);
    out[at++] = (uint8_t)rdataLen;

    memcpy(out + at, rdata, rdataLen);
    at += rdataLen;

    out[6] = 0;
    out[7] = 1;

    *outLen = at;
    return true;
}

bool MsgBuildTruncated(uint8_t *out, size_t cap, const uint8_t *query,
                       size_t queryLen, size_t *outLen)
{
    return BuildFromQuestion(out, cap, query, queryLen, MSG_FLAG_TC,
                             MSG_RCODE_NOERROR, outLen);
}

bool MsgFirstAddress(const uint8_t *msg, size_t len, uint16_t type,
                     uint8_t *addr, uint8_t *addrLen)
{
    if(msg == NULL || addr == NULL || addrLen == NULL)
        return false;

    uint16_t want = (type == WIRE_TYPE_AAAA) ? 16 : 4;
    if(type != WIRE_TYPE_A && type != WIRE_TYPE_AAAA)
        return false;

    Reader     reader;
    WireHeader header;

    ReaderInit(&reader, msg, len);
    if(!WireParseHeader(&reader, &header) || header.anCount == 0)
        return false;

    for(uint16_t i = 0; i < header.qdCount; i++)
    {
        WireQuestion question;
        if(!WireParseQuestion(&reader, &question))
            return false;
    }

    for(uint16_t i = 0; i < header.anCount; i++)
    {
        WireRecord record;
        if(!WireReadRecord(&reader, &record))
            return false;

        if(record.type != type || record.klass != WIRE_CLASS_IN
           || record.rdLength != want)
            continue;

        if(record.rdOffset > len || len - record.rdOffset < want)
            return false;

        memcpy(addr, msg + record.rdOffset, want);
        *addrLen = (uint8_t)want;
        return true;
    }

    return false;
}
