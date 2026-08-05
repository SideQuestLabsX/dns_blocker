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

bool MsgBuildTruncated(uint8_t *out, size_t cap, const uint8_t *query,
                       size_t queryLen, size_t *outLen)
{
    return BuildFromQuestion(out, cap, query, queryLen, MSG_FLAG_TC,
                             MSG_RCODE_NOERROR, outLen);
}
