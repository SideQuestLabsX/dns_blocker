#include "verify.h"

#include "msg.h"

/* Zones the response is allowed to speak about. It starts as the queried name
   and grows as the answer section walks a CNAME chain. */
#define VERIFY_MAX_ZONES 8

typedef struct
{
    WireName names[VERIFY_MAX_ZONES];
    size_t   count;
} ZoneSet;

static void ZoneAdd(ZoneSet *set, const WireName *name)
{
    if(set->count >= VERIFY_MAX_ZONES)
        return;

    set->names[set->count] = *name;
    set->count++;
}

static bool OwnerAllowed(const ZoneSet *set, const WireName *owner)
{
    for(size_t i = 0; i < set->count; i++)
    {
        if(WireNameInZone(owner, &set->names[i]))
            return true;

        /* A parent of the queried name may speak for it. This is what lets a
           negative answer carry the zone SOA, and a referral carry NS. */
        if(WireNameInZone(&set->names[i], owner))
            return true;
    }

    return false;
}

static bool ReadTargetName(const uint8_t *msg, size_t len, size_t rdOffset,
                           WireName *out)
{
    Reader reader;

    /* Bounded by the whole message, because a name inside rdata may use a
       compression pointer into an earlier section. */
    ReaderInit(&reader, msg, len);
    return ReaderSkip(&reader, rdOffset) && WireReadName(&reader, out);
}

VerifyResult VerifyResponse(const uint8_t *query, size_t queryLen,
                            const uint8_t *response, size_t responseLen)
{
    Reader       queryReader;
    WireHeader   queryHeader;
    WireQuestion asked;

    ReaderInit(&queryReader, query, queryLen);
    if(!WireParseHeader(&queryReader, &queryHeader) || queryHeader.qdCount != 1
       || !WireParseQuestion(&queryReader, &asked))
        return VerifyResult_Malformed;

    return VerifyAnswer(&asked, response, responseLen);
}

VerifyResult VerifyAnswer(const WireQuestion *asked,
                          const uint8_t *response, size_t responseLen)
{
    Reader       reader;
    WireHeader   header;
    WireQuestion answered;
    ZoneSet      zones = { .count = 0 };

    ReaderInit(&reader, response, responseLen);
    if(!WireParseHeader(&reader, &header))
        return VerifyResult_Malformed;

    if((header.flags & MSG_FLAG_QR) == 0)
        return VerifyResult_NotAResponse;

    if(header.qdCount != 1 || !WireParseQuestion(&reader, &answered))
        return VerifyResult_Malformed;

    if(answered.type != asked->type || answered.klass != asked->klass
       || !WireNameEqualExact(&answered.name, &asked->name))
        return VerifyResult_QuestionMismatch;

    ZoneAdd(&zones, &asked->name);

    uint32_t total = (uint32_t)header.anCount + header.nsCount + header.arCount;
    for(uint32_t i = 0; i < total; i++)
    {
        WireRecord record;

        if(!WireReadRecord(&reader, &record))
            return VerifyResult_Malformed;

        /* OPT is owned by the root and carries transport options, not data
           about the queried name. */
        if(record.type == WIRE_TYPE_OPT)
            continue;

        if(!OwnerAllowed(&zones, &record.name))
            return VerifyResult_OutOfBailiwick;

        /* Following the chain has to happen after the owner check, so a
           forged CNAME cannot widen the set that validates itself. */
        if(i < header.anCount
           && (record.type == WIRE_TYPE_CNAME || record.type == WIRE_TYPE_DNAME))
        {
            WireName target;
            if(!ReadTargetName(response, responseLen, record.rdOffset, &target))
                return VerifyResult_Malformed;

            ZoneAdd(&zones, &target);
        }
    }

    return VerifyResult_Ok;
}

const char *VerifyResultName(VerifyResult result)
{
    switch(result)
    {
        case VerifyResult_Ok:               return "ok";
        case VerifyResult_Malformed:        return "malformed";
        case VerifyResult_NotAResponse:     return "not a response";
        case VerifyResult_QuestionMismatch: return "question mismatch";
        case VerifyResult_OutOfBailiwick:   return "out of bailiwick";
    }

    return "unknown";
}
