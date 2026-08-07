#include "qlog.h"

#if defined(FEATURE_QUERY_LOG) && FEATURE_QUERY_LOG

#include "config.h"
#include "msg.h"

#include <stdio.h>

static const char *RcodeName(uint16_t rcode, char *scratch, size_t cap)
{
    switch(rcode)
    {
        case MSG_RCODE_NOERROR:  return "NOERROR";
        case MSG_RCODE_FORMERR:  return "FORMERR";
        case MSG_RCODE_SERVFAIL: return "SERVFAIL";
        case MSG_RCODE_NXDOMAIN: return "NXDOMAIN";
        case MSG_RCODE_NOTIMP:   return "NOTIMP";
        case MSG_RCODE_REFUSED:  return "REFUSED";
        default: break;
    }

    snprintf(scratch, cap, "%u", (unsigned)rcode);
    return scratch;
}

void QueryLogLine(bool bOverTcp, const WireQuestion *question,
                  const char *outcome, uint16_t rcode)
{
    char name[CFG_MAX_NAME_BYTES * 4 + 1];
    char typeScratch[8];
    char rcodeScratch[8];

    if(question == NULL || !WireNameText(&question->name, name, sizeof name))
        return;

    /* One printf, because a line split across calls interleaves with another
       writer on the same descriptor */
    printf("query %s %s %s %s %s\n",
           bOverTcp ? "tcp" : "udp",
           name,
           WireTypeName(question->type, typeScratch, sizeof typeScratch),
           outcome,
           RcodeName(rcode, rcodeScratch, sizeof rcodeScratch));
}

#endif
