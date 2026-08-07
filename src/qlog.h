#ifndef DNS_BLOCKER_QLOG_H
#define DNS_BLOCKER_QLOG_H

#include "wire.h"

#include <stdbool.h>
#include <stdint.h>

/* One line per answered query on stdout, and nothing else. There is no ring,
   no buffer and no writer thread, because the supervisor owns capture,
   transport and disk policy. A supervisor that wants these lines gone routes
   stdout to /dev/null, and `stderr` is never gated because that carries the
   daemon's own faults.

   The stream names every domain each device on the network resolved, so it is
   the largest and most sensitive output the daemon produces. That is why it is
   compile-time: FEATURE_QUERY_LOG=0 removes the call sites entirely rather
   than leaving a branch that a misconfiguration can turn on. */

#define QLOG_OUTCOME_LOCAL     "local"
#define QLOG_OUTCOME_BLOCKED   "blocked"
#define QLOG_OUTCOME_HIT       "hit"
#define QLOG_OUTCOME_FORWARDED "forwarded"
#define QLOG_OUTCOME_TRUNCATED "truncated"
#define QLOG_OUTCOME_FAILED    "failed"
#define QLOG_OUTCOME_MALFORMED "malformed"

#if defined(FEATURE_QUERY_LOG) && FEATURE_QUERY_LOG

void QueryLogLine(bool bOverTcp, const WireQuestion *question,
                  const char *outcome, uint16_t rcode);

#define QueryLog(bOverTcp, question, outcome, rcode) \
    QueryLogLine((bOverTcp), (question), (outcome), (rcode))

#else

/* The arguments are still consumed, so turning the feature off cannot leave an
   unused variable behind at a call site. */
#define QueryLog(bOverTcp, question, outcome, rcode) \
    do {                                             \
        (void)(bOverTcp);                            \
        (void)(question);                            \
        (void)(outcome);                             \
        (void)(rcode);                               \
    } while(0)

#endif

#endif
