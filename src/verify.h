#ifndef DNS_BLOCKER_VERIFY_H
#define DNS_BLOCKER_VERIFY_H

#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Checks an upstream response against the query that produced it.

   A matching transaction ID and source port are not enough. An attacker who
   wins the race can attach any record to an answer, so the daemon also has to
   refuse records that the question does not cover. */

typedef enum
{
    VerifyResult_Ok,
    VerifyResult_Malformed,
    VerifyResult_NotAResponse,
    VerifyResult_QuestionMismatch,
    VerifyResult_OutOfBailiwick,
    VerifyResult_Rebind,
    /* Holds the status segment's copy of these names honest. status.c asserts
       it against STATUS_REJECT_COUNT */
    VerifyResult_Count
} VerifyResult;

/* The question comparison is byte-exact, including letter case, so it also
   enforces the 0x20 echo when the query used randomised case. */
VerifyResult VerifyResponse(const uint8_t *query, size_t queryLen,
                            const uint8_t *response, size_t responseLen);

/* Same check against a question kept from the query that went out. The
   in-flight table holds this instead of the whole query, which is the
   difference between 270 bytes a slot and a buffer for a full message. */
VerifyResult VerifyAnswer(const WireQuestion *asked,
                          const uint8_t *response, size_t responseLen);

/* A public name answering with a private address is a rebind: the client is
   being pointed at something on its own network. That is a property of the
   answer and not of the name, so no blocklist can state it.

   Kept apart from VerifyAnswer because it is a policy an operator may turn off,
   while the bailiwick checks are not optional. Answer-section `A` and `AAAA`
   only: a stub resolves from there, and the additional section carries glue a
   forwarder never follows.

   Names inside `CFG_LOCAL_DOMAIN` are exempt. An operator whose public name
   intentionally resolves into RFC 1918 puts it in the host map, which answers
   before anything reaches an upstream. */
VerifyResult VerifyRebind(const WireQuestion *asked, const uint8_t *response,
                          size_t responseLen);

const char *VerifyResultName(VerifyResult result);

#endif
