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
    VerifyResult_OutOfBailiwick
} VerifyResult;

/* The question comparison is byte-exact, including letter case, so it also
   enforces the 0x20 echo when the query used randomised case. */
VerifyResult VerifyResponse(const uint8_t *query, size_t queryLen,
                            const uint8_t *response, size_t responseLen);

const char *VerifyResultName(VerifyResult result);

#endif
