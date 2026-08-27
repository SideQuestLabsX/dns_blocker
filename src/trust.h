#ifndef DNS_BLOCKER_TRUST_H
#define DNS_BLOCKER_TRUST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The TLS trust anchor, mapped read-only at boot. It is concatenated DER rather
   than PEM, because the shim parses DER and a bounded file is the whole point:
   a full system store is around 150 KB against a cap in the tens of KB.

   Every refusal is named. A missing file, an empty one and one that is merely
   too big need different fixes from the operator, and reporting them as one
   failure sent an earlier deployment looking for the wrong thing. */

typedef enum
{
    TrustLoad_Ok,
    TrustLoad_Missing,
    TrustLoad_Empty,
    TrustLoad_TooLarge,
    TrustLoad_Unreadable
} TrustResult;

typedef struct
{
    const uint8_t *base;
    size_t         size;
    /* What the file measured, kept even when it was refused, so the caller can
       report the size beside the cap it broke */
    size_t         fileSize;
} TrustMap;

TrustResult TrustLoad(TrustMap *trust, const char *path, size_t cap);
void TrustUnload(TrustMap *trust);

/* A short reason for a log line. Never NULL. */
const char *TrustResultText(TrustResult result);

#endif
