#ifndef DNS_BLOCKER_STATUS_H
#define DNS_BLOCKER_STATUS_H

#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "server.h"
#include "upstream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Current state in a file the daemon maps and anybody may read. The log stream
   says what happened and a supervisor drains it. This says what is true now,
   without stopping the daemon or parsing a line of it.

   One writer, no locks. The sequence counter is odd for the length of a write,
   so a reader that sees an odd value, or a different value either side of its
   copy, tried during a write and reads again.

   The layout does not depend on the profile or on any feature switch, so one
   reader works against every build. */

#define STATUS_MAGIC   "DBS1"
#define STATUS_VERSION 1u

typedef struct
{
    uint8_t  address[16];
    uint8_t  addressLen;
    uint8_t  transport;
    uint8_t  bDown;
    uint8_t  reserved;
    uint16_t port;
    uint16_t consecutiveFailures;
    uint32_t srttMs;              /* UINT32_MAX until something is measured */
    uint32_t downForMs;
    uint64_t queries;
    uint64_t failures;
    uint64_t rejected;
    uint64_t probes;
} StatusUpstream;

/* What the sync driver knows and the server does not. Zero everywhere on a
   build without it. */
typedef struct
{
    uint32_t bActive;
    uint32_t fail;                /* SyncFail, 0 when nothing has failed */
    uint64_t installedBytes;
    uint64_t nextDueMs;           /* until the next attempt */
} StatusSync;

typedef struct
{
    char     magic[4];
    uint32_t version;
    uint32_t bytes;
    uint32_t upstreamCount;

    uint32_t sequence;
    uint32_t pid;
    uint64_t uptimeMs;

    uint64_t queries;
    uint64_t hits;
    uint64_t blocked;
    uint64_t local;
    uint64_t forwarded;
    uint64_t failures;
    uint64_t malformed;
    uint64_t truncated;
    uint64_t refusedConnections;
    uint64_t evictedTransactions;
    uint64_t retries;

    uint64_t cacheHits;
    uint64_t cacheMisses;
    uint64_t cacheInserts;
    uint64_t cacheEvictions;
    uint64_t cacheRejects;

    uint32_t blocklistSource;
    uint32_t blocklistReserved;
    uint64_t blocklistBytes;

    StatusSync     sync;
    StatusUpstream upstreams[CFG_MAX_UPSTREAMS];
} StatusBlock;

typedef struct
{
    StatusBlock *block;
    uint32_t     startedMs;
} Status;

/* Creates the file and maps it. False leaves the daemon serving with no
   segment, because a reader nobody started must not stop the resolver. */
bool StatusOpen(Status *status, const char *path, uint32_t nowMs);
void StatusClose(Status *status);

/* One snapshot. Cheap enough for the serve loop, but the caller decides how
   often, because nothing here reads a clock of its own. */
void StatusPublish(Status *status, const Server *server, const Cache *cache,
                   const UpstreamPool *pool, const Blocklist *list,
                   const StatusSync *sync, uint32_t nowMs);

/* Reader side. Copies a consistent snapshot out of the mapping, retrying while
   a write is in progress. False for a missing file, a foreign version or a
   segment that never settled. */
bool StatusRead(const char *path, StatusBlock *out);

/* The daemon reads its own segment under --status, so there is no second binary
   to install and no second copy of this layout to drift. */
void StatusPrint(const StatusBlock *block, FILE *out);
bool StatusReport(const char *path, FILE *out);

const char *StatusTransportName(uint8_t transport);

#endif
