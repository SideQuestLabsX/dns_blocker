#ifndef DNS_BLOCKER_SYNC_H
#define DNS_BLOCKER_SYNC_H

#include "fetch.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Installing a downloaded blocklist. The body lands in a staging file beside
   the target, and only a digest match promotes it with rename(2). A rename
   within one directory is atomic, so a reader either maps the whole old file
   or the whole new one and never a half-written trie. */

typedef enum
{
    SyncInstall_Ok,
    SyncInstall_Mismatch,
    SyncInstall_Failed
} SyncInstall;

/* `<path>.new`. The staging file has to share a directory with the target,
   because rename(2) across filesystems fails. */
bool SyncStagingPath(char *out, size_t cap, const char *path);

/* Truncates any staging file left by an interrupted run. */
int SyncOpenStaging(const char *stagingPath);

/* Compares the digests, flushes and renames. Consumes `stagingFd` either way,
   and removes the staging file unless it was promoted. */
SyncInstall SyncCommit(int stagingFd, const char *stagingPath,
                       const char *path,
                       const uint8_t got[FETCH_DIGEST_BYTES],
                       const uint8_t want[FETCH_DIGEST_BYTES]);

/* Drops a transfer that failed before it produced a digest. */
void SyncAbandon(int stagingFd, const char *stagingPath);

#endif
