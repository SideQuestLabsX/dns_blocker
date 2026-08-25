#ifndef DNS_BLOCKER_SYNC_H
#define DNS_BLOCKER_SYNC_H

#include "blocklist.h"
#include "fetch.h"
#include "upstream.h"

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

/* Makes the directory `path` lives in. Nothing else creates it: `init` has no
   tmpfiles facility, and a tmpfs loses it at every boot. True when the
   directory is already there. */
bool SyncPrepareDirectory(const char *path);

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

/* Lowercase letters, digits and interior single hyphens */
bool SyncTierIsValid(const char *tier);
bool SyncBuildAssetName(char *out, size_t cap, const char *tier);

/* Returns the file tier or CFG_BLOCKLIST_TIER. Missing and empty files are
   silent; malformed content reports once. The result points to `out` or the
   config string */
const char *SyncLoadTier(const char *path, char *out, size_t cap);

bool SyncParseLocator(const uint8_t *data, size_t len, char *releaseTag,
                      size_t releaseTagCap);
bool SyncBuildReleaseUrl(char *out, size_t cap, const char *releaseTag,
                         const char *asset);

#if defined(PROFILE_ENCRYPTED)

typedef enum
{
    SyncState_Idle,
    SyncState_Resolve,
    SyncState_Transfer,
    SyncState_Compare,
    SyncState_Done,
    SyncState_Failed
} SyncState;

typedef enum
{
    SyncPhase_Locator,
    SyncPhase_Digest,
    SyncPhase_Asset
} SyncPhase;

typedef enum
{
    SyncStep_NeedAddress,
    SyncStep_Again,
    SyncStep_Done,
    SyncStep_Failed
} SyncStep;

typedef enum
{
    SyncFail_None,
    SyncFail_Transfer,
    SyncFail_Staging,
    SyncFail_Listing,
    SyncFail_Digest,
    SyncFail_Install,
    SyncFail_Locator,
    SyncFail_Url,
    SyncFail_Tier,
    SyncFail_Capacity
} SyncFail;

/* Sequences the three transfers and the install. Nothing here resolves a name:
   when a host has to become an address the driver stops and asks, which keeps
   the upstream pool and the poll loop out of this file. */
typedef struct
{
    SyncState   state;
    SyncPhase   phase;
    FetchJob    job;
    UpstreamPool *pool;
    TlsChannel   *channel;
    size_t        tlsSlot;

    char path[CFG_SYNC_PATH_BYTES];
    char staging[CFG_SYNC_PATH_BYTES];
    char releaseTag[CFG_SYNC_RELEASE_TAG_BYTES];
    /* Shared by the digest lookup and download */
    char asset[CFG_BLOCKLIST_ASSET_BYTES];
    char failText[CFG_BLOCKLIST_ASSET_BYTES + 32];
    int  stagingFd;

    /* Set when a redirect moved the target, so the answer to the next address
       request belongs to the new host rather than the original one */
    bool bFollowing;
    unsigned readRetries;

    uint8_t  metadataText[CFG_SYNC_DIGEST_BYTES];
    uint8_t  want[FETCH_DIGEST_BYTES];
    const Blocklist *active;
    mbedtls_sha256_context activeSha;
    size_t   activeAt;
    bool     bHaveWant;
    bool     bInstalled;
    bool     bActiveShaReady;
    SyncFail fail;
} SyncJob;

/* Prepares a run against `path` and reserves its shared TLS slot. `tier` NULL
   uses the compiled default */
bool SyncBegin(SyncJob *job, UpstreamPool *pool, const char *path,
               const char *tier, const Blocklist *active);

/* The host the driver is waiting on, valid after SyncStep_NeedAddress. */
const char *SyncHost(const SyncJob *job);

bool SyncProvideAddress(SyncJob *job, const struct sockaddr_storage *addr,
                        socklen_t addrLen, uint32_t nowMs);

short SyncEvents(const SyncJob *job);

/* The descriptor the transfer is running on, or -1 when none is. Lets the
   caller hand it to a poll loop it already owns. */
int SyncFd(const SyncJob *job);
SyncStep SyncProgress(SyncJob *job, uint32_t nowMs);
bool SyncNeedsProgress(const SyncJob *job);
bool SyncInstalled(const SyncJob *job);
void SyncEnd(SyncJob *job);

/* Which transfer was running, and why it stopped. Both are for a log line and
   neither is ever NULL. A run that fails silently retries on a timer, which
   hides a permanent defect behind what looks like a flaky network. */
const char *SyncPhaseText(const SyncJob *job);
const char *SyncFailText(const SyncJob *job);

#endif

#endif
