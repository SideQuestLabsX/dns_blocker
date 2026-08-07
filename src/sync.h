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

#if defined(PROFILE_ENCRYPTED)

typedef enum
{
    SyncState_Idle,
    SyncState_Resolve,
    SyncState_Transfer,
    SyncState_Done,
    SyncState_Failed
} SyncState;

typedef enum
{
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

/* Sequences the two transfers and the install. Nothing here resolves a name:
   when a host has to become an address the driver stops and asks, which keeps
   the upstream pool and the poll loop out of this file. */
typedef struct
{
    SyncState   state;
    SyncPhase   phase;
    FetchJob    job;
    TlsBackend *backend;

    char path[CFG_SYNC_PATH_BYTES];
    char staging[CFG_SYNC_PATH_BYTES];
    int  stagingFd;

    /* Set when a redirect moved the target, so the answer to the next address
       request belongs to the new host rather than the original one */
    bool bFollowing;

    uint8_t digestText[CFG_SYNC_DIGEST_BYTES];
    uint8_t want[FETCH_DIGEST_BYTES];
    bool    bHaveWant;
} SyncJob;

/* Prepares a run against `path`. The first step always asks for an address. */
bool SyncBegin(SyncJob *job, TlsBackend *backend, const char *path);

/* The host the driver is waiting on, valid after SyncStep_NeedAddress. */
const char *SyncHost(const SyncJob *job);

bool SyncProvideAddress(SyncJob *job, const struct sockaddr_storage *addr,
                        socklen_t addrLen);

short SyncEvents(const SyncJob *job);

/* The descriptor the transfer is running on, or -1 when none is. Lets the
   caller hand it to a poll loop it already owns. */
int SyncFd(const SyncJob *job);
SyncStep SyncProgress(SyncJob *job);
void SyncEnd(SyncJob *job);

#endif

#endif
