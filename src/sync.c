#define _POSIX_C_SOURCE 200809L

#include "sync.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>   /* rename(2) */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char G_SUFFIX[] = ".new";

bool SyncStagingPath(char *out, size_t cap, const char *path)
{
    if(out == NULL || path == NULL || cap == 0)
        return false;

    size_t len = 0;
    while(path[len] != '\0')
    {
        if(len >= cap)
            return false;
        len++;
    }

    if(len == 0 || len + sizeof G_SUFFIX > cap)
        return false;

    memcpy(out, path, len);
    memcpy(out + len, G_SUFFIX, sizeof G_SUFFIX);
    return true;
}

bool SyncPrepareDirectory(const char *path)
{
    if(path == NULL)
        return false;

    size_t cut = 0;
    for(size_t i = 0; path[i] != '\0'; i++)
    {
        if(path[i] == '/')
            cut = i;
    }

    /* A bare filename or a file at the root has no directory to make */
    if(cut == 0)
        return true;

    char dir[CFG_SYNC_PATH_BYTES];
    if(cut >= sizeof dir)
        return false;

    memcpy(dir, path, cut);
    dir[cut] = '\0';

    if(mkdir(dir, 0750) == 0)
        return true;

    return errno == EEXIST;
}

int SyncOpenStaging(const char *stagingPath)
{
    if(stagingPath == NULL)
        return -1;

    return open(stagingPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
}

void SyncAbandon(int stagingFd, const char *stagingPath)
{
    if(stagingFd >= 0)
        close(stagingFd);

    if(stagingPath != NULL)
        (void)unlink(stagingPath);
}

SyncInstall SyncCommit(int stagingFd, const char *stagingPath,
                       const char *path,
                       const uint8_t got[FETCH_DIGEST_BYTES],
                       const uint8_t want[FETCH_DIGEST_BYTES])
{
    if(stagingPath == NULL || path == NULL || got == NULL || want == NULL)
    {
        SyncAbandon(stagingFd, stagingPath);
        return SyncInstall_Failed;
    }

    if(memcmp(got, want, FETCH_DIGEST_BYTES) != 0)
    {
        SyncAbandon(stagingFd, stagingPath);
        return SyncInstall_Mismatch;
    }

    /* The rename can outrun the data to disk, which on a power cut leaves the
       target naming a file whose blocks were never written */
    if(stagingFd < 0 || fsync(stagingFd) != 0)
    {
        SyncAbandon(stagingFd, stagingPath);
        return SyncInstall_Failed;
    }

    if(close(stagingFd) != 0)
    {
        (void)unlink(stagingPath);
        return SyncInstall_Failed;
    }

    if(rename(stagingPath, path) != 0)
    {
        (void)unlink(stagingPath);
        return SyncInstall_Failed;
    }

    return SyncInstall_Ok;
}

#if defined(PROFILE_ENCRYPTED)

static bool CopyString(char *out, size_t cap, const char *text)
{
    size_t len = 0;
    while(text[len] != '\0')
    {
        if(len + 1 >= cap)
            return false;
        len++;
    }

    memcpy(out, text, len + 1);
    return true;
}

bool SyncBegin(SyncJob *job, TlsBackend *backend, const char *path)
{
    if(job == NULL || backend == NULL || path == NULL)
        return false;

    memset(job, 0, sizeof *job);
    job->backend   = backend;
    job->stagingFd = -1;
    job->phase     = SyncPhase_Digest;

    if(!CopyString(job->path, sizeof job->path, path)
       || !SyncStagingPath(job->staging, sizeof job->staging, job->path))
        return false;

    /* The URL is parsed now so a bad one fails at the call rather than after a
       resolution has already been spent on it */
    FetchUrl url;
    if(!FetchParseUrl(CFG_BLOCKLIST_DIGEST_URL, &url))
        return false;

    job->job.url = url;
    job->state   = SyncState_Resolve;
    return true;
}

const char *SyncHost(const SyncJob *job)
{
    return (job != NULL) ? job->job.url.host : NULL;
}

static const char *PhaseUrl(const SyncJob *job)
{
    return (job->phase == SyncPhase_Digest)
         ? CFG_BLOCKLIST_DIGEST_URL : CFG_BLOCKLIST_URL;
}

bool SyncProvideAddress(SyncJob *job, const struct sockaddr_storage *addr,
                        socklen_t addrLen)
{
    if(job == NULL || addr == NULL || job->state != SyncState_Resolve)
        return false;

    bool bStarted;
    if(job->bFollowing)
    {
        bStarted = FetchFollow(&job->job, job->backend, addr, addrLen);
    }
    else if(job->phase == SyncPhase_Digest)
    {
        bStarted = FetchBeginToMemory(&job->job, job->backend, PhaseUrl(job),
                                      addr, addrLen, job->digestText,
                                      sizeof job->digestText);
    }
    else
    {
        job->stagingFd = SyncOpenStaging(job->staging);
        if(job->stagingFd < 0)
        {
            job->state = SyncState_Failed;
            job->fail  = SyncFail_Staging;
            return false;
        }

        bStarted = FetchBegin(&job->job, job->backend, PhaseUrl(job), addr,
                              addrLen, job->stagingFd,
                              CFG_BLOCKLIST_MAX_BYTES);
    }

    if(!bStarted)
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Transfer;
        return false;
    }

    job->state = SyncState_Transfer;
    return true;
}

short SyncEvents(const SyncJob *job)
{
    if(job == NULL || job->state != SyncState_Transfer)
        return 0;

    return FetchEvents(&job->job);
}

int SyncFd(const SyncJob *job)
{
    if(job == NULL || job->state != SyncState_Transfer)
        return -1;

    return job->job.fd;
}

static SyncStep FinishDigest(SyncJob *job)
{
    if(!FetchFindDigest(job->digestText, FetchBodyLength(&job->job),
                        CFG_BLOCKLIST_ASSET, job->want))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Listing;
        return SyncStep_Failed;
    }

    job->bHaveWant  = true;
    job->phase      = SyncPhase_Asset;
    job->bFollowing = false;
    FetchEnd(&job->job);

    /* The asset lives on the same host as the listing, but it is resolved
       again rather than assumed, because a redirect moved the last one */
    FetchUrl url;
    if(!FetchParseUrl(CFG_BLOCKLIST_URL, &url))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Transfer;
        return SyncStep_Failed;
    }

    job->job.url = url;
    job->state   = SyncState_Resolve;
    return SyncStep_NeedAddress;
}

static SyncStep FinishAsset(SyncJob *job)
{
    uint8_t got[FETCH_DIGEST_BYTES];

    if(!FetchDigest(&job->job, got) || !job->bHaveWant)
    {
        SyncAbandon(job->stagingFd, job->staging);
        job->stagingFd = -1;
        job->state     = SyncState_Failed;
        job->fail      = SyncFail_Digest;
        return SyncStep_Failed;
    }

    SyncInstall result = SyncCommit(job->stagingFd, job->staging, job->path,
                                    got, job->want);
    job->stagingFd = -1;

    if(result != SyncInstall_Ok)
    {
        job->state = SyncState_Failed;
        job->fail  = (result == SyncInstall_Mismatch) ? SyncFail_Digest
                                                      : SyncFail_Install;
        return SyncStep_Failed;
    }

    job->state = SyncState_Done;
    return SyncStep_Done;
}

SyncStep SyncProgress(SyncJob *job)
{
    if(job == NULL)
        return SyncStep_Failed;

    if(job->state == SyncState_Resolve)
        return SyncStep_NeedAddress;

    if(job->state == SyncState_Done)
        return SyncStep_Done;

    if(job->state != SyncState_Transfer)
        return SyncStep_Failed;

    FetchStep step = FetchProgress(&job->job);

    if(step == FetchStep_Again)
        return SyncStep_Again;

    if(step == FetchStep_Redirect)
    {
        /* FetchFollow needs an address for the host the redirect named, and
           this file does not resolve one */
        job->bFollowing = true;
        job->state      = SyncState_Resolve;
        return SyncStep_NeedAddress;
    }

    if(step == FetchStep_Failed)
    {
        if(job->stagingFd >= 0)
        {
            SyncAbandon(job->stagingFd, job->staging);
            job->stagingFd = -1;
        }
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Transfer;
        return SyncStep_Failed;
    }

    return (job->phase == SyncPhase_Digest) ? FinishDigest(job)
                                            : FinishAsset(job);
}

const char *SyncPhaseText(const SyncJob *job)
{
    if(job == NULL)
        return "no run";

    return (job->phase == SyncPhase_Digest) ? "digest listing" : "trie";
}

const char *SyncFailText(const SyncJob *job)
{
    if(job == NULL)
        return "no run";

    switch(job->fail)
    {
        case SyncFail_None:     return "no failure";
        case SyncFail_Transfer: return FetchFailText(&job->job);
        case SyncFail_Staging:  return "the staging file could not be opened";
        case SyncFail_Listing:  return "the listing names no " CFG_BLOCKLIST_ASSET;
        case SyncFail_Digest:   return "the digest did not match";
        case SyncFail_Install:  return "the install failed";
    }

    return "unknown";
}

void SyncEnd(SyncJob *job)
{
    if(job == NULL)
        return;

    FetchEnd(&job->job);

    if(job->stagingFd >= 0)
    {
        SyncAbandon(job->stagingFd, job->staging);
        job->stagingFd = -1;
    }

    job->state = SyncState_Idle;
}

#endif
