#define _POSIX_C_SOURCE 200809L

#include "sync.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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
            return false;
        }

        bStarted = FetchBegin(&job->job, job->backend, PhaseUrl(job), addr,
                              addrLen, job->stagingFd,
                              CFG_BLOCKLIST_MAX_BYTES);
    }

    if(!bStarted)
    {
        job->state = SyncState_Failed;
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

static SyncStep FinishDigest(SyncJob *job)
{
    if(!FetchFindDigest(job->digestText, FetchBodyLength(&job->job),
                        CFG_BLOCKLIST_ASSET, job->want))
    {
        fprintf(stderr, "sync: the listing names no %s, refusing\n",
                CFG_BLOCKLIST_ASSET);
        job->state = SyncState_Failed;
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
        return SyncStep_Failed;
    }

    SyncInstall result = SyncCommit(job->stagingFd, job->staging, job->path,
                                    got, job->want);
    job->stagingFd = -1;

    if(result != SyncInstall_Ok)
    {
        if(result == SyncInstall_Mismatch)
            fprintf(stderr, "sync: digest mismatch, keeping the current list\n");
        job->state = SyncState_Failed;
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
        return SyncStep_Failed;
    }

    return (job->phase == SyncPhase_Digest) ? FinishDigest(job)
                                            : FinishAsset(job);
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
