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
