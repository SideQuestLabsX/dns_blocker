#define _POSIX_C_SOURCE 200809L

#include "sync.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>   /* rename(2) */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char G_SUFFIX[] = ".new";

#define SYNC_HASH_CHUNK_BYTES (64u * 1024u)

_Static_assert(CFG_SYNC_RELEASE_TAG_BYTES + 1 <= CFG_SYNC_DIGEST_BYTES,
               "locator body exceeds its buffer");

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

static bool IsDigit(uint8_t value)
{
    return value >= '0' && value <= '9';
}

bool SyncTierIsValid(const char *tier)
{
    if(tier == NULL)
        return false;

    size_t len = strnlen(tier, CFG_BLOCKLIST_TIER_BYTES);
    if(len == 0 || len == CFG_BLOCKLIST_TIER_BYTES)
        return false;

    /* Reject names the release script cannot produce */
    if(tier[0] == '-' || tier[len - 1] == '-')
        return false;

    for(size_t i = 0; i < len; i++)
    {
        uint8_t c = (uint8_t)tier[i];
        bool bAllowed = (c >= 'a' && c <= 'z') || IsDigit(c) || c == '-';

        if(!bAllowed || (c == '-' && tier[i + 1] == '-'))
            return false;
    }

    return true;
}

const char *SyncLoadTier(const char *path, char *out, size_t cap)
{
    if(path == NULL || out == NULL || cap == 0)
        return CFG_BLOCKLIST_TIER;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return CFG_BLOCKLIST_TIER;

    char    buf[CFG_BLOCKLIST_TIER_BYTES];
    ssize_t got = read(fd, buf, sizeof buf);
    close(fd);

    if(got <= 0)
        return CFG_BLOCKLIST_TIER;

    /* Refuse truncation into another valid tier */
    if((size_t)got == sizeof buf)
    {
        fprintf(stderr, "sync: %s is too long for a tier name, using %s\n",
                path, CFG_BLOCKLIST_TIER);
        return CFG_BLOCKLIST_TIER;
    }

    size_t len = (size_t)got;
    while(len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        len--;
    buf[len] = '\0';

    if(!SyncTierIsValid(buf) || len + 1 > cap)
    {
        fprintf(stderr, "sync: %s does not name a tier, using %s\n",
                path, CFG_BLOCKLIST_TIER);
        return CFG_BLOCKLIST_TIER;
    }

    memcpy(out, buf, len + 1);
    return out;
}

bool SyncBuildAssetName(char *out, size_t cap, const char *tier)
{
    static const char prefix[] = "dns_blocker-blocklist-";
    static const char suffix[] = ".trie";

    if(out == NULL || cap == 0)
        return false;
    out[0] = '\0';

    if(!SyncTierIsValid(tier))
        return false;

    size_t tierLen = strnlen(tier, CFG_BLOCKLIST_TIER_BYTES);
    size_t need    = sizeof prefix - 1 + tierLen + sizeof suffix;
    if(need > cap)
        return false;

    memcpy(out, prefix, sizeof prefix - 1);
    memcpy(out + sizeof prefix - 1, tier, tierLen);
    memcpy(out + sizeof prefix - 1 + tierLen, suffix, sizeof suffix);
    return true;
}

static bool DecimalFieldIsValid(const uint8_t *data, size_t begin, size_t end)
{
    if(begin == end || data[begin] == '0')
        return false;

    for(size_t i = begin; i < end; i++)
    {
        if(!IsDigit(data[i]))
            return false;
    }

    return true;
}

static bool LocatorTagIsValid(const uint8_t *data, size_t len)
{
    static const char prefix[] = "blocklist-";
    if(data == NULL || len < 24 || memcmp(data, prefix, sizeof prefix - 1) != 0)
        return false;

    for(size_t i = 10; i < 14; i++)
    {
        if(!IsDigit(data[i]))
            return false;
    }

    if(data[14] != '-' || !IsDigit(data[15]) || !IsDigit(data[16])
       || data[17] != '-' || !IsDigit(data[18]) || !IsDigit(data[19])
       || data[20] != '-')
        return false;

    unsigned year = (unsigned)(data[10] - '0') * 1000u
                  + (unsigned)(data[11] - '0') * 100u
                  + (unsigned)(data[12] - '0') * 10u
                  + (unsigned)(data[13] - '0');
    unsigned month = (unsigned)(data[15] - '0') * 10u
                   + (unsigned)(data[16] - '0');
    unsigned day = (unsigned)(data[18] - '0') * 10u
                 + (unsigned)(data[19] - '0');
    static const uint8_t days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };

    if(year == 0 || month == 0 || month > 12)
        return false;

    unsigned maxDay = days[month - 1];
    bool bLeap = (year % 4u == 0 && year % 100u != 0) || year % 400u == 0;
    if(month == 2 && bLeap)
        maxDay++;
    if(day == 0 || day > maxDay)
        return false;

    size_t separator = 21;
    while(separator < len && IsDigit(data[separator]))
        separator++;

    if(separator >= len || data[separator] != '-'
       || !DecimalFieldIsValid(data, 21, separator)
       || !DecimalFieldIsValid(data, separator + 1, len))
        return false;

    return true;
}

bool SyncParseLocator(const uint8_t *data, size_t len, char *releaseTag,
                      size_t releaseTagCap)
{
    if(releaseTag == NULL || releaseTagCap == 0)
        return false;
    releaseTag[0] = '\0';

    if(data == NULL || len == 0)
        return false;

    size_t tagLen = len;
    if(data[tagLen - 1] == '\n')
    {
        tagLen--;
        if(tagLen > 0 && data[tagLen - 1] == '\r')
            tagLen--;
    }

    if(tagLen + 1 > releaseTagCap || !LocatorTagIsValid(data, tagLen))
        return false;

    memcpy(releaseTag, data, tagLen);
    releaseTag[tagLen] = '\0';
    return true;
}

bool SyncBuildReleaseUrl(char *out, size_t cap, const char *releaseTag,
                         const char *asset)
{
    if(out == NULL || cap == 0)
        return false;
    out[0] = '\0';

    if(releaseTag == NULL || asset == NULL)
        return false;

    size_t tagLen = strnlen(releaseTag, CFG_SYNC_RELEASE_TAG_BYTES);
    size_t assetLen = strnlen(asset, CFG_FETCH_URL_BYTES);
    size_t baseLen = sizeof CFG_BLOCKLIST_RELEASE_BASE_URL - 1;
    if(tagLen == CFG_SYNC_RELEASE_TAG_BYTES || assetLen == 0
       || assetLen == CFG_FETCH_URL_BYTES
       || !LocatorTagIsValid((const uint8_t *)releaseTag, tagLen)
       || baseLen + tagLen + 1 + assetLen + 1 > cap)
        return false;

    memcpy(out, CFG_BLOCKLIST_RELEASE_BASE_URL, baseLen);
    memcpy(out + baseLen, releaseTag, tagLen);
    out[baseLen + tagLen] = '/';
    memcpy(out + baseLen + tagLen + 1, asset, assetLen);
    out[baseLen + tagLen + 1 + assetLen] = '\0';
    return true;
}

#if defined(PROFILE_ENCRYPTED)

_Static_assert(sizeof CFG_BLOCKLIST_ASSET <= CFG_BLOCKLIST_ASSET_BYTES,
               "the compiled tier does not fit the asset buffer");
_Static_assert(sizeof CFG_BLOCKLIST_RELEASE_BASE_URL
               + CFG_SYNC_RELEASE_TAG_BYTES + CFG_BLOCKLIST_ASSET_BYTES
               <= CFG_FETCH_URL_BYTES,
               "blocklist release URL exceeds the fetch buffer");

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

static bool BuildPhaseUrl(const SyncJob *job, char *out, size_t cap)
{
    if(job->phase == SyncPhase_Locator)
        return CopyString(out, cap, CFG_BLOCKLIST_LOCATOR_URL);

    const char *asset = (job->phase == SyncPhase_Digest)
                      ? CFG_BLOCKLIST_DIGEST_ASSET : job->asset;
    return SyncBuildReleaseUrl(out, cap, job->releaseTag, asset);
}

static bool SetPhaseUrl(SyncJob *job)
{
    char urlText[CFG_FETCH_URL_BYTES];
    FetchUrl url;
    if(!BuildPhaseUrl(job, urlText, sizeof urlText)
       || !FetchParseUrl(urlText, &url))
        return false;

    job->job.url = url;
    return true;
}

bool SyncBegin(SyncJob *job, UpstreamPool *pool, const char *path,
               const char *tier, const Blocklist *active)
{
    if(job == NULL)
        return false;

    /* Before the argument checks, not after. The caller reads job->fail to say
       why a run did not start, so every rejection has to leave a defined job */
    memset(job, 0, sizeof *job);
    job->stagingFd = -1;
    job->tlsSlot   = UPSTREAM_NONE;
    job->phase     = SyncPhase_Locator;

    /* fd 0 is stdin, and a run that ends before FetchBegin dials would close it */
    job->job.fd = -1;

    if(pool == NULL || path == NULL)
        return false;

    job->pool   = pool;
    job->active = active;

    if(!SyncBuildAssetName(job->asset, sizeof job->asset,
                           (tier != NULL) ? tier : CFG_BLOCKLIST_TIER))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Tier;
        return false;
    }

    if(!CopyString(job->path, sizeof job->path, path)
       || !SyncStagingPath(job->staging, sizeof job->staging, job->path))
        return false;

    if(!SetPhaseUrl(job))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Url;
        return false;
    }

    if(!UpstreamPoolAcquireFetchChannel(pool, &job->tlsSlot, &job->channel))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Capacity;
        return false;
    }

    job->state = SyncState_Resolve;
    return true;
}

const char *SyncHost(const SyncJob *job)
{
    return (job != NULL) ? job->job.url.host : NULL;
}

bool SyncProvideAddress(SyncJob *job, const struct sockaddr_storage *addr,
                        socklen_t addrLen, uint32_t nowMs)
{
    if(job == NULL || addr == NULL || job->state != SyncState_Resolve)
        return false;

    bool bStarted;
    if(job->job.fail == FetchFail_Read)
    {
        bStarted = FetchRetry(&job->job, job->pool->tls, addr, addrLen);
    }
    else if(job->bFollowing)
    {
        bStarted = FetchFollow(&job->job, job->pool->tls, addr, addrLen);
    }
    else
    {
        char urlText[CFG_FETCH_URL_BYTES];
        if(!BuildPhaseUrl(job, urlText, sizeof urlText))
        {
            job->state = SyncState_Failed;
            job->fail  = SyncFail_Url;
            return false;
        }

        if(job->phase != SyncPhase_Asset)
        {
            size_t cap = (job->phase == SyncPhase_Locator)
                       ? CFG_SYNC_RELEASE_TAG_BYTES + 1
                       : sizeof job->metadataText;
            bStarted = FetchBeginToMemory(&job->job, job->pool->tls, urlText,
                                          addr, addrLen, job->metadataText,
                                          cap, nowMs, job->channel);
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

            bStarted = FetchBegin(&job->job, job->pool->tls, urlText, addr,
                                  addrLen, job->stagingFd,
                                  CFG_BLOCKLIST_MAX_BYTES, nowMs,
                                  job->channel);
        }
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

static SyncStep StartPhase(SyncJob *job, SyncPhase phase)
{
    /* Each phase resolves its own release URL after the last transfer's redirects */
    FetchEnd(&job->job);
    job->phase       = phase;
    job->bFollowing  = false;
    job->readRetries = 0;
    if(!SetPhaseUrl(job))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Url;
        return SyncStep_Failed;
    }

    job->state = SyncState_Resolve;
    return SyncStep_NeedAddress;
}

static SyncStep FinishLocator(SyncJob *job)
{
    if(!SyncParseLocator(job->metadataText, FetchBodyLength(&job->job),
                         job->releaseTag, sizeof job->releaseTag))
    {
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Locator;
        return SyncStep_Failed;
    }

    return StartPhase(job, SyncPhase_Digest);
}

static SyncStep FinishDigest(SyncJob *job)
{
    if(!FetchFindDigest(job->metadataText, FetchBodyLength(&job->job),
                        job->asset, job->want))
    {
        snprintf(job->failText, sizeof job->failText,
                 "the listing names no %s", job->asset);
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Listing;
        return SyncStep_Failed;
    }

    job->bHaveWant = true;

    if(job->active != NULL
       && job->active->source == BlocklistSource_Mapped
       && job->active->base != NULL && job->active->size != 0)
    {
        FetchEnd(&job->job);
        mbedtls_sha256_init(&job->activeSha);
        if(mbedtls_sha256_starts(&job->activeSha, 0) == 0)
        {
            job->activeAt        = 0;
            job->bActiveShaReady = true;
            job->state           = SyncState_Compare;
            return SyncStep_Again;
        }

        mbedtls_sha256_free(&job->activeSha);
    }

    return StartPhase(job, SyncPhase_Asset);
}

static SyncStep CompareActive(SyncJob *job)
{
    size_t remaining = job->active->size - job->activeAt;
    size_t count = (remaining < SYNC_HASH_CHUNK_BYTES)
                 ? remaining : SYNC_HASH_CHUNK_BYTES;

    if(mbedtls_sha256_update(&job->activeSha,
                             job->active->base + job->activeAt, count) != 0)
    {
        mbedtls_sha256_free(&job->activeSha);
        job->bActiveShaReady = false;
        return StartPhase(job, SyncPhase_Asset);
    }

    job->activeAt += count;
    if(job->activeAt < job->active->size)
        return SyncStep_Again;

    uint8_t active[FETCH_DIGEST_BYTES];
    bool bFinished = mbedtls_sha256_finish(&job->activeSha, active) == 0;
    mbedtls_sha256_free(&job->activeSha);
    job->bActiveShaReady = false;

    if(bFinished && memcmp(active, job->want, sizeof active) == 0)
    {
        job->state = SyncState_Done;
        return SyncStep_Done;
    }

    return StartPhase(job, SyncPhase_Asset);
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

    job->bInstalled = true;
    job->state = SyncState_Done;
    return SyncStep_Done;
}

SyncStep SyncProgress(SyncJob *job, uint32_t nowMs)
{
    if(job == NULL)
        return SyncStep_Failed;

    if(job->state == SyncState_Resolve)
        return SyncStep_NeedAddress;

    if(job->state == SyncState_Done)
        return SyncStep_Done;

    if(job->state == SyncState_Compare)
        return CompareActive(job);

    if(job->state != SyncState_Transfer)
        return SyncStep_Failed;

    FetchStep step = FetchProgress(&job->job, nowMs);

    if(step == FetchStep_Again)
        return SyncStep_Again;

    if(step == FetchStep_Redirect)
    {
        /* FetchFollow needs an address for the host the redirect named, and
           this file does not resolve one */
        job->bFollowing  = true;
        job->readRetries = 0;
        job->state       = SyncState_Resolve;
        return SyncStep_NeedAddress;
    }

    if(step == FetchStep_Failed)
    {
        if(job->job.fail == FetchFail_Read
           && job->readRetries < CFG_FETCH_READ_RETRIES)
        {
            FetchEnd(&job->job);
            job->readRetries++;
            job->state = SyncState_Resolve;
            return SyncStep_NeedAddress;
        }

        if(job->stagingFd >= 0)
        {
            SyncAbandon(job->stagingFd, job->staging);
            job->stagingFd = -1;
        }
        job->state = SyncState_Failed;
        job->fail  = SyncFail_Transfer;
        return SyncStep_Failed;
    }

    switch(job->phase)
    {
        case SyncPhase_Locator: return FinishLocator(job);
        case SyncPhase_Digest:  return FinishDigest(job);
        case SyncPhase_Asset:   return FinishAsset(job);
    }

    return SyncStep_Failed;
}

const char *SyncPhaseText(const SyncJob *job)
{
    if(job == NULL)
        return "no run";

    switch(job->phase)
    {
        case SyncPhase_Locator: return "release locator";
        case SyncPhase_Digest:  return "digest listing";
        case SyncPhase_Asset:   return "trie";
    }

    return "unknown";
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
        case SyncFail_Listing:  return job->failText;
        case SyncFail_Digest:   return "the digest did not match";
        case SyncFail_Install:  return "the install failed";
        case SyncFail_Locator:  return "the locator names no valid release";
        case SyncFail_Url:      return "the release URL is invalid";
        case SyncFail_Tier:     return "the configured tier is not a valid name";
        case SyncFail_Capacity: return "TLS capacity is reserved for client queries";
    }

    return "unknown";
}

bool SyncInstalled(const SyncJob *job)
{
    return job != NULL && job->state == SyncState_Done && job->bInstalled;
}

bool SyncNeedsProgress(const SyncJob *job)
{
    return job != NULL && job->state == SyncState_Compare;
}

void SyncEnd(SyncJob *job)
{
    if(job == NULL)
        return;

    FetchEnd(&job->job);
    job->job.channel = NULL;

    if(job->bActiveShaReady)
    {
        mbedtls_sha256_free(&job->activeSha);
        job->bActiveShaReady = false;
    }

    if(job->pool != NULL && job->tlsSlot != UPSTREAM_NONE)
        UpstreamPoolReleaseFetchChannel(job->pool, job->tlsSlot);

    if(job->stagingFd >= 0)
    {
        SyncAbandon(job->stagingFd, job->staging);
        job->stagingFd = -1;
    }

    job->state   = SyncState_Idle;
    job->pool    = NULL;
    job->channel = NULL;
    job->tlsSlot = UPSTREAM_NONE;
}

#endif
