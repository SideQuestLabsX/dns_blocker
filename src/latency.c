#include "latency.h"

#include <string.h>

/* Below the linear region every value is its own bucket. Above it a value maps
   to its octave and to one of four slots inside that octave. */
#define LATENCY_LINEAR 8u
#define LATENCY_SUBS   4u

static unsigned Octave(uint32_t value)
{
    return 31u - (unsigned)__builtin_clz(value);
}

static unsigned BucketOf(uint32_t microseconds)
{
    if(microseconds < LATENCY_LINEAR)
        return microseconds;

    unsigned e   = Octave(microseconds);
    unsigned sub = (microseconds >> (e - 2u)) & 3u;
    unsigned b   = LATENCY_LINEAR + (e - 3u) * LATENCY_SUBS + sub;

    return (b < LATENCY_BUCKETS) ? b : LATENCY_BUCKETS - 1u;
}

bool LatencyBucketRange(unsigned index, uint32_t *low, uint32_t *high)
{
    if(index >= LATENCY_BUCKETS || low == NULL || high == NULL)
        return false;

    if(index < LATENCY_LINEAR)
    {
        *low  = index;
        *high = index;
        return true;
    }

    unsigned offset = index - LATENCY_LINEAR;
    unsigned e      = 3u + offset / LATENCY_SUBS;
    unsigned sub    = offset % LATENCY_SUBS;
    unsigned shift  = e - 2u;

    *low  = (uint32_t)((LATENCY_SUBS + sub) << shift);
    *high = *low + (uint32_t)((1u << shift) - 1u);
    return true;
}

void LatencyReset(LatencyHist *hist)
{
    if(hist == NULL)
        return;

    memset(hist, 0, sizeof *hist);
    hist->minUs = UINT32_MAX;
}

void LatencyAdd(LatencyHist *hist, uint32_t microseconds)
{
    if(hist == NULL)
        return;

    /* Owning structs are often zero-initialized without LatencyReset */
    if(hist->count == 0)
        hist->minUs = UINT32_MAX;

    hist->buckets[BucketOf(microseconds)]++;
    hist->count++;
    hist->sumUs += microseconds;

    if(microseconds < hist->minUs)
        hist->minUs = microseconds;
    if(microseconds > hist->maxUs)
        hist->maxUs = microseconds;
}

uint32_t LatencyMean(const LatencyHist *hist)
{
    if(hist == NULL || hist->count == 0)
        return 0;

    return (uint32_t)(hist->sumUs / hist->count);
}

uint32_t LatencyPercentile(const LatencyHist *hist, unsigned permille)
{
    if(hist == NULL || hist->count == 0)
        return 0;

    /* Keep observed endpoints exact */
    if(permille == 0)
        return hist->minUs;
    if(permille >= 1000u)
        return hist->maxUs;

    uint64_t target = (hist->count * permille + 999u) / 1000u;
    if(target == 0)
        target = 1;

    uint64_t seen = 0;
    for(unsigned i = 0; i < LATENCY_BUCKETS; i++)
    {
        seen += hist->buckets[i];
        if(seen < target)
            continue;

        uint32_t low  = 0;
        uint32_t high = 0;
        if(!LatencyBucketRange(i, &low, &high))
            break;

        /* Keep the bucket midpoint within observed endpoints */
        uint32_t value = low + (high - low) / 2u;
        if(value < hist->minUs)
            value = hist->minUs;
        if(value > hist->maxUs)
            value = hist->maxUs;
        return value;
    }

    return hist->maxUs;
}
