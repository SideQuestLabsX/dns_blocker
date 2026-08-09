#ifndef DNS_BLOCKER_LATENCY_H
#define DNS_BLOCKER_LATENCY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Fixed microsecond histogram. Values below 8us are exact. Four buckets per
   octave cover the rest of uint32 with at most one-part-in-eight error */
#define LATENCY_BUCKETS 128

typedef struct
{
    uint64_t count;
    uint64_t sumUs;
    uint32_t minUs;
    uint32_t maxUs;
    uint32_t buckets[LATENCY_BUCKETS];
} LatencyHist;

void LatencyReset(LatencyHist *hist);
void LatencyAdd(LatencyHist *hist, uint32_t microseconds);

/* Distribution threshold in permille, zero when empty */
uint32_t LatencyPercentile(const LatencyHist *hist, unsigned permille);

uint32_t LatencyMean(const LatencyHist *hist);

/* Exposed for bucket-boundary tests */
bool LatencyBucketRange(unsigned index, uint32_t *low, uint32_t *high);

#endif
