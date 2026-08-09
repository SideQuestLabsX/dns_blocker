#include "latency.h"

#include <stdio.h>
#include <string.h>

static int G_FAILURES;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if(!(cond))                                                        \
        {                                                                  \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
            G_FAILURES++;                                                  \
        }                                                                  \
    } while(0)

static void TestEmpty(void)
{
    LatencyHist hist;

    LatencyReset(&hist);
    CHECK(hist.count == 0);
    CHECK(LatencyMean(&hist) == 0);
    CHECK(LatencyPercentile(&hist, 500) == 0);
    CHECK(LatencyPercentile(&hist, 990) == 0);

    CHECK(LatencyMean(NULL) == 0);
    CHECK(LatencyPercentile(NULL, 500) == 0);
    LatencyAdd(NULL, 5);
    LatencyReset(NULL);
}

/* Bucket ranges tile uint32 without gaps */
static void TestBucketsTile(void)
{
    uint32_t low      = 0;
    uint32_t high     = 0;
    uint32_t previous = 0;

    CHECK(LatencyBucketRange(0, &low, &high));
    CHECK(low == 0 && high == 0);

    for(unsigned i = 1; i < LATENCY_BUCKETS; i++)
    {
        CHECK(LatencyBucketRange(i, &low, &high));
        CHECK(low == previous + 1);
        CHECK(high >= low);
        previous = high;
    }

    CHECK(!LatencyBucketRange(LATENCY_BUCKETS, &low, &high));
    CHECK(!LatencyBucketRange(0, NULL, &high));
    CHECK(!LatencyBucketRange(0, &low, NULL));

    CHECK(previous == UINT32_MAX);
}

static void TestExactStatistics(void)
{
    LatencyHist hist;

    LatencyReset(&hist);
    for(uint32_t i = 1; i <= 100; i++)
        LatencyAdd(&hist, i * 1000u);

    CHECK(hist.count == 100);
    CHECK(hist.minUs == 1000);
    CHECK(hist.maxUs == 100000);
    CHECK(LatencyMean(&hist) == 50500);
}

/* Owning structs are commonly zero-initialized */
static void TestZeroedIsUsable(void)
{
    LatencyHist hist;

    memset(&hist, 0, sizeof hist);
    LatencyAdd(&hist, 9000);

    CHECK(hist.count == 1);
    CHECK(hist.minUs == 9000);
    CHECK(hist.maxUs == 9000);
}

static void TestPercentilesAreBounded(void)
{
    LatencyHist hist;

    LatencyReset(&hist);
    for(uint32_t i = 0; i < 1000; i++)
        LatencyAdd(&hist, 1000u + i * 100u);

    uint32_t p50 = LatencyPercentile(&hist, 500);
    uint32_t p90 = LatencyPercentile(&hist, 900);
    uint32_t p99 = LatencyPercentile(&hist, 990);

    CHECK(p50 <= p90);
    CHECK(p90 <= p99);
    CHECK(p99 <= hist.maxUs);
    CHECK(p50 >= hist.minUs);

    /* Catch a percentile assigned to an adjacent bucket */
    CHECK(p50 > 45000 && p50 < 60000);
    CHECK(p90 > 85000 && p90 < 105000);

    CHECK(LatencyPercentile(&hist, 0) >= hist.minUs);
    CHECK(LatencyPercentile(&hist, 1000) == hist.maxUs);
    CHECK(LatencyPercentile(&hist, 5000) == hist.maxUs);
}

static void TestOutlierStaysAtTheTop(void)
{
    LatencyHist hist;

    LatencyReset(&hist);
    for(uint32_t i = 0; i < 9999; i++)
        LatencyAdd(&hist, 1000);
    LatencyAdd(&hist, 8000000);

    CHECK(hist.maxUs == 8000000);
    CHECK(LatencyPercentile(&hist, 500) == 1000);
    CHECK(LatencyPercentile(&hist, 990) == 1000);
    CHECK(LatencyPercentile(&hist, 1000) == 8000000);
}

static void TestSaturation(void)
{
    LatencyHist hist;

    LatencyReset(&hist);
    LatencyAdd(&hist, 0);
    LatencyAdd(&hist, UINT32_MAX);

    CHECK(hist.count == 2);
    CHECK(hist.minUs == 0);
    CHECK(hist.maxUs == UINT32_MAX);
    CHECK(LatencyPercentile(&hist, 1000) == UINT32_MAX);
}

int main(void)
{
    TestEmpty();
    TestBucketsTile();
    TestExactStatistics();
    TestZeroedIsUsable();
    TestPercentilesAreBounded();
    TestOutlierStaysAtTheTop();
    TestSaturation();

    if(G_FAILURES != 0)
    {
        printf("latency: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("latency: all checks passed\n");
    return 0;
}
