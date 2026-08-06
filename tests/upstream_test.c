#include "upstream.h"

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

#define NOW 1000000u

static bool PoolOf(UpstreamPool *pool, size_t count)
{
    static const char *const addrs[] = { "127.0.0.1", "127.0.0.2",
                                         "127.0.0.3", "127.0.0.4" };

    UpstreamPoolInit(pool, NOW);

    for(size_t i = 0; i < count; i++)
    {
        if(!UpstreamPoolAdd(pool, addrs[i], 53))
            return false;
    }

    return pool->count == count;
}

static void TestOrderDecidesUntilSomethingIsMeasured(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 3));
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 0);

    /* A measurement on the third alone is still the fastest known one. */
    UpstreamPoolSample(&pool, 2, 40);
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 2);
}

static void TestLowestRoundTripIsSelected(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 3));

    UpstreamPoolSample(&pool, 0, 90);
    UpstreamPoolSample(&pool, 1, 20);
    UpstreamPoolSample(&pool, 2, 55);
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 1);

    /* Sustained, because one fast answer is smoothed rather than believed. */
    for(int i = 0; i < 40; i++)
        UpstreamPoolSample(&pool, 2, 5);

    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 2);
}

/* Selection follows a sustained change, not one slow answer, or a momentary
   spike moves every query to another resolver and back again. */
static void TestOneSpikeDoesNotMoveSelection(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));

    UpstreamPoolSample(&pool, 0, 20);
    UpstreamPoolSample(&pool, 1, 40);

    UpstreamPoolSample(&pool, 0, 100);
    CHECK(pool.members[0].srttMs > 20);
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 0);

    for(int i = 0; i < 40; i++)
        UpstreamPoolSample(&pool, 0, 100);

    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 1);
}

static void TestFailureRunTakesAnUpstreamOutOfService(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));
    UpstreamPoolSample(&pool, 0, 10);
    UpstreamPoolSample(&pool, 1, 90);

    for(int i = 0; i < CFG_UPSTREAM_DOWN_FAILURES - 1; i++)
        UpstreamPoolFail(&pool, 0, NOW);

    /* Still the fastest, and still in service, so nothing has moved yet. */
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 0);

    UpstreamPoolFail(&pool, 0, NOW);
    CHECK(pool.members[0].bDown);
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 1);
}

static void TestTheHoldExpires(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));
    UpstreamPoolSample(&pool, 0, 10);
    UpstreamPoolSample(&pool, 1, 90);

    for(int i = 0; i < CFG_UPSTREAM_DOWN_FAILURES; i++)
        UpstreamPoolFail(&pool, 0, NOW);

    CHECK(UpstreamPoolSelect(&pool, NOW + CFG_UPSTREAM_DOWN_MS - 1,
                             UPSTREAM_NONE) == 1);
    CHECK(UpstreamPoolSelect(&pool, NOW + CFG_UPSTREAM_DOWN_MS,
                             UPSTREAM_NONE) == 0);
}

static void TestAnAnswerClearsTheFailureRun(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));

    for(int i = 0; i < CFG_UPSTREAM_DOWN_FAILURES - 1; i++)
        UpstreamPoolFail(&pool, 0, NOW);

    UpstreamPoolSample(&pool, 0, 10);
    CHECK(pool.members[0].consecutiveFailures == 0);

    /* The run restarts from zero, so the next single failure holds nothing. */
    UpstreamPoolFail(&pool, 0, NOW);
    CHECK(!pool.members[0].bDown);
}

/* A resolver that fails closed takes the network down, so a pool with every
   member held down still names one. */
static void TestEveryUpstreamDownStillForwards(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));
    UpstreamPoolSample(&pool, 0, 90);
    UpstreamPoolSample(&pool, 1, 10);

    for(int i = 0; i < CFG_UPSTREAM_DOWN_FAILURES; i++)
    {
        UpstreamPoolFail(&pool, 0, NOW);
        UpstreamPoolFail(&pool, 1, NOW);
    }

    CHECK(pool.members[0].bDown && pool.members[1].bDown);
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 1);
}

static void TestRetryMovesToAnotherUpstream(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 3));
    UpstreamPoolSample(&pool, 0, 10);
    UpstreamPoolSample(&pool, 1, 20);
    UpstreamPoolSample(&pool, 2, 30);

    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == 0);
    CHECK(UpstreamPoolSelect(&pool, NOW, 0) == 1);
    CHECK(UpstreamPoolSelect(&pool, NOW, 1) == 0);
}

/* One upstream and a retry: there is nowhere else to go and refusing to send
   would fail the query that a resend might still answer. */
static void TestAvoidCannotEmptyASinglePool(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 1));
    CHECK(UpstreamPoolSelect(&pool, NOW, 0) == 0);
}

static void TestAnEmptyPoolSelectsNothing(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 0));
    CHECK(UpstreamPoolSelect(&pool, NOW, UPSTREAM_NONE) == UPSTREAM_NONE);
}

static void TestAddRefusesWhatIsNotAnAddress(void)
{
    UpstreamPool pool;

    UpstreamPoolInit(&pool, NOW);
    CHECK(!UpstreamPoolAdd(&pool, "one.one.one.one", 53));
    CHECK(pool.count == 0);

    CHECK(UpstreamPoolAdd(&pool, "2606:4700:4700::1111", 53));
    CHECK(pool.count == 1);

    for(size_t i = 0; i < CFG_MAX_UPSTREAMS; i++)
        UpstreamPoolAdd(&pool, "127.0.0.1", 53);

    CHECK(pool.count == CFG_MAX_UPSTREAMS);
}

/* Clears an open probe without counting it against its target, which is what
   a sweep would do. */
static void ProbeForget(UpstreamPool *pool)
{
    UpstreamEnd(&pool->probe);
    pool->bProbing = false;
}

static void TestProbeSkipsTheSelectedUpstreamAndRotates(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 3));
    UpstreamPoolSample(&pool, 0, 10);
    UpstreamPoolSample(&pool, 1, 20);
    UpstreamPoolSample(&pool, 2, 30);

    uint32_t at   = NOW + CFG_UPSTREAM_PROBE_MS;
    bool     bHit[3] = { false, false, false };

    for(int round = 0; round < 4; round++)
    {
        CHECK(UpstreamPoolProbeBegin(&pool, at));
        CHECK(pool.probe.index != 0);
        bHit[pool.probe.index] = true;
        ProbeForget(&pool);
        at += CFG_UPSTREAM_PROBE_MS;
    }

    /* Both unselected upstreams get measured, so neither can sit at an old
       reading and never be reconsidered. */
    CHECK(!bHit[0]);
    CHECK(bHit[1] && bHit[2]);
}

static void TestProbeWaitsForItsInterval(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));
    CHECK(!UpstreamPoolProbeDue(&pool, NOW + CFG_UPSTREAM_PROBE_MS - 1));
    CHECK(UpstreamPoolProbeDue(&pool, NOW + CFG_UPSTREAM_PROBE_MS));

    CHECK(UpstreamPoolProbeBegin(&pool, NOW + CFG_UPSTREAM_PROBE_MS));
    ProbeForget(&pool);

    CHECK(!UpstreamPoolProbeDue(&pool, NOW + CFG_UPSTREAM_PROBE_MS + 1));
}

/* Nothing to compare against, so a probe would be traffic that buys no
   ranking. */
static void TestASingleUpstreamIsNeverProbed(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 1));
    CHECK(!UpstreamPoolProbeDue(&pool, NOW + CFG_UPSTREAM_PROBE_MS));
    CHECK(!UpstreamPoolProbeBegin(&pool, NOW + CFG_UPSTREAM_PROBE_MS));
}

static void TestUnansweredProbeCountsAgainstItsTarget(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));
    UpstreamPoolSample(&pool, 0, 10);

    uint32_t at = NOW + CFG_UPSTREAM_PROBE_MS;

    for(int i = 0; i < CFG_UPSTREAM_DOWN_FAILURES; i++)
    {
        CHECK(UpstreamPoolProbeBegin(&pool, at));
        CHECK(pool.probe.index == 1);

        UpstreamPoolProbeSweep(&pool, at + CFG_UPSTREAM_TIMEOUT_MS);
        CHECK(!pool.bProbing);
        at += CFG_UPSTREAM_PROBE_MS;
    }

    CHECK(pool.probeFailures == CFG_UPSTREAM_DOWN_FAILURES);
    CHECK(pool.members[1].bDown);
}

static void TestProbeSurvivesItsDeadlineUntilItPasses(void)
{
    UpstreamPool pool;

    CHECK(PoolOf(&pool, 2));
    CHECK(UpstreamPoolProbeBegin(&pool, NOW + CFG_UPSTREAM_PROBE_MS));

    UpstreamPoolProbeSweep(&pool, NOW + CFG_UPSTREAM_PROBE_MS
                                  + CFG_UPSTREAM_TIMEOUT_MS - 1);
    CHECK(pool.bProbing);
    CHECK(pool.probeFailures == 0);

    ProbeForget(&pool);
}

int main(void)
{
    TestOrderDecidesUntilSomethingIsMeasured();
    TestLowestRoundTripIsSelected();
    TestOneSpikeDoesNotMoveSelection();
    TestFailureRunTakesAnUpstreamOutOfService();
    TestTheHoldExpires();
    TestAnAnswerClearsTheFailureRun();
    TestEveryUpstreamDownStillForwards();
    TestRetryMovesToAnotherUpstream();
    TestAvoidCannotEmptyASinglePool();
    TestAnEmptyPoolSelectsNothing();
    TestAddRefusesWhatIsNotAnAddress();
    TestProbeSkipsTheSelectedUpstreamAndRotates();
    TestProbeWaitsForItsInterval();
    TestASingleUpstreamIsNeverProbed();
    TestUnansweredProbeCountsAgainstItsTarget();
    TestProbeSurvivesItsDeadlineUntilItPasses();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("upstream: all checks passed\n");
    return 0;
}
