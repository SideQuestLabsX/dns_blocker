#include "listline.h"
#include "removals.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int G_FAILURES;

/* ListLineName rewrites its argument, so every case gets its own buffer. */
static void Expect(const char *input, const char *want)
{
    char line[1024];

    snprintf(line, sizeof line, "%s", input);

    const char *got = ListLineName(line);

    bool bSame = (got == NULL) ? (want == NULL)
                               : (want != NULL && strcmp(got, want) == 0);

    if(!bSame)
    {
        printf("FAIL  \"%s\" -> %s, want %s\n", input,
               (got != NULL) ? got : "(none)",
               (want != NULL) ? want : "(none)");
        G_FAILURES++;
    }
}

/* The survey counts refusals by reason, so a reason that drifts from the
   refusal it names would misreport what a source offers. */
static void ExpectReason(const char *input, ListLineReason want)
{
    char           line[1024];
    ListLineReason got = ListLine_Name;

    snprintf(line, sizeof line, "%s", input);
    (void)ListLineNameWhy(line, &got);

    if(got != want)
    {
        printf("FAIL  \"%s\" -> %s, want %s\n", input,
               ListLineReasonName(got), ListLineReasonName(want));
        G_FAILURES++;
    }
}

/* The allowlist corrects a false positive in a published list. It must take
   the name it names and leave the subtree alone, because a blocked child of a
   legitimate parent is usually the entry the publisher meant. */
static void Check(bool bOk, const char *what)
{
    if(!bOk)
    {
        printf("FAIL  removals: %s\n", what);
        G_FAILURES++;
    }
}

static void TestRemovals(void)
{
    RemovalSet set = { NULL, 0, 0 };
    FILE      *in  = tmpfile();

    if(in == NULL)
    {
        Check(false, "no temporary file");
        return;
    }

    fputs("# a comment line\n", in);
    fputs("\n", in);
    fputs("example.com   # 2026-01-01, breaks sign-in\n", in);
    fputs("0.0.0.0 hosts-form.example  # a hosts line too\n", in);
    fputs("*.wild.example             # and a wildcard rule\n", in);
    rewind(in);

    size_t skipped = 0;
    bool   bLoaded = RemovalSetLoad(&set, in, &skipped);
    fclose(in);

    Check(bLoaded, "the file loads");
    Check(set.count == 3, "three names load");
    Check(skipped == 2, "the comment and the blank line are skipped");

    /* The removed parent, and its www. form with it */
    Check(RemovalSetHas(&set, "example.com"), "the removed parent goes");
    Check(RemovalSetHas(&set, "www.example.com"), "its www. form goes");

    /* An explicitly blocked child survives, or the allowlist discards true
       positives that happen to share a parent */
    Check(!RemovalSetHas(&set, "ads.example.com"), "a blocked child stays");
    Check(!RemovalSetHas(&set, "a.b.example.com"), "a deeper child stays");

    /* Unrelated names, including one that merely ends the same way */
    Check(!RemovalSetHas(&set, "other.example"), "an unrelated name stays");
    Check(!RemovalSetHas(&set, "notexample.com"), "a similar name stays");
    Check(!RemovalSetHas(&set, "www.other.example"), "www. of a kept name stays");

    /* The other accepted line formats reached the set as bare names */
    Check(RemovalSetHas(&set, "hosts-form.example"), "a hosts line removes");
    Check(RemovalSetHas(&set, "wild.example"), "a wildcard rule removes");
    Check(RemovalSetHas(&set, "www.wild.example"), "and its www. form");

    RemovalSetFree(&set);
    Check(set.count == 0, "the set frees");

    /* An empty allowlist removes nothing, which is the shipped state */
    RemovalSet none = { NULL, 0, 0 };
    Check(!RemovalSetHas(&none, "example.com"), "an empty set removes nothing");
}

int main(void)
{
    Expect("ads.example.com", "ads.example.com");
    Expect("0.0.0.0 ads.example.com", "ads.example.com");
    Expect("127.0.0.1\tads.example.com", "ads.example.com");
    Expect("  ads.example.com  \r\n", "ads.example.com");
    Expect("ADS.Example.COM", "ads.example.com");
    Expect("ads.example.com.", "ads.example.com");

    /* oisd publishes every entry this way, and 56395 of its 56408 lines have
       it. Splitting on the dot instead makes `*` a label, which blocks the
       literal name and nothing else. */
    Expect("*.0-02.net", "0-02.net");
    Expect("*.ads.example.com", "ads.example.com");
    Expect("0.0.0.0 *.ads.example.com", "ads.example.com");
    Expect("*.*.ads.example.com", "ads.example.com");

    Expect("# a comment", NULL);
    Expect("ads.example.com # trailing comment", "ads.example.com");
    Expect("0.0.0.0 ads.example.com # trailing comment", "ads.example.com");
    Expect("", NULL);
    Expect("\n", NULL);
    Expect("localhost", NULL);
    Expect("*", NULL);
    Expect("*.com", NULL);
    Expect(".", NULL);

    /* A wildcard the trie cannot express must not become a label. */
    Expect("ad*.example.com", NULL);
    Expect("*ads.example.com", NULL);

    ExpectReason("ads.example.com", ListLine_Name);
    ExpectReason("*.ads.example.com", ListLine_Name);
    ExpectReason("# a comment", ListLine_Blank);
    ExpectReason("", ListLine_Blank);
    ExpectReason("localhost", ListLine_NoDot);
    /* The strip wants `*.`, so a bare star is a name of one label */
    ExpectReason("*", ListLine_NoDot);
    ExpectReason("*.com", ListLine_NoDot);
    ExpectReason("ad*.example.com", ListLine_Wildcard);
    ExpectReason("*ads.example.com", ListLine_Wildcard);
    ExpectReason("0.0.0.0 ads-*.example.com", ListLine_Wildcard);

    TestRemovals();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("listline: all checks passed\n");
    return 0;
}
