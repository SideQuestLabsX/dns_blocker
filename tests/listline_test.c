#include "listline.h"

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

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("listline: all checks passed\n");
    return 0;
}
