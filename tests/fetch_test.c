#include "fetch.h"

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

static FetchParse ParseText(const char *text, FetchHeaders *out,
                            size_t *headerEnd)
{
    return FetchParseHeaders((const uint8_t *)text, strlen(text), out,
                             headerEnd);
}

static void TestUrl(void)
{
    FetchUrl url;

    CHECK(FetchParseUrl(CFG_BLOCKLIST_URL, &url));
    CHECK(strcmp(url.host, "github.com") == 0);
    CHECK(url.port == 443);
    CHECK(strncmp(url.path, "/SideQuestLabsX/dns_blocker/releases/", 37) == 0);

    CHECK(FetchParseUrl("https://example.com", &url));
    CHECK(strcmp(url.path, "/") == 0);

    CHECK(FetchParseUrl("https://example.com:8443/x", &url));
    CHECK(url.port == 8443);
    CHECK(strcmp(url.host, "example.com") == 0);

    CHECK(FetchParseUrl("HTTPS://example.com/x", &url));

    CHECK(!FetchParseUrl("http://example.com/x", &url));
    CHECK(!FetchParseUrl("https://", &url));
    CHECK(!FetchParseUrl("https:///path", &url));
    CHECK(!FetchParseUrl("https://user@evil.example/x", &url));
    CHECK(!FetchParseUrl("https://example.com:0/x", &url));
    CHECK(!FetchParseUrl("https://example.com:99999/x", &url));
    CHECK(!FetchParseUrl("https://exa mple.com/x", &url));
    CHECK(!FetchParseUrl("https://example.com/a\rb", &url));
    CHECK(!FetchParseUrl("ftp://example.com/x", &url));
    CHECK(!FetchParseUrl(NULL, &url));

    char oversize[CFG_FETCH_URL_BYTES + 64];
    memset(oversize, 'a', sizeof oversize);
    memcpy(oversize, "https://", 8);
    oversize[sizeof oversize - 1] = '\0';
    CHECK(!FetchParseUrl(oversize, &url));
}

/* The header shapes below are the bytes the live release actually returned:
   two 302 hops with Content-Length: 0, then a 200 with the real length. */
static void TestHeaders(void)
{
    FetchHeaders headers;
    size_t       headerEnd = 0;

    CHECK(ParseText("HTTP/1.1 200 OK\r\n"
                    "Content-Length: 6544992\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Accept-Ranges: bytes\r\n\r\nbody",
                    &headers, &headerEnd) == FetchParse_Ok);
    CHECK(headers.status == 200);
    CHECK(headers.bHasContentLength);
    CHECK(headers.contentLength == 6544992);
    CHECK(headerEnd == strlen("HTTP/1.1 200 OK\r\n"
                              "Content-Length: 6544992\r\n"
                              "Content-Type: application/octet-stream\r\n"
                              "Accept-Ranges: bytes\r\n\r\n"));

    CHECK(ParseText("HTTP/1.1 302 Found\r\n"
                    "Location: https://release-assets.githubusercontent.com/x?sig=a%2Bb\r\n"
                    "Content-Length: 0\r\n\r\n",
                    &headers, &headerEnd) == FetchParse_Ok);
    CHECK(headers.status == 302);
    CHECK(FetchStatusIsRedirect(headers.status));
    CHECK(strcmp(headers.location,
                 "https://release-assets.githubusercontent.com/x?sig=a%2Bb") == 0);

    CHECK(ParseText("HTTP/1.0 204 No Content\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Ok);
    CHECK(headers.status == 204);
    CHECK(!headers.bHasContentLength);

    /* The version token is case-sensitive, unlike field names */
    CHECK(ParseText("http/1.1 200 OK\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);

    CHECK(ParseText("HTTP/1.1 200 OK\r\n"
                    "CONTENT-LENGTH:   12\t\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Ok);
    CHECK(headers.contentLength == 12);

    CHECK(ParseText("HTTP/1.1 404 Not Found\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Ok);
    CHECK(headers.status == 404);
    CHECK(!FetchStatusIsRedirect(404));

    CHECK(ParseText("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n",
                    &headers, &headerEnd) == FetchParse_Incomplete);
    CHECK(ParseText("HTTP/1.1 20", &headers, &headerEnd)
          == FetchParse_Incomplete);
    CHECK(ParseText("", &headers, &headerEnd) == FetchParse_Incomplete);

    CHECK(ParseText("HTTP/1.1 200 OK\r\n"
                    "Content-Length: 5\r\n"
                    "Content-Length: 9\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 200 OK\r\n"
                    "Transfer-Encoding: chunked\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 200 OK\r\n"
                    "Content-Length: 12x\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 200 OK\r\n"
                    "Content-Length: \r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 200 OK\r\n: novalue\r\n\r\n",
                    &headers, &headerEnd) == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 200 OK\r\nNoColonHere\r\n\r\n",
                    &headers, &headerEnd) == FetchParse_Failed);
    CHECK(ParseText("HTTP/2 200 OK\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 99 Bad\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 2000 Bad\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("HTTP/1.1 abc OK\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);
    CHECK(ParseText("garbage\r\n\r\n", &headers, &headerEnd)
          == FetchParse_Failed);

    /* A header block that never ends is refused once it fills the buffer,
       rather than asking for bytes forever */
    static uint8_t flood[CFG_FETCH_HEADER_BYTES + 64];
    memset(flood, 'a', sizeof flood);
    memcpy(flood, "HTTP/1.1 200 OK\r\nX: ", 20);
    CHECK(FetchParseHeaders(flood, sizeof flood, &headers, &headerEnd)
          == FetchParse_Failed);

    char longLocation[CFG_FETCH_URL_BYTES + 128];
    int n = snprintf(longLocation, sizeof longLocation,
                     "HTTP/1.1 302 Found\r\nLocation: https://a.example/");
    memset(longLocation + n, 'p', CFG_FETCH_URL_BYTES);
    memcpy(longLocation + n + CFG_FETCH_URL_BYTES, "\r\n\r\n", 5);
    CHECK(ParseText(longLocation, &headers, &headerEnd) == FetchParse_Failed);
}

/* github.com answers the download URL with a 5191-byte header block: a 949-byte
   signed Location beside a 2KB Content-Security-Policy. The whole block has to
   fit, or every redirect is refused. */
#define GITHUB_REDIRECT_BYTES 5191

static const char G_REDIRECT_PREFIX[] =
    "Location: https://release-assets.githubusercontent.com/asset?sig=";
static const char G_REDIRECT_TAIL[] = "\r\nContent-Length: 0\r\n\r\n";

/* The block is built to a fixed size, so a smaller buffer would be written
   past */
_Static_assert(CFG_FETCH_HEADER_BYTES >= GITHUB_REDIRECT_BYTES,
               "the header buffer must hold a measured github.com redirect");

static void TestLargeRedirectHeader(void)
{
    static char  block[CFG_FETCH_HEADER_BYTES];
    FetchHeaders headers;
    size_t       headerEnd = 0;
    size_t       at        = 0;
    size_t       locationFill = 1300;

    at += (size_t)snprintf(block, sizeof block, "HTTP/1.1 302 Found\r\n%s",
                           G_REDIRECT_PREFIX);
    memset(block + at, 'a', locationFill);
    at += locationFill;

    at += (size_t)snprintf(block + at, sizeof block - at,
                           "\r\nContent-Security-Policy: ");

    CHECK(at + sizeof G_REDIRECT_TAIL < GITHUB_REDIRECT_BYTES);
    size_t policyFill = GITHUB_REDIRECT_BYTES - at - (sizeof G_REDIRECT_TAIL - 1);
    memset(block + at, 'b', policyFill);
    at += policyFill;

    at += (size_t)snprintf(block + at, sizeof block - at, "%s", G_REDIRECT_TAIL);

    CHECK(at == GITHUB_REDIRECT_BYTES);
    CHECK(FetchParseHeaders((const uint8_t *)block, at, &headers, &headerEnd)
          == FetchParse_Ok);
    CHECK(headers.status == 302);
    CHECK(strncmp(headers.location, G_REDIRECT_PREFIX + strlen("Location: "),
                  sizeof G_REDIRECT_PREFIX - 1 - strlen("Location: ")) == 0);
    CHECK(strlen(headers.location)
          == sizeof G_REDIRECT_PREFIX - 1 - strlen("Location: ") + locationFill);
    CHECK(headerEnd == at);
}

/* Exact matching keeps a base from taking a variation's digest */
static const char G_DIGESTS[] =
    "25b93f9c8b855b0e995741207aec6ab979ece317d5bed1327991da54a4382f4c  dns_blocker-blocklist-standard.trie\n"
    "8d4a70100bf861ea3f9dcd701938a183e89c300932ad6ac6b35fa5c8fe4979f9  dns_blocker-blocklist.sources\n"
    "c86452db645ad1c0a6467bde3ac6b4dda539b479186259fa6bfde17523fa771d  dns_blocker-blocklist-sources.tar.gz\n"
    "3f1c0f5f7fd2a1b4e6c8d9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0  dns_blocker-blocklist-standard-nsfw.trie\n"
    "4e2d1e6e8ae3b2c5f7d9eab1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1  dns_blocker-blocklist-aggressive.trie\n"
    "1dffc3ee0dd92d950596eff74d0a112033f0a2f4e90030ef5ac0000f38d8ba38  THIRD_PARTY_LICENSES.md\n";

static void TestDigest(void)
{
    uint8_t digest[FETCH_DIGEST_BYTES];

    CHECK(FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                          CFG_BLOCKLIST_ASSET, digest));
    CHECK(digest[0] == 0x25 && digest[1] == 0xb9 && digest[31] == 0x4c);

    CHECK(FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                          "dns_blocker-blocklist-standard-nsfw.trie", digest));
    CHECK(digest[0] == 0x3f && digest[31] == 0xc0);
    CHECK(FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                          "dns_blocker-blocklist-aggressive.trie", digest));
    CHECK(digest[0] == 0x4e && digest[31] == 0xd1);

    CHECK(FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                          "THIRD_PARTY_LICENSES.md", digest));
    CHECK(digest[0] == 0x1d && digest[31] == 0x38);

    /* A prefix of a real name must not match the longer line */
    CHECK(!FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                           "dns_blocker-blocklist", digest));
    CHECK(!FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                           "dns_blocker-blocklist.trie.sha256", digest));
    CHECK(!FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                           "absent.txt", digest));
    CHECK(!FetchFindDigest((const uint8_t *)G_DIGESTS, strlen(G_DIGESTS),
                           "", digest));

    static const char crlf[] =
        "25b93f9c8b855b0e995741207aec6ab979ece317d5bed1327991da54a4382f4c  a.trie\r\n";
    CHECK(FetchFindDigest((const uint8_t *)crlf, strlen(crlf), "a.trie",
                          digest));

    static const char binaryMode[] =
        "25b93f9c8b855b0e995741207aec6ab979ece317d5bed1327991da54a4382f4c *a.trie\n";
    CHECK(FetchFindDigest((const uint8_t *)binaryMode, strlen(binaryMode),
                          "a.trie", digest));

    static const char noTrailingNewline[] =
        "25b93f9c8b855b0e995741207aec6ab979ece317d5bed1327991da54a4382f4c  a.trie";
    CHECK(FetchFindDigest((const uint8_t *)noTrailingNewline,
                          strlen(noTrailingNewline), "a.trie", digest));

    static const char nonHex[] =
        "zzb93f9c8b855b0e995741207aec6ab979ece317d5bed1327991da54a4382f4c  a.trie\n";
    CHECK(!FetchFindDigest((const uint8_t *)nonHex, strlen(nonHex), "a.trie",
                           digest));

    static const char tooShort[] =
        "25b93f9c  a.trie\n";
    CHECK(!FetchFindDigest((const uint8_t *)tooShort, strlen(tooShort),
                           "a.trie", digest));

    static const char oneSpace[] =
        "25b93f9c8b855b0e995741207aec6ab979ece317d5bed1327991da54a4382f4c a.trie\n";
    CHECK(!FetchFindDigest((const uint8_t *)oneSpace, strlen(oneSpace),
                           "a.trie", digest));

    CHECK(!FetchFindDigest((const uint8_t *)"", 0, "a.trie", digest));
}

int main(void)
{
    TestUrl();
    TestHeaders();
    TestLargeRedirectHeader();
    TestDigest();

    if(G_FAILURES != 0)
    {
        printf("fetch: %d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("fetch: all checks passed\n");
    return 0;
}
