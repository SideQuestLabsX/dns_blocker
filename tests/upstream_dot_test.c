#include "msg.h"
#include "upstream.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static TlsIo   G_HANDSHAKE_RESULT;
static ssize_t G_WRITE_RESULT;
static ssize_t G_READ_RESULT;
static size_t  G_WRITE_CHUNK;
static size_t  G_READ_CHUNK;
static size_t  G_READ_AT;
static size_t  G_READ_LEN;
static int     G_CLOSES;
static uint8_t G_READ_DATA[CFG_DOH_HEADER_BYTES + CFG_TCP_MSG_BYTES];

static void FakeReset(void)
{
    G_HANDSHAKE_RESULT = TlsIo_Ok;
    G_WRITE_RESULT     = 0;
    G_READ_RESULT      = 0;
    G_WRITE_CHUNK      = SIZE_MAX;
    G_READ_CHUNK       = SIZE_MAX;
    G_READ_AT          = 0;
    G_READ_LEN         = 0;
    G_CLOSES           = 0;
}

TlsIo TlsChannelStart(TlsBackend *backend, TlsChannel *channel, int fd,
                      const char *hostname)
{
    (void)backend;
    (void)hostname;
    memset(channel, 0, sizeof *channel);
    channel->fd     = fd;
    channel->want   = TlsIo_WantRead;
    channel->bReady = true;
    return TlsIo_Ok;
}

TlsIo TlsChannelHandshake(TlsChannel *channel)
{
    channel->want = G_HANDSHAKE_RESULT;
    return G_HANDSHAKE_RESULT;
}

ssize_t TlsChannelRead(TlsChannel *channel, uint8_t *out, size_t cap)
{
    if(G_READ_RESULT != 0)
    {
        ssize_t result = G_READ_RESULT;
        G_READ_RESULT = 0;
        channel->want = (TlsIo)result;
        return result;
    }

    if(G_READ_AT >= G_READ_LEN)
        return TlsIo_Closed;

    size_t count = G_READ_LEN - G_READ_AT;
    if(count > cap)
        count = cap;
    if(count > G_READ_CHUNK)
        count = G_READ_CHUNK;

    memcpy(out, G_READ_DATA + G_READ_AT, count);
    G_READ_AT += count;
    channel->want = TlsIo_WantRead;
    return (ssize_t)count;
}

ssize_t TlsChannelWrite(TlsChannel *channel, const uint8_t *data, size_t len)
{
    (void)data;

    if(G_WRITE_RESULT != 0)
    {
        ssize_t result = G_WRITE_RESULT;
        G_WRITE_RESULT = 0;
        channel->want = (TlsIo)result;
        return result;
    }

    size_t count = (len < G_WRITE_CHUNK) ? len : G_WRITE_CHUNK;
    channel->want = TlsIo_WantWrite;
    return (ssize_t)count;
}

short TlsChannelEvents(const TlsChannel *channel)
{
    return (channel->want == TlsIo_WantWrite) ? POLLOUT : POLLIN;
}

void TlsChannelClose(TlsChannel *channel)
{
    if(channel->fd >= 0)
        close(channel->fd);

    channel->fd     = -1;
    channel->bReady = false;
    G_CLOSES++;
}

static void ExchangeOf(UpstreamPool *pool, UpstreamExchange *exchange,
                       DotState state, int fd)
{
    UpstreamPoolInit(pool, NOW);
    CHECK(UpstreamPoolAddDot(pool, "127.0.0.1", 853, "example.com"));

    UpstreamTlsSlot *slot = &pool->tlsSlots[0];
    slot->bUsed        = true;
    slot->state        = state;
    slot->channel.fd   = fd;
    slot->channel.want = TlsIo_WantRead;
    slot->channel.bReady = true;
    slot->query[0] = 0;
    slot->query[1] = WIRE_HEADER_BYTES;
    slot->requestLen = WIRE_HEADER_BYTES + 2;

    memset(exchange, 0, sizeof *exchange);
    exchange->fd        = fd;
    exchange->index     = 0;
    exchange->tlsSlot   = 0;
    exchange->sentMs    = NOW;
    exchange->transport = UpstreamTransport_Dot;
    exchange->pool      = pool;
}

static bool BuildAnswer(UpstreamExchange *exchange, uint8_t *answer,
                        size_t cap, size_t *answerLen)
{
    WireName name;
    uint8_t  query[CFG_TX_QUERY_BYTES];
    size_t   queryLen = 0;
    uint8_t  address[4] = { 192, 0, 2, 1 };

    if(!WireEncodeName("example.com", &name)
       || !MsgBuildQuery(query, sizeof query, &name, WIRE_TYPE_A, 0x1234,
                         &queryLen))
        return false;

    Reader     reader;
    WireHeader header;
    ReaderInit(&reader, query, queryLen);
    if(!WireParseHeader(&reader, &header)
       || !WireParseQuestion(&reader, &exchange->asked))
        return false;

    exchange->id = 0x1234;
    return MsgBuildAnswer(answer, cap, query, queryLen, WIRE_TYPE_A, 60,
                          address, sizeof address, answerLen);
}

static bool Contains(const uint8_t *data, size_t len, const char *text)
{
    size_t textLen = strlen(text);
    if(textLen > len)
        return false;

    for(size_t i = 0; i <= len - textLen; i++)
    {
        if(memcmp(data + i, text, textLen) == 0)
            return true;
    }

    return false;
}

static int OpenListener(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return -1;

    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if(bind(fd, (struct sockaddr *)&address, sizeof address) != 0
       || listen(fd, 1) != 0)
    {
        close(fd);
        return -1;
    }

    socklen_t addressLen = sizeof address;
    if(getsockname(fd, (struct sockaddr *)&address, &addressLen) != 0)
    {
        close(fd);
        return -1;
    }

    *port = ntohs(address.sin_port);
    return fd;
}

static void TestDohRequestContainsDnsMessage(void)
{
    uint16_t port = 0;
    int listener = OpenListener(&port);
    CHECK(listener >= 0);
    if(listener < 0)
        return;

    UpstreamPool     pool;
    UpstreamExchange exchange;
    TlsBackend       backend;
    WireName         name;
    uint8_t          query[CFG_TX_QUERY_BYTES];
    size_t           queryLen = 0;

    memset(&backend, 0, sizeof backend);
    backend.bReady = true;
    UpstreamPoolInit(&pool, NOW);
    UpstreamPoolSetTlsBackend(&pool, &backend);
    CHECK(UpstreamPoolAddDoh(&pool, "127.0.0.1", port, "resolver.example",
                             "/custom-dns"));
    CHECK(WireEncodeName("example.com", &name));
    CHECK(MsgBuildQuery(query, sizeof query, &name, WIRE_TYPE_A, 0x1234,
                        &queryLen));
    CHECK(UpstreamBegin(&pool, 0, query, queryLen, NOW, &exchange)
          == UpstreamStart_Started);

    UpstreamTlsSlot *slot = &pool.tlsSlots[exchange.tlsSlot];
    CHECK(slot->requestLen > queryLen);
    CHECK(Contains(slot->query, slot->requestLen,
                   "POST /custom-dns HTTP/1.1\r\n"));
    char hostHeader[CFG_TLS_HOSTNAME_BYTES + 16];
    int hostHeaderLen = snprintf(hostHeader, sizeof hostHeader,
                                 "Host: resolver.example:%u\r\n",
                                 (unsigned int)port);
    CHECK(hostHeaderLen > 0);
    CHECK(Contains(slot->query, slot->requestLen, hostHeader));
    CHECK(Contains(slot->query, slot->requestLen,
                   "Content-Type: application/dns-message\r\n"));
    char lengthHeader[64];
    int lengthHeaderLen = snprintf(lengthHeader, sizeof lengthHeader,
                                   "Content-Length: %zu\r\n", queryLen);
    CHECK(lengthHeaderLen > 0);
    CHECK(Contains(slot->query, slot->requestLen, lengthHeader));

    size_t bodyAt = slot->requestLen - queryLen;
    CHECK(MsgId(slot->query + bodyAt, queryLen) == exchange.id);

    G_WRITE_CHUNK = 5;
    uint8_t answer[CFG_TCP_MSG_BYTES];
    size_t answerLen = 0;
    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Again);
    CHECK(slot->sent == 5);

    UpstreamEnd(&exchange);
    close(listener);
}

static void TestWriteUsesTlsPollDirection(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    ExchangeOf(&pool, &exchange, DotState_Write, fds[0]);

    pool.tlsSlots[0].channel.want = TlsIo_WantRead;
    CHECK(UpstreamEvents(&exchange) == POLLIN);
    pool.tlsSlots[0].channel.want = TlsIo_WantWrite;
    CHECK(UpstreamEvents(&exchange) == POLLOUT);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestWriteWantReadChangesPollDirection(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DotState_Write, fds[0]);
    G_WRITE_RESULT = TlsIo_WantRead;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Again);
    CHECK(UpstreamEvents(&exchange) == POLLIN);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestReadWantWriteChangesPollDirection(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DotState_ReadLength, fds[0]);
    G_READ_RESULT = TlsIo_WantWrite;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Again);
    CHECK(UpstreamEvents(&exchange) == POLLOUT);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestConnectAdvancesToHandshake(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DotState_Connect, fds[0]);
    G_HANDSHAKE_RESULT = TlsIo_WantRead;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Again);
    CHECK(pool.tlsSlots[0].state == DotState_Handshake);
    CHECK(UpstreamEvents(&exchange) == POLLIN);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestPartialFrameCompletes(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          expected[CFG_TCP_MSG_BYTES];
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           expectedLen = 0;
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DotState_Write, fds[0]);
    CHECK(BuildAnswer(&exchange, expected, sizeof expected, &expectedLen));

    G_READ_DATA[0] = (uint8_t)(expectedLen >> 8);
    G_READ_DATA[1] = (uint8_t)expectedLen;
    memcpy(G_READ_DATA + 2, expected, expectedLen);
    G_READ_LEN    = expectedLen + 2;
    G_READ_CHUNK  = 3;
    G_WRITE_CHUNK = 2;

    UpstreamRead result = UpstreamRead_Again;
    for(size_t i = 0; i < CFG_TCP_MSG_BYTES && result == UpstreamRead_Again; i++)
    {
        result = UpstreamComplete(&pool, &exchange, NOW + 10, answer,
                                  sizeof answer, &answerLen);
    }

    CHECK(result == UpstreamRead_Answer);
    CHECK(answerLen == expectedLen);
    CHECK(memcmp(answer, expected, expectedLen) == 0);
    CHECK(pool.members[0].srttMs == 10);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestInvalidFrameFails(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DotState_ReadLength, fds[0]);
    G_READ_DATA[0] = 0;
    G_READ_DATA[1] = 1;
    G_READ_LEN = 2;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Failed);

    UpstreamEnd(&exchange);
    CHECK(!pool.tlsSlots[0].bUsed);
    close(fds[1]);
}

static void TestPartialDohResponseCompletes(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          expected[CFG_TCP_MSG_BYTES];
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           expectedLen = 0;
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DohState_ReadHeaders, fds[0]);
    pool.members[0].transport = UpstreamTransport_Doh;
    exchange.transport = UpstreamTransport_Doh;
    CHECK(BuildAnswer(&exchange, expected, sizeof expected, &expectedLen));

    int headerLen = snprintf((char *)G_READ_DATA, sizeof G_READ_DATA,
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/dns-message\r\n"
                             "Content-Length: %zu\r\n"
                             "Connection: close\r\n\r\n",
                             expectedLen);
    CHECK(headerLen > 0);
    CHECK((size_t)headerLen + expectedLen <= sizeof G_READ_DATA);
    memcpy(G_READ_DATA + headerLen, expected, expectedLen);
    G_READ_LEN   = (size_t)headerLen + expectedLen;
    G_READ_CHUNK = 7;

    UpstreamRead result = UpstreamRead_Again;
    for(size_t i = 0; i < CFG_TCP_MSG_BYTES && result == UpstreamRead_Again; i++)
    {
        result = UpstreamComplete(&pool, &exchange, NOW + 12, answer,
                                  sizeof answer, &answerLen);
    }

    CHECK(result == UpstreamRead_Answer);
    CHECK(answerLen == expectedLen);
    CHECK(memcmp(answer, expected, expectedLen) == 0);
    CHECK(pool.members[0].srttMs == 12);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestDohRejectsHttpFailure(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DohState_ReadHeaders, fds[0]);
    pool.members[0].transport = UpstreamTransport_Doh;
    exchange.transport = UpstreamTransport_Doh;

    static const char response[] =
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: 12\r\n\r\n"
        "abcdefghijkl";
    memcpy(G_READ_DATA, response, sizeof response - 1);
    G_READ_LEN = sizeof response - 1;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Failed);

    /* 503 is the server having a bad day, so it stays in the pool */
    CHECK(!pool.members[0].bUnusable);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

/* Quad9's DoH endpoint is HTTP/2 only and answers 505 to this client. That is
   the server refusing the protocol, and no retry or wait changes it, so the
   resolver has to leave the rotation rather than absorb queries forever. */
static void TestDohVersionRefusalMarksTheUpstream(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DohState_ReadHeaders, fds[0]);
    pool.members[0].transport = UpstreamTransport_Doh;
    exchange.transport = UpstreamTransport_Doh;

    static const char response[] =
        "HTTP/1.1 505 HTTP Version Not Supported\r\n"
        "Content-Length: 0\r\n\r\n";
    memcpy(G_READ_DATA, response, sizeof response - 1);
    G_READ_LEN = sizeof response - 1;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Failed);
    CHECK(pool.members[0].bUnusable);
    CHECK(pool.members[0].failures == 1);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestDohRejectsChunkedResponse(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DohState_ReadHeaders, fds[0]);
    pool.members[0].transport = UpstreamTransport_Doh;
    exchange.transport = UpstreamTransport_Doh;

    static const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/dns-message\r\n"
        "Transfer-Encoding: chunked\r\n\r\n";
    memcpy(G_READ_DATA, response, sizeof response - 1);
    G_READ_LEN = sizeof response - 1;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Failed);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestDohRejectsTrailingBytes(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DohState_ExpectClose, fds[0]);
    pool.members[0].transport = UpstreamTransport_Doh;
    exchange.transport = UpstreamTransport_Doh;
    pool.tlsSlots[0].got = WIRE_HEADER_BYTES;
    pool.tlsSlots[0].responseLen = WIRE_HEADER_BYTES;
    G_READ_DATA[0] = 0;
    G_READ_LEN = 1;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Failed);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestDohRejectsHeaderAtCapacity(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool     pool;
    UpstreamExchange exchange;
    uint8_t          answer[CFG_TCP_MSG_BYTES];
    size_t           answerLen = 0;
    ExchangeOf(&pool, &exchange, DohState_ReadHeaders, fds[0]);
    pool.members[0].transport = UpstreamTransport_Doh;
    exchange.transport = UpstreamTransport_Doh;
    memset(G_READ_DATA, 'a', CFG_DOH_HEADER_BYTES);
    G_READ_LEN = CFG_DOH_HEADER_BYTES;

    CHECK(UpstreamComplete(&pool, &exchange, NOW, answer, sizeof answer,
                           &answerLen) == UpstreamRead_Failed);

    UpstreamEnd(&exchange);
    close(fds[1]);
}

static void TestFailedProbeReleasesItsSlot(void)
{
    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    UpstreamPool pool;
    ExchangeOf(&pool, &pool.probe, DotState_Handshake, fds[0]);
    pool.bProbing = true;
    G_HANDSHAKE_RESULT = TlsIo_Error;

    UpstreamPoolProbeReadable(&pool, NOW);

    CHECK(!pool.bProbing);
    CHECK(!pool.tlsSlots[0].bUsed);
    CHECK(pool.probeFailures == 1);
    CHECK(pool.members[0].failures == 1);
    CHECK(G_CLOSES == 1);
    close(fds[1]);
}

static void TestFullPoolRefusesExchange(void)
{
    UpstreamPool     pool;
    UpstreamExchange exchange;
    TlsBackend       backend;
    WireName         name;
    uint8_t          query[CFG_TX_QUERY_BYTES];
    size_t           queryLen = 0;

    memset(&backend, 0, sizeof backend);
    backend.bReady = true;
    UpstreamPoolInit(&pool, NOW);
    UpstreamPoolSetTlsBackend(&pool, &backend);
    CHECK(UpstreamPoolAddDot(&pool, "127.0.0.1", 853, "example.com"));
    for(size_t i = 0; i < CFG_TLS_SLOTS; i++)
        pool.tlsSlots[i].bUsed = true;

    CHECK(WireEncodeName("example.com", &name));
    CHECK(MsgBuildQuery(query, sizeof query, &name, WIRE_TYPE_A, 0x1234,
                        &queryLen));
    CHECK(UpstreamBegin(&pool, 0, query, queryLen, NOW, &exchange)
          == UpstreamStart_Busy);
    CHECK(exchange.fd == -1);
}

int main(void)
{
    FakeReset();
    TestDohRequestContainsDnsMessage();
    FakeReset();
    TestWriteUsesTlsPollDirection();
    FakeReset();
    TestWriteWantReadChangesPollDirection();
    FakeReset();
    TestReadWantWriteChangesPollDirection();
    FakeReset();
    TestConnectAdvancesToHandshake();
    FakeReset();
    TestPartialFrameCompletes();
    FakeReset();
    TestInvalidFrameFails();
    FakeReset();
    TestPartialDohResponseCompletes();
    FakeReset();
    TestDohRejectsHttpFailure();
    FakeReset();
    TestDohVersionRefusalMarksTheUpstream();
    FakeReset();
    TestDohRejectsChunkedResponse();
    FakeReset();
    TestDohRejectsTrailingBytes();
    FakeReset();
    TestDohRejectsHeaderAtCapacity();
    FakeReset();
    TestFailedProbeReleasesItsSlot();
    FakeReset();
    TestFullPoolRefusesExchange();

    if(G_FAILURES != 0)
    {
        printf("%d check(s) failed\n", G_FAILURES);
        return 1;
    }

    printf("upstream dot: all checks passed\n");
    return 0;
}
