#define _GNU_SOURCE

#include "upstream.h"

#include "config.h"
#include "msg.h"
#include "verify.h"
#include "wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static uint16_t RandomId(void)
{
    uint16_t id = 0;

    while(getrandom(&id, sizeof id, 0) != (ssize_t)sizeof id)
    {
        if(errno != EINTR)
            return 0;
    }

    return id;
}

/* 0x20 encoding. DNS matches names without regard to case, so the case of the
   question is free entropy on top of the transaction ID and the source port.
   A resolver echoes the question byte for byte, and VerifyResponse requires
   that, so an attacker has to guess the case of every letter as well. */
static void ApplyCaseRandomisation(uint8_t *msg, size_t len)
{
#if CFG_UPSTREAM_0X20
    Reader     reader;
    WireHeader header;
    uint8_t    bits[CFG_MAX_NAME_BYTES];

    ReaderInit(&reader, msg, len);
    if(!WireParseHeader(&reader, &header) || header.qdCount != 1)
        return;

    size_t start = reader.pos;
    WireName name;
    if(!WireReadName(&reader, &name))
        return;

    size_t nameBytes = reader.pos - start;
    if(nameBytes > sizeof bits)
        return;

    /* One draw for the whole name. A per-byte call would be the same entropy
       at many times the syscall cost. */
    if(getrandom(bits, nameBytes, 0) != (ssize_t)nameBytes)
        return;

    for(size_t i = 0; i < nameBytes; i++)
    {
        uint8_t c = msg[start + i];

        if(c >= 'a' && c <= 'z' && (bits[i] & 1u))
            msg[start + i] = (uint8_t)(c - 32);
        else if(c >= 'A' && c <= 'Z' && (bits[i] & 1u) == 0)
            msg[start + i] = (uint8_t)(c + 32);
    }
#else
    (void)msg;
    (void)len;
#endif
}

bool UpstreamInit(Upstream *upstream, const char *address, uint16_t port)
{
    memset(upstream, 0, sizeof *upstream);

    struct sockaddr_in *v4 = (struct sockaddr_in *)&upstream->addr;
    if(inet_pton(AF_INET, address, &v4->sin_addr) == 1)
    {
        v4->sin_family    = AF_INET;
        v4->sin_port      = htons(port);
        upstream->addrLen = sizeof *v4;
        return true;
    }

    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&upstream->addr;
    if(inet_pton(AF_INET6, address, &v6->sin6_addr) == 1)
    {
        v6->sin6_family   = AF_INET6;
        v6->sin6_port     = htons(port);
        upstream->addrLen = sizeof *v6;
        return true;
    }

    return false;
}

bool UpstreamBegin(Upstream *upstream, const uint8_t *query, size_t queryLen,
                   UpstreamExchange *exchange)
{
    uint8_t      sent[CFG_UDP_MSG_BYTES];
    Reader       reader;
    WireHeader   header;

    exchange->fd = -1;

    if(queryLen < WIRE_HEADER_BYTES || queryLen > sizeof sent
       || upstream->addrLen == 0)
        return false;

    memcpy(sent, query, queryLen);
    exchange->id = RandomId();
    MsgSetId(sent, queryLen, exchange->id);
    ApplyCaseRandomisation(sent, queryLen);

    /* Parsed after randomisation, so the stored question carries the case the
       answer has to echo. */
    ReaderInit(&reader, sent, queryLen);
    if(!WireParseHeader(&reader, &header) || header.qdCount != 1
       || !WireParseQuestion(&reader, &exchange->asked))
        return false;

    int fd = socket(upstream->addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return false;

    if(connect(fd, (struct sockaddr *)&upstream->addr, upstream->addrLen) != 0
       || send(fd, sent, queryLen, 0) != (ssize_t)queryLen)
    {
        close(fd);
        return false;
    }

    exchange->fd = fd;
    upstream->queries++;
    return true;
}

UpstreamRead UpstreamComplete(Upstream *upstream, const UpstreamExchange *exchange,
                              uint8_t *out, size_t cap, size_t *outLen)
{
    ssize_t got = recv(exchange->fd, out, cap, MSG_DONTWAIT);

    if(got < 0)
        return UpstreamRead_Empty;

    if(got < (ssize_t)WIRE_HEADER_BYTES)
        return UpstreamRead_Again;

    if(MsgId(out, (size_t)got) != exchange->id)
    {
        upstream->mismatches++;
        return UpstreamRead_Again;
    }

    VerifyResult verdict = VerifyAnswer(&exchange->asked, out, (size_t)got);
    if(verdict != VerifyResult_Ok)
    {
        upstream->rejected++;
        upstream->lastReject = verdict;
        return UpstreamRead_Again;
    }

    *outLen = (size_t)got;
    return UpstreamRead_Answer;
}

void UpstreamEnd(UpstreamExchange *exchange)
{
    if(exchange->fd >= 0)
        close(exchange->fd);

    exchange->fd = -1;
}
