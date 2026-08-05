#define _GNU_SOURCE

#include "upstream.h"

#include "config.h"
#include "msg.h"

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

static bool QueryOnce(Upstream *upstream, const uint8_t *query, size_t queryLen,
                      uint8_t *out, size_t cap, size_t *outLen)
{
    int fd = socket(upstream->addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0)
        return false;

    if(connect(fd, (struct sockaddr *)&upstream->addr, upstream->addrLen) != 0)
    {
        close(fd);
        return false;
    }

    uint16_t id = RandomId();
    uint8_t  header[2] = { (uint8_t)(id >> 8), (uint8_t)id };

    struct iovec  parts[2] = {
        { header, sizeof header },
        { (void *)(uintptr_t)(query + 2), queryLen - 2 }
    };
    struct msghdr message;

    memset(&message, 0, sizeof message);
    message.msg_iov    = parts;
    message.msg_iovlen = 2;

    if(sendmsg(fd, &message, 0) != (ssize_t)queryLen)
    {
        close(fd);
        return false;
    }

    struct pollfd waiting = { .fd = fd, .events = POLLIN, .revents = 0 };
    int ready = poll(&waiting, 1, CFG_UPSTREAM_TIMEOUT_MS);

    if(ready <= 0)
    {
        close(fd);
        if(ready == 0)
            upstream->timeouts++;
        return false;
    }

    ssize_t got = recv(fd, out, cap, 0);
    close(fd);

    if(got < (ssize_t)WIRE_HEADER_BYTES)
        return false;

    if(MsgId(out, (size_t)got) != id)
    {
        upstream->mismatches++;
        return false;
    }

    *outLen = (size_t)got;
    return true;
}

bool UpstreamQuery(Upstream *upstream, const uint8_t *query, size_t queryLen,
                   uint8_t *out, size_t cap, size_t *outLen)
{
    if(queryLen < WIRE_HEADER_BYTES || upstream->addrLen == 0)
        return false;

    upstream->queries++;

    for(int attempt = 0; attempt <= CFG_UPSTREAM_RETRIES; attempt++)
    {
        if(QueryOnce(upstream, query, queryLen, out, cap, outLen))
            return true;
    }

    upstream->failures++;
    return false;
}
