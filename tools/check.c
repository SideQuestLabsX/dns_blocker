#define _GNU_SOURCE

/* Health probe. Resolves a known-good name against the local resolver and
   exits 0 when the answer is usable. Exercises the socket, parser, cache and
   response path together, so a hang in any of them is caught. */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define PROBE_NAME      "example.com"
#define PROBE_SERVER    "127.0.0.1"
#define PROBE_PORT      53
#define PROBE_TIMEOUT_S 2
#define QUERY_MAX       512

static int EncodeName(const char *name, uint8_t *out, size_t cap, size_t *written)
{
    size_t pos   = 0;
    size_t label = 0;

    for(const char *p = name; ; p++)
    {
        if(*p != '.' && *p != '\0')
        {
            label++;
            continue;
        }

        if(label == 0 || label > 63 || pos + label + 1 >= cap)
            return -1;

        out[pos] = (uint8_t)label;
        memcpy(out + pos + 1, p - label, label);
        pos += label + 1;
        label = 0;

        if(*p == '\0')
            break;
    }

    if(pos + 1 >= cap)
        return -1;

    out[pos++] = 0;
    *written = pos;
    return 0;
}

static uint16_t RandomId(void)
{
    uint16_t id = 0;

    if(getrandom(&id, sizeof id, 0) != (ssize_t)sizeof id)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        id = (uint16_t)(tv.tv_usec ^ (long)getpid());
    }

    return id;
}

int main(int argc, char **argv)
{
    const char *name   = argc > 1 ? argv[1] : PROBE_NAME;
    const char *server = argc > 2 ? argv[2] : PROBE_SERVER;

    uint8_t  query[QUERY_MAX];
    size_t   nameLen = 0;
    uint16_t id      = RandomId();

    query[0] = (uint8_t)(id >> 8);
    query[1] = (uint8_t)(id & 0xFF);
    query[2] = 0x01;                    /* RD */
    query[3] = 0x00;
    query[4] = 0x00; query[5] = 0x01;   /* QDCOUNT */
    memset(query + 6, 0, 6);

    if(EncodeName(name, query + 12, sizeof query - 12 - 4, &nameLen) != 0)
    {
        fprintf(stderr, "check: bad name '%s'\n", name);
        return 1;
    }

    size_t len = 12 + nameLen;
    query[len++] = 0x00; query[len++] = 0x01;   /* QTYPE A */
    query[len++] = 0x00; query[len++] = 0x01;   /* QCLASS IN */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PROBE_PORT);
    if(inet_pton(AF_INET, server, &addr.sin_addr) != 1)
    {
        fprintf(stderr, "check: bad server '%s'\n", server);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        perror("check: socket");
        return 1;
    }

    struct timeval tv = { .tv_sec = PROBE_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    if(connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0
       || send(fd, query, len, 0) != (ssize_t)len)
    {
        perror("check: send");
        close(fd);
        return 1;
    }

    uint8_t reply[QUERY_MAX];
    ssize_t n = recv(fd, reply, sizeof reply, 0);
    close(fd);

    if(n < 12)
    {
        fprintf(stderr, "check: no usable reply from %s\n", server);
        return 1;
    }

    uint16_t replyId  = (uint16_t)((reply[0] << 8) | reply[1]);
    int      rcode    = reply[3] & 0x0F;
    int      anCount  = (reply[6] << 8) | reply[7];

    if(replyId != id || (reply[2] & 0x80) == 0)
    {
        fputs("check: reply does not match the query\n", stderr);
        return 1;
    }

    if(rcode != 0 || anCount < 1)
    {
        fprintf(stderr, "check: rcode %d, %d answers\n", rcode, anCount);
        return 1;
    }

    return 0;
}
