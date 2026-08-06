#define _DEFAULT_SOURCE

#include "hosts.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define HOSTS_LINE_BYTES  512
#define HOSTS_READ_BYTES  4096
#define HOSTS_MAX_LABELS  40

static bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Presentation name to wire form, exactly as given. */
static bool EncodeNameRaw(const char *dotted, WireName *out)
{
    size_t len = strlen(dotted);

    if(len == 0)
        return false;

    if(dotted[len - 1] == '.')
        len--;

    size_t at = 0;
    size_t start = 0;

    for(size_t i = 0; i <= len; i++)
    {
        if(i != len && dotted[i] != '.')
            continue;

        size_t labelLen = i - start;
        if(labelLen == 0 || labelLen > CFG_MAX_LABEL_BYTES)
            return false;
        if(at + 1 + labelLen + 1 > sizeof out->wire)
            return false;

        out->wire[at] = (uint8_t)labelLen;
        for(size_t k = 0; k < labelLen; k++)
        {
            char c = dotted[start + k];
            if(c >= 'A' && c <= 'Z')
                c = (char)(c + 32);
            out->wire[at + 1 + k] = (uint8_t)c;
        }

        at += 1 + labelLen;
        start = i + 1;
    }

    if(at + 1 > sizeof out->wire)
        return false;

    out->wire[at] = 0;
    out->len = at + 1;
    return true;
}

/* The local domain is appended to a name with no dot in it, which is what makes
   `iPhone` in the file answer as `iphone.lan`. */
static bool EncodeName(const char *dotted, WireName *out)
{
    char joined[CFG_MAX_NAME_BYTES];

    if(strchr(dotted, '.') == NULL && CFG_LOCAL_DOMAIN[0] != '\0')
    {
        int written = snprintf(joined, sizeof joined, "%s.%s", dotted,
                               CFG_LOCAL_DOMAIN);
        if(written < 0 || (size_t)written >= sizeof joined)
            return false;

        dotted = joined;
    }

    return EncodeNameRaw(dotted, out);
}

size_t HostsParseLine(char *line, uint8_t *addr, uint8_t *addrLen,
                      WireName *names, size_t maxNames)
{
    char *at = strchr(line, '#');
    if(at != NULL)
        *at = '\0';

    char  *field = line;
    size_t count = 0;

    while(*field != '\0' && IsSpace(*field))
        field++;

    if(*field == '\0')
        return 0;

    char *end = field;
    while(*end != '\0' && !IsSpace(*end))
        end++;

    if(*end != '\0')
        *end++ = '\0';

    struct in_addr  v4;
    struct in6_addr v6;

    if(inet_pton(AF_INET, field, &v4) == 1)
    {
        memcpy(addr, &v4.s_addr, 4);
        *addrLen = 4;
    }
    else if(inet_pton(AF_INET6, field, &v6) == 1)
    {
        memcpy(addr, v6.s6_addr, 16);
        *addrLen = 16;
    }
    else
    {
        return 0;
    }

    while(*end != '\0' && count < maxNames)
    {
        while(*end != '\0' && IsSpace(*end))
            end++;

        if(*end == '\0')
            break;

        char *nameStart = end;
        while(*end != '\0' && !IsSpace(*end))
            end++;

        if(*end != '\0')
            *end++ = '\0';

        if(EncodeName(nameStart, &names[count]))
            count++;
    }

    return count;
}

static void AddLine(HostMap *map, char *line)
{
    uint8_t  addr[16];
    uint8_t  addrLen = 0;
    WireName names[8];

    size_t count = HostsParseLine(line, addr, &addrLen, names,
                                  sizeof names / sizeof names[0]);

    for(size_t i = 0; i < count; i++)
    {
        if(map->count == map->capacity)
        {
            map->rejected++;
            continue;
        }

        HostEntry *entry = &map->entries[map->count];

        entry->name = names[i];
        entry->addrLen = addrLen;
        memcpy(entry->addr, addr, addrLen);
        map->count++;
    }
}

static void ReadFile(HostMap *map, int fd)
{
    char   line[HOSTS_LINE_BYTES];
    char   chunk[HOSTS_READ_BYTES];
    size_t at = 0;
    bool   bTooLong = false;
    ssize_t got;

    while((got = read(fd, chunk, sizeof chunk)) > 0)
    {
        for(ssize_t i = 0; i < got; i++)
        {
            if(chunk[i] != '\n')
            {
                if(at + 1 < sizeof line)
                    line[at++] = chunk[i];
                else
                    bTooLong = true;
                continue;
            }

            line[at] = '\0';
            if(bTooLong)
                map->rejected++;
            else
                AddLine(map, line);

            at = 0;
            bTooLong = false;
        }
    }

    if(at > 0 && !bTooLong)
    {
        line[at] = '\0';
        AddLine(map, line);
    }
}

bool HostsLoad(HostMap *map, Arena *arena, const char *path)
{
    memset(map, 0, sizeof *map);

    map->entries = ARENA_ARRAY(arena, HostEntry, CFG_HOSTS_MAX);
    if(map->entries == NULL)
        return false;

    map->capacity = CFG_HOSTS_MAX;
    map->bHasDomain = CFG_LOCAL_DOMAIN[0] != '\0'
                   && EncodeNameRaw(CFG_LOCAL_DOMAIN, &map->domain);

    if(path == NULL)
        return true;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return true;

    ReadFile(map, fd);
    close(fd);

    if(map->rejected != 0)
        fprintf(stderr, "hosts: %s, %zu line(s) ignored\n", path, map->rejected);

    return true;
}

bool HostsLookup(const HostMap *map, const WireName *name, uint16_t type,
                 const HostEntry **out, bool *bNameExists)
{
    uint8_t want = (type == WIRE_TYPE_AAAA) ? 16 : 4;

    *bNameExists = false;

    if(type != WIRE_TYPE_A && type != WIRE_TYPE_AAAA)
    {
        /* Any other type still needs to know the name is ours, so the answer is
           NODATA rather than a query sent upstream for a name it cannot
           resolve. */
        want = 0;
    }

    for(size_t i = 0; i < map->count; i++)
    {
        const HostEntry *entry = &map->entries[i];

        if(!WireNameEqual(&entry->name, name))
            continue;

        *bNameExists = true;

        if(entry->addrLen == want)
        {
            *out = entry;
            return true;
        }
    }

    return false;
}

bool HostsNameIsLocal(const HostMap *map, const WireName *name)
{
    return map->bHasDomain && WireNameInZone(name, &map->domain);
}

const HostEntry *HostsByAddress(const HostMap *map, const uint8_t *addr,
                                uint8_t addrLen)
{
    for(size_t i = 0; i < map->count; i++)
    {
        const HostEntry *entry = &map->entries[i];

        if(entry->addrLen == addrLen && memcmp(entry->addr, addr, addrLen) == 0)
            return entry;
    }

    return NULL;
}

static bool LabelEquals(const uint8_t *label, size_t len, const char *text)
{
    if(strlen(text) != len)
        return false;

    for(size_t i = 0; i < len; i++)
    {
        uint8_t c = label[i];
        if(c >= 'A' && c <= 'Z')
            c = (uint8_t)(c + 32);

        if(c != (uint8_t)text[i])
            return false;
    }

    return true;
}

static bool DecimalLabel(const uint8_t *label, size_t len, uint8_t *out)
{
    unsigned value = 0;

    if(len == 0 || len > 3)
        return false;

    for(size_t i = 0; i < len; i++)
    {
        if(label[i] < '0' || label[i] > '9')
            return false;

        value = value * 10u + (unsigned)(label[i] - '0');
    }

    if(value > 255u)
        return false;

    *out = (uint8_t)value;
    return true;
}

static bool HexLabel(const uint8_t *label, size_t len, uint8_t *out)
{
    if(len != 1)
        return false;

    uint8_t c = label[0];
    if(c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return true; }
    if(c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return true; }
    if(c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return true; }

    return false;
}

bool HostsReverseAddress(const WireName *name, uint8_t *addr, uint8_t *addrLen)
{
    const uint8_t *labels[HOSTS_MAX_LABELS];
    size_t         lengths[HOSTS_MAX_LABELS];
    size_t         count = 0;
    size_t         at = 0;

    while(at < name->len)
    {
        uint8_t labelLen = name->wire[at];

        if(labelLen == 0)
            break;
        if(count == HOSTS_MAX_LABELS || name->len - at - 1 < labelLen)
            return false;

        labels[count] = name->wire + at + 1;
        lengths[count] = labelLen;
        count++;
        at += 1u + labelLen;
    }

    if(count < 3 || !LabelEquals(labels[count - 1], lengths[count - 1], "arpa"))
        return false;

    if(LabelEquals(labels[count - 2], lengths[count - 2], "in-addr"))
    {
        if(count != 6)
            return false;

        for(size_t i = 0; i < 4; i++)
        {
            if(!DecimalLabel(labels[3 - i], lengths[3 - i], &addr[i]))
                return false;
        }

        *addrLen = 4;
        return true;
    }

    if(LabelEquals(labels[count - 2], lengths[count - 2], "ip6"))
    {
        uint8_t nibbles[32];

        if(count != 34)
            return false;

        /* The name lists nibbles least significant first, so it reads
           backwards into the address. */
        for(size_t i = 0; i < 32; i++)
        {
            if(!HexLabel(labels[31 - i], lengths[31 - i], &nibbles[i]))
                return false;
        }

        for(size_t i = 0; i < 16; i++)
            addr[i] = (uint8_t)((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]);

        *addrLen = 16;
        return true;
    }

    return false;
}

bool HostsAddressIsPrivate(const uint8_t *addr, uint8_t addrLen)
{
    if(addrLen == 4)
    {
        if(addr[0] == 10)  return true;
        if(addr[0] == 127) return true;
        if(addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31) return true;
        if(addr[0] == 192 && addr[1] == 168) return true;
        if(addr[0] == 169 && addr[1] == 254) return true;
        return false;
    }

    if(addrLen == 16)
    {
        static const uint8_t loopback[16] = { [15] = 1 };

        /* fc00::/7 unique local, fe80::/10 link local, ::1 loopback. */
        if((addr[0] & 0xFEu) == 0xFCu) return true;
        if(addr[0] == 0xFE && (addr[1] & 0xC0u) == 0x80u) return true;
        if(memcmp(addr, loopback, 16) == 0) return true;
    }

    return false;
}
