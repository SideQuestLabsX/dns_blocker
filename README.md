# dns_blocker

A DNS filtering and forwarding daemon for embedded Linux. The daemon reserves
one memory arena at start-up and does no other allocation. It uses no database
engine and no scripting runtime. It links static musl, and mbedTLS for the
encrypted profile.

The daemon resolves names and filters them. It listens on UDP and TCP, parses
RFC 1035 messages, caches responses, blocks names from a compiled list and
forwards the rest through plaintext DNS, DNS-over-HTTPS or DNS-over-TLS.

## Setup

The device is a DNS addon behind an existing router. It is not a gateway.

```text
clients ──DNS(53)──> [dns_blocker] ──DoH──> upstream resolver
   │
   └──all other traffic──> router ──> internet
```

Set the router's DHCP to give this device as the LAN DNS server. The router
stays the DHCP authority.

Set the IPv6 resolver as well. If the router gives its own resolver through
Router Advertisement RDNSS, the clients go around this device, and the network
continues to look correct. Give this device for IPv6, or stop the IPv6 DNS
advertisement.

The daemon runs on any Linux host. The prebuilt appliance images target the
Raspberry Pi Zero W and the Zero 2 W.

## Behavior

| Area | Behavior |
|---|---|
| Listeners | UDP and TCP on port 53, IPv4 and IPv6, with EDNS0 support |
| Caching | Keeps each TTL and decrements it by the time that passed, negative caching to RFC 2308, CLOCK eviction |
| Upstream | Plaintext DNS in the minimal profile, DNS-over-HTTPS by default in the encrypted profile |
| Upstream choice | Each query goes to the fastest configured resolver, timed by the answers it gives and by an occasional probe to the others |
| Filtering | A reverse-label trie with exact and suffix matches, so one entry covers a whole subtree |
| Local names | A static host map serves `A`, `AAAA` and `PTR` for the LAN, before everything else |
| Local reverse | Unknown IPv4 `PTR` names in the configured LAN prefix go to the router, and other private reverse names get `NXDOMAIN` |
| Blocked answers | `NXDOMAIN`, given before the cache and before the upstream |
| Hardening | Random transaction IDs, random source ports, 0x20 case in the question, and a bailiwick check on every answer |

The daemon passes HTTPS and SVCB records through without change, so Encrypted
Client Hello continues to operate.

Every answered query writes one line to `stdout`:

```text
query udp doubleclick.net A blocked NXDOMAIN
query udp example.com A forwarded NOERROR
query tcp example.com A hit NOERROR
```

The fields are the transport, the name, the record type, the outcome and the
response code. The outcome is one of `local`, `blocked`, `hit`, `forwarded`,
`truncated` or `failed`. A name is printed with `\DDD` in place of any byte
that would otherwise split the line, because the name came from a client.

Keep the query stream off permanent storage. It is the largest output in the
system, frequent small appends are the worst write pattern for an SD card, and
the stream records every domain that each device on the network resolved. The
daemon writes only to `stdout`, so the supervisor makes this decision. With
systemd, set `StandardOutput=null`, or set journald `Storage=volatile`. If you
do not, the card receives every query.

To remove the stream from the binary, build with `FEATURE_QUERY_LOG=0`. That
deletes the call sites, so no configuration can turn it back on. `stderr`
carries the daemon's own faults and is never gated.

```sh
make FEATURES=-DFEATURE_QUERY_LOG=0
```

The daemon serves TCP on port 53. A response that is larger than the UDP
payload size gets the `TC` bit, and the client sends the query again over TCP.

## Profiles

| Profile | Contents |
|---|---|
| `minimal` | The core engine and plaintext upstream forwarding |
| `encrypted` | Adds mbedTLS, DoH and DoT upstream |

The default is `encrypted`, and it is the shipped image. The build downloads
the pinned mbedTLS 3.6.7 release, verifies its SHA-256 digest and compiles it
with the fixed-buffer allocator enabled. It needs `curl`, `python3` and
`sha256sum`.

## Blocklists

`make tools` builds `mkblocklist`, which compiles domain lists into the file the
daemon maps. It reads a domain per line, a hosts-file line and a `*.example.com`
wildcard rule alike.

```sh
mkblocklist blocklist.trie list1.txt list2.txt
```

An entry blocks the name and every name below it, so `doubleclick.net` also
covers `ad.doubleclick.net`. The generator reloads its own output through the
daemon's lookup and fails if anything it inserted does not match.

Point `CFG_BLOCKLIST_PATH` at the result.

The weekly workflow publishes a dated release and republishes the same assets
under the fixed tag `blocklist-latest`, so these URLs always serve the newest
build:

```text
https://github.com/SideQuestLabsX/dns_blocker/releases/download/blocklist-latest/<asset>
```

| Asset | Contents |
|---|---|
| `dns_blocker-blocklist.trie` | The compiled list the daemon maps |
| `dns_blocker-blocklist.trie.sha256` | A digest for every other asset |
| `dns_blocker-blocklist.sources` | Each source URL, size, accepted-name count and SHA-256 digest |
| `dns_blocker-blocklist.domains.txt.gz` | The exact domain list the trie was compiled from |
| `THIRD_PARTY_LICENSES.md` | The license terms the release carries |

Download the whole release into a staging directory on the same tmpfs as
`CFG_BLOCKLIST_PATH`, then verify and install it. The digest file names every
asset, so `sha256sum -c` fails if any of them is missing:

```sh
(cd /run/dns_blocker/update && sha256sum -c dns_blocker-blocklist.trie.sha256)
mv /run/dns_blocker/update/dns_blocker-blocklist.trie \
  /run/dns_blocker/blocklist.trie
```

Rename the trie to `CFG_BLOCKLIST_PATH` only after verification. The rename
keeps a complete old file in place until the new file is ready. The daemon uses
the embedded list when the mapped file is absent or its header is invalid. It
bounds every lookup inside a mapped body, but checksum verification is what
rejects body corruption.

The binary also carries a list of its own. `EMBED_LIST` names the source and
defaults to `blocklists/embedded.txt`. The build compiles it with
`mkblocklist -c`, which writes the trie as a C array, and links that into
`.rodata`.

```sh
make EMBED_LIST=my-list.txt
make EMBED_LIST=
```

`CFG_BLOCKLIST_PATH` decides what that list is for. With a path, the mapped file
wins whenever it is there, and the compiled-in list covers a boot that has no
file yet. Set the path to `NULL` and the daemon reads no file at all: the
compiled-in list is the whole policy, it changes only by re-flashing, and the
device needs nothing from the network to filter. Embed the full list for that
build rather than the small one.

An empty `EMBED_LIST` ships without an embedded list. If the mapped file is
missing or unreadable and there is no embedded list either, the daemon says so
and forwards without filtering, because a resolver that fails closed takes the
network down with it.

## Upstream resolvers

`CFG_UPSTREAM_ADDRS` lists them, up to `CFG_MAX_UPSTREAMS`, as literal addresses
in preference order.

```c
#define CFG_UPSTREAM_ADDRS { "1.1.1.1", "9.9.9.9" }
```

A query goes to one of them, the one answering fastest, so no resolver receives
everything you look up. The daemon times a resolver from the answers it gives,
and sends one small probe every `CFG_UPSTREAM_PROBE_MS` to one of the others, so
a resolver it is not using still gets measured. It sends no probe while nothing
is querying it. The first address in the list serves until the first
measurement arrives.

A resolver that stops answering is passed over for `CFG_UPSTREAM_DOWN_MS` and a
query that timed out is retried against a different one. If all of them are
failing the daemon keeps forwarding to the best of them anyway.

The encrypted profile also needs one TLS authentication name for each address:

```c
#define CFG_UPSTREAM_ADDRS    { "1.1.1.1", "9.9.9.9" }
#define CFG_UPSTREAM_TLS_NAMES { "cloudflare-dns.com", "dns.quad9.net" }
#define CFG_UPSTREAM_DOH_PATHS { "/dns-query", "/dns-query" }
```

The encrypted transport setting is:

| Setting | Transport |
|---|---|
| `CFG_ENCRYPTED_USE_DOH=1` | DoH on `CFG_DOH_PORT`, the default |
| `CFG_ENCRYPTED_USE_DOH=0` | DoT on `CFG_DOT_PORT` |

`CFG_TLS_CA_DER_PATH` names a DER trust bundle that validates the configured
resolvers. Concatenate multiple DER certificates in that file when the
resolvers use different roots. The file is mapped read-only at startup and must
stay within `CFG_TLS_CA_MAX_BYTES`. DoH sends HTTP/1.1 POST requests with a
bounded response header. Three encrypted exchanges can run at once. Another
query gets `SERVFAIL` when those fixed slots are busy.

## Local names

The router hands out the leases, so this daemon never sees one. Give it the
names you care about instead, in the format `/etc/hosts` uses, at the path
`CFG_HOSTS_PATH` names:

```text
192.168.1.47   iPhone
192.168.1.10   nas printer
fd00::1        router
```

A name with no dot in it gets `CFG_LOCAL_DOMAIN` appended, so `iPhone` answers
as `iphone.lan`. The daemon serves `A`, `AAAA` and `PTR` from this file, before
the blocklist and before the cache.

Names in the local domain stay on the device. A name under `CFG_LOCAL_DOMAIN`
that the file does not list gets `NXDOMAIN` from the daemon rather than a query
to your upstream resolver. A known private reverse name is answered from the map.
An unknown IPv4 reverse name in `CFG_PTR_LOCAL_PREFIX_ADDR` with
`CFG_PTR_LOCAL_PREFIX_BITS` is sent to `CFG_PTR_ROUTER_ADDR`, which knows the
router's DHCP leases. Other private reverse names get `NXDOMAIN` here. Public
reverse names use the normal upstream route.

The conditional route is configured at build time:

```c
#define CFG_PTR_ROUTER_ADDR       "192.168.1.1"
#define CFG_PTR_ROUTER_PORT       53
#define CFG_PTR_LOCAL_PREFIX_ADDR "192.168.1.0"
#define CFG_PTR_LOCAL_PREFIX_BITS 24
```

Set `CFG_PTR_ROUTER_ADDR` to `NULL` to disable it.

## Build

The supported targets are `x86_64`, `aarch64`, `armv7` and `armv6`. ARMv6 and
ARMv7 are different targets.

```sh
make
make ARCH=armv6
make PROFILE=minimal
```

A cross build also needs a native compiler, because the generator that compiles
the embedded list runs on the build host. `HOSTCC` names it and defaults to
`gcc`.

Every target links static, and `-fstack-protector-strong` is always on. The
64-bit targets also link position independent, so they get ASLR. 32-bit ARM
does not, because gcc there accepts `-static-pie` and gives a dynamic binary.
The build reads the linked file and stops if the result needs a loader.

## Test

```sh
make test
```

This runs the unit tests and the end-to-end tests with AddressSanitizer and
UndefinedBehaviorSanitizer, then a short fuzz run. `make fuzz` builds the
libFuzzer target and needs clang. `make test-static` builds sanitizer-free wire,
cache, message, verification, blocklist and host-map tests. These tests can run
under emulation on the target instruction set. The encrypted profile also runs
the DoH/DoT state tests and the real mbedTLS backend test this way.

CI runs the host and encrypted tests, links both profiles and fuzzes against a
corpus that stays between runs. It then builds each target in an Alpine
container on that target's instruction set and runs the tests there. An x86
test cannot find an unaligned access fault on ARM1176. `ci/build.sh` runs the
same containers locally and needs docker with qemu binfmt handlers.

## Install

The daemon makes `/run/dns_blocker` at start-up when its account may write to
`/run`. The directory holds the synced list and the staging file that is renamed
onto it, and a tmpfs loses it at every boot.

### Under `init`

[`init`](https://github.com/SideQuestLabsX/init) runs the daemon as a generic
task. Install the binary as an `always` task, and the health probe beside it
under the name the supervisor expects:

```sh
install -Dm755 build/armv6-encrypted/dns_blocker /tasks/always/dns_blocker
install -Dm755 build/armv6-encrypted/dns_blocker.check /tasks/always/dns_blocker.check
install -dm755 /etc/dns_blocker
```

Port 53 and the query stream are per-task settings in `init`'s `config.h`:

```c
static const TaskRule TASK_RULES[] =
{
    /* bit 10 is CAP_NET_BIND_SERVICE */
    { .name = "dns_blocker", .uid = 65534, .capMask = CAP_BIT(10),
      .flags = RULE_CRITICAL, .outPolicy = LOGP_DROP },
    { .name = NULL },
};
```

`capMask` is retained across `execve`, so the daemon binds port 53 without
root. `outPolicy = LOGP_DROP` discards `stdout`, which carries one line per
answered query and names every domain every device resolved. `stderr` keeps the
shipped route and carries the operational messages. The probe runs with the
task's identity and capabilities, so it needs no entry of its own.

`RULE_CRITICAL` gates the hardware watchdog, so a device whose only purpose is
DNS reboots when this task stays unhealthy. Leave the flag out where the device
does other work.

A task rule with a `uid` also decides who owns the runtime directory. The
daemon creates `/run/dns_blocker` at start-up only where its own account may
write to `/run`, which for an unprivileged `uid` means a `boot` task creates it
first:

```sh
#!/bin/sh
mkdir -p /run/dns_blocker
chown 65534:65534 /run/dns_blocker
chmod 0750 /run/dns_blocker
```

Without the directory the daemon still resolves and filters. Only the blocklist
sync fails, and it says so on `stderr`.

### Under systemd

`deploy/dns_blocker.service` runs the daemon under systemd 247 or later. Put the
binary and the runtime files where the unit expects them:

```sh
sudo install -Dm755 build/x86_64-encrypted/dns_blocker /usr/local/sbin/dns_blocker
sudo install -Dm644 deploy/dns_blocker.service /etc/systemd/system/dns_blocker.service
sudo install -dm755 /etc/dns_blocker
sudo systemctl enable --now dns_blocker
```

The encrypted profile also needs the DER trust bundle at
`/etc/dns_blocker/ca.der`. Local names go in `/etc/dns_blocker/hosts`, and the
daemon starts without that file.

| Question | Answer |
|---|---|
| Which account | `DynamicUser=yes`. There is no account to create |
| Port 53 without root | `AmbientCapabilities=CAP_NET_BIND_SERVICE` |
| Who makes `/run/dns_blocker` | `RuntimeDirectory=dns_blocker`, owned by the service |
| The synced list after a restart | Kept, through `RuntimeDirectoryPreserve=yes` |
| The synced list after a reboot | Gone with the tmpfs, so the embedded list filters until the next sync |

The unit sends `stdout` to `/dev/null`, because it carries one line per answered
query and names every domain every device resolved. Set
`StandardOutput=journal` to keep that stream, or build with
`FEATURE_QUERY_LOG=0` to remove it from the binary. `stderr` carries the
operational messages and goes to the journal either way.

To run the daemon by hand instead, create `/run/dns_blocker` yourself and give
the binary the capability once:

```sh
sudo setcap cap_net_bind_service=+ep /usr/local/sbin/dns_blocker
```

[`init`](https://github.com/SideQuestLabsX/init) supervises the daemon as a
generic task and needs none of this.

## Health probe

`make check` builds `dns_blocker.check`. This small companion program resolves
a known-good name against `127.0.0.1:53`, examines the response and exits 0 or
non-zero. It exercises the socket, the parser, the cache and the response path
together, so it also finds a hang in any one of them. Any supervisor that runs
an exec probe can use it.

## Scope

This daemon prevents DNS-layer interference, such as a hijacked or poisoned
resolver. Authenticated DoH or DoT protects traffic between this daemon and the
upstream resolver.

This daemon cannot prevent SNI-layer blocking, because no traffic other than
DNS reaches the device. If `dig @1.1.1.1 <site>` gives the correct address and
the site still fails to load, the block is at the TLS layer. Use a tool in the
forwarding path, such as [zapret](https://github.com/bol-van/zapret) on the
router.

## Related

[`init`](https://github.com/SideQuestLabsX/init) is a freestanding init system
that can supervise this daemon. The two repositories have no build dependency
on each other, and `dns_blocker` also runs under systemd or from a shell.

## License

The source in this repository is [The Unlicense](LICENSE), public domain.

The published artifacts also contain third party work.
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) holds the full text of every
license involved.
