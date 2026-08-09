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

The file is a succinct trie over the reversed names: nodes are numbered
breadth-first, each degree is written in unary and each character is packed into
as few bits as the list's alphabet needs. Nothing in it is an offset, which is
where the size goes.

Point `CFG_BLOCKLIST_PATH` at the result.

The weekly workflow publishes an immutable dated release. A one-line file on
the `blocklist-pointer` branch names the current release:

```text
https://raw.githubusercontent.com/SideQuestLabsX/dns_blocker/blocklist-pointer/latest
```

The daemon reads that file, validates its dated release tag and derives the
digest and trie URLs from the same tag. The workflow updates the pointer only
after GitHub reports the dated release as published and immutable.

A release carries one set of assets per tier. A tier is how much the list
blocks. `tools/build-blocklist-release.sh` declares the sources of each one.

A base tier decides how hard ads and trackers are blocked:

| Base | Blocks |
|---|---|
| `compact` | The common ad and tracker names, and small enough to link into the binary |
| `standard` | Ads and trackers, and is not expected to break a site. The default |
| `aggressive` | Every rung the publishers offer. Blocks more, breaks more |

A base blocks ads and trackers and nothing else. Everything beyond that is a
category you choose. The more aggressive tiers breaks more legitimate use cases.

Categories are independent of the base and of each other. Every combination of
these five categories is published against every base:

| Category | Adds |
|---|---|
| `nsfw` | Adult domains |
| `tif` | Malware, phishing and command-and-control domains from threat-intelligence feeds |
| `gambling` | Betting and casino domains |
| `piracy` | File sharing and streaming piracy domains |
| `bypass` | Public resolvers, VPNs, proxies and Tor entry points, which a client can otherwise use to go around this daemon |

The name is the base followed by the categories in that order, so
`standard-nsfw-tif-gambling` is a tier and so is `aggressive-piracy` and so is
plain `compact`. Three bases against thirty-two subsets is 96 published lists,
and you take the combination you want rather than a bundle somebody else chose.

| Asset | Contents |
|---|---|
| `dns_blocker-blocklist-<tier>.trie` | The compiled list the daemon maps, one a tier |
| `dns_blocker-blocklist.sources` | Every source with its URL, size, accepted-name count and digest, then the composition of every tier |
| `dns_blocker-blocklist-sources.tar.gz` | The fetched lists themselves |
| `dns_blocker-blocklist.sha256` | A digest for every other asset in the release |
| `THIRD_PARTY_LICENSES.md` | The license terms the release carries |

`CFG_BLOCKLIST_TIER` selects the tier a build downloads. The same asset name is
used for the download and digest lookup, so a run cannot fetch one tier and
verify another.

To change the tier without rebuilding, write the name into `/etc/dns_blocker/tier`
and restart:

```sh
echo aggressive-nsfw-tif-gambling > /etc/dns_blocker/tier
systemctl restart dns_blocker
```

If the file is absent, the daemon uses `CFG_BLOCKLIST_TIER`. An invalid value is
reported once on `stderr` and ignored. A valid tier with no published trie stops
the sync and leaves the current list in place. `dns_blocker --status` reports
the selected tier.

During an update, `/run` holds the live trie and a staging copy. Allow twice the
trie size, and keep each trie below `CFG_BLOCKLIST_MAX_BYTES`.

To install one by hand, download the trie and the digest into a staging
directory on the same tmpfs as `CFG_BLOCKLIST_PATH`, check that one line, then
rename it into place:

```sh
cd /run/dns_blocker/update
grep '  dns_blocker-blocklist-standard.trie$' dns_blocker-blocklist.sha256 \
  | sha256sum -c
mv dns_blocker-blocklist-standard.trie /run/dns_blocker/blocklist.trie
```

Rename the trie to `CFG_BLOCKLIST_PATH` only after verification. The rename
keeps a complete old file in place until the new file is ready. The daemon uses
the embedded list when the mapped file is absent or its header is invalid. It
bounds every lookup inside a mapped body, but checksum verification is what
rejects body corruption.

The binary can carry a list of its own, for a device that never syncs. This is
the immutable build: the compiled-in list is the whole policy and changing it
means writing a new image. The build compiles the list with `mkblocklist -c`,
which writes the trie as a C array and links that into `.rodata`.

`EMBED_TIER` picks a published tier. The build downloads that tier's compiled
trie, checks it against the release digest and wraps it, so what gets linked is
the exact asset the release published:

```sh
make EMBED_TIER=compact
```

`EMBED_LIST` points at a domain list instead and wins over `EMBED_TIER`. A
`.gz` is expanded:

```sh
make EMBED_LIST=my-list.txt
```

Any tier can be embedded. The `compact` base is the one sized for it.

Both knobs are empty by default: a unit that syncs takes its list from a
release, and a list small enough to link without thinking about it blocks too
little to be worth trusting.

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

`CFG_TLS_CA_DER_PATH` names the DER trust bundle for the configured resolvers
and blocklist sync. The default sync connects to `raw.githubusercontent.com`,
`github.com`, `objects.githubusercontent.com` and
`release-assets.githubusercontent.com`. Concatenate their root certificates
and the resolver roots in that file. The file is mapped read-only at startup
and must stay within `CFG_TLS_CA_MAX_BYTES`. DoH sends HTTP/1.1 POST requests
with a bounded response header. Six encrypted exchanges can run at once. A
query waits in its transaction slot when all six are busy and gets `SERVFAIL`
only if its deadline expires.

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

The supported targets are:

| `ARCH` | Target |
|---|---|
| `x86_64` | 64-bit x86 |
| `x86` | 32-bit x86 |
| `aarch64` | 64-bit ARM |
| `armv7` | 32-bit ARMv7 with hard float |
| `armv6` | 32-bit ARMv6 with hard float |
| `riscv64` | 64-bit RISC-V |
| `loongarch64` | 64-bit LoongArch |
| `mips` | 32-bit big-endian MIPS32r2 |
| `mipsel` | 32-bit little-endian MIPS32r2 |

ARMv6 and ARMv7 are different targets.

```sh
make
make ARCH=armv6
make PROFILE=minimal
```

A cross build also needs a native compiler, because the generator that compiles
the embedded list runs on the build host. `HOSTCC` names it and defaults to
`gcc`.

Every target links static, and `-fstack-protector-strong` is always on. The
`x86_64`, `x86`, `aarch64` and `riscv64` Alpine builds also link position
independent. ARM, LoongArch and MIPS use static executables because their
selected toolchains do not produce a valid static PIE. The build reads the
linked file and stops if the result needs a loader.

The manually triggered `Binary release` workflow creates a dated tag such as
`binary-2026-08-09-31315414666-1` and publishes these assets:

| Asset | Contents |
|---|---|
| `dns_blocker-<arch>-minimal` | Minimal profile daemon |
| `dns_blocker-<arch>-encrypted` | Encrypted profile daemon |
| `dns_blocker-<arch>.check` | Health probe |
| `dns_blocker.sha256` | SHA-256 digest for every binary and the license file |
| `THIRD_PARTY_LICENSES.md` | License text shipped with the binaries |

Each binary is static musl. The release workflow builds and tests every
supported target before it publishes the release.

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
corpus that stays between runs. Alpine target toolchains build six targets in
containers. Zig builds LoongArch and both MIPS byte orders. QEMU runs each
non-x86 target on its instruction set. This exposes ARM1176 unaligned access
faults that x86 tests cannot reproduce.

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

## Status

The daemon keeps its current state in a small file at `CFG_STATUS_PATH`, beside
the blocklist. Reading it needs no signal, no port and no restart:

```sh
dns_blocker --status
```

```text
pid         941
uptime      2 s
queries     4, hits 1, blocked 0, local 0, forwarded 3, failed 0
refused     malformed 0, truncated 0, connections 0, evicted 0, retries 0
cache       hits 1, misses 3, inserts 3, evictions 0, refused 0
channels    opened 1, reused 2, stale 0
blocklist   mapped, 2717008 bytes, tier standard
sync        idle, next in 3600 s, installed 2717008 bytes
latency     service, n 4, min 41 us, mean 6.85 ms, p50 52 us, p90 27.30 ms, p99 27.30 ms, max 27.30 ms
upstream    1.1.1.1:53 plain, 27 ms, queries 3, failures 0, rejected 0, probes 0
latency       round trip, n 3, min 24.00 ms, mean 27.00 ms, p50 26.62 ms, p90 29.00 ms, p99 29.00 ms, max 29.00 ms
upstream    9.9.9.9:53 plain, unmeasured, queries 0, failures 0, rejected 0, probes 0
latency       round trip, no samples
```

Pass a path to read a segment somewhere else: `dns_blocker --status /run/x`.

`blocklist` shows the active list and selected tier. `latency` uses microseconds
below one millisecond. The minimum, mean and maximum are exact. Histogram
percentiles have up to one part in eight of error. `service` includes local,
cached and forwarded answers.

The same binary reads and writes it, so a reader can never hold a stale idea of
the layout. It maps the file read-only and exits, which cannot disturb a running
daemon. The header carries a version, and a reader refuses a segment it does not
recognise instead of printing nonsense.

The daemon writes a snapshot every `CFG_STATUS_PERIOD_MS` and once more on the
way out, so the file also says how a stopped daemon left things. It is on a
tmpfs and a reboot takes it.

Log lines and this file answer different questions. `stdout` and `stderr` are a
stream of events for whatever drains them. This is the current state, and
nothing has to be kept or parsed to sample it.

The file follows the directory it lives in: an operator who can read
`/run/dns_blocker` can read the status.

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
