# dns_blocker

A DNS filtering and forwarding daemon for embedded Linux. The daemon reserves
one memory arena at start-up and does no other allocation. It uses no database
engine and no scripting runtime. It links static musl, and mbedTLS for the
encrypted profile.

The daemon resolves names and filters them. It listens on UDP and TCP, parses
RFC 1035 messages, caches responses, blocks names from a compiled list and
forwards the rest to a plaintext upstream resolver.

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
| Upstream | Plaintext forwarding to one resolver, asynchronous, so a slow resolver delays only the client that asked |
| Filtering | A reverse-label trie with exact and suffix matches, so one entry covers a whole subtree |
| Blocked answers | `NXDOMAIN`, given before the cache and before the upstream |
| Hardening | Random transaction IDs, random source ports, 0x20 case in the question, and a bailiwick check on every answer |

These parts are not built yet: DNS-over-TLS, DNS-over-HTTPS, the local host map,
query logging and the shared memory status segment.

The daemon passes HTTPS and SVCB records through without change, so Encrypted
Client Hello continues to operate.

Keep the query stream off permanent storage. It is the largest output in the
system, frequent small appends are the worst write pattern for an SD card, and
the stream records every domain that each device on the network resolved. The
daemon writes only to `stdout`, so the supervisor makes this decision. With
systemd, set `StandardOutput=null`, or set journald `Storage=volatile`. If you
do not, the card receives every query.

The daemon serves TCP on port 53. A response that is larger than the UDP
payload size gets the `TC` bit, and the client sends the query again over TCP.

## Profiles

| Profile | Contents |
|---|---|
| `minimal` | The core engine and plaintext upstream forwarding |
| `encrypted` | Adds mbedTLS, DoH and DoT upstream, and blocklist release sync |

The default is `encrypted`, and it is the shipped image. mbedTLS is the only
external dependency, and only the `encrypted` profile needs it.

## Blocklists

`make tools` builds `mkblocklist`, which compiles domain lists into the file the
daemon maps. It reads one domain per line and hosts-file lines alike.

```sh
mkblocklist blocklist.trie list1.txt list2.txt
```

An entry blocks the name and every name below it, so `doubleclick.net` also
covers `ad.doubleclick.net`. The generator reloads its own output through the
daemon's lookup and fails if anything it inserted does not match.

Point `CFG_BLOCKLIST_PATH` at the result. If the file is missing or unreadable,
the daemon says so and forwards without filtering, because a resolver that
fails closed takes the network down with it.

## Build

The supported targets are `x86_64`, `aarch64`, `armv7` and `armv6`. ARMv6 and
ARMv7 are different targets.

```sh
make
make ARCH=armv6
make PROFILE=minimal
```

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
libFuzzer target and needs clang. `make test-static` builds the same tests
without sanitizers, so they cross-compile and run under emulation on the target
instruction set.

CI runs the host tests, links the encrypted profile and fuzzes against a corpus
that stays between runs. It then builds each target in an Alpine container on
that target's instruction set and runs the tests there. An x86 test cannot find
an unaligned access fault on ARM1176. `ci/build.sh` runs the same containers
locally, and needs docker with qemu binfmt handlers.

## Health probe

`make check` builds `dns_blocker.check`. This small companion program resolves
a known-good name against `127.0.0.1:53`, examines the response and exits 0 or
non-zero. It exercises the socket, the parser, the cache and the response path
together, so it also finds a hang in any one of them. Any supervisor that runs
an exec probe can use it.

## Scope

This daemon prevents DNS-layer interference, such as a hijacked or poisoned
resolver. DoH upstream prevents it for the whole network.

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

[The Unlicense](LICENSE). Public domain.
