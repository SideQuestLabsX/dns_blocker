# dns_blocker

A DNS filtering and forwarding daemon for embedded Linux. The daemon reserves
one memory arena at start-up and does no other allocation. It uses no database
engine and no scripting runtime. It links static musl, and mbedTLS for the
encrypted profile.

The boot arena, the memory budget and the health probe are built. The daemon
does not resolve names yet: it reports its memory budget and exits non-zero. The
table below gives the target behavior.

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
| Filtering | A reverse-label trie with exact and suffix matches, for example `*.doubleclick.net` |
| Blocked answers | `NXDOMAIN` by default, with `NODATA` and null-address alternatives |
| Caching | Keeps each TTL and decrements it by the time that passed, negative caching to RFC 2308, CLOCK eviction |
| Listeners | UDP and TCP on port 53, IPv4 and IPv6, with EDNS0 support |
| Upstream | Plaintext, DNS-over-TLS or DNS-over-HTTPS |
| Hardening | Random transaction IDs and source ports, bailiwick checking, bounded in-flight state |
| Logging | One line for each query to `stdout`, one line for each fault to `stderr`. The daemon keeps no log |
| Status | A read-only shared memory segment with counters and recent queries |

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

## Build

The supported targets are `x86_64`, `aarch64`, `armv7` and `armv6`. ARMv6 and
ARMv7 are different targets.

```sh
make
make ARCH=armv6
make PROFILE=minimal
```

The build is static PIE with `-fstack-protector-strong`. A daemon that parses
data from the network needs both. The build examines the linked file and stops
if the toolchain gave a dynamic binary.

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
