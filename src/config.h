#ifndef DNS_BLOCKER_CONFIG_H
#define DNS_BLOCKER_CONFIG_H

/* Build-time defaults. CFG_BLOCKLIST_TIER_PATH may override the tier at boot */

#define KIB(n) ((size_t)(n) * 1024u)
#define MIB(n) ((size_t)(n) * 1024u * 1024u)

/* Query logs contain client domains. Zero removes the call sites */
#ifndef FEATURE_QUERY_LOG
  #define FEATURE_QUERY_LOG 1
#endif

/* Zero removes service-path clock reads. Upstream ranking still samples RTT */
#ifndef FEATURE_LATENCY_STATS
  #define FEATURE_LATENCY_STATS 1
#endif

/* Core boot arena. Every slice has a compile-time size and never grows, so
   the slices must add up to ARENA_TOTAL_BYTES. A _Static_assert in main.c
   holds the sum, so one slice cannot grow at the cost of another. Override
   any slice with -D; main.c asserts the sum and alignment at compile time.

   The blocklist has its own mapping, because a compiled list gives its size at
   boot. See blocklist.h. The supervisor owns output routing, so the daemon
   writes lines and keeps no log buffer. */
#ifndef ARENA_TOTAL_BYTES
  #define ARENA_TOTAL_BYTES     KIB(2272)
#endif
#ifndef ARENA_CACHE_BYTES
  #define ARENA_CACHE_BYTES     KIB(1536)
#endif
#ifndef ARENA_TXTABLE_BYTES
  #define ARENA_TXTABLE_BYTES   KIB(128)
#endif
#ifndef ARENA_CONN_BYTES
  #define ARENA_CONN_BYTES      KIB(192)
#endif
#ifndef ARENA_HOSTS_BYTES
  #define ARENA_HOSTS_BYTES     KIB(32)
#endif

#if defined(PROFILE_ENCRYPTED)
  /* Backs MBEDTLS_MEMORY_BUFFER_ALLOC_C so the TLS stack never reaches libc.
     64KB a channel, so this follows CFG_TLS_SLOTS */
  #ifndef ARENA_TLS_BYTES
    #define ARENA_TLS_BYTES     KIB(384)
  #endif
  #ifndef ARENA_SPARE_BYTES
    #define ARENA_SPARE_BYTES   KIB(0)
  #endif
#else
  #ifndef ARENA_TLS_BYTES
    #define ARENA_TLS_BYTES     KIB(0)
  #endif
  #ifndef ARENA_SPARE_BYTES
    #define ARENA_SPARE_BYTES   KIB(384)
  #endif
#endif

/* Blocklist. Mapped separately from the arena at boot and sized from the
   compiled file. The cap bounds a hostile or accidentally huge list on a 512MB
   board. A list above it is refused and any linked-in list is used.

   NULL consults no file, which leaves the list linked into .rodata as the whole
   policy. That is the build for a device that never syncs, where a list changes
   by writing a new image and by nothing else. */
#ifndef CFG_BLOCKLIST_PATH
  #define CFG_BLOCKLIST_PATH    "/run/dns_blocker/blocklist.trie"
#endif
/* Guarded like the rest, so a measurement can raise it. Without the guard a -D
   override is silently discarded and the run reports the shipped cap.

   **The cap is a memory limit, not an address space limit.** CFG_BLOCKLIST_PATH
   is on a tmpfs, so the file's pages are RAM whether anything maps them or not,
   and the sync holds the staging copy and the live one at once. 32MB therefore
   costs up to 64MB of a 426MB board while a sync runs. Mapping the file is what
   keeps a lookup from copying it, and it does not make the bytes free.

   Two more reasons it cannot simply be removed: `st_size` is assigned to a
   size_t, which is 32 bits on the board, and the daemon must refuse a hostile
   list rather than discover its size by running out. A device with more memory
   raises this knob. */
#ifndef CFG_BLOCKLIST_MAX_BYTES
  #define CFG_BLOCKLIST_MAX_BYTES MIB(32)
#endif

/* Read-only state for anything that wants to look, beside the list it shares a
   directory with. NULL publishes nothing. The interval bounds the write rate:
   a snapshot is a few hundred bytes and the serve loop would otherwise take one
   per packet. */
#ifndef CFG_STATUS_PATH
  #define CFG_STATUS_PATH       "/run/dns_blocker/status"
#endif
#ifndef CFG_STATUS_PERIOD_MS
  #define CFG_STATUS_PERIOD_MS  1000u
#endif

/* Local names. The router is the DHCP authority and this daemon never sees a
   lease, so the map is static: an address followed by the names it answers to,
   in the format /etc/hosts uses. A name without a dot gets CFG_LOCAL_DOMAIN
   appended. NULL for the path serves no local names at all.

   The TTL is short because the map is a statement about a LAN, where an address
   changes without anything being able to tell a client in advance. */
/* Guarded like the rest, so a test run can point them somewhere writable.
   Without the guard a -D override is silently discarded and the run tests the
   shipped path instead of the one it asked for */
#ifndef CFG_HOSTS_PATH
  #define CFG_HOSTS_PATH        "/etc/dns_blocker/hosts"
#endif
#ifndef CFG_LOCAL_DOMAIN
  #define CFG_LOCAL_DOMAIN      "lan"
#endif
#ifndef CFG_HOSTS_MAX
  #define CFG_HOSTS_MAX         96
#endif
#ifndef CFG_LOCAL_TTL_SEC
  #define CFG_LOCAL_TTL_SEC     60
#endif

/* A reverse query for a private address is answered here rather than forwarded.
   The upstream cannot know a LAN, so forwarding leaks the internal addressing
   and gets NXDOMAIN back anyway. RFC 6303 asks resolvers to serve these zones
   locally for the same reason. */
#ifndef CFG_PRIVATE_PTR_LOCAL
  #define CFG_PRIVATE_PTR_LOCAL 1
#endif

/* Unknown IPv4 PTR names in this prefix go to the router that knows the DHCP
   leases. Set CFG_PTR_ROUTER_ADDR to NULL to keep unknown private PTR names
   local */
#ifndef CFG_PTR_ROUTER_ADDR
  #define CFG_PTR_ROUTER_ADDR       "192.168.1.1"
#endif
#ifndef CFG_PTR_ROUTER_PORT
  #define CFG_PTR_ROUTER_PORT       53
#endif
#ifndef CFG_PTR_LOCAL_PREFIX_ADDR
  #define CFG_PTR_LOCAL_PREFIX_ADDR  "192.168.1.0"
#endif
#ifndef CFG_PTR_LOCAL_PREFIX_BITS
  #define CFG_PTR_LOCAL_PREFIX_BITS 24
#endif

/* Listeners. TCP carries whatever exceeded the UDP payload size, so its buffer
   is sized well above CFG_EDNS_PAYLOAD_BYTES rather than at it. TCP DNS is rare
   on a LAN, so slots are few and the cap is generous instead of the reverse. */
#ifndef CFG_DNS_PORT
  #define CFG_DNS_PORT          53
#endif

/* In-flight upstream queries. Each slot keeps the query, so a retry can resend
   it and a failure can echo its question back. At capacity the oldest slot is
   taken, which displaces the query closest to giving up instead of refusing
   the new one. */
#define CFG_TX_SLOTS            64
#define CFG_TX_QUERY_BYTES      512

/* The last slot belongs to the daemon's own lookups, which today means the
   blocklist sync resolving a release host. Client traffic cannot reach it, so
   a burst that fills the table cannot starve the sync, and the sync cannot
   evict a client query to make room for itself. */
#define CFG_TX_CLIENT_SLOTS     (CFG_TX_SLOTS - 1)
#define CFG_TX_INTERNAL_SLOT    (CFG_TX_SLOTS - 1)
#define CFG_TCP_SLOTS           16
#define CFG_TCP_MSG_BYTES       8192
#define CFG_TCP_IDLE_MS         5000
#define CFG_UDP_MSG_BYTES       1500

/* Cache. Clamps bound both thrash and staleness. */
#ifndef CFG_CACHE_MIN_TTL_SEC
  #define CFG_CACHE_MIN_TTL_SEC 60
#endif
#ifndef CFG_CACHE_MAX_TTL_SEC
  #define CFG_CACHE_MAX_TTL_SEC 86400
#endif

/* Set-associative. A lookup or an insert touches one bucket only. This bounds
   the probe to CFG_CACHE_WAYS entries and keeps indexing to a mask. ARMv6 has
   no hardware divide, so a modulo here would call libgcc on the hot path.

   The cache refuses a response larger than CFG_CACHE_ENTRY_BYTES, and one that
   carries more than CFG_CACHE_MAX_TTLS records. The daemon still serves
   both. */
#define CFG_CACHE_WAYS          8
#define CFG_CACHE_ENTRY_BYTES   640
#define CFG_CACHE_MAX_TTLS      16

/* Parser. A compression pointer must target a strictly earlier offset, and the
   jump count is capped independently of message size. */
#define CFG_MAX_NAME_BYTES      255
#define CFG_MAX_LABEL_BYTES     63
#define CFG_MAX_PTR_JUMPS       16
#define CFG_EDNS_PAYLOAD_BYTES  1232

/* Upstream. 0x20 encoding randomises the case of the question sent upstream.
   A resolver echoes the question unchanged, so an attacker who wants to forge
   a response must guess the case of every letter as well as the transaction ID
   and the source port. */
#define CFG_UPSTREAM_0X20       1

/* Literal addresses only, in preference order. Each query goes to one of them,
   the one with the lowest measured round trip. Selection is by latency alone,
   so a consistently faster resolver receives essentially the whole stream and
   the others see only the rotating probe: a second address buys failover, not a
   split. The order decides the boot choice and breaks a tie, because no
   measurement exists yet. Two independent operators, so one going down is not
   correlated with the other.

   CFG_UPSTREAM_ADDRS, CFG_UPSTREAM_TLS_NAMES and CFG_UPSTREAM_DOH_PATHS share
   indices and must be overridden together. */
#ifndef CFG_UPSTREAM_ADDRS
  #define CFG_UPSTREAM_ADDRS    { "1.1.1.1", "8.8.8.8" }
#endif
#ifndef CFG_UPSTREAM_PORT
  #define CFG_UPSTREAM_PORT     53
#endif

#if defined(PROFILE_ENCRYPTED)
  /* Authentication names follow CFG_UPSTREAM_ADDRS in the same order.
     Both endpoints have to answer HTTP/1.1, which is what this client speaks.
     Measured: Cloudflare, Google and AdGuard return 200, Quad9 returns 505 and
     is DoH over HTTP/2 only. Quad9 works on DoT, so it belongs in the pool only
     with CFG_ENCRYPTED_USE_DOH set to 0 */
  #ifndef CFG_UPSTREAM_TLS_NAMES
    #define CFG_UPSTREAM_TLS_NAMES { "cloudflare-dns.com", "dns.google" }
  #endif
  #ifndef CFG_DOT_PORT
    #define CFG_DOT_PORT            853
  #endif
  #ifndef CFG_DOH_PORT
    #define CFG_DOH_PORT            443
  #endif
  #ifndef CFG_ENCRYPTED_USE_DOH
    #define CFG_ENCRYPTED_USE_DOH   1
  #endif
  #ifndef CFG_UPSTREAM_DOH_PATHS
    #define CFG_UPSTREAM_DOH_PATHS  { "/dns-query", "/dns-query" }
  #endif
  #ifndef CFG_TLS_CA_DER_PATH
    #define CFG_TLS_CA_DER_PATH     "/etc/dns_blocker/ca.der"
  #endif
  #ifndef CFG_TLS_CA_MAX_BYTES
    #define CFG_TLS_CA_MAX_BYTES    KIB(16)
  #endif
#endif
/* Guarded so a test can shrink the wait. Without the guard a -D override is
   silently discarded and the test still waits the shipped six seconds. */
#ifndef CFG_UPSTREAM_TIMEOUT_MS
  #define CFG_UPSTREAM_TIMEOUT_MS 2000
#endif
#ifndef CFG_UPSTREAM_RETRIES
  #define CFG_UPSTREAM_RETRIES    2
#endif
#define CFG_MAX_UPSTREAMS       4

/* A slot is held for a whole exchange, and an exchange that has to handshake
   costs 350 to 430ms on ARM1176. Six covers the burst one device makes when it
   wakes up and asks for six names at once, together with the queue in server.c.
   The record buffers have to stay within ARENA_TLS_BYTES, which is sized
   alongside this. */
#define CFG_TLS_SLOTS           6

/* The sync holds a slot for a whole trie download, minutes on ARM1176, so it is
   refused below this many free. Its 15 minute retry makes refusal cheap */
#ifndef CFG_TLS_FETCH_MIN_FREE_SLOTS
  #define CFG_TLS_FETCH_MIN_FREE_SLOTS 2
#endif
#define CFG_TLS_HOSTNAME_BYTES  128
#define CFG_DOH_PATH_BYTES      64
#define CFG_DOH_HEADER_BYTES    1024
#define CFG_DOH_REQUEST_BYTES   512

/* Channel reuse. An answered channel stays open against the resolver it was
   opened to, and the next query for that resolver skips the handshake, which is
   where the whole 350ms sits. A server closing an idle channel is ordinary, so a
   query that finds a dead one is resent on a fresh channel and no resolver is
   blamed for it.

   The idle timeout is the client's own, well under the 60 to 75s an HTTP server
   usually keeps a connection for, so this side closes first and a query rarely
   meets a channel the server has already dropped. 0 closes every channel after
   one exchange. */
#ifndef CFG_TLS_REUSE
  #define CFG_TLS_REUSE         1
#endif
#ifndef CFG_TLS_IDLE_MS
  #define CFG_TLS_IDLE_MS       30000
#endif

/* A held channel can be dead with neither side saying so: a NAT or a middlebox
   drops an idle TCP mapping and sends nothing, so the write succeeds into
   nowhere and no answer or close ever arrives. A reused exchange that has
   received nothing therefore gives up early and goes out again on a fresh
   channel. Measured: a channel idle for seven minutes cost 2238ms and a failure
   against a resolver that was working.

   Keep this above a healthy reused round trip, which is the upstream RTT with no
   handshake in it, or a slow answer is abandoned for a second one. */
#ifndef CFG_TLS_REUSE_TIMEOUT_MS
  #define CFG_TLS_REUSE_TIMEOUT_MS 1000
#endif

/* Blocklist download. A locator branch names one immutable dated release. The
   daemon accepts only the release tag and derives both asset URLs itself */
#ifndef CFG_BLOCKLIST_TIER
  #define CFG_BLOCKLIST_TIER    "standard"
#endif

/* Optional one-line tier override. Missing or empty uses the compiled tier.
   Malformed content reports once and uses the compiled tier. NULL skips it */
#ifndef CFG_BLOCKLIST_TIER_PATH
  #define CFG_BLOCKLIST_TIER_PATH "/etc/dns_blocker/tier"
#endif

/* Bounds the composed asset name, and the status field that reports it */
#define CFG_BLOCKLIST_TIER_BYTES  64
#define CFG_BLOCKLIST_ASSET_BYTES (CFG_BLOCKLIST_TIER_BYTES + 32)
#ifndef CFG_BLOCKLIST_LOCATOR_URL
  #define CFG_BLOCKLIST_LOCATOR_URL \
      "https://raw.githubusercontent.com/SideQuestLabsX/dns_blocker/blocklist-pointer/latest"
#endif
#ifndef CFG_BLOCKLIST_RELEASE_BASE_URL
  #define CFG_BLOCKLIST_RELEASE_BASE_URL \
      "https://github.com/SideQuestLabsX/dns_blocker/releases/download/"
#endif
#define CFG_BLOCKLIST_DIGEST_ASSET "dns_blocker-blocklist.sha256"
/* Asset for the compiled tier. Runtime sync uses the effective tier */
#define CFG_BLOCKLIST_ASSET     "dns_blocker-blocklist-" CFG_BLOCKLIST_TIER ".trie"
#define CFG_FETCH_URL_BYTES     2048
#define CFG_FETCH_HOST_BYTES    CFG_TLS_HOSTNAME_BYTES
#define CFG_FETCH_PATH_BYTES    1024
/* Holds a whole header block, measured at 5191 bytes on github.com's 302: a
   949-byte signed Location beside a 2KB Content-Security-Policy */
#define CFG_FETCH_HEADER_BYTES  16384
#define CFG_FETCH_MAX_REDIRECTS 4
/* One budget for the initial URL, redirects and same-URL read retries */
#ifndef CFG_FETCH_TIMEOUT_MS
  #define CFG_FETCH_TIMEOUT_MS  (10u * 60u * 1000u)
#endif
/* A peer can close between the request and the complete response header */
#ifndef CFG_FETCH_READ_RETRIES
  #define CFG_FETCH_READ_RETRIES 2
#endif
_Static_assert(CFG_FETCH_READ_RETRIES > 0,
               "a fetch must retry a transient response close");
/* Sized from the path and host caps. The signed CDN path is 905 bytes */
#define CFG_FETCH_REQUEST_BYTES (CFG_FETCH_PATH_BYTES + CFG_FETCH_HOST_BYTES + 128)

#define CFG_SYNC_RELEASE_TAG_BYTES 96
/* The 99-line digest is 11649 bytes with the current tier names */
#define CFG_SYNC_DIGEST_BYTES   16384
#define CFG_SYNC_PATH_BYTES     256

/* The first attempt happens after the daemon is already serving, because the
   clock may still be unstepped at boot and certificate validation needs it.
   A failure backs off to the retry interval rather than the full period. */
#ifndef CFG_SYNC_FIRST_MS
  #define CFG_SYNC_FIRST_MS     (120u * 1000u)
#endif
#ifndef CFG_SYNC_PERIOD_MS
  #define CFG_SYNC_PERIOD_MS    (6u * 3600u * 1000u)
#endif
#ifndef CFG_SYNC_RETRY_MS
  #define CFG_SYNC_RETRY_MS     (15u * 60u * 1000u)
#endif

/* Latency probing. A real answer times the selected upstream for free, so a
   probe only has to measure the others. One probe goes to one upstream on this
   interval and the target rotates, which keeps an unselected resolver seeing a
   trickle rather than traffic. The daemon does not probe while it is idle, so a
   device nobody is querying stays silent. */
#ifndef CFG_UPSTREAM_PROBE_MS
  #define CFG_UPSTREAM_PROBE_MS   30000
#endif
#define CFG_UPSTREAM_PROBE_NAME "example.com"

/* Health. A run of failures takes an upstream out of selection until the hold
   expires. Selection never refuses to forward: with every upstream held down
   the best of them is used anyway, because a resolver that fails closed takes
   the network down. */
#ifndef CFG_UPSTREAM_DOWN_FAILURES
  #define CFG_UPSTREAM_DOWN_FAILURES 3
#endif
#ifndef CFG_UPSTREAM_DOWN_MS
  #define CFG_UPSTREAM_DOWN_MS    60000
#endif

/* Answer given for a blocked name. NXDOMAIN fails at once and the client moves
   on. A null address makes the client open a connection and wait for a timeout
   instead, which shows up as a stalled page. */
#define CFG_BLOCKED_RCODE       MSG_RCODE_NXDOMAIN

#endif
