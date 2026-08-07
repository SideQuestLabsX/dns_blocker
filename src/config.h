#ifndef DNS_BLOCKER_CONFIG_H
#define DNS_BLOCKER_CONFIG_H

/* All build-time policy. There is no runtime configuration file. */

#define KIB(n) ((size_t)(n) * 1024u)
#define MIB(n) ((size_t)(n) * 1024u * 1024u)

/* Core boot arena. Every slice has a compile-time size and never grows, so
   the slices must add up to ARENA_TOTAL_BYTES. A _Static_assert in main.c
   holds the sum, so one slice cannot grow at the cost of another.

   The blocklist has its own mapping, because a compiled list gives its size at
   boot. See blocklist.h. The supervisor owns output routing, so the daemon
   writes lines and keeps no log buffer. */
#define ARENA_TOTAL_BYTES       KIB(2080)
#define ARENA_CACHE_BYTES       KIB(1536)
#define ARENA_TXTABLE_BYTES     KIB(128)
#define ARENA_CONN_BYTES        KIB(192)
#define ARENA_HOSTS_BYTES       KIB(32)

#if defined(PROFILE_ENCRYPTED)
  /* Backs MBEDTLS_MEMORY_BUFFER_ALLOC_C so the TLS stack never reaches libc. */
  #define ARENA_TLS_BYTES       KIB(192)
  #define ARENA_SPARE_BYTES     KIB(0)
#else
  #define ARENA_TLS_BYTES       KIB(0)
  #define ARENA_SPARE_BYTES     KIB(192)
#endif

/* Blocklist. Mapped separately from the arena at boot and sized from the
   compiled file. The cap bounds a hostile or accidentally huge list on a 512MB
   board. A list above it is refused and the embedded fallback is used.

   NULL consults no file, which leaves the list linked into .rodata as the whole
   policy. That is the air-gapped build, where a list is changed by re-flashing
   and by nothing else. */
#define CFG_BLOCKLIST_PATH      "/run/dns_blocker/blocklist.trie"
#define CFG_BLOCKLIST_MAX_BYTES MIB(16)

/* Local names. The router is the DHCP authority and this daemon never sees a
   lease, so the map is static: an address followed by the names it answers to,
   in the format /etc/hosts uses. A name without a dot gets CFG_LOCAL_DOMAIN
   appended. NULL for the path serves no local names at all.

   The TTL is short because the map is a statement about a LAN, where an address
   changes without anything being able to tell a client in advance. */
#define CFG_HOSTS_PATH          "/etc/dns_blocker/hosts"
#define CFG_LOCAL_DOMAIN        "lan"
#define CFG_HOSTS_MAX           96
#define CFG_LOCAL_TTL_SEC       60

/* A reverse query for a private address is answered here rather than forwarded.
   The upstream cannot know a LAN, so forwarding leaks the internal addressing
   and gets NXDOMAIN back anyway. RFC 6303 asks resolvers to serve these zones
   locally for the same reason. */
#define CFG_PRIVATE_PTR_LOCAL   1

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
#define CFG_TCP_SLOTS           16
#define CFG_TCP_MSG_BYTES       8192
#define CFG_TCP_IDLE_MS         5000
#define CFG_UDP_MSG_BYTES       1500

/* Cache. Clamps bound both thrash and staleness. */
#define CFG_CACHE_MIN_TTL_SEC   60
#define CFG_CACHE_MAX_TTL_SEC   86400

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
   the one with the lowest measured round trip, so no resolver receives the
   whole query stream. The order decides the boot choice and breaks a tie,
   because no measurement exists yet. Two independent operators, so one going
   down is not correlated with the other. */
#define CFG_UPSTREAM_ADDRS      { "1.1.1.1", "9.9.9.9" }
#define CFG_UPSTREAM_PORT       53

#if defined(PROFILE_ENCRYPTED)
  /* Authentication names follow CFG_UPSTREAM_ADDRS in the same order */
  #ifndef CFG_UPSTREAM_TLS_NAMES
    #define CFG_UPSTREAM_TLS_NAMES { "cloudflare-dns.com", "dns.quad9.net" }
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

/* Three TLS channels keep their record buffers within ARENA_TLS_BYTES */
#define CFG_TLS_SLOTS           3
#define CFG_TLS_HOSTNAME_BYTES  128
#define CFG_DOH_PATH_BYTES      64
#define CFG_DOH_HEADER_BYTES    1024
#define CFG_DOH_REQUEST_BYTES   512

/* Blocklist download. The release redirects twice and lands on a signed CDN
   URL of about 1.4KB, so the URL and header buffers are sized from that rather
   than from a round number. The body never lands in memory. */
#ifndef CFG_BLOCKLIST_URL
  #define CFG_BLOCKLIST_URL "https://github.com/SideQuestLabsX/dns_blocker/releases/download/blocklist-latest/dns_blocker-blocklist.trie"
#endif
#ifndef CFG_BLOCKLIST_DIGEST_URL
  #define CFG_BLOCKLIST_DIGEST_URL "https://github.com/SideQuestLabsX/dns_blocker/releases/download/blocklist-latest/dns_blocker-blocklist.trie.sha256"
#endif
#define CFG_BLOCKLIST_ASSET     "dns_blocker-blocklist.trie"
#define CFG_FETCH_URL_BYTES     2048
#define CFG_FETCH_HOST_BYTES    CFG_TLS_HOSTNAME_BYTES
#define CFG_FETCH_PATH_BYTES    1024
#define CFG_FETCH_HEADER_BYTES  4096
#define CFG_FETCH_MAX_REDIRECTS 4

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
