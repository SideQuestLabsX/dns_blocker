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
#define ARENA_TOTAL_BYTES       KIB(1280)
#define ARENA_CACHE_BYTES       KIB(768)
#define ARENA_TXTABLE_BYTES     KIB(128)
#define ARENA_CONN_BYTES        KIB(192)

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

/* Listeners. TCP carries whatever exceeded the UDP payload size, so its buffer
   is sized well above CFG_EDNS_PAYLOAD_BYTES rather than at it. TCP DNS is rare
   on a LAN, so slots are few and the cap is generous instead of the reverse. */
#define CFG_DNS_PORT            53

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
#define CFG_UPSTREAM_ADDR       "1.1.1.1"
#define CFG_UPSTREAM_PORT       53
/* Guarded so a test can shrink the wait. Without the guard a -D override is
   silently discarded and the test still waits the shipped six seconds. */
#ifndef CFG_UPSTREAM_TIMEOUT_MS
  #define CFG_UPSTREAM_TIMEOUT_MS 2000
#endif
#ifndef CFG_UPSTREAM_RETRIES
  #define CFG_UPSTREAM_RETRIES    2
#endif
#define CFG_MAX_UPSTREAMS       4

/* Answer given for a blocked name. NXDOMAIN fails at once and the client moves
   on. A null address makes the client open a connection and wait for a timeout
   instead, which shows up as a stalled page. */
#define CFG_BLOCKED_RCODE       MSG_RCODE_NXDOMAIN

#endif
