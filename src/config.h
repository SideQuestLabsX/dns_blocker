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
#define ARENA_TOTAL_BYTES       KIB(1024)
#define ARENA_CACHE_BYTES       KIB(768)
#define ARENA_TXTABLE_BYTES     KIB(64)

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
   board. A list above it is refused and the embedded fallback is used. */
#define CFG_BLOCKLIST_PATH      "/run/dns_blocker/blocklist.trie"
#define CFG_BLOCKLIST_MAX_BYTES MIB(16)

/* Listeners */
#define CFG_DNS_PORT            53
#define CFG_TCP_SLOTS           32
#define CFG_TCP_IDLE_MS         5000

/* Cache. Clamps bound both thrash and staleness. */
#define CFG_CACHE_MIN_TTL_SEC   60
#define CFG_CACHE_MAX_TTL_SEC   86400

/* Parser. A compression pointer must target a strictly earlier offset, and the
   jump count is capped independently of message size. */
#define CFG_MAX_NAME_BYTES      255
#define CFG_MAX_LABEL_BYTES     63
#define CFG_MAX_PTR_JUMPS       16
#define CFG_EDNS_PAYLOAD_BYTES  1232

/* Upstream */
#define CFG_UPSTREAM_TIMEOUT_MS 2000
#define CFG_UPSTREAM_RETRIES    2
#define CFG_MAX_UPSTREAMS       4

/* Blocked response: 0 = NXDOMAIN, 1 = NODATA, 2 = null address. */
#define CFG_BLOCK_POLICY        0

#endif
