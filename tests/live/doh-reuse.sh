#!/bin/sh
# Live check: one DoH channel carries many queries.
#
#   sh tests/live/doh-reuse.sh
#
# Needs outbound HTTPS and dig. It talks to the configured resolvers, so this is
# a network check rather than a unit test.
#
# CFG_TLS_IDLE_MS is ten minutes here, so the resolver is the side that decides
# when the channel closes. The shipped 30 s sweep closes first and hides the
# case this check exists for.
#
# The build carries no blocklist path, so nothing but these queries can take a
# TLS slot and the channel counters mean what they say.

. "$(dirname "$0")/common.sh"

Require dig make openssl

work=$LIVE_ROOT/doh-reuse
status=$work/status
ca=$work/ca.der
queries=${LIVE_QUERIES:-8}

rm -rf "$work"
mkdir -p "$work"

trap 'StopDaemon' EXIT INT TERM

TrustBundle "$ca"

Build "$work/build" "-DCFG_DNS_PORT=$LIVE_PORT \
 -DCFG_STATUS_PATH=$(Quoted "$status") \
 -DCFG_TLS_CA_DER_PATH=$(Quoted "$ca") \
 -DCFG_BLOCKLIST_PATH=NULL \
 -DCFG_HOSTS_PATH=NULL \
 -DCFG_TLS_IDLE_MS=600000"

bin=$work/build/dns_blocker

StartDaemon "$bin" "$work"

# Distinct names every run, because a repeat is answered from the cache and
# never reaches a channel at all
stamp=$(date +%s)
n=0
while [ "$n" -lt "$queries" ]; do
    Query "live-$stamp-$n.example.com" > /dev/null 2>&1 || true
    n=$((n + 1))
    sleep 1
done

report=$(Status "$bin" "$status")
channels=$(StatusLine "$report" channels)
counters=$(StatusLine "$report" queries)

opened=$(StatusCount "$channels" opened)
reused=$(StatusCount "$channels" reused)
stale=$(StatusCount "$channels" stale)
forwarded=$(StatusCount "$counters" forwarded)
failed=$(StatusCount "$counters" failed)

Note "live doh-reuse: channels $channels"
Note "live doh-reuse: queries $counters"

[ "${forwarded:-0}" -ge "$queries" ] \
    || Fail "live doh-reuse: $forwarded of $queries queries reached an upstream"
[ "${failed:-1}" -eq 0 ] \
    || Fail "live doh-reuse: $failed queries failed"
[ "${opened:-0}" -ge 1 ] \
    || Fail "live doh-reuse: no channel was opened"
[ "${reused:-0}" -gt 0 ] \
    || Fail "live doh-reuse: $opened handshakes and no reuse"

# Two upstreams and the rotating probe, so a run this short dials once or twice
[ "${opened:-0}" -le 4 ] \
    || Fail "live doh-reuse: $opened handshakes for $queries queries"

# The sweep is ten minutes out, so a stale channel here is one the resolver
# closed under a daemon that thought it still held it
[ "${stale:-1}" -eq 0 ] \
    || Fail "live doh-reuse: $stale channels went stale inside the run"

StopDaemon
Note "live doh-reuse: passed"
