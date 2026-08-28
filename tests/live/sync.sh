#!/bin/sh
# Live check: the blocklist sync against the published release.
#
#   sh tests/live/sync.sh
#
# Needs outbound HTTPS and dig. It downloads the compact tier from the current
# release, so this is a network check rather than a unit test.
#
# Two runs over one work directory. The first installs a list and filters with
# it. The second hashes the list it already has, matches the published digest
# and downloads nothing. That second path only exists against a real release,
# which is why it survived a green suite once already.

. "$(dirname "$0")/common.sh"

Require dig make openssl sha256sum

work=$LIVE_ROOT/sync
status=$work/status
trie=$work/blocklist.trie
ca=$work/ca.der

rm -rf "$work"
mkdir -p "$work"

trap 'StopDaemon' EXIT INT TERM

TrustBundle "$ca"

Build "$work/build" "-DCFG_DNS_PORT=$LIVE_PORT \
 -DCFG_STATUS_PATH=$(Quoted "$status") \
 -DCFG_BLOCKLIST_PATH=$(Quoted "$trie") \
 -DCFG_TLS_CA_DER_PATH=$(Quoted "$ca") \
 -DCFG_BLOCKLIST_TIER=$(Quoted compact) \
 -DCFG_BLOCKLIST_TIER_PATH=NULL \
 -DCFG_HOSTS_PATH=NULL \
 -DCFG_SYNC_FIRST_MS=3000 \
 -DCFG_SYNC_RETRY_MS=20000"

bin=$work/build/dns_blocker

Note "live sync: first run, expecting a download"
StartDaemon "$bin" "$work"

n=0
while [ "$n" -lt 90 ]; do
    if grep -q 'sync: installed' "$work/daemon.log"; then
        break
    fi

    if grep -q 'retrying in' "$work/daemon.log"; then
        sed 's/^/  /' "$work/daemon.log" >&2
        Fail "live sync: the sync failed"
    fi

    n=$((n + 1))
    sleep 2
done

grep -q 'sync: installed' "$work/daemon.log" \
    || Fail "live sync: nothing was installed within 180 s"

report=$(Status "$bin" "$status")
blocklist=$(Line "$report" blocklist)
bytes=$(Count "$blocklist" bytes)

case $blocklist in
    mapped,*) ;;
    *) Fail "live sync: the installed list is not mapped: $blocklist" ;;
esac

[ "${bytes:-0}" -gt 0 ] || Fail "live sync: the mapped list is empty"
Note "live sync: $blocklist"

# A downloaded list that filters nothing would still map and still report
# healthy, so one of these names has to be refused
blocked=0
for name in doubleclick.net googlesyndication.com google-analytics.com; do
    if Query "$name" | grep -q 'status: NXDOMAIN'; then
        blocked=$((blocked + 1))
    fi
done

[ "$blocked" -gt 0 ] || Fail "live sync: the compact tier blocked none of the probes"
Query example.com | grep -q 'status: NOERROR' \
    || Fail "live sync: a name that is not on the list did not resolve"

Note "live sync: $blocked of 3 probes blocked, second run, expecting no download"

StopDaemon
before=$(sha256sum "$trie" | cut -d' ' -f1)
: > "$work/daemon.log"

StartDaemon "$bin" "$work"

# A finished run schedules CFG_SYNC_PERIOD_MS, so a due time past the hour says
# this run ended. The first one is three seconds out
n=0
while [ "$n" -lt 90 ]; do
    report=$(Status "$bin" "$status")
    sync=$(Line "$report" sync)
    due=$(Count "$sync" in)

    case $sync in
        idle,*)
            if [ "${due:-0}" -gt 3600 ]; then
                break
            fi
            ;;
    esac

    n=$((n + 1))
done

[ "${due:-0}" -gt 3600 ] || Fail "live sync: the second run did not finish"

if grep -q 'sync: installed' "$work/daemon.log"; then
    Fail "live sync: the second run downloaded a list it already had"
fi

if grep -q 'retrying in' "$work/daemon.log"; then
    sed 's/^/  /' "$work/daemon.log" >&2
    Fail "live sync: the second run failed"
fi

# The sync line reports the size of the live list, so the skipped run has to
# leave the same number the first run mapped
installed=$(Count "$sync" installed)
[ "${installed:-0}" -eq "$bytes" ] \
    || Fail "live sync: the list is $installed bytes, was $bytes"

after=$(sha256sum "$trie" | cut -d' ' -f1)
[ "$before" = "$after" ] || Fail "live sync: the list changed under a skipped run"

StopDaemon
Note "live sync: passed"
