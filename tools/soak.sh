#!/bin/sh
set -eu

# Samples a running daemon into a table, for an operational soak.
#
#   soak.sh [--binary PATH] [--status PATH] [--interval S] [--duration S]
#           [--out FILE] [--cap BYTES]
#
# It reads the status segment the daemon publishes and writes one row a sample
# to soak.tsv, the whole report to soak.log and a summary on exit. Nothing is
# sent to the daemon and nothing is written where it can see it, so a soak
# measures the daemon rather than this script.
#
# Ctrl-C ends the run and still prints the summary. Without --duration it runs
# until it is stopped.
#
# Every counter here is cumulative since the daemon started. A restart resets
# them, and the summary says so by reporting uptime going backwards.

. "$(dirname "$0")/statusfields.sh"

binary=dns_blocker
statusPath=
interval=60
duration=0
out=soak.tsv
cap=$((32 * 1024 * 1024))

while [ $# -gt 0 ]; do
    case $1 in
        --binary)   binary=$2; shift 2 ;;
        --status)   statusPath=$2; shift 2 ;;
        --interval) interval=$2; shift 2 ;;
        --duration) duration=$2; shift 2 ;;
        --out)      out=$2; shift 2 ;;
        --cap)      cap=$2; shift 2 ;;
        -h|--help)
            awk 'NR == 1 { next }
                 /^#/ { sub(/^# ?/, ""); print; started = 1; next }
                 started { exit }' "$0"
            exit 0
            ;;
        *)
            printf 'soak: unknown argument %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

for value in "$interval" "$duration" "$cap"; do
    case $value in
        ''|*[!0-9]*)
            printf 'soak: %s is not a number\n' "$value" >&2
            exit 1
            ;;
    esac
done

log=${out%.tsv}.log

Report()
{
    if [ -n "$statusPath" ]; then
        "$binary" --status "$statusPath"
    else
        "$binary" --status
    fi
}

Report > /dev/null 2>&1 || {
    printf 'soak: cannot read the status segment through %s\n' "$binary" >&2
    printf '  the segment is owned by the daemon, so this may need sudo\n' >&2
    exit 1
}

printf 'time\tuptime_s\tqueries\thits\tblocked\tlocal\tforwarded\tfailed\t' > "$out"
printf 'deferred\topened\treused\tstale\tcache_hits\tcache_misses\t' >> "$out"
printf 'cache_evictions\tcache_refused\ttrie_bytes\trss_kb\tsync\n' >> "$out"

: > "$log"

G_SAMPLES=0
G_STARTED=$(date +%s)

Summary()
{
    printf '\n'

    if [ "$G_SAMPLES" -lt 2 ]; then
        printf 'soak: %s samples, too few to compare\n' "$G_SAMPLES"
        return 0
    fi

    # Tab separated: the sync column carries spaces, and the default separator
    # would split it into columns of its own
    awk -F'\t' -v cap="$cap" -v samples="$G_SAMPLES" -v file="$out" '
        function delta(column) { return last[column] - first[column] }

        NR == 1 { for(i = 1; i <= NF; i++) column[$i] = i; next }
        NR == 2 { for(i = 1; i <= NF; i++) first[i] = $i }
        { for(i = 1; i <= NF; i++) last[i] = $i; rows++ }

        END {
            if(rows < 2)
                exit 0

            hours = (last[column["uptime_s"]] - first[column["uptime_s"]]) / 3600
            printf "soak: %d samples over %.2f h, from %s\n", samples, hours, file
            printf "  uptime      %s s at the end, %s at the start\n",
                   last[column["uptime_s"]], first[column["uptime_s"]]
            if(last[column["uptime_s"]] < first[column["uptime_s"]])
                printf "  RESTARTED   uptime went backwards, counters below are wrong\n"

            printf "  queries     %d, forwarded %d, failed %d, deferred %d\n",
                   delta(column["queries"]), delta(column["forwarded"]),
                   delta(column["failed"]), delta(column["deferred"])
            printf "  channels    opened %d, reused %d, stale %d\n",
                   delta(column["opened"]), delta(column["reused"]),
                   delta(column["stale"])
            printf "  cache       hits %d, misses %d, evictions %d, refused %d\n",
                   delta(column["cache_hits"]), delta(column["cache_misses"]),
                   delta(column["cache_evictions"]), delta(column["cache_refused"])
            printf "  blocklist   %d bytes, %.1f%% of the %d byte cap\n",
                   last[column["trie_bytes"]],
                   last[column["trie_bytes"]] * 100 / cap, cap
            printf "  rss         %s kB at the end, %s at the start\n",
                   last[column["rss_kb"]], first[column["rss_kb"]]

            # The segment holds the last snapshot of a daemon that has stopped,
            # so a sample can look healthy with nothing running behind it
            if(last[column["rss_kb"]] == 0)
                printf "  STOPPED     no process behind the pid in the segment\n"

            opens = delta(column["opened"])
            reuses = delta(column["reused"])
            if(opens + reuses > 0)
                printf "  reuse       %.1f%% of exchanges took a held channel\n",
                       reuses * 100 / (opens + reuses)

            hits = delta(column["cache_hits"])
            misses = delta(column["cache_misses"])
            if(hits + misses > 0)
                printf "  cache rate  %.1f%%\n", hits * 100 / (hits + misses)
        }' "$out"

    printf '\nEvery upstream line is in %s, one report a sample.\n' "$log"
}

trap 'exit 0' INT TERM
trap Summary EXIT

while :; do
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # A restart takes the segment with the tmpfs and makes it again, so one
    # unreadable sample ends that sample rather than the soak
    if ! report=$(Report 2>/dev/null); then
        printf '%s\nunreadable\n\n' "$now" >> "$log"
        sleep "$interval"
        continue
    fi

    printf '%s\n%s\n\n' "$now" "$report" >> "$log"

    counters=$(StatusLine "$report" queries)
    channels=$(StatusLine "$report" channels)
    cache=$(StatusLine "$report" cache)
    blocklist=$(StatusLine "$report" blocklist)
    sync=$(StatusLine "$report" sync)
    pid=$(StatusLine "$report" pid)

    rss=$(awk '/^VmRSS:/ { print $2 }' "/proc/${pid:-0}/status" 2>/dev/null \
          || true)
    rss=${rss:-0}

    # `uptime`, `queries` and `deferred` carry their number beside the key
    # itself, which the line reader has already taken off
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t' \
        "$now" \
        "$(StatusCount "$report" uptime)" \
        "$(StatusCount "$report" queries)" \
        "$(StatusCount "$counters" hits)" \
        "$(StatusCount "$counters" blocked)" \
        "$(StatusCount "$counters" local)" \
        "$(StatusCount "$counters" forwarded)" \
        "$(StatusCount "$counters" failed)" >> "$out"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(StatusCount "$report" deferred)" \
        "$(StatusCount "$channels" opened)" \
        "$(StatusCount "$channels" reused)" \
        "$(StatusCount "$channels" stale)" \
        "$(StatusCount "$cache" hits)" \
        "$(StatusCount "$cache" misses)" \
        "$(StatusCount "$cache" evictions)" \
        "$(StatusCount "$cache" refused)" \
        "$(StatusCount "$blocklist" bytes)" \
        "$rss" \
        "$sync" >> "$out"

    G_SAMPLES=$((G_SAMPLES + 1))

    if [ "$duration" -gt 0 ]; then
        elapsed=$(( $(date +%s) - G_STARTED ))
        [ "$elapsed" -lt "$duration" ] || break
    fi

    sleep "$interval"
done
