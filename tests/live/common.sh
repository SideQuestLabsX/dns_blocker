# Shared mechanics for the live checks. Source it, do not run it.
#
# Each check compiles its own daemon, because everything they have to vary is a
# compile-time constant: the port, the file paths, the first sync delay and the
# TLS idle sweep. Overriding those through FEATURES also keeps a check out of
# /etc. Binding a fake one costs the namespace its /etc/alternatives, and awk
# disappears with it.

set -eu

LIVE_PORT=${LIVE_PORT:-15353}
LIVE_ROOT=${LIVE_ROOT:-build/live}
LIVE_MBEDTLS_DIR=${LIVE_MBEDTLS_DIR:-build/x86_64-encrypted/mbedtls}

# The status segment is republished every CFG_STATUS_PERIOD_MS, so a read taken
# straight after a query run returns the snapshot from before it
LIVE_SNAPSHOT_WAIT=${LIVE_SNAPSHOT_WAIT:-2}

G_DAEMON_PID=

Fail()
{
    printf '%s\n' "$*" >&2
    exit 1
}

Note()
{
    printf '%s\n' "$*"
}

Require()
{
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || Fail "live: $tool is required"
    done
}

# A string macro has to survive make and then the shell that runs the compiler
Quoted()
{
    printf '\\"%s\\"' "$1"
}

Build() # <build dir> <features>
{
    if ! make PROFILE=encrypted BUILD="$1" MBEDTLS_DIR="$LIVE_MBEDTLS_DIR" \
              FEATURES="$2" > "$1.log" 2>&1; then
        sed 's/^/  /' "$1.log" >&2
        Fail "live: the build failed"
    fi
}

# dns.google answers from a set of chains and one of them roots on a
# cross-signed authority, so the tool collects a root from one connection and
# can fail to verify it on the next. Seen once in about ten runs
TrustBundle() # <output>
{
    n=0
    while [ "$n" -lt 3 ]; do
        if sh tools/make-trust-bundle.sh "$1" > "$1.log" 2>&1; then
            return 0
        fi

        n=$((n + 1))
        sleep 2
    done

    sed 's/^/  /' "$1.log" >&2
    Fail "live: no trust bundle after 3 attempts. Is the network up"
}

Query() # <name>
{
    dig +tries=1 +time=3 @127.0.0.1 -p "$LIVE_PORT" "$1" A
}

StartDaemon() # <binary> <work directory>
{
    "$1" > "$2/queries.log" 2> "$2/daemon.log" &
    G_DAEMON_PID=$!

    # An answer is the only proof it is listening
    n=0
    while [ "$n" -lt 20 ]; do
        if Query example.com > /dev/null 2>&1; then
            return 0
        fi

        kill -0 "$G_DAEMON_PID" 2>/dev/null || break
        n=$((n + 1))
        sleep 1
    done

    sed 's/^/  /' "$2/daemon.log" >&2
    Fail "live: the daemon never answered on port $LIVE_PORT"
}

StopDaemon()
{
    [ -n "$G_DAEMON_PID" ] || return 0

    kill "$G_DAEMON_PID" 2>/dev/null || true
    wait "$G_DAEMON_PID" 2>/dev/null || true
    G_DAEMON_PID=
}

Status() # <binary> <status path>
{
    sleep "$LIVE_SNAPSHOT_WAIT"
    "$1" --status "$2" || Fail "live: cannot read the status segment"
}

# One line of a status report, without its leading key
Line() # <report> <key>
{
    printf '%s\n' "$1" | awk -v key="$2" '
        $1 == key { $1 = ""; sub(/^ +/, ""); print; exit }'
}

# The number a label carries. The report writes both orders, `reused 12` and
# `12 bytes`, so each pair is read from either side. Commas belong to the
# report, so a word is stripped to its own alphabet before it is compared
Count() # <line> <label>
{
    printf '%s\n' "$1" | awk -v want="$2" '
        function word(s) { gsub(/[^a-z0-9]/, "", s); return s }
        {
            # Label first, because `local 0, forwarded 9` reads as a value
            # before `forwarded` as well, and that reading is the wrong one
            for(i = 1; i < NF; i++)
            {
                if(word($i) == want && word($(i + 1)) ~ /^[0-9]+$/)
                {
                    print word($(i + 1))
                    exit
                }
            }

            for(i = 1; i < NF; i++)
            {
                if(word($(i + 1)) == want && word($i) ~ /^[0-9]+$/)
                {
                    print word($i)
                    exit
                }
            }
        }'
}
