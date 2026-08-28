#!/bin/sh
set -eu

# Builds the bounded DER trust anchor the encrypted profile needs.
#
#   make-trust-bundle.sh [output]
#   make-trust-bundle.sh --print-env
#
# Default output is build/ca.der, installed to CFG_TLS_CA_DER_PATH.
#
# The daemon parses concatenated DER, not PEM, and maps the file under
# CFG_TLS_CA_MAX_BYTES. A whole system store is around 150 KB and is refused, so
# this collects only the roots the configured endpoints actually chain to.
#
# The cap and the host list come from src/config.h. A release package has no
# header, so it carries trust-bundle.env beside this script, which --print-env
# writes from the same parse.
#
# Roots rotate. Regenerate after changing an upstream, and again if the sync and
# DoH start failing together, because one stale bundle breaks both.

output=build/ca.der
printEnv=0

case "${1:-}" in
    --print-env) printEnv=1 ;;
    -*)
        printf 'make-trust-bundle: unknown option %s\n' "$1" >&2
        exit 1
        ;;
    ?*) output=$1 ;;
esac

config=${CONFIG_H:-src/config.h}
store=${CA_STORE:-/etc/ssl/certs/ca-certificates.crt}
envFile=${TRUST_ENV:-$(dirname "$0")/trust-bundle.env}

if [ -z "${CAP:-}" ] && [ -z "${HOSTS:-}" ] && [ -r "$envFile" ]; then
    . "$envFile"
fi

cap=${CAP:-}
hosts=${HOSTS:-}

# The sync host, plus the hosts its redirects land on. Those two are not in the
# header because they only appear in a signed Location, measured from a real
# release download.
syncHosts="raw.githubusercontent.com github.com objects.githubusercontent.com release-assets.githubusercontent.com"

if [ -z "$cap" ] || [ -z "$hosts" ]; then
    for tool in awk sed; do
        command -v "$tool" >/dev/null 2>&1 || {
            printf 'make-trust-bundle: %s is required\n' "$tool" >&2
            exit 1
        }
    done

    if [ ! -r "$config" ]; then
        printf 'make-trust-bundle: cannot read %s\n' "$config" >&2
        printf '  set CAP and HOSTS to run without a source checkout\n' >&2
        exit 1
    fi

    # The cap the daemon enforces, so the tool refuses what the daemon would
    # refuse
    [ -n "$cap" ] || cap=$(awk '/define[ \t]+CFG_TLS_CA_MAX_BYTES/ {
               for(i = 1; i <= NF; i++)
                   if($i ~ /^KIB\(/) { gsub(/[^0-9]/, "", $i); print $i * 1024 }
           }' "$config")

    # The resolvers this build authenticates, taken from the same header the
    # daemon compiles, so the bundle cannot drift from the configuration.
    if [ -z "$hosts" ]; then
        resolvers=$(awk '/define[ \t]+CFG_UPSTREAM_TLS_NAMES/, /}/' "$config" \
                    | tr ',{}' '\n\n\n' | sed -n 's/.*"\([a-z0-9.-]*\)".*/\1/p')
        hosts=$(printf '%s %s' "$resolvers" "$syncHosts")
    fi
fi

case "$cap" in
    ''|*[!0-9]*)
        printf 'make-trust-bundle: no byte cap. Set CAP, or check %s\n' \
            "$config" >&2
        exit 1
        ;;
esac

if [ -z "$(printf '%s' "$hosts" | tr -d ' \n')" ]; then
    printf 'make-trust-bundle: no hosts to collect roots for\n' >&2
    exit 1
fi

if [ "$printEnv" -eq 1 ]; then
    printf 'CAP=%s\n' "$cap"
    printf 'HOSTS="%s"\n' "$(printf '%s' "$hosts" | tr '\n' ' ')"
    exit 0
fi

for tool in openssl awk sed; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'make-trust-bundle: %s is required\n' "$tool" >&2
        exit 1
    }
done

if [ ! -r "$store" ]; then
    printf 'make-trust-bundle: cannot read the CA store %s\n' "$store" >&2
    printf '  set CA_STORE to a PEM bundle of trusted roots\n' >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# One file a root, named by subject hash, so a chain's issuer can be looked up
mkdir -p "$work/store"
awk -v dir="$work/store" '
    /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%04d.pem", dir, n) }
    f { print > f }
    /-----END CERTIFICATE-----/ { close(f); f = "" }
' "$store"

for pem in "$work"/store/*.pem; do
    [ -e "$pem" ] || continue
    hash=$(openssl x509 -in "$pem" -noout -subject_hash 2>/dev/null || true)
    [ -n "$hash" ] || continue
    i=0
    while [ -e "$work/by-subject/$hash.$i.pem" ]; do i=$((i + 1)); done
    mkdir -p "$work/by-subject"
    cp "$pem" "$work/by-subject/$hash.$i.pem"
done

: > "$work/roots.txt"

for host in $hosts; do
    printf 'make-trust-bundle: %s\n' "$host" >&2

    if ! openssl s_client -connect "$host:443" -servername "$host" \
            -showcerts </dev/null > "$work/chain.txt" 2>/dev/null; then
        printf 'make-trust-bundle: cannot reach %s\n' "$host" >&2
        exit 1
    fi

    # The server rarely sends the root, so the last certificate it does send
    # names the root in its issuer
    awk -v dir="$work" '
        /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/hop%04d.pem", dir, n) }
        f { print > f }
        /-----END CERTIFICATE-----/ { close(f); f = "" }
    ' "$work/chain.txt"

    last=$(ls "$work"/hop*.pem 2>/dev/null | tail -1)
    if [ -z "$last" ]; then
        printf 'make-trust-bundle: %s sent no certificate\n' "$host" >&2
        exit 1
    fi

    issuer=$(openssl x509 -in "$last" -noout -issuer_hash)
    subject=$(openssl x509 -in "$last" -noout -subject_hash)

    found=""
    for candidate in "$work"/by-subject/"$issuer".*.pem; do
        [ -e "$candidate" ] && { found=$candidate; break; }
    done

    # dns.google ends on a root cross-signed by an authority the store may not
    # carry, so its issuer resolves to nothing. The certificate's own subject
    # then names the root to trust, which is GTS Root R4 today.
    if [ -z "$found" ]; then
        for candidate in "$work"/by-subject/"$subject".*.pem; do
            [ -e "$candidate" ] && { found=$candidate; break; }
        done
    fi

    if [ -z "$found" ]; then
        printf 'make-trust-bundle: no root in %s for %s\n' "$store" "$host" >&2
        exit 1
    fi

    openssl x509 -in "$found" -noout -subject >&2
    cat "$found" >> "$work/roots.txt"
    rm -f "$work"/hop*.pem
done

# One copy a root however many hosts chain to it
awk '
    /-----BEGIN CERTIFICATE-----/ { body = ""; inCert = 1 }
    inCert { body = body $0 "\n" }
    /-----END CERTIFICATE-----/ {
        inCert = 0
        if(!(body in seen)) { seen[body] = 1; printf "%s", body }
    }
' "$work/roots.txt" > "$work/unique.pem"

count=$(grep -c 'BEGIN CERTIFICATE' "$work/unique.pem" || true)
if [ "${count:-0}" -eq 0 ]; then
    printf 'make-trust-bundle: collected no roots\n' >&2
    exit 1
fi

# Concatenated DER, which is what the shim parses
: > "$work/bundle.der"
n=0
while [ "$n" -lt "$count" ]; do
    n=$((n + 1))
    awk -v want="$n" '
        /-----BEGIN CERTIFICATE-----/ { seen++ }
        seen == want { print }
        /-----END CERTIFICATE-----/ { if(seen == want) exit }
    ' "$work/unique.pem" > "$work/one.pem"
    openssl x509 -in "$work/one.pem" -outform DER >> "$work/bundle.der"
done

size=$(wc -c < "$work/bundle.der")
size=$(printf '%s' "$size" | tr -d ' ')

# Every configured chain has to verify against the bundle alone, or the daemon
# will fail at run time on a host this tool said it covered
for host in $hosts; do
    if ! openssl s_client -connect "$host:443" -servername "$host" \
            -CAfile "$work/unique.pem" -verify_return_error \
            </dev/null >/dev/null 2>&1; then
        printf 'make-trust-bundle: %s does not verify against the bundle\n' \
            "$host" >&2
        exit 1
    fi
done

if [ "$size" -gt "$cap" ]; then
    printf 'make-trust-bundle: %s bytes from %s roots, cap is %s\n' \
        "$size" "$count" "$cap" >&2
    printf '  drop a host, or raise CFG_TLS_CA_MAX_BYTES and the TLS arena\n' >&2
    exit 1
fi

mkdir -p "$(dirname "$output")"
cp "$work/bundle.der" "$output"

printf 'make-trust-bundle: %s, %s roots, %s bytes, cap %s\n' \
    "$output" "$count" "$size" "$cap"
