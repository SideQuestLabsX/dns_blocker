#!/bin/sh
set -eu

# Downloads the compiled trie of one tier and verifies it against the release
# digest, for a build that links a list into .rodata.
#
#   fetch-embed-list.sh <tier> <output.trie>
#
# The published trie is already the bytes .rodata wants, so an embedded build
# takes the release asset rather than compiling the lists again. `mkblocklist -t`
# checks the header before it wraps the file, so a download that arrived wrong
# stops the build.

tier=${1:?usage: fetch-embed-list.sh <tier> <output.trie>}
output=${2:?usage: fetch-embed-list.sh <tier> <output.trie>}
config=${CONFIG_HEADER:-src/config.h}

# The daemon's own base URL, so an embedded list and a synced one come from the
# same release
base=$(sed -n 's/^ *#define CFG_BLOCKLIST_BASE_URL *"\(.*\)".*/\1/p' "$config")
if [ -z "$base" ]; then
    printf 'fetch-embed-list: no CFG_BLOCKLIST_BASE_URL in %s\n' "$config" >&2
    exit 1
fi

asset="dns_blocker-blocklist-$tier.trie"
work="$output.work"

rm -rf "$work"
mkdir -p "$work"

# No --retry-all-errors: a 404 here is a tier the release does not carry, and
# asking four times does not change that
get()
{
    if ! curl --proto '=https' --tlsv1.2 -fsSL \
        --retry 3 --connect-timeout 30 --max-time 600 \
        --max-filesize 134217728 "$1" -o "$2"
    then
        printf 'fetch-embed-list: cannot download %s\n' "$1" >&2
        printf '  a 404 means the release carries no tier named %s\n' "$tier" >&2
        exit 1
    fi
}

get "$base$asset" "$work/$asset"
get "${base}dns_blocker-blocklist.sha256" "$work/digest"

# The digest file names every asset in the release, so the line for this one is
# picked out. Running the whole file would check assets that were never fetched
if ! grep -E "  $asset\$" "$work/digest" > "$work/want"; then
    printf 'fetch-embed-list: the release digest does not name %s\n' "$asset" >&2
    exit 1
fi

(cd "$work" && sha256sum -c want)

mv "$work/$asset" "$output"
rm -rf "$work"

printf 'embed: %s, %s bytes\n' "$tier" "$(wc -c < "$output")"
