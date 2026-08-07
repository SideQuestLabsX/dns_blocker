#!/bin/sh
set -eu

sourceList=${1:-blocklists/sources.txt}
outputDir=${2:-build/blocklist-release}
mkblocklist=${MKBLOCKLIST:-build/x86_64-minimal/mkblocklist}
combined="$outputDir/combined.txt"
asset="$outputDir/dns_blocker-blocklist.trie"
checksum="$outputDir/dns_blocker-blocklist.trie.sha256"
manifest="$outputDir/dns_blocker-blocklist.sources"
# GPL-3.0 sources require the compiler input beside the compiled trie
domains="$outputDir/dns_blocker-blocklist.domains.txt.gz"
licenses="$outputDir/THIRD_PARTY_LICENSES.md"

mkdir -p "$outputDir/sources"
: > "$combined"
: > "$manifest"

count=0
while read -r minimum url extra || [ -n "${minimum:-}" ]; do
    case "${minimum:-}" in
        ''|'#'*) continue ;;
        *[!0-9]*)
            printf 'blocklist release: invalid minimum: %s\n' "$minimum" >&2
            exit 1
            ;;
    esac

    if [ -n "${extra:-}" ]; then
        printf 'blocklist release: extra source fields: %s\n' "$extra" >&2
        exit 1
    fi

    case "$url" in
        https://*) ;;
        *)
            printf 'blocklist release: non-HTTPS source: %s\n' "$url" >&2
            exit 1
            ;;
    esac

    count=$((count + 1))
    target="$outputDir/sources/source-$count.txt"
    temp="$target.tmp"
    curl --proto '=https' --tlsv1.2 -fsSL \
        --retry 3 --retry-all-errors --connect-timeout 30 --max-time 300 \
        --max-filesize 67108864 "$url" -o "$temp"

    if [ ! -s "$temp" ]; then
        printf 'blocklist release: empty source: %s\n' "$url" >&2
        exit 1
    fi

    mv "$temp" "$target"

    result=$("$mkblocklist" "$target.trie" "$target" 2>&1) || {
        printf '%s\n' "$result" >&2
        exit 1
    }
    printf '%s\n' "$result" >&2
    accepted=${result#mkblocklist: }
    accepted=${accepted%% names,*}
    case "$accepted" in
        ''|*[!0-9]*)
            printf 'blocklist release: cannot read accepted count\n' >&2
            exit 1
            ;;
    esac
    if [ "$accepted" -lt "$minimum" ]; then
        printf 'blocklist release: %s accepted names from %s, minimum %s\n' \
            "$accepted" "$url" "$minimum" >&2
        exit 1
    fi

    sourceHash=$(sha256sum "$target")
    sourceHash=${sourceHash%% *}
    sourceBytes=$(wc -c < "$target")
    printf '%s  %s  %s  %s\n' "$sourceHash" "$sourceBytes" \
        "$accepted" "$url" >> "$manifest"

    cat "$target" >> "$combined"
    printf '\n' >> "$combined"
done < "$sourceList"

if [ "$count" -eq 0 ]; then
    printf 'blocklist release: no sources in %s\n' "$sourceList" >&2
    exit 1
fi

"$mkblocklist" "$asset" "$combined"
gzip -9 -c "$combined" > "$domains"
cp THIRD_PARTY_LICENSES.md "$licenses"

: > "$checksum"
for published in dns_blocker-blocklist.trie dns_blocker-blocklist.sources \
    dns_blocker-blocklist.domains.txt.gz THIRD_PARTY_LICENSES.md
do
    digest=$(sha256sum "$outputDir/$published")
    printf '%s  %s\n' "${digest%% *}" "$published" >> "$checksum"
done
(cd "$outputDir" && sha256sum -c dns_blocker-blocklist.trie.sha256)

printf 'blocklist release: %s source(s), %s\n' "$count" "$asset"
