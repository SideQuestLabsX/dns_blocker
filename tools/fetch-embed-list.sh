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

configValue()
{
    awk -v name="$1" '
        $1 == "#define" && $2 == name {
            if (match($0, /"[^"]*"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
                exit
            }
            if (getline > 0 && match($0, /"[^"]*"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
                exit
            }
        }
    ' "$config"
}

configNumber()
{
    awk -v name="$1" '
        $1 == "#define" && $2 == name && $3 ~ /^[0-9]+$/ {
            print $3
            exit
        }
    ' "$config"
}

locator=$(configValue CFG_BLOCKLIST_LOCATOR_URL)
releaseBase=$(configValue CFG_BLOCKLIST_RELEASE_BASE_URL)
releaseTagBytes=$(configNumber CFG_SYNC_RELEASE_TAG_BYTES)
case "$releaseTagBytes" in
    *[!0-9]*|'') releaseTagBytes=0 ;;
esac
if [ -z "$locator" ] || [ -z "$releaseBase" ] \
   || [ "$releaseTagBytes" -lt 2 ]
then
    printf 'fetch-embed-list: invalid release configuration in %s\n' "$config" >&2
    exit 1
fi

asset="dns_blocker-blocklist-$tier.trie"
work="$output.work"

rm -rf "$work"
mkdir -p "$work"

# A missing locator or tier will not appear during repeated HTTP-error retries
get()
{
    if ! curl --proto '=https' --tlsv1.2 -fsSL \
        --retry 3 --connect-timeout 30 --max-time 600 \
        --max-filesize "${3:-134217728}" "$1" -o "$2"
    then
        printf 'fetch-embed-list: cannot download %s\n' "$1" >&2
        exit 1
    fi
}

locatorIsValid()
{
    awk '
        NR == 1 {
            if ($0 !~ /^blocklist-[0-9][0-9][0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])-[1-9][0-9]*-[1-9][0-9]*$/)
                exit 1

            split($0, field, "-")
            year = field[2] + 0
            month = field[3] + 0
            day = field[4] + 0
            days[1] = 31
            days[2] = 28
            days[3] = 31
            days[4] = 30
            days[5] = 31
            days[6] = 30
            days[7] = 31
            days[8] = 31
            days[9] = 30
            days[10] = 31
            days[11] = 30
            days[12] = 31
            if (year == 0)
                exit 1
            if (month == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0))
                days[2]++
            if (day > days[month])
                exit 1
            valid = 1
        }
        END {
            if (NR != 1 || !valid)
                exit 1
        }
    ' "$1"
}

get "$locator" "$work/locator" "$releaseTagBytes"
tag=$(sed -n '1p' "$work/locator")
if [ "$(wc -l < "$work/locator")" -ne 1 ] \
   || [ "$(wc -c < "$work/locator")" -ne $((${#tag} + 1)) ] \
   || ! locatorIsValid "$work/locator"
then
    printf 'fetch-embed-list: invalid release locator\n' >&2
    exit 1
fi

base="${releaseBase}${tag}/"
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
