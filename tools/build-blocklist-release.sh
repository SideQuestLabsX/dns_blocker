#!/bin/sh
set -eu

# Compiles one tier, or every tier when given none.
#
#   build-blocklist-release.sh [tier] [outputDir]
#
# A tier publishes one asset, its trie. Everything else a release needs is one
# asset for the whole release however many tiers there are: the manifest naming
# every source and the composition of every tier, the archive of the fetched
# lists, the digest and the licenses.

tier=${1:-}
outputDir=${2:-build/blocklist-release}
mkblocklist=${MKBLOCKLIST:-build/x86_64-minimal/mkblocklist}
checksum="$outputDir/dns_blocker-blocklist.sha256"
manifest="$outputDir/dns_blocker-blocklist.sources"
archive="$outputDir/dns_blocker-blocklist-sources.tar.gz"
licenses="$outputDir/THIRD_PARTY_LICENSES.md"
removals=${REMOVALS:-tools/blocklist-removals.txt}
project="$outputDir/LICENSE"

# The sources, the base tiers and the categories combined onto them.
#
#   source   <name> <minimum accepted names> <SPDX license> <https URL>
#   group    <name> <source>...
#   base     <name> <source-or-group>...
#   category <name> <base> <source-or-group>...
#
# A group is one publisher that ships its inputs as separate files. Repeat the
# line to keep it readable; the members accumulate.
#
# A base decides how hard ads and trackers are blocked. A category is one more
# thing to block, and every subset of the categories is published against every
# base, so an operator takes exactly the combination they want and never a
# bundle somebody else chose. The tier name is the base followed by its
# categories in the order declared here.
#
# A category names its own sources per base, because the publishers offer sizes
# and the large adult list on a compact base would spend most of the file on
# that axis alone.
#
# The count is the product: bases times two to the power of categories. Adding a
# category doubles the release.
#
# The minimum rejects a truncated source or a format change before it reaches a
# release. Every source is a plain hosts file or a domain-per-line list.
#
# Each source carries its own license and a compiled trie is a combined work
# under all of them, so every source states its license here and the manifest
# publishes it. Take that license from the publisher's own license file or terms
# page, never from the repository a generated file happens to sit in. Record a
# new source in THIRD_PARTY_LICENSES.md before it ships.
#
# Every license here has to be conveyable under GPL-3.0, because the tries are.
# A NonCommercial term is not: GPL-3.0 section 7 forbids further restrictions.
# See DECISIONS D-045.
# StevenBlack publishes each of its inputs separately under data/<name>/hosts,
# and this takes those rather than the merged master/hosts. The merge pulls in
# mvps.org (CC BY-NC-SA 3.0) and someonewhocares.org (non-commercial), whose
# terms cannot be conveyed under GPL-3.0 and reach every tier through every
# base. Measured on 2026-08-20: of the 16056 domains unique to those two lists,
# 0 of a random 300 still resolved, so the exclusion costs no live coverage.
# yoyo.org is excluded for the same reason: it grants redistribution but states
# no license, and its 2111 unique domains were 0 of 250 live.
TIERS=${TIERS:-'
source sb-stevenblack  2000  MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts
source sb-baddboyz     900   MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/Badd-Boyz-Hosts/hosts
source sb-hostsvn      1200  MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/hostsVN/hosts
source sb-uncheckyads  5     MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts
source sb-2o7net       1500  MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts
source sb-dead         5     MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Dead/hosts
source sb-risk         1500  MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts
source sb-spam         20    MIT           https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts
source sb-adaway       5000  CC-BY-3.0     https://raw.githubusercontent.com/StevenBlack/hosts/master/data/adaway.org/hosts
source sb-tiuxo        1200  CC-BY-4.0     https://raw.githubusercontent.com/StevenBlack/hosts/master/data/tiuxo/hosts
source sb-kadhosts     40000 CC-BY-SA-4.0  https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts
source sb-minecraft    5     CC0-1.0       https://raw.githubusercontent.com/StevenBlack/hosts/master/data/minecraft-hosts/hosts
source sb-urlhaus      50    CC0-1.0       https://raw.githubusercontent.com/StevenBlack/hosts/master/data/URLHaus/hosts

group  stevenblack sb-stevenblack sb-baddboyz sb-hostsvn sb-uncheckyads
group  stevenblack sb-2o7net sb-dead sb-risk sb-spam
group  stevenblack sb-adaway sb-tiuxo sb-kadhosts
group  stevenblack sb-minecraft sb-urlhaus

source hagezi-lite   35000  GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt
source hagezi-pro    190000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt
source hagezi-max    240000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
source oisd-small    50000  GPL-3.0-only https://small.oisd.nl/domainswild
source oisd-big      220000 GPL-3.0-only https://big.oisd.nl/domainswild

source adult-small   70000  GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt
source adult-big     400000 GPL-3.0-only https://nsfw.oisd.nl/domainswild

source tif-small     120000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt
source tif-mid       250000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt
source tif-big       1500000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt

source gambling-small 65000  GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini-onlydomains.txt
source gambling-mid   100000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.medium-onlydomains.txt
source gambling-big   280000 GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt

source piracy        27000  GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/anti.piracy-onlydomains.txt
source bypass        12000  GPL-3.0-only https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt

base compact    stevenblack hagezi-lite
base standard   stevenblack hagezi-pro oisd-small
base aggressive stevenblack hagezi-max oisd-big

category nsfw     compact    adult-small
category nsfw     standard   adult-big
category nsfw     aggressive adult-big

category tif      compact    tif-small
category tif      standard   tif-mid
category tif      aggressive tif-big

category gambling compact    gambling-small
category gambling standard   gambling-mid
category gambling aggressive gambling-big

category piracy   compact    piracy
category piracy   standard   piracy
category piracy   aggressive piracy

category bypass   compact    bypass
category bypass   standard   bypass
category bypass   aggressive bypass
'}

# Materialises every base against every subset of the categories, as the
# `tier <name> <source>...` lines the rest of this script reads.
materialise()
{
    printf '%s\n' "$TIERS" | awk '
        # A group stands for its members wherever a source may appear. Repeated
        # lines accumulate, so one publisher can be declared a few names at a time
        function expand(list,   i, n, parts, out) {
            n = split(list, parts, /[ \t]+/)
            for (i = 1; i <= n; i++)
            {
                if (parts[i] == "")
                    continue
                out = out ((parts[i] in grp) ? grp[parts[i]] : " " parts[i])
            }
            return out
        }
        $1 == "source"   { print; next }
        $1 == "group"    {
            for (i = 3; i <= NF; i++)
                grp[$2] = grp[$2] " " $i
            next
        }
        $1 == "base"     { bases[++nb] = $0; next }
        $1 == "category" {
            if (!($2 in seen)) { seen[$2] = ++nc; order[nc] = $2 }
            for (i = 4; i <= NF; i++)
                add[$2 "\0" $3] = add[$2 "\0" $3] " " $i
            next
        }
        END {
            for (b = 1; b <= nb; b++)
            {
                split(bases[b], f, /[ \t]+/)
                name = f[2]
                sources = ""
                for (i = 3; i in f; i++)
                    sources = sources " " f[i]

                for (mask = 0; mask < 2 ^ nc; mask++)
                {
                    tier = name
                    extra = ""
                    for (c = 1; c <= nc; c++)
                    {
                        if (int(mask / 2 ^ (c - 1)) % 2 == 0)
                            continue

                        key = order[c] "\0" name
                        if (!(key in add))
                        {
                            printf "category %s names no source for base %s\n", \
                                order[c], name > "/dev/stderr"
                            exit 1
                        }

                        tier = tier "-" order[c]
                        extra = extra add[key]
                    }

                    print "tier", tier, expand(sources extra)
                }
            }
        }
    '
}

names()
{
    materialise | awk '$1 == "tier" { print $2 }'
}

if [ -z "$tier" ]; then
    mkdir -p "$outputDir"
    names > "$outputDir/tiers"

    if [ ! -s "$outputDir/tiers" ]; then
        printf 'blocklist release: no tiers declared\n' >&2
        exit 1
    fi

    : > "$outputDir/manifest.tiers"
    : > "$outputDir/manifest.sources"

    while read -r name; do
        sh "$0" "$name" "$outputDir"
    done < "$outputDir/tiers"

    cp THIRD_PARTY_LICENSES.md "$licenses"
    cp LICENSE "$project"

    # One manifest for the release: every source with the bytes and digest of
    # what was fetched, then the composition of every tier. With the archive it
    # is the corresponding source of every trie here
    {
        printf '# source <name> <sha256> <bytes> <accepted names> <license> <url>\n'
        sort "$outputDir/manifest.sources"
        printf '\n# tier <name> <source>...\n'
        sort "$outputDir/manifest.tiers"
        printf '\n# removal <name> <reason>. Subtracted from every tier above.\n'
        printf '# The exact name and its www. form only, never the subtree.\n'
        awk '{ sub(/\r$/, "") }
             /^[ \t]*#/ || /^[ \t]*$/ { next }
             { name = $1
               reason = ""
               at = index($0, "#")
               if(at > 0)
               {
                   reason = substr($0, at + 1)
                   sub(/^[ \t]+/, "", reason)
               }
               printf "removal %s %s\n", name, reason }' "$removals"
    } > "$manifest"

    tar -czf "$archive" -C "$outputDir/cache" .

    : > "$checksum"
    for published in $(cd "$outputDir" && ls dns_blocker-blocklist-*.trie \
        dns_blocker-blocklist-sources.tar.gz dns_blocker-blocklist.sources \
        THIRD_PARTY_LICENSES.md LICENSE)
    do
        digest=$(sha256sum "$outputDir/$published")
        printf '%s  %s\n' "${digest%% *}" "$published" >> "$checksum"
    done
    (cd "$outputDir" && sha256sum -c dns_blocker-blocklist.sha256 > /dev/null)

    printf 'blocklist release: %s tier(s), %s of assets\n' \
        "$(wc -l < "$outputDir/tiers")" \
        "$(cat "$outputDir"/dns_blocker-blocklist-*.trie "$archive" \
            | wc -c | awk '{ printf "%.0f MB", $1 / 1048576 }')"
    exit 0
fi

combined="$outputDir/combined-$tier.txt"
asset="$outputDir/dns_blocker-blocklist-$tier.trie"

case "$tier" in
    *[!a-z0-9-]*|'')
        printf 'blocklist release: tier is not a lowercase name: %s\n' "$tier" >&2
        exit 1
        ;;
esac

mkdir -p "$outputDir/sources" "$outputDir/cache"
: > "$combined"

# Resolves the tier to the name, minimum and URL of each source it draws on. An
# undeclared source stops the build, because a tier that quietly loses one
# publishes as though it never had it
expand="$outputDir/sources/$tier.expanded"

materialise | awk -v want="$tier" '
    $1 == "source" {
        if ($2 in minimum) { printf "duplicate source %s\n", $2 > "/dev/stderr"; exit 1 }
        minimum[$2] = $3
        license[$2] = $4
        url[$2]     = $5
        next
    }
    $1 == "tier" && $2 == want {
        found = 1
        for (i = 3; i <= NF; i++)
        {
            if (!(($i) in url)) { printf "no such source: %s\n", $i > "/dev/stderr"; exit 1 }
            if (seen[$i]++) continue
            print $i, minimum[$i], license[$i], url[$i]
        }
    }
    END {
        if (!found) { printf "no such tier: %s\n", want > "/dev/stderr"; exit 1 }
    }
' > "$expand"

count=0
used=""

while read -r sname minimum license url; do
    case "$minimum" in
        *[!0-9]*)
            printf 'blocklist release: invalid minimum: %s\n' "$minimum" >&2
            exit 1
            ;;
    esac

    case "$url" in
        https://*) ;;
        *)
            printf 'blocklist release: non-HTTPS source: %s\n' "$url" >&2
            exit 1
            ;;
    esac

    # Every tier asks for the same handful of URLs, so a release fetches each
    # one once. Inside the output directory, so it lives exactly as long as one
    # build and can never serve a stale list
    count=$((count + 1))
    used="$used $sname"
    target="$outputDir/cache/$sname.txt"

    if [ ! -s "$target" ]; then
        temp="$target.tmp"
        curl --proto '=https' --tlsv1.2 -fsSL \
            --retry 3 --retry-all-errors --connect-timeout 30 --max-time 300 \
            --max-filesize 134217728 "$url" -o "$temp"

        if [ ! -s "$temp" ]; then
            printf 'blocklist release: empty source: %s\n' "$url" >&2
            exit 1
        fi

        mv "$temp" "$target"
    fi

    # A source appears in many tiers and its accepted count does not depend on
    # which one, so the check runs once a release rather than once a tier
    if [ ! -s "$target.accepted" ]; then
        result=$("$mkblocklist" "$target.trie" "$target" 2>&1) || {
            printf '%s\n' "$result" >&2
            exit 1
        }
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

        printf '%s' "$accepted" > "$target.accepted"
        rm -f "$target.trie"

        sourceHash=$(sha256sum "$target")
        printf 'source %s %s %s %s %s %s\n' "$sname" "${sourceHash%% *}" \
            "$(wc -c < "$target")" "$accepted" "$license" "$url" \
            >> "$outputDir/manifest.sources"
    fi

    cat "$target" >> "$combined"
    printf '\n' >> "$combined"
done < "$expand"

if [ "$count" -eq 0 ]; then
    printf 'blocklist release: tier %s names no sources\n' "$tier" >&2
    exit 1
fi

"$mkblocklist" -x "$removals" "$asset" "$combined" >/dev/null 2>&1
rm -f "$combined"

printf 'tier %s%s\n' "$tier" "$used" >> "$outputDir/manifest.tiers"

# mkblocklist reads CFG_BLOCKLIST_MAX_BYTES from the same header the daemon
# does and refuses a list above it, so a tier that would not map cannot reach a
# release
printf 'blocklist release: tier %s, %s source(s), %s bytes\n' \
    "$tier" "$count" "$(wc -c < "$asset")"
