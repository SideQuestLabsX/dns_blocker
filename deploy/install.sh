#!/bin/sh
set -eu

# Installs one release package on a systemd host. Run it from the unpacked
# directory:
#
#   sh install.sh [--destdir DIR]
#
# It copies files and nothing else. Enabling the unit is a separate command,
# because the encrypted profile needs its trust bundle installed first and a
# unit that restarts on failure would loop until systemd gives up on it.

destdir=

while [ $# -gt 0 ]; do
    case $1 in
        --destdir)
            [ $# -ge 2 ] || {
                printf 'install: --destdir needs a directory\n' >&2
                exit 1
            }
            destdir=$2
            shift 2
            ;;
        --destdir=*)
            destdir=${1#--destdir=}
            shift
            ;;
        -h|--help)
            printf 'usage: sh install.sh [--destdir DIR]\n'
            exit 0
            ;;
        *)
            printf 'install: unknown argument %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

# Resolved before the directory changes, so a relative one still means what the
# caller typed
case $destdir in
    ''|/*) ;;
    *) destdir=$PWD/$destdir ;;
esac

cd "$(dirname "$0")"

for file in dns_blocker dns_blocker.check dns_blocker.service SHA256SUMS; do
    [ -r "$file" ] || {
        printf 'install: %s is missing from the package\n' "$file" >&2
        exit 1
    }
done

# A package arrives over the network like everything else here
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS >/dev/null || {
        printf 'install: the package does not match SHA256SUMS\n' >&2
        exit 1
    }
else
    printf 'install: sha256sum is absent, contents unverified\n' >&2
fi

sbin=$destdir/usr/local/sbin
unitDir=$destdir/etc/systemd/system
confDir=$destdir/etc/dns_blocker
libDir=$destdir/usr/local/lib/dns_blocker

install -Dm755 dns_blocker "$sbin/dns_blocker"
install -Dm755 dns_blocker.check "$sbin/dns_blocker.check"
install -Dm644 dns_blocker.service "$unitDir/dns_blocker.service"
install -dm755 "$confDir"

install -Dm644 LICENSE "$libDir/LICENSE"
install -Dm644 THIRD_PARTY_LICENSES.md "$libDir/THIRD_PARTY_LICENSES.md"

bEncrypted=0
if [ -r make-trust-bundle.sh ]; then
    bEncrypted=1
    # The tool reads trust-bundle.env from its own directory, so the two move
    # together or the tool loses the configuration it was built against
    install -Dm755 make-trust-bundle.sh "$libDir/make-trust-bundle.sh"
    install -Dm644 trust-bundle.env "$libDir/trust-bundle.env"
fi

printf 'install: daemon in %s, unit in %s\n' "$sbin" "$unitDir"

if [ "$bEncrypted" -eq 1 ]; then
    printf '\nThe encrypted profile refuses to start without its trust bundle:\n'
    printf '  sudo sh /usr/local/lib/dns_blocker/make-trust-bundle.sh /etc/dns_blocker/ca.der\n'
fi

printf '\n  sudo systemctl daemon-reload\n'
printf '  sudo systemctl enable --now dns_blocker\n'
