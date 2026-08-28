#!/bin/sh
set -eu

# Assembles one deployment package from a build tree.
#
#   package-release.sh <arch> <profile> [outdir]
#
# Default outdir is build/package. The result is
# build/package/dns_blocker-<arch>-<profile>.tar.gz, holding the daemon, the
# probe, the unit, the installer, the license files and, for the encrypted
# profile, the trust tool with the configuration it was built against.
#
# The binaries have to exist already:
#
#   make ARCH=<arch> PROFILE=<profile>
#   make ARCH=<arch> PROFILE=<profile> check
#
# Each package carries its own license text, so one downloaded file arrives with
# the terms of everything linked into it.
#
# Runs on the build host with GNU tar. The encrypted package takes its trust
# values from src/config.h, so a build that overrides CFG_TLS_CA_MAX_BYTES or
# the resolver names through FEATURES needs CAP and HOSTS set to match here.

if [ $# -lt 2 ]; then
    printf 'usage: package-release.sh <arch> <profile> [outdir]\n' >&2
    exit 1
fi

arch=$1
profile=$2
outDir=${3:-build/package}

case $profile in
    minimal|encrypted) ;;
    *)
        printf 'package-release: unknown profile %s\n' "$profile" >&2
        exit 1
        ;;
esac

buildDir=${BUILD:-build/$arch-$profile}
name=dns_blocker-$arch-$profile

# The probe is profile independent and the release workflow builds it once,
# under minimal. CHECK_BIN points both packages at that copy, which keeps the
# packager out of a build tree the Alpine container left owned by root
checkBin=${CHECK_BIN:-$buildDir/dns_blocker.check}

for file in "$buildDir/dns_blocker" "$checkBin"; do
    [ -x "$file" ] || {
        printf 'package-release: %s is missing. Build it first\n' "$file" >&2
        exit 1
    }
done

for file in deploy/dns_blocker.service deploy/install.sh deploy/INSTALL.md \
            LICENSE THIRD_PARTY_LICENSES.md; do
    [ -r "$file" ] || {
        printf 'package-release: %s is missing from the tree\n' "$file" >&2
        exit 1
    }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

stage=$work/$name
mkdir -p "$stage"

install -m755 "$buildDir/dns_blocker" "$stage/dns_blocker"
install -m755 "$checkBin" "$stage/dns_blocker.check"
install -m644 deploy/dns_blocker.service "$stage/dns_blocker.service"
install -m755 deploy/install.sh "$stage/install.sh"
install -m644 deploy/INSTALL.md "$stage/INSTALL.md"
install -m644 LICENSE "$stage/LICENSE"
install -m644 THIRD_PARTY_LICENSES.md "$stage/THIRD_PARTY_LICENSES.md"

if [ "$profile" = encrypted ]; then
    install -m755 tools/make-trust-bundle.sh "$stage/make-trust-bundle.sh"

    # Written by the tool that reads it, so the package cannot carry a second
    # parse of the header
    sh tools/make-trust-bundle.sh --print-env > "$stage/trust-bundle.env"
    chmod 644 "$stage/trust-bundle.env"
fi

# Relative names, so the installer can check them from the unpacked directory
(cd "$stage" && find . -type f ! -name SHA256SUMS -print \
    | sed 's|^\./||' | sort | xargs sha256sum > SHA256SUMS)
(cd "$stage" && sha256sum -c SHA256SUMS > /dev/null)

mkdir -p "$outDir"
archive=$outDir/$name.tar.gz

# Fixed owner, name order and timestamps, and gzip without its own timestamp,
# so two builds of the same tree give the same archive. Needs GNU tar.
# A pipe here would report gzip's exit status and leave a truncated archive
# that looks written
tar --format=ustar --numeric-owner --owner=0 --group=0 --sort=name \
    --mtime='@0' -cf "$work/$name.tar" -C "$work" "$name"
gzip -n -9 -c "$work/$name.tar" > "$archive"

printf 'package-release: %s, %s bytes\n' "$archive" "$(wc -c < "$archive" | tr -d ' ')"
