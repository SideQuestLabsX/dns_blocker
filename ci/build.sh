#!/bin/sh
# Build every shipped artifact. Skips a target whose cross compiler is absent
# and fails on any compiler error.
set -eu

ARCHES="x86_64 aarch64 armv7 armv6"
PROFILES="minimal encrypted"

cc_for()
{
    case "$1" in
        x86_64)  echo "musl-gcc" ;;
        aarch64) echo "aarch64-linux-musl-gcc" ;;
        armv7)   echo "arm-linux-musleabihf-gcc" ;;
        armv6)   echo "arm-linux-musleabihf-gcc" ;;
    esac
}

skipped=0
built=0

for arch in $ARCHES; do
    cc=$(cc_for "$arch")
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "skip $arch: $cc not installed"
        skipped=$((skipped + 1))
        continue
    fi

    for profile in $PROFILES; do
        echo "build $arch $profile"
        make ARCH="$arch" PROFILE="$profile" CC="$cc"
        make ARCH="$arch" PROFILE="$profile" CC="$cc" check
        built=$((built + 1))
    done
done

echo "built $built, skipped $skipped"
test "$built" -gt 0
