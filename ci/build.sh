#!/bin/sh
# Builds and tests each target the way CI does, in an Alpine container on the
# target instruction set. Needs docker and qemu-user binfmt handlers:
#   docker run --privileged --rm tonistiigi/binfmt --install all
set -eu

TARGETS="x86_64:linux/amd64:alpine:3.20
aarch64:linux/arm64:arm64v8/alpine:3.20
armv7:linux/arm/v7:arm32v7/alpine:3.20
armv6:linux/arm/v6:arm32v6/alpine:3.20"

script=$(mktemp)
cat > "$script" <<'INNER'
set -e
apk add --no-cache build-base
make ARCH="$ARCH" PROFILE=minimal
make ARCH="$ARCH" PROFILE=minimal check
make ARCH="$ARCH" PROFILE=minimal test-static-run
INNER

built=0
echo "$TARGETS" | while IFS= read -r line; do
    arch=${line%%:*}
    rest=${line#*:}
    platform=${rest%%:*}
    image=${rest#*:}

    echo "== $arch on $image"
    docker run --rm --platform "$platform" -e ARCH="$arch" \
        -v "$PWD:/w" -v "$script:/build.sh" -w /w "$image" sh /build.sh
    built=$((built + 1))
done

rm -f "$script"
echo "done"
