#!/bin/sh
set -eu

VERSION=3.6.7
SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
URL="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$VERSION/mbedtls-$VERSION.tar.bz2"

root=${1:?output directory required}
sourceDir="$root/source"
archive="$root/mbedtls-$VERSION.tar.bz2"

mkdir -p "$root"

DownloadArchive()
{
    tempArchive="$archive.tmp.$$"
    trap 'rm -f "$tempArchive"' EXIT HUP INT TERM
    curl -fsSL "$URL" -o "$tempArchive"
    printf '%s  %s\n' "$SHA256" "$tempArchive" | sha256sum -c -
    mv "$tempArchive" "$archive"
    trap - EXIT HUP INT TERM
}

if [ ! -f "$archive" ] \
   || ! printf '%s  %s\n' "$SHA256" "$archive" | sha256sum -c - >/dev/null 2>&1
then
    DownloadArchive
fi

printf '%s  %s\n' "$SHA256" "$archive" | sha256sum -c -
rm -rf "$sourceDir"

python3 - "$archive" "$sourceDir" <<'PY'
import pathlib
import shutil
import tarfile
import sys

archivePath = pathlib.Path(sys.argv[1])
targetPath = pathlib.Path(sys.argv[2])
targetPath.mkdir(parents=True, exist_ok=True)

with tarfile.open(archivePath, "r:bz2") as bundle:
    for member in bundle.getmembers():
        parts = pathlib.PurePosixPath(member.name).parts[1:]
        if not parts or ".." in parts:
            continue
        outputPath = targetPath.joinpath(*parts)
        if member.isdir():
            outputPath.mkdir(parents=True, exist_ok=True)
        elif member.isfile():
            outputPath.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot extract {member.name}")
            with source, outputPath.open("wb") as output:
                shutil.copyfileobj(source, output)
            outputPath.chmod(member.mode & 0o777)
PY

python3 "$sourceDir/scripts/config.py" set MBEDTLS_MEMORY_BUFFER_ALLOC_C
python3 "$sourceDir/scripts/config.py" set MBEDTLS_PLATFORM_C
python3 "$sourceDir/scripts/config.py" set MBEDTLS_PLATFORM_MEMORY

make -C "$sourceDir" -j2 CC="${CC:-cc}" AR="${AR:-ar}" \
    CFLAGS="${MBEDTLS_CFLAGS:?MBEDTLS_CFLAGS is required}" lib
