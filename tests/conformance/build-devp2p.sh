#!/bin/sh
# Build the devp2p tool of go-ethereum v1.17.10 for every OS and ISA it runs
# on, inside the image from platform/linux/Dockerfile.
# Usage: tests/conformance/build-devp2p.sh OUT_DIR    (OUT_DIR must be outside this repo)
#
# Writes OUT_DIR/devp2p-<goos>-<goarch>[.exe]. OUT_DIR keeps the Go module and
# build caches (.go/), so a second run downloads nothing again. The Go module
# checksum database checks every module.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
case "$out/" in
  "$root"/*) echo "build-devp2p.sh: $out is inside the repo" >&2; exit 2 ;;
esac

docker build -q -t asm-discv5-build -f "$root/platform/linux/Dockerfile" "$root/platform/linux" >/dev/null
docker run --rm -v "$out:/out" asm-discv5-build sh -eu -c '
    export GOPATH=/out/.go GOCACHE=/out/.go/cache GOTOOLCHAIN=local CGO_ENABLED=0
    host=$(go env GOHOSTOS)_$(go env GOHOSTARCH)
    for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64; do
        goos=${target%_*}
        goarch=${target#*_}
        ext=""
        [ "$goos" = windows ] && ext=.exe
        GOOS=$goos GOARCH=$goarch go install github.com/ethereum/go-ethereum/cmd/devp2p@v1.17.10
        src=/out/.go/bin
        [ "$target" = "$host" ] || src=$src/$target
        cp "$src/devp2p$ext" "/out/devp2p-$goos-$goarch$ext"
    done
'
