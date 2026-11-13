#!/bin/sh
# Generate the asm-discv5 vectors inside the image from platform/linux/Dockerfile.
# Usage: tests/generator/run.sh OUT_DIR    (OUT_DIR must be outside this repo)
#
# OUT_DIR keeps the downloads (sources/) and the Go module and build caches
# (.go/), so a second run downloads nothing again. go.sum pins every module.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
case "$out/" in
  "$root"/*) echo "run.sh: $out is inside the repo; vectors are stored outside it" >&2; exit 2 ;;
esac

docker build -q -t asm-discv5-build -f "$root/platform/linux/Dockerfile" "$root/platform/linux" >/dev/null
docker run --rm -v "$root:/src:ro" -v "$out:/out" asm-discv5-build sh -eu -c '
    devp2p=https://raw.githubusercontent.com/ethereum/devp2p/88f1c80800d622cc3a542a2125bbe33cc18c9f9c
    mkdir -p /out/sources
    fetch() {
        if [ ! -f /out/sources/$1 ] || ! echo "$3  /out/sources/$1" | sha256sum -c - >/dev/null 2>&1; then
            curl -fsSL -o /out/sources/$1 $devp2p/$2
            echo "$3  /out/sources/$1" | sha256sum -c - >/dev/null
        fi
    }
    fetch discv5-wire-test-vectors.md discv5/discv5-wire-test-vectors.md dbcb81f70bc963cad2d5b28fd7ef99e0c4b4ce4d03497f7c75d63ef752115170
    fetch enr.md enr.md 29260bceb96e289140dc08c1336e1f26e070613664a7ec6db72fffbfb85cc58d
    export GOPATH=/out/.go GOCACHE=/out/.go/cache GOFLAGS=-mod=readonly GOTOOLCHAIN=local
    cd /src/tests/generator
    go run . /out /out/sources
'
