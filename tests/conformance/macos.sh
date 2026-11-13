#!/bin/sh
# Run the conformance suite on this Mac, against the test node that
# platform/macos/link-runner.sh links from the library tests/runner/docker.sh built.
# Usage: tests/conformance/macos.sh DEVP2P_DIR    (from build-devp2p.sh)
#
# The second tester address is 127.0.0.1 too: macOS gives the loopback only
# 127.0.0.1 unless an alias is added.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
tools=$(cd "$1" && pwd)
case "$(uname -m)" in
  arm64)  isa=arm64;  tool=$tools/devp2p-darwin-arm64 ;;
  x86_64) isa=x86_64; tool=$tools/devp2p-darwin-amd64 ;;
  *) echo "unsupported Mac: $(uname -m)" >&2; exit 2 ;;
esac
"$root/platform/macos/link-runner.sh" $isa "$root/build/macos-$isa"
echo "== macos $isa"
"$root/tests/conformance/run.sh" "$tool" "$root/build/macos-$isa/node" 127.0.0.1
