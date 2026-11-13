#!/bin/sh
# Run the conformance suite for the three Linux ISAs in Docker, against the
# test nodes that tests/runner/docker.sh built into build/linux-<isa>/.
# Usage: tests/conformance/docker.sh DEVP2P_DIR    (from build-devp2p.sh)
#
# The node of an ISA other than the host's runs under QEMU user mode. The
# second tester address is 127.0.0.2: the Linux loopback takes all of 127/8.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
tools=$(cd "$1" && pwd)
docker run --rm -v "$root:/src" -v "$tools:/tools:ro" -w /src asm-discv5-build sh -eu -c '
    case $(uname -m) in
      x86_64)  host=x86_64; tool=/tools/devp2p-linux-amd64 ;;
      aarch64) host=arm64;  tool=/tools/devp2p-linux-arm64 ;;
      *) echo "unsupported build host" >&2; exit 2 ;;
    esac
    status=0
    for isa in x86_64 arm64 riscv64; do
        case $isa in
          x86_64)  qemu=qemu-x86_64 ;;
          arm64)   qemu=qemu-aarch64 ;;
          riscv64) qemu=qemu-riscv64 ;;
        esac
        [ "$isa" = "$host" ] && qemu=""
        echo "== linux $isa${qemu:+ (under $qemu)}"
        tests/conformance/run.sh $tool build/linux-$isa/node 127.0.0.2 $qemu || status=1
    done
    exit $status
'
