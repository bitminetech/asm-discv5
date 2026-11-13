#!/bin/sh
# Build the asm-discv5 library, its dependency objects, the test runner and
# the conformance node for one Linux ISA.
# Usage: platform/linux/build.sh ISA OUT_DIR    (ISA: x86_64, arm64 or riscv64)
# Runs inside the image from platform/linux/Dockerfile, after platform/deps.sh.
set -eu
isa=$1
out=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
crypto=$root/build/deps/asm-crypto
rlp=$root/build/deps/asm-rlp

case "$isa" in
  x86_64)  target=x86_64-linux-gnu;  march="-march=x86-64" ;;
  arm64)   target=aarch64-linux-gnu; march="-march=armv8-a" ;;
  riscv64) target=riscv64-linux-gnu; march="-march=rv64gc -mabi=lp64d" ;;
  *) echo "unknown ISA: $isa" >&2; exit 2 ;;
esac

mkdir -p "$out"
clang --target=$target $march -I"$root/include" -I"$crypto/include" -I"$rlp/include" -I"$root/platform/linux" \
    -c "$root/asm/core/$isa/discv5.s" -o "$out/discv5.o"
clang --target=$target $march -I"$root/include" -I"$root/platform/linux" \
    -c "$root/asm/shell/linux/$isa/shell.s" -o "$out/shell.o"
rm -f "$out/libasm-discv5.a"
llvm-ar rcs "$out/libasm-discv5.a" "$out/discv5.o" "$out/shell.o"

# Dependency objects: the asm-crypto and asm-rlp files the library calls.
deps=""
for name in sha256 keccak hmac aes secp256k1; do
    clang --target=$target $march -I"$crypto/include" -I"$crypto/platform/linux" \
        -c "$crypto/asm/core/$isa/$name.s" -o "$out/crypto-$name.o"
    deps="$deps $out/crypto-$name.o"
done
clang --target=$target $march -I"$rlp/include" -I"$rlp/platform/linux" \
    -c "$rlp/asm/core/$isa/rlp.s" -o "$out/rlp.o"
deps="$deps $out/rlp.o"

# Test runner and conformance node (C), linked statically so QEMU user mode needs no target libraries.
clang --target=$target $march -std=c11 -O2 -Wall -Wextra -Werror -static -fuse-ld=lld \
    "$root/tests/runner/runner.c" "$root/tests/runner/step.c" -I"$root/platform/linux" "$root/tests/runner/abi_$isa.s" \
    "$out/libasm-discv5.a" $deps -o "$out/runner"
clang --target=$target $march -std=c11 -O2 -Wall -Wextra -Werror -static -fuse-ld=lld \
    "$root/tests/conformance/node.c" "$out/libasm-discv5.a" $deps -o "$out/node"
