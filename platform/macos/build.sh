#!/bin/sh
# Build the asm-discv5 library and its dependency objects for one macOS ISA.
# Usage: platform/macos/build.sh ISA OUT_DIR    (ISA: x86_64 or arm64)
# Runs inside the image from platform/linux/Dockerfile, after platform/deps.sh, so
# the library uses the pinned LLVM. link-runner.sh links the test runner and the
# conformance node on a Mac.
set -eu
isa=$1
out=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
crypto=$root/build/deps/asm-crypto
rlp=$root/build/deps/asm-rlp

case "$isa" in
  x86_64) target=x86_64-apple-macos11 ;;
  arm64)  target=arm64-apple-macos11 ;;
  *) echo "unknown ISA: $isa" >&2; exit 2 ;;
esac

mkdir -p "$out"
clang --target=$target -I"$root/include" -I"$crypto/include" -I"$rlp/include" -I"$root/platform/macos" \
    -c "$root/asm/core/$isa/discv5.s" -o "$out/discv5.o"
clang --target=$target -I"$root/include" -I"$root/platform/macos" \
    -c "$root/asm/shell/macos/$isa/shell.s" -o "$out/shell.o"
rm -f "$out/libasm-discv5.a"
llvm-ar --format=darwin rcs "$out/libasm-discv5.a" "$out/discv5.o" "$out/shell.o"
for name in sha256 keccak hmac aes secp256k1; do
    clang --target=$target -I"$crypto/include" -I"$crypto/platform/macos" \
        -c "$crypto/asm/core/$isa/$name.s" -o "$out/crypto-$name.o"
done
clang --target=$target -I"$rlp/include" -I"$rlp/platform/macos" \
    -c "$rlp/asm/core/$isa/rlp.s" -o "$out/rlp.o"
