#!/bin/sh
# Pin the dependencies, fetch them into build/deps/, and name the functions
# this repo calls in them (ARCHITECTURE.md section 5).
# Runs inside the image from platform/linux/Dockerfile, from the repo root.
#
# The functions this repo calls in each dependency. platform/check.py rejects
# a call to any other function.
# uses asm-crypto: crypto_sha256 crypto_keccak256 crypto_hkdf_extract crypto_hkdf_expand crypto_aes128_ctr crypto_aes128_gcm_ae crypto_aes128_gcm_ad crypto_secp256k1_public_key crypto_secp256k1_decompress crypto_secp256k1_ecdh crypto_secp256k1_sign crypto_secp256k1_verify
# uses asm-rlp: rlp_decode
# uses libSystem (macOS shell, macOS 11.0 SDK): socket setsockopt bind getsockname sendto recvfrom poll close __error clock_gettime_nsec_np getentropy
# uses ws2_32, kernel32 and bcrypt (Windows shell, Windows 10): WSAStartup WSACleanup WSAGetLastError WSAPoll socket setsockopt bind getsockname sendto recvfrom closesocket GetTickCount64 BCryptGenRandom

set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
fetch() {
    dir=$root/build/deps/$1
    if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$2" ]; then
        rm -rf "$dir"
        git init -q "$dir"
        git -C "$dir" fetch -q --depth 1 "https://github.com/bitminetech/$1" "$2"
        git -C "$dir" checkout -q FETCH_HEAD
    fi
}
fetch asm-crypto 6df4597fa0c3584d5eef4f89cbc647797316853d
fetch asm-rlp 40cca377a1621ed660a73724192a4a0b2c059a84
