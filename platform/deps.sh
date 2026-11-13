#!/bin/sh
# Fetch the dependencies that the README pins into build/deps/.
# Runs inside the image from platform/linux/Dockerfile, from the repo root.
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
fetch asm-crypto fc3ab5fdb5402d03414f1a2ff229abf48abed5ca    # README Dependencies
fetch asm-rlp 40cca377a1621ed660a73724192a4a0b2c059a84       # README Dependencies
