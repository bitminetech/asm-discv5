# asm-discv5

Node Discovery Protocol v5.1 (discv5), in assembly.

Node records, the wire protocol, the handshake, the node table, lookups and a UDP shell, for an Ethereum consensus client.

Standard: [asm-standard@2a19d3f](https://github.com/bitminetech/asm-standard/blob/2a19d3f7fa737af1c01720b6e891703e53a682aa/ARCHITECTURE.md)

## Reference

| File | Covers |
|---|---|
| [docs/reference/enr.md](docs/reference/enr.md) | Node records |
| [docs/reference/wire.md](docs/reference/wire.md) | Wire protocol |
| [docs/reference/handshake.md](docs/reference/handshake.md) | Handshake |
| [docs/reference/node.md](docs/reference/node.md) | Node: table, sessions, requests, lookups, events and actions |
| [docs/reference/shell.md](docs/reference/shell.md) | Shell: UDP socket, clock and random bytes |
| [include/discv5.inc](include/discv5.inc) | Constants and layouts |

## Targets

| OS | ISAs |
|---|---|
| Linux | x86-64, ARM64, RISC-V |
| Windows | x86-64, ARM64 |
| macOS | x86-64, ARM64 |

## Dependencies

| Repo | Commit | Functions used |
|---|---|---|
| [asm-crypto](https://github.com/bitminetech/asm-crypto) | [`fc3ab5f`](https://github.com/bitminetech/asm-crypto/tree/fc3ab5fdb5402d03414f1a2ff229abf48abed5ca) | `crypto_sha256`, `crypto_keccak256`, `crypto_hkdf_extract`, `crypto_hkdf_expand`, `crypto_aes128_ctr`, `crypto_aes128_gcm_ae`, `crypto_aes128_gcm_ad`, `crypto_secp256k1_public_key`, `crypto_secp256k1_decompress`, `crypto_secp256k1_ecdh`, `crypto_secp256k1_sign`, `crypto_secp256k1_verify` |
| [asm-rlp](https://github.com/bitminetech/asm-rlp) | [`40cca37`](https://github.com/bitminetech/asm-rlp/tree/40cca377a1621ed660a73724192a4a0b2c059a84) | `rlp_decode` |
| libSystem (macOS shell) | macOS 11.0 SDK | `socket`, `setsockopt`, `bind`, `getsockname`, `sendto`, `recvfrom`, `poll`, `close`, `__error`, `clock_gettime_nsec_np`, `getentropy` |
| ws2_32, kernel32 and bcrypt (Windows shell) | Windows 10 | `WSAStartup`, `WSACleanup`, `WSAGetLastError`, `WSAPoll`, `socket`, `setsockopt`, `bind`, `getsockname`, `sendto`, `recvfrom`, `closesocket`, `GetTickCount64`, `BCryptGenRandom` |

## Build tools

| Used for | Tool |
|---|---|
| Library | LLVM 23.1.5, official release (`clang`, `llvm-ar`, `lld`) |
| Windows test runner and node | [llvm-mingw 20261104](https://github.com/mstorsjo/llvm-mingw/releases/tag/20261104) (LLVM 23.1.5) |
| macOS test runner and node | The host Xcode clang, because they need the macOS SDK |
| Vector generator and conformance tool | Go 1.27.3, the toolchain go-ethereum v1.17.10 pins |
| Build image | [platform/linux/Dockerfile](platform/linux/Dockerfile) on `debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2` |

## Tests

| Item | Location |
|---|---|
| Export and frame check | [platform/check.py](platform/check.py) |
| Vector generator | [tests/generator/](tests/generator/) |
| Test runner | [tests/runner/](tests/runner/) |
| Conformance against go-ethereum | [tests/conformance/](tests/conformance/) |

## Target profile

| ISA | Instructions |
|---|---|
| x86-64 | x86-64-v1 |
| ARM64 | Armv8.0-A |
| RISC-V | RV64GC |

| Item | Value |
|---|---|
| macOS objects | Marked for macOS 11.0 or later |
| Linux kernel | 3.17 or later, for `getrandom` |

## Environment boundaries

| OS | Call | Requirements |
|---|---|---|
| Linux | System calls `socket`, `setsockopt`, `bind`, `getsockname`, `sendto`, `recvfrom`, `ppoll`, `clock_gettime`, `getrandom`, `close` | Numbers and layouts from the kernel uapi headers of each ISA, as in Debian trixie |
| macOS | libSystem functions in the Dependencies table | macOS 11.0 or later |
| Windows | Winsock 2.2, `GetTickCount64`, `BCryptGenRandom` | Windows 10 or later |

## Stack

| Item | Value |
|---|---|
| Stack per call | At most 16384 bytes, callees included |
| Shell calls | The OS calls of the shell add their own native stack |

## Integration

| Item | Value |
|---|---|
| Startup | `discv5_shell_clock` gives the time and entropy for `discv5_init`; `discv5_shell_open` binds the socket |
| Event loop | The application owns it: it calls `discv5_step` with a fresh tick and the events since the last step |
| Actions | After a step returns 0, the application performs each SEND with `discv5_shell_send` and passes the SENT events to the next step |
| Wakeup | The application waits with `discv5_shell_receive` until the WAKEUP time or a datagram, and passes the event to the next step |
| Action room | `DISCV5_ACTIONS_BASE` + events × `DISCV5_ACTIONS_PER_EVENT` bytes after the 24-byte header |
| Bootnodes, lookups, record | ADD_NODE, LOOKUP, SET_ENDPOINT and SET_ENTRY events; NODE_FOUND, LOOKUP_DONE, ENDPOINT and RECORD actions |
| Shutdown | `discv5_shell_close` |
| Concurrency | One thread at a time for a state and its shell context |
