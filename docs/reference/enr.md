# Node records

Read, write and sign node records.

## Contents

### Functions

- [`discv5_enr_decode`](#function-discv5_enr_decode): checks a node record and writes its fields.
- [`discv5_enr_text_decode`](#function-discv5_enr_text_decode): decodes the text form of a node record.
- [`discv5_local_record`](#function-discv5_local_record): copies the local node record.
- [`discv5_copy`](#function-discv5_copy): copies bytes.
- [`discv5_zero`](#function-discv5_zero): writes zero bytes.
- [`discv5_equal`](#function-discv5_equal): compares bytes.
- [`discv5_load_be`](#function-discv5_load_be): reads a big-endian number.
- [`discv5_store_be`](#function-discv5_store_be): writes a big-endian number.
- [`discv5_rlp_header`](#function-discv5_rlp_header): writes an RLP header.
- [`discv5_rlp_bytes`](#function-discv5_rlp_bytes): writes an RLP byte string.
- [`discv5_rlp_uint`](#function-discv5_rlp_uint): writes an RLP number.
- [`discv5_hash`](#function-discv5_hash): hashes bytes with SHA-256 or Keccak-256.
- [`discv5_entry_set`](#function-discv5_entry_set): sets one entry of the local record.
- [`discv5_record_build`](#function-discv5_record_build): signs the local record.
- [`discv5_set_endpoint`](#function-discv5_set_endpoint): sets the address and port entries.
- [`discv5_owned_key`](#function-discv5_owned_key): tells whether the core owns a record key.

### Types

- [`ByteList`](#type-bytelist): a byte string with its buffer size.
- [`Enr`](#type-enr): the fields of a checked node record.
- [`EnrPair`](#type-enrpair): one key/value pair of a record.
- [`EnrScratch`](#type-enrscratch): the workspace of the record decoder.
- [`LocalEntry`](#type-localentry): one entry of the local record.

### Constants

- `DISCV5_MAX_RECORD`: the largest record, 300 bytes.
- `DISCV5_ENR_SCRATCH`: the scratch `discv5_enr_decode` needs.
- `DISCV5_INVALID_RECORD`: status 4.
- `DISCV5_INVALID_TEXT`: status 5.

## Spec

- Document: [enr.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/enr.md), the EIP-778 text in devp2p at commit 88f1c80.
- Section: Record structure, RLP encoding, the "v4" identity scheme.

## Function `discv5_enr_decode`

Checks a node record under EIP-778 and the v4 identity scheme, and writes its fields.

### Signature

```
discv5_enr_decode(record, scratch, enr) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `record` | input | [`ByteList`](enr.md#type-bytelist) |
| `scratch` | scratch | `EnrScratch` |
| `enr` | output | `Enr` |

### Returns

- `DISCV5_OK`: `enr` holds the fields of a valid record.
- `DISCV5_BUFFER_TOO_SMALL`: `scratch` is smaller than `DISCV5_ENR_SCRATCH`. Nothing is written.
- `DISCV5_INVALID_RECORD`: The record breaks a rule below. `enr` may be partly written.

### Caller must

- Pass a valid `ByteList` in `record`.
- Set the `size` field of `scratch`.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Zeroes `enr`.
- Takes a record of 1 to 300 bytes.
- Decodes it with `rlp_decode`: one list, canonical encodings, no bytes after it.
- Takes the signature (a 64-byte string), then the sequence number (a canonical number of at most 8 bytes), then key/value pairs.
- Takes keys that are byte strings, sorted and unique, and at most 128 pairs. A value is a byte string or a list.
- Takes "id" = "v4" and a 33-byte "secp256k1" key.
- Keeps "ip" (4 bytes), "udp" (a canonical number of at most 2 bytes), "ip6" (16 bytes) and "udp6" in fixed fields, and marks each in `has`. A value of another size is left out of the fixed fields.
- Writes the node ID: Keccak-256 of the decompressed public key, x then y.
- Checks the signature with `crypto_secp256k1_verify` over Keccak-256 of the list [seq, k, v, ...]. That check rejects a high S.

### Function never

- Writes more than `scratch`, `enr` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 1928 bytes on x86-64 (return address included), 1968 bytes on ARM64, 2064 bytes on RISC-V, callees included.
- Record bytes: 300.
- Pairs: 128.

### ABI

- Role: L2.
- Symbol: `discv5_enr_decode` (`_discv5_enr_decode` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `record`, `scratch`, `enr`.

## Function `discv5_enr_text_decode`

Decodes "enr:" and URL-safe base64 with no padding into record bytes.

### Signature

```
discv5_enr_text_decode(text, record) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `text` | input | [`ByteList`](enr.md#type-bytelist) |
| `record` | output | [`ByteList`](enr.md#type-bytelist) |

### Returns

- `DISCV5_OK`: `record` holds the bytes.
- `DISCV5_BUFFER_TOO_SMALL`: The room of `record` is below 3 / 4 of the characters after "enr:". Nothing is written.
- `DISCV5_INVALID_TEXT`: The text has no "enr:", a character outside A-Z, a-z, 0-9, "-" and "_", or one character over a multiple of 4.

### Caller must

- Pass a valid `ByteList` in `text`.
- Set the `size` field of `record`.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Checks every character before it checks the room of `record`.
- Writes `record` with `offset` 24.
- Leaves the record unchecked: `discv5_enr_decode` checks it.

### Function never

- Writes more than `record` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 56 bytes on x86-64 (return address included), 0 bytes on ARM64, 112 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_enr_text_decode` (`_discv5_enr_text_decode` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `text`, `record`.

## Function `discv5_local_record`

Copies the local node record from the state.

### Signature

```
discv5_local_record(state, record) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | input | [`State`](node.md#type-state) |
| `record` | output | [`ByteList`](enr.md#type-bytelist) |

### Returns

- `DISCV5_OK`: `record` holds the local record.
- `DISCV5_BUFFER_TOO_SMALL`: The room of `record` is below the record length. Nothing is written.

### Caller must

- Pass a state from `discv5_init`.
- Set the `size` field of `record`.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Writes `record` with `offset` 24 and the record bytes.

### Function never

- Writes more than `record` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 72 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V, callees included.
- Record bytes: 300.

### ABI

- Role: L2.
- Symbol: `discv5_local_record` (`_discv5_local_record` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `state`, `record`.

## Function `discv5_copy`

Copies n bytes.

### Signature

```
discv5_copy(dst, src, n) -> dst + n
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | n bytes |
| `src` | input | n bytes |
| `n` | input | u64 in a register |

### Caller must

- Keep the regions apart.

### Function does

- Copies the bytes in order.

### Function never

- Writes more than `dst`.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_copy`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns `dst` + `n`, not a status.
- Argument order: `dst`, `src`, `n`.

## Function `discv5_zero`

Writes n zero bytes.

### Signature

```
discv5_zero(dst, n) -> dst + n
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | n bytes |
| `n` | input | u64 in a register |

### Function never

- Writes more than `dst`.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_zero`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns `dst` + `n`, not a status.
- Argument order: `dst`, `n`.

## Function `discv5_equal`

Compares n bytes.

### Signature

```
discv5_equal(a, b, n) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `a` | input | n bytes |
| `b` | input | n bytes |
| `n` | input | u64 in a register |

### Function does

- Returns 1 when the bytes are equal, else 0.
- Reads all n bytes of both, whatever they hold.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_equal`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `a`, `b`, `n`.

## Function `discv5_load_be`

Reads n bytes as a big-endian number.

### Signature

```
discv5_load_be(p, n) -> number
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | n bytes |
| `n` | input | u64 in a register, at most 8 |

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_load_be`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the number, not a status.
- Argument order: `p`, `n`.

## Function `discv5_store_be`

Writes the low n bytes of a number, big endian.

### Signature

```
discv5_store_be(p, v, n) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | output | n bytes |
| `v` | input | u64 in a register |
| `n` | input | u64 in a register, at most 8 |

### Function never

- Writes more than `p`.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_store_be`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `p`, `v`, `n`.

## Function `discv5_rlp_header`

Writes the RLP header of a byte string or list of a given payload length.

### Signature

```
discv5_rlp_header(out, length, base) -> out after the header
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `out` | output | 1 to 9 bytes |
| `length` | input | u64 in a register |
| `base` | input | 0x80 for a byte string, 0xC0 for a list |

### Function does

- Writes base + length for a length of at most 55, else base + 55 + the length bytes, then the length big endian.

### Function never

- Writes more than the header.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_rlp_header`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the position after the header, not a status.
- Argument order: `out`, `length`, `base`.

## Function `discv5_rlp_bytes`

Writes a byte string in RLP.

### Signature

```
discv5_rlp_bytes(out, data, len) -> out after the string
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `out` | output | up to 9 + len bytes |
| `data` | input | len bytes |
| `len` | input | u64 in a register |

### Function does

- Writes a single byte below 0x80 as itself, else a header and the bytes.

### Function never

- Writes more than the encoding.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_rlp_bytes`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the position after the string, not a status.
- Argument order: `out`, `data`, `len`.

## Function `discv5_rlp_uint`

Writes a number as an RLP byte string, big endian with no leading zero.

### Signature

```
discv5_rlp_uint(out, value) -> out after the string
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `out` | output | up to 9 bytes |
| `value` | input | u64 in a register |

### Function does

- Writes 0x80 for 0, the byte itself below 0x80, else a header and the bytes.

### Function never

- Writes more than the encoding.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_rlp_uint`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the position after the string, not a status.
- Argument order: `out`, `value`.

## Function `discv5_hash`

Hashes up to 304 bytes with SHA-256 or Keccak-256.

### Signature

```
discv5_hash(data, len, digest, keccak) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `data` | input | len bytes |
| `len` | input | u64 in a register, at most 304 |
| `digest` | output | 32 bytes |
| `keccak` | input | u64 in a register: 0 SHA-256, 1 Keccak-256 |

### Caller must

- Keep `digest` apart from `data`.

### Function does

- Copies the bytes into a `ByteList` on its stack, then calls `crypto_sha256` or `crypto_keccak256`.

### Function never

- Writes more than `digest` and its own stack.
- Makes an OS call.

### Limits

- Stack of its own: 400 bytes on x86-64 (return address included), 432 bytes on ARM64, 448 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_hash`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `data`, `len`, `digest`, `keccak`.

## Function `discv5_entry_set`

Sets one key/value entry of the local record, keeping the keys sorted.

### Signature

```
discv5_entry_set(state, key, key_len, value, value_len) -> 0 or 1
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | [`State`](node.md#type-state) |
| `key` | input | key_len bytes |
| `key_len` | input | u64 in a register, 1 to 16 |
| `value` | input | value_len bytes |
| `value_len` | input | u64 in a register, 0 to 64 |

### Function does

- Replaces the value of an entry with the same key.
- Inserts a new key in byte order: a key that is a prefix of another comes first.
- Returns 1 and changes nothing when a new key finds all 16 entries in use, else 0.

### Function never

- Writes more than the entries of `state`.
- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_entry_set`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 0 or 1, not a status.
- Argument order: `state`, `key`, `key_len`, `value`, `value_len`.

## Function `discv5_record_build`

Signs the entries at the sequence number and writes the local record.

### Signature

```
discv5_record_build(state) -> 0 or 1
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | [`State`](node.md#type-state) |

### Function does

- Builds [seq, k, v, ...] from the sorted entries.
- Signs Keccak-256 of that list with `crypto_secp256k1_sign` (RFC 6979 nonces, low S).
- Writes the record [signature, seq, k, v, ...] into the state.
- Returns 1 and leaves the record as it was when it would pass 300 bytes, else 0.

### Function never

- Writes more than the record fields of `state` and its own stack.
- Makes an OS call.

### Limits

- Stack of its own: 2176 bytes on x86-64 (return address included), 2208 bytes on ARM64, 2224 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_record_build`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 0 or 1, not a status.
- Argument order: `state`.

## Function `discv5_set_endpoint`

Sets "ip" and "udp", or "ip6" and "udp6", from an endpoint.

### Signature

```
discv5_set_endpoint(state, endpoint) -> 0 or 1
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | [`State`](node.md#type-state) |
| `endpoint` | input | [`Endpoint`](node.md#type-endpoint) |

### Function does

- Sets "ip" (4 bytes) and "udp" for family 4, or "ip6" (16 bytes) and "udp6" for family 6.
- Sets no port entry for port 0, and no entry at all for another family.
- Writes a port below 256 as 1 byte, else 2 bytes.
- Returns 1 when an entry did not fit, else 0. The caller restores the entries then.

### Function never

- Writes more than the entries of `state` and its own stack.
- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 112 bytes on ARM64, 128 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_set_endpoint`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 0 or 1, not a status.
- Argument order: `state`, `endpoint`.

## Function `discv5_owned_key`

Tells whether a key is one the core sets itself.

### Signature

```
discv5_owned_key(key, length) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `key` | input | length bytes |
| `length` | input | u64 in a register |

### Function does

- Returns 1 for "id", "secp256k1", "ip", "udp", "ip6" and "udp6", else 0.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_owned_key`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `key`, `length`.

## Type `ByteList`

A byte string in a buffer that also states its size.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Total buffer size in bytes |
| 8 | `offset` | u64 | Where the bytes start, from the buffer start |
| 16 | `count` | u64 | Bytes in use |

### Rules

- The buffer starts at a multiple of 8.
- `offset` is at least 24 and `offset` + `count` is at most `size`.
- Functions write an output `ByteList` with `offset` 24.

## Type `Enr`

The fields of a checked node record, as `discv5_enr_decode` writes them.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `node_id` | 32 bytes | Keccak-256 of the public key, x then y |
| 32 | `pubkey` | 33 bytes | The "secp256k1" value |
| 72 | `seq` | u64 | The sequence number |
| 80 | `ip4` | 4 bytes | The "ip" value |
| 88 | `udp4` | u64 | The "udp" value |
| 96 | `ip6` | 16 bytes | The "ip6" value |
| 112 | `udp6` | u64 | The "udp6" value |
| 120 | `has` | u64 | Bit 0 "ip", bit 1 "udp", bit 2 "ip6", bit 3 "udp6" |
| 128 | `count` | u64 | Key/value pairs |
| 136 | `pairs` | `EnrPair` [128] | Every pair, in record order |

### Rules

- Size: 3208 bytes (`DISCV5_ENR_SIZE`).
- A field whose bit in `has` is 0 holds zeros.

## Type `EnrPair`

Where one key and its value sit in the record bytes.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `key_offset` | u32 | The key bytes, from the record start |
| 4 | `key_len` | u32 | Key length |
| 8 | `value_offset` | u32 | The value bytes, or the whole encoded list |
| 12 | `value_len` | u32 | Value length |
| 16 | `value_kind` | u32 | 1 byte string, 2 list |

### Rules

- Size: 24 bytes; the last 4 are zero.

## Type `EnrScratch`

The workspace of `discv5_enr_decode`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Total buffer size in bytes |
| 8 | `sig` | 64 bytes | The signature |
| 72 | `content` | 304 bytes | The signed list |
| 376 | `point` | 64 bytes | The public key, x then y |
| 440 | `hash` | 32 bytes | The hash of the signed list |
| 472 | `valid` | u64 | The signature check |
| 480 | `items` | asm-rlp `Items` | The decoded record |

### Rules

- `size` is at least `DISCV5_ENR_SCRATCH` (10240).

## Type `LocalEntry`

One key/value entry of the local record, in the state.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `key_len` | u8 | 1 to 16 |
| 1 | `value_len` | u8 | 0 to 64 |
| 8 | `key` | 16 bytes | The key |
| 24 | `value` | 64 bytes | The value |

### Rules

- Size: 96 bytes.
- The state holds up to 16, sorted by key.

## Test vectors

- devp2p discv5 wire test vectors
  - File: [discv5-wire-test-vectors.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-wire-test-vectors.md), SHA-256 dbcb81f70bc963cad2d5b28fd7ef99e0c4b4ce4d03497f7c75d63ef752115170
- devp2p node record examples
  - File: [enr.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/enr.md), SHA-256 29260bceb96e289140dc08c1336e1f26e070613664a7ec6db72fffbfb85cc58d
- go-ethereum v1.17.10 (commit 1df30b18): records, packets, handshakes and keys built with its `enr`, `enode` and `v5wire` packages
  - Files: written by [tests/generator/](../../tests/generator/) and run by [tests/runner/](../../tests/runner/)

## Results

<!-- CI generates the tick table for each function here. -->

### `discv5_enr_decode`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_enr_text_decode`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_local_record`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_copy`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_zero`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_equal`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_load_be`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_store_be`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_rlp_header`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_rlp_bytes`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_rlp_uint`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_hash`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_entry_set`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_record_build`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_set_endpoint`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_owned_key`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
