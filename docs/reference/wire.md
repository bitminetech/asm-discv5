# Wire protocol

## Contents

### Functions

- [`discv5_packet_decode`](#function-discv5_packet_decode): unmasks a packet and reads its header.
- [`discv5_message_decrypt`](#function-discv5_message_decrypt): opens the message of a packet.
- [`discv5_packet_encode`](#function-discv5_packet_encode): builds and masks a packet.

### Types

- [`Header`](#type-header): a packet header.
- [`NodeId`](#type-nodeid): a node ID.

### Constants

- `DISCV5_MAX_PACKET`: 1280 bytes.
- `DISCV5_MIN_PACKET`: 63 bytes.
- `DISCV5_INVALID_PACKET`: status 6.
- `DISCV5_DECRYPT_FAIL`: status 7.

## Spec

- Document: [discv5-wire.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-wire.md), devp2p at commit 88f1c80.
- Section: Packet Encoding, Protocol Messages.

## Function `discv5_packet_decode`

Unmasks a packet with the local node ID and reads its header.

### Signature

```
discv5_packet_decode(packet, local_id, header) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `packet` | input | [`ByteList`](enr.md#type-bytelist) |
| `local_id` | input | `NodeId` |
| `header` | output | `Header` |

### Returns

- `DISCV5_OK`: `header` holds the header.
- `DISCV5_INVALID_PACKET`: The packet breaks a rule below. `header` may be partly written.

### Caller must

- Pass a valid `ByteList` in `packet`.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Takes 63 to 1280 bytes.
- Unmasks up to 496 bytes after the IV with `crypto_aes128_ctr`: the first 16 bytes of `local_id` as key, the IV as counter.
- Takes "discv5", a version of at least 1, and an authdata size that fits the packet and 473 bytes.
- Takes at least 48 bytes after the static header for flags 0 and 2.
- Flag 0: takes 32 bytes of authdata, the source ID.
- Flag 1: takes 24 bytes of authdata, the ID nonce and the record sequence number.
- Flag 2: takes the source ID, a signature size of 64, a key size of 33, the signature, the ephemeral key, and a record of at most 300 bytes.
- Writes the unmasked IV, static header and authdata into the `header` field of `header`.
- Leaves the message sealed and the record unchecked.

### Function never

- Writes more than `header` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 2552 bytes on x86-64 (return address included), 2560 bytes on ARM64, 2640 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_packet_decode` (`_discv5_packet_decode` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `packet`, `local_id`, `header`.

## Function `discv5_message_decrypt`

Opens the AES-128-GCM message after the header of a packet.

### Signature

```
discv5_message_decrypt(header, key, packet, message) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `header` | input | `Header` |
| `key` | input | 16 bytes |
| `packet` | input | [`ByteList`](enr.md#type-bytelist) |
| `message` | output | [`ByteList`](enr.md#type-bytelist) |

### Returns

- `DISCV5_OK`: `message` holds the plaintext.
- `DISCV5_BUFFER_TOO_SMALL`: The room of `message` is below the plaintext.
- `DISCV5_DECRYPT_FAIL`: The sealed bytes are fewer than 17 or more than 1304, or the tag does not match.

### Caller must

- Pass the `header` that `discv5_packet_decode` wrote for `packet`.
- Set the `size` field of `message`.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Opens the bytes after the header with `crypto_aes128_gcm_ad`: the header nonce, and the unmasked header as associated data.

### Function never

- Writes more than `message` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 2920 bytes on x86-64 (return address included), 2944 bytes on ARM64, 3024 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_message_decrypt` (`_discv5_message_decrypt` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `header`, `key`, `packet`, `message`.

## Function `discv5_packet_encode`

Builds a packet from a header, seals its message, and masks the header.

### Signature

```
discv5_packet_encode(header, dest_id, key, message, packet) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `header` | state | `Header`: the function writes its `header` field |
| `dest_id` | input | `NodeId` |
| `key` | input | 16 bytes |
| `message` | input | [`ByteList`](enr.md#type-bytelist) |
| `packet` | output | [`ByteList`](enr.md#type-bytelist) |

### Returns

- `DISCV5_OK`: `packet` holds the packet.
- `DISCV5_BUFFER_TOO_SMALL`: The room of `packet` is below the packet.
- `DISCV5_INVALID_PACKET`: The flag is above 2, the record passes 300 bytes, or the packet would pass 1280 bytes.

### Caller must

- Set the IV, nonce, flag and the authdata fields of the flag in `header`.
- Set the `size` field of `packet`.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Makes every check before its first write, so a failure leaves `header` unchanged.
- Writes the unmasked header (IV, "discv5", version 1, flag, nonce, authdata size, authdata) into the `header` field of `header`.
- Seals `message` with `crypto_aes128_gcm_ae` under `key`, the nonce, and the unmasked header as associated data, except for flag 1.
- Masks the header after the IV with `crypto_aes128_ctr`: the first 16 bytes of `dest_id` as key, the IV as counter.

### Function never

- Writes more than `packet`, the `header` field of `header` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 3976 bytes on x86-64 (return address included), 3984 bytes on ARM64, 4064 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_packet_encode` (`_discv5_packet_encode` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `header`, `dest_id`, `key`, `message`, `packet`.

## Type `Header`

A packet header, as `discv5_packet_decode` writes it and `discv5_packet_encode` reads it.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `iv` | 16 bytes | The masking IV |
| 16 | `nonce` | 12 bytes | The message nonce |
| 32 | `flag` | u64 | 0 message, 1 WHOAREYOU, 2 handshake |
| 40 | `src_id` | 32 bytes | Flags 0 and 2 |
| 72 | `id_nonce` | 16 bytes | Flag 1 |
| 88 | `enr_seq` | u64 | Flag 1 |
| 96 | `signature` | 64 bytes | Flag 2 |
| 160 | `eph_key` | 33 bytes | Flag 2 |
| 200 | `record` | `ByteList` of 324 bytes | Flag 2; `count` 0 for none |
| 528 | `header` | `ByteList` of 536 bytes | The unmasked IV, static header and authdata |

### Rules

- Size: 1064 bytes (`DISCV5_HDR_SIZE`).

## Type `NodeId`

A node ID: 32 bytes, Keccak-256 of the public key.

### Rules

- Its first 16 bytes are the masking key of packets to the node.

## Test vectors

- devp2p discv5 wire test vectors
  - File: [discv5-wire-test-vectors.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-wire-test-vectors.md), SHA-256 dbcb81f70bc963cad2d5b28fd7ef99e0c4b4ce4d03497f7c75d63ef752115170
- devp2p node record examples
  - File: [enr.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/enr.md), SHA-256 29260bceb96e289140dc08c1336e1f26e070613664a7ec6db72fffbfb85cc58d
- go-ethereum v1.17.10 (commit 1df30b18): records, packets, handshakes and keys built with its `enr`, `enode` and `v5wire` packages
  - Files: written by [tests/generator/](../../tests/generator/) and run by [tests/runner/](../../tests/runner/)

## Results

<!-- CI generates the tick table for each function here. -->

### `discv5_packet_decode`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_message_decrypt`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_packet_encode`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
