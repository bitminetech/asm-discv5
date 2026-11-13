# Handshake

## Contents

### Functions

- [`discv5_derive_keys`](#function-discv5_derive_keys): derives the session keys of a handshake.
- [`discv5_id_sign`](#function-discv5_id_sign): signs the ID proof.
- [`discv5_id_verify`](#function-discv5_id_verify): checks the ID proof.

### Types

- [`Challenge`](#type-challenge): the challenge data of a handshake.
- [`SessionKeys`](#type-sessionkeys): the two keys of a session.

### Constants

- `DISCV5_INVALID_KEY`: status 2.

## Spec

- Document: [discv5-theory.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-theory.md), devp2p at commit 88f1c80.
- Section: Handshake Steps, Identity-Specific Cryptography in the Handshake.

## Function `discv5_derive_keys`

Derives the two session keys of a handshake from an ECDH secret and the challenge.

### Signature

```
discv5_derive_keys(private_key, public_key, challenge, ids, keys) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `private_key` | input | 32 bytes |
| `public_key` | input | 33 bytes, compressed |
| `challenge` | input | `Challenge` |
| `ids` | input | 64 bytes: the initiator node ID, then the recipient node ID |
| `keys` | output | `SessionKeys` |

### Returns

- `DISCV5_OK`: `keys` holds the keys.
- `DISCV5_INVALID_KEY`: A key is not valid. Nothing is written.

### Caller must

- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Computes the secret with `crypto_secp256k1_ecdh`: the compressed shared point, 33 bytes.
- Computes prk = HKDF-Extract(challenge, secret) with `crypto_hkdf_extract`.
- Computes 32 bytes of HKDF-Expand(prk, "discovery v5 key agreement" || ids) with `crypto_hkdf_expand`.

### Function never

- Writes more than `keys` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Effects

- Its stack holds the secret after it returns.

### Limits

- Stack: 2088 bytes on x86-64 (return address included), 2160 bytes on ARM64, 2256 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_derive_keys` (`_discv5_derive_keys` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `private_key`, `public_key`, `challenge`, `ids`, `keys`.

## Function `discv5_id_sign`

Signs the ID proof of a handshake.

### Signature

```
discv5_id_sign(private_key, challenge, ephemeral_key, dest_id, signature) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `private_key` | input | 32 bytes |
| `challenge` | input | `Challenge` |
| `ephemeral_key` | input | 33 bytes |
| `dest_id` | input | `NodeId` |
| `signature` | output | 64 bytes |

### Returns

- `DISCV5_OK`: `signature` holds r then s.
- `DISCV5_INVALID_KEY`: The private key is not valid.

### Caller must

- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Signs SHA-256("discovery v5 identity proof" || challenge || ephemeral_key || dest_id) with `crypto_secp256k1_sign`.

### Function never

- Writes more than `signature` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 2248 bytes on x86-64 (return address included), 2320 bytes on ARM64, 2416 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_id_sign` (`_discv5_id_sign` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `private_key`, `challenge`, `ephemeral_key`, `dest_id`, `signature`.

## Function `discv5_id_verify`

Checks the ID proof in a handshake header.

### Signature

```
discv5_id_verify(public_key, challenge, header, dest_id, valid) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `public_key` | input | 33 bytes |
| `challenge` | input | `Challenge` |
| `header` | input | [`Header`](wire.md#type-header) |
| `dest_id` | input | `NodeId` |
| `valid` | output | u64 |

### Returns

- `DISCV5_OK`: `valid` holds 1 for a good signature, else 0.
- `DISCV5_INVALID_KEY`: The public key is not valid.

### Caller must

- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Checks the signature and ephemeral key of `header` over SHA-256("discovery v5 identity proof" || challenge || ephemeral key || dest_id) with `crypto_secp256k1_verify`.

### Function never

- Writes more than `valid` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Limits

- Stack: 2072 bytes on x86-64 (return address included), 2144 bytes on ARM64, 2240 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_id_verify` (`_discv5_id_verify` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `public_key`, `challenge`, `header`, `dest_id`, `valid`.

## Type `Challenge`

The unmasked WHOAREYOU packet: its IV, static header and authdata.

### Rules

- Size: 63 bytes (`DISCV5_CHALLENGE_SIZE`).

## Type `SessionKeys`

The keys HKDF-Expand gives.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `initiator_key` | 16 bytes | The initiator writes with it |
| 16 | `recipient_key` | 16 bytes | The recipient writes with it |

## Test vectors

- devp2p discv5 wire test vectors
  - File: [discv5-wire-test-vectors.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-wire-test-vectors.md), SHA-256 dbcb81f70bc963cad2d5b28fd7ef99e0c4b4ce4d03497f7c75d63ef752115170
- devp2p node record examples
  - File: [enr.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/enr.md), SHA-256 29260bceb96e289140dc08c1336e1f26e070613664a7ec6db72fffbfb85cc58d
- go-ethereum v1.17.10 (commit 1df30b18): records, packets, handshakes and keys built with its `enr`, `enode` and `v5wire` packages
  - Files: written by [tests/generator/](../../tests/generator/) and run by [tests/runner/](../../tests/runner/)

## Results

<!-- CI generates the tick table for each function here. -->
