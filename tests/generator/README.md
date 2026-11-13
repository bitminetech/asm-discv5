# Vector generation

`run.sh` writes the binary case files to one output folder, which must be outside this repo.

```bash
tests/generator/run.sh ~/.cache/asm-discv5/vectors
```

| Script | Writes | Needs |
|---|---|---|
| `run.sh` | `enr.bin`, `enr-text.bin`, `packet.bin`, `handshake.bin`, `init.bin`, `step.bin` | Docker; it runs `main.go` in the image of [platform/linux/Dockerfile](../../platform/linux/Dockerfile) |

`run.sh` keeps its downloads in `sources/` and the Go module and build caches in `.go/` in the output folder, so a second run downloads nothing again.

| Reference | Pin |
|---|---|
| go-ethereum | v1.17.10, with every module pinned in [go.sum](go.sum) |
| devp2p specs and vectors | [devp2p@88f1c80](https://github.com/ethereum/devp2p/tree/88f1c80800d622cc3a542a2125bbe33cc18c9f9c); `run.sh` checks the SHA-256 of `discv5-wire-test-vectors.md` and `enr.md` |

`main.go` stops when go-ethereum disagrees with an official devp2p result that it uses.

## File format

- A file starts with "DISCV5V1", then the case count (u64).
- A case is its kind (u64), its name (blob), then its body.
- Numbers are u64 little endian. A blob is its length (u64), then its bytes.

| Kind | File | Body |
|---|---|---|
| 1 | `enr.bin` | Record (blob), status; for a valid record, the first 136 bytes of `Enr`, then its pairs (blob) |
| 2 | `enr-text.bin` | Text (blob), status, record (blob) |
| 3 | `packet.bin` | Packet (blob), local node ID (32), decode status, flag, IV (16), nonce (12), source ID (32), ID nonce (16), record sequence number, signature (64), ephemeral key (40), record (blob), unmasked header (blob), key (16), decrypt status, plaintext (blob), 1 when the runner also encodes the packet |
| 4 | `handshake.bin` | Private key (32), public key (40), challenge (64), IDs (64), status, keys (32) |
| 5 | `handshake.bin` | Private key (32), challenge (64), ephemeral key (40), destination ID (32), status, signature (64) |
| 6 | `handshake.bin` | Public key (40), challenge (64), ephemeral key (40), destination ID (32), signature (64), status, valid |
| 7 | `init.bin` | Private key (32), sequence number, port, family, address (16), status, record (blob) |
| 8 | `step.bin` | Sub kind, then its body |

Fixed fields are zero padded to the sizes shown.

| Step sub kind | Body |
|---|---|
| 1 record | Private key (32), sequence number, port, family, address (16), change count; each change: the event (blob), the step status, the record geth signs (blob, empty when the change is refused) |
| 2 nodes | Three private keys (32 each) |
| 3 errors | A private key (32) |
| 4 challenge | The node's private key (32), the sender's private key (32) |
