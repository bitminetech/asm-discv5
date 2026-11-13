# Conformance

The test node runs the library and the shell of a target as an application would, and go-ethereum's discv5 test suite checks it over UDP.

```bash
tests/conformance/build-devp2p.sh ~/.cache/asm-discv5/devp2p
```

```bash
tests/conformance/docker.sh ~/.cache/asm-discv5/devp2p
```

```bash
tests/conformance/macos.sh ~/.cache/asm-discv5/devp2p
```

| File | What it does |
|---|---|
| `node.c` | The test node: it prints its record as "enr:..." text, then runs the event loop. Test code in C. |
| `build-devp2p.sh` | Builds the `devp2p` tool of go-ethereum v1.17.10 for Linux, macOS and Windows on x86-64 and ARM64, in the image of [platform/linux/Dockerfile](../../platform/linux/Dockerfile). |
| `run.sh` | Starts the node of one target, runs `devp2p discv5 test` against it, then checks that a second node closes its socket. It prints "FUNCTION <name> PASS" for each shell function when all of it passed. |
| `docker.sh` | Runs `run.sh` for Linux x86-64, ARM64 and RISC-V in Docker, against the nodes that [tests/runner/docker.sh](../runner/docker.sh) built. ISAs other than the host's run under QEMU user mode. |
| `macos.sh` | Links the node on a Mac and runs `run.sh`. |

| Reference | Pin |
|---|---|
| Test suite | go-ethereum v1.17.10, `cmd/devp2p/internal/v5test`: Ping, PingLargeRequestID, PingMultiIP, HandshakeResend, TalkRequest, FindnodeWrongIP, FindnodeHandshake, FindnodeZeroDistance, FindnodeResults, UnsolicitedNodes |

The second tester address is 127.0.0.2 on Linux, where the loopback takes all of 127/8, and 127.0.0.1 elsewhere. Sessions are per address and port, so a tester on another port of the same address is another endpoint.

| Node option | What it does |
|---|---|
| `-v` | Prints every action. |
| `-b ENR` | Adds a record, such as a bootnode. |
| `-l SECONDS` | Looks up a random node ID every SECONDS; `-t HEX` fixes the target. |
| `-x SECONDS` | Stops after SECONDS: closes the socket and prints "closed". |
| `-c COUNT` | Prints "peer N ID enr:..." for each new node ID that lookups find, and stops after COUNT of them. |
| IP `0.0.0.0` | Binds every interface and leaves the address out of the record. |
