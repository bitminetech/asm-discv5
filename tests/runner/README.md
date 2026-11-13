# Test runner

`runner.c` and `step.c` read the binary case files from [tests/generator/](../generator/), call the library for every case, and compare the results. They are test code in C; the library itself is pure assembly.

```bash
tests/generator/run.sh ~/.cache/asm-discv5/vectors
```

```bash
tests/runner/docker.sh ~/.cache/asm-discv5/vectors
```

```bash
tests/runner/macos.sh ~/.cache/asm-discv5/vectors
```

| Script | What it does |
|---|---|
| `docker.sh` | Builds the Docker image, builds the library for all 7 targets into `build/`, and runs the vectors for Linux x86-64, ARM64 and RISC-V. ISAs other than the host's run under QEMU user mode. |
| `macos.sh` | Links the runner on a Mac against the library that `docker.sh` built, and runs the vectors. |
| `tick_tables.py` | Writes the tick table of each function into its document, from the results of every target. |
| `abi_x86_64.s`, `abi_arm64.s`, `abi_riscv64.s` | `abi_call`, through which the runner calls every library function. Test code in assembly. |

Name vector files after the folder to run only those files, for example `tests/runner/docker.sh DIR step.bin`.

[.github/workflows/ci.yml](../../.github/workflows/ci.yml) runs every file on all 7 targets: Linux on GitHub's x64 and ARM64 runners (RISC-V under QEMU), Windows on `windows-2025` and `windows-11-arm`, and macOS on `macos-15-intel` and `macos-15`.

Inputs sit in buffers of their exact size and must stay unchanged. Outputs have guard bytes on both sides. Each `ByteList` output and scratch buffer gets exactly the size the function needs; the runner also calls with one byte less, which must give `DISCV5_BUFFER_TOO_SMALL`.

## Step cases

| Case | What it checks |
|---|---|
| record | Each SET_ENDPOINT or SET_ENTRY gives the record go-ethereum signs for the same entries, or no record when the change is refused; a refused event leaves the state unchanged. |
| nodes | Three nodes on a simulated network: two know only the third; after their handshakes and checks, a lookup by one finds the other, and a PONG reports the endpoint seen. |
| errors | Short scratch or action room, and every malformed event kind, give their status and leave the state unchanged; datagrams that do not decode and shell results change nothing; the time never goes back. |
| challenge | A packet without a session gets WHOAREYOU for its nonce; another within 1 second gets the same bytes; one after 1 second gets a new one. |

## ABI and stack check

- The runner calls every L2 function through `abi_call`, in `abi_x86_64.s`, `abi_arm64.s` and `abi_riscv64.s`. It is test code in assembly.
- Before the call, `abi_call` sets each register that the callee must keep to a known value, and paints the stack below the call.
- After the call, it records the status, the kept state that changed, and the bytes of stack the call used.
- The runner fails when a call changes kept state, or uses more than 16384 bytes of stack.
