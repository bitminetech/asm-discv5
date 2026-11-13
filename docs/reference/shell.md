# Shell

## Contents

### Functions

- [`discv5_shell_open`](#function-discv5_shell_open): opens the UDP socket.
- [`discv5_shell_clock`](#function-discv5_shell_clock): reads the time and random bytes.
- [`discv5_shell_send`](#function-discv5_shell_send): performs a SEND action.
- [`discv5_shell_receive`](#function-discv5_shell_receive): waits for a datagram.
- [`discv5_shell_close`](#function-discv5_shell_close): closes the socket.
- [`discv5_shell_sockaddr`](#function-discv5_shell_sockaddr): builds a native socket address.
- [`discv5_shell_endpoint`](#function-discv5_shell_endpoint): reads a native socket address.
- [`discv5_shell_now`](#function-discv5_shell_now): reads the clock.

### Types

- [`ShellContext`](#type-shellcontext): the socket of the shell.

### Constants

- `DISCV5_OS_ERROR`: status 8.
- `DISCV5_EVENT_MAX`: the largest event, 1336 bytes.

## Spec

- Document: ARCHITECTURE.md section 2 (core and shell) and section 6 (actions and events).
- Section: the shell of this library: one UDP socket, the clock and random bytes.

## Function `discv5_shell_open`

Opens a UDP socket bound to an endpoint.

### Signature

```
discv5_shell_open(endpoint, context, event) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `endpoint` | input | [`Endpoint`](node.md#type-endpoint) |
| `context` | resource context | `ShellContext` |
| `event` | output | [`OpenedEvent`](node.md#type-openedevent) |

### Returns

- `DISCV5_OK`: `event` holds 0 and the bound endpoint, or the OS error.

### Caller must

- Pass family 4 or 6; port 0 binds any free port.
- Call `discv5_shell_close` before the context is reused.

### Function does

- Windows: starts Winsock 2.2 first.
- Makes a datagram socket of the family; an IPv6 socket also takes IPv4.
- Binds it, then reads the bound endpoint.
- On an error closes the socket and keeps the error.

### Function never

- Writes more than `context`, `event` and its own stack.
- Keeps a pointer after it returns.

### Effects

- The context owns the socket until `discv5_shell_close`.

### Limits

- Stack of its own: 208 bytes on Linux x86-64, 208 bytes on Linux ARM64, 208 bytes on Linux RISC-V, 208 bytes on macOS x86-64, 208 bytes on macOS ARM64, 656 bytes on Windows x86-64, 624 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `discv5_shell_open` (`_discv5_shell_open` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `endpoint`, `context`, `event`.

## Function `discv5_shell_clock`

Reads the time and 32 random bytes.

### Signature

```
discv5_shell_clock(tick) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `tick` | output | [`Tick`](node.md#type-tick) |

### Returns

- `DISCV5_OK`: `tick` holds the time and the bytes.
- `DISCV5_OS_ERROR`: The clock or the random source failed.

### Function does

- Linux: `clock_gettime(CLOCK_MONOTONIC)` and `getrandom`.
- macOS: `clock_gettime_nsec_np(CLOCK_MONOTONIC)` and `getentropy`.
- Windows: `GetTickCount64` and `BCryptGenRandom` with the system RNG.

### Function never

- Writes more than `tick` and its own stack.
- Keeps a pointer after it returns.

### Limits

- Stack of its own: 64 bytes on Linux x86-64, 64 bytes on Linux ARM64, 64 bytes on Linux RISC-V, 64 bytes on macOS x86-64, 64 bytes on macOS ARM64, 96 bytes on Windows x86-64, 64 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `discv5_shell_clock` (`_discv5_shell_clock` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `tick`.

## Function `discv5_shell_send`

Sends the datagram of a SEND action.

### Signature

```
discv5_shell_send(context, action, event) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `context` | resource context | `ShellContext` |
| `action` | input | [`SendAction`](node.md#type-sendaction) |
| `event` | output | [`SentEvent`](node.md#type-sentevent) |

### Returns

- `DISCV5_OK`: `event` holds 0, or the OS error.

### Caller must

- Pass the context of an open socket.

### Function does

- Sends with `sendto`; an IPv4 endpoint on an IPv6 socket goes as an IPv4-mapped address.
- Gives EINVAL for another action kind and EAFNOSUPPORT for an endpoint the socket cannot reach.

### Function never

- Writes more than `event` and its own stack.
- Keeps a pointer after it returns.

### Limits

- Stack of its own: 192 bytes on Linux x86-64, 192 bytes on Linux ARM64, 192 bytes on Linux RISC-V, 192 bytes on macOS x86-64, 192 bytes on macOS ARM64, 104 bytes on Windows x86-64, 192 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `discv5_shell_send` (`_discv5_shell_send` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `context`, `action`, `event`.

## Function `discv5_shell_receive`

Waits for a datagram until a time.

### Signature

```
discv5_shell_receive(context, until, event) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `context` | resource context | `ShellContext` |
| `until` | input | u64: milliseconds, the clock of `discv5_shell_clock` |
| `event` | output | `DISCV5_EVENT_MAX` bytes: a [`DatagramEvent`](node.md#type-datagramevent) or an [`IdleEvent`](node.md#type-idleevent) |

### Returns

- `DISCV5_OK`: `event` holds a datagram, or IDLE with 0 when the time passed, else the OS error.

### Caller must

- Pass the context of an open socket.
- Pass an `event` of `DISCV5_EVENT_MAX` bytes.

### Function does

- Waits with `ppoll`, `poll` or `WSAPoll`, then reads one datagram without blocking.
- Gives an IPv4-mapped sender as IPv4.
- Reads at most 1280 bytes: Linux and macOS cut a longer datagram off; Windows gives IDLE with the error.

### Function never

- Writes more than `event` and its own stack.
- Keeps a pointer after it returns.

### Limits

- Stack of its own: 224 bytes on Linux x86-64, 224 bytes on Linux ARM64, 224 bytes on Linux RISC-V, 208 bytes on macOS x86-64, 208 bytes on macOS ARM64, 256 bytes on Windows x86-64, 224 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `discv5_shell_receive` (`_discv5_shell_receive` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `context`, `until`, `event`.

## Function `discv5_shell_close`

Closes the socket.

### Signature

```
discv5_shell_close(context) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `context` | resource context | `ShellContext` |

### Returns

- `DISCV5_OK`: The socket is closed.

### Function does

- Closes an open socket and marks the context closed.
- Windows: then stops Winsock when `discv5_shell_open` started it.

### Function never

- Writes more than `context` and its own stack.
- Keeps a pointer after it returns.

### Limits

- Stack of its own: 8 bytes on Linux x86-64, 0 bytes on Linux ARM64, 0 bytes on Linux RISC-V, 64 bytes on macOS x86-64, 64 bytes on macOS ARM64, 96 bytes on Windows x86-64, 64 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `discv5_shell_close` (`_discv5_shell_close` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `context`.

## Function `discv5_shell_sockaddr`

Builds the native socket address of an endpoint.

### Signature

```
discv5_shell_sockaddr(endpoint, family, sockaddr) -> length or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `endpoint` | input | [`Endpoint`](node.md#type-endpoint) |
| `family` | input | u64 in a register: 4 or 6 |
| `sockaddr` | output | 32 bytes |

### Function does

- Returns the length of `sockaddr_in` or `sockaddr_in6`, or 0 when the endpoint does not fit the socket family.
- Maps IPv4 into IPv6 for a family 6 socket.

### Function never

- Writes more than `sockaddr`.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on Linux x86-64, 0 bytes on Linux ARM64, 0 bytes on Linux RISC-V, 8 bytes on macOS x86-64, 0 bytes on macOS ARM64, 8 bytes on Windows x86-64, 0 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `discv5_shell_sockaddr`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the length or 0, not a status.
- Argument order: `endpoint`, `family`, `sockaddr`.

## Function `discv5_shell_endpoint`

Reads a native socket address as an endpoint.

### Signature

```
discv5_shell_endpoint(sockaddr, endpoint) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `sockaddr` | input | a native socket address |
| `endpoint` | output | [`Endpoint`](node.md#type-endpoint) |

### Function does

- Returns 1 for IPv4 or IPv6, else 0.
- Gives an IPv4-mapped IPv6 address as IPv4.

### Function never

- Writes more than `endpoint`.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on Linux x86-64, 0 bytes on Linux ARM64, 0 bytes on Linux RISC-V, 8 bytes on macOS x86-64, 0 bytes on macOS ARM64, 8 bytes on Windows x86-64, 0 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `discv5_shell_endpoint`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `sockaddr`, `endpoint`.

## Function `discv5_shell_now`

Reads the monotonic clock in milliseconds.

### Signature

```
discv5_shell_now() -> milliseconds
```

### Function does

- Returns 0 when the clock fails (Linux and macOS).

### Function never

- Writes more than its own stack.

### Limits

- Stack of its own: 32 bytes on Linux x86-64, 16 bytes on Linux ARM64, 16 bytes on Linux RISC-V, 64 bytes on macOS x86-64, 64 bytes on macOS ARM64, 48 bytes on Windows x86-64, 64 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `discv5_shell_now`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns milliseconds, not a status.

## Type `ShellContext`

The native resource context of the shell: one UDP socket.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `socket` | u64 | The descriptor or SOCKET; all ones when closed |
| 8 | `family` | u64 | 4 or 6 |
| 16 | `started` | u64 | Windows: 1 after WSAStartup |

### Rules

- Size: 64 bytes (`DISCV5_SHELL_SIZE`).
- Native and opaque: the core never reads it.
- One thread uses a context at a time.

## Test vectors

- go-ethereum v1.17.10 conformance suite: `devp2p discv5 test`
  - Run by: [tests/conformance/](../../tests/conformance/) against the test node on each target

## Results

<!-- CI generates the tick table for each function here. -->

### `discv5_shell_open`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_clock`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_send`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_receive`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_close`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_sockaddr`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_endpoint`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_shell_now`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
