# Node

The node: table, sessions, lookups, step.

## Contents

### Functions

- [`discv5_init`](#function-discv5_init): starts a node.
- [`discv5_step`](#function-discv5_step): runs the node on events.
- [`discv5_random`](#function-discv5_random): reads bytes from the DRBG.
- [`discv5_reseed`](#function-discv5_reseed): reseeds the DRBG.
- [`discv5_log_distance`](#function-discv5_log_distance): measures the log distance of two node IDs.
- [`discv5_action`](#function-discv5_action): adds an action.
- [`discv5_send_packet`](#function-discv5_send_packet): adds a SEND action.
- [`discv5_enr_endpoint`](#function-discv5_enr_endpoint): reads the UDP endpoint of a record.
- [`discv5_session_find`](#function-discv5_session_find): finds a session.
- [`discv5_session_put`](#function-discv5_session_put): stores a session.
- [`discv5_challenge_find`](#function-discv5_challenge_find): finds a WHOAREYOU sent.
- [`discv5_challenge_new`](#function-discv5_challenge_new): makes a WHOAREYOU.
- [`discv5_send_whoareyou`](#function-discv5_send_whoareyou): sends a WHOAREYOU.
- [`discv5_request_find`](#function-discv5_request_find): finds a request by nonce.
- [`discv5_request_match`](#function-discv5_request_match): matches a response to a request.
- [`discv5_bucket`](#function-discv5_bucket): gives the bucket of a node ID.
- [`discv5_node_find`](#function-discv5_node_find): finds a node in the table.
- [`discv5_node_count`](#function-discv5_node_count): counts a bucket.
- [`discv5_ip_lan`](#function-discv5_ip_lan): tests for a local network address.
- [`discv5_prefix_equal`](#function-discv5_prefix_equal): compares the first bits of two addresses.
- [`discv5_ip_fits`](#function-discv5_ip_fits): checks the IP limits.
- [`discv5_node_add`](#function-discv5_node_add): adds a node to the table.
- [`discv5_node_remove`](#function-discv5_node_remove): removes a node from the table.
- [`discv5_msg_finish`](#function-discv5_msg_finish): finishes a message.
- [`discv5_send_message`](#function-discv5_send_message): sends a message.
- [`discv5_emit_record`](#function-discv5_emit_record): adds a RECORD action.
- [`discv5_emit_found`](#function-discv5_emit_found): adds a NODE_FOUND action.
- [`discv5_emit_done`](#function-discv5_emit_done): adds a LOOKUP_DONE action.
- [`discv5_request_message`](#function-discv5_request_message): writes a request message.
- [`discv5_request_start`](#function-discv5_request_start): starts a request.
- [`discv5_request_end`](#function-discv5_request_end): ends a request.
- [`discv5_requests_resend`](#function-discv5_requests_resend): resends waiting requests.
- [`discv5_candidate_find`](#function-discv5_candidate_find): finds a lookup candidate.
- [`discv5_closer`](#function-discv5_closer): compares distances to a target.
- [`discv5_candidate_insert`](#function-discv5_candidate_insert): adds a lookup candidate.
- [`discv5_lookup_distances`](#function-discv5_lookup_distances): picks the distances to ask.
- [`discv5_lookup_advance`](#function-discv5_lookup_advance): moves a lookup on.
- [`discv5_lookup_start`](#function-discv5_lookup_start): starts a lookup.
- [`discv5_msg_field`](#function-discv5_msg_field): finds a field of the message.
- [`discv5_item_uint`](#function-discv5_item_uint): reads a number field.
- [`discv5_handle_message`](#function-discv5_handle_message): handles a decrypted message.
- [`discv5_reply`](#function-discv5_reply): sends a response.
- [`discv5_reqid_out`](#function-discv5_reqid_out): writes the request ID back.
- [`discv5_on_ping`](#function-discv5_on_ping): answers PING.
- [`discv5_on_pong`](#function-discv5_on_pong): takes PONG.
- [`discv5_on_talkreq`](#function-discv5_on_talkreq): answers TALKREQ.
- [`discv5_result_record`](#function-discv5_result_record): gives a FINDNODE result record.
- [`discv5_nodes_send`](#function-discv5_nodes_send): sends one NODES packet.
- [`discv5_nodes_pack`](#function-discv5_nodes_pack): packs NODES packets.
- [`discv5_on_findnode`](#function-discv5_on_findnode): answers FINDNODE.
- [`discv5_nodes_record`](#function-discv5_nodes_record): takes one record of NODES.
- [`discv5_on_nodes`](#function-discv5_on_nodes): takes NODES.
- [`discv5_on_message_packet`](#function-discv5_on_message_packet): takes a message packet.
- [`discv5_on_whoareyou`](#function-discv5_on_whoareyou): answers WHOAREYOU.
- [`discv5_on_handshake`](#function-discv5_on_handshake): takes a handshake packet.
- [`discv5_on_datagram`](#function-discv5_on_datagram): takes a datagram.
- [`discv5_on_add_node`](#function-discv5_on_add_node): takes ADD_NODE.
- [`discv5_record_change`](#function-discv5_record_change): takes SET_ENDPOINT or SET_ENTRY.
- [`discv5_timers`](#function-discv5_timers): runs the timers.
- [`discv5_wakeup`](#function-discv5_wakeup): adds the WAKEUP action.

### Types

- [`Config`](#type-config): the input of discv5_init.
- [`Tick`](#type-tick): the time and fresh random bytes.
- [`Endpoint`](#type-endpoint): an IP address and UDP port.
- [`State`](#type-state): the node.
- [`NodeSlot`](#type-nodeslot): a slot of the node table.
- [`Session`](#type-session): established keys.
- [`ChallengeSlot`](#type-challengeslot): a WHOAREYOU sent.
- [`Request`](#type-request): a request waiting for an answer.
- [`Lookup`](#type-lookup): a running lookup.
- [`Candidate`](#type-candidate): a lookup candidate.
- [`StepScratch`](#type-stepscratch): the workspace of a step.
- [`EventList`](#type-eventlist): the events of a step.
- [`ActionList`](#type-actionlist): the actions of a step.
- [`DatagramEvent`](#type-datagramevent): event 1: a received datagram.
- [`AddNodeEvent`](#type-addnodeevent): event 2: a record to add.
- [`LookupEvent`](#type-lookupevent): event 3: start a lookup.
- [`SetEndpointEvent`](#type-setendpointevent): event 4: the local endpoint.
- [`SetEntryEvent`](#type-setentryevent): event 5: a local record entry.
- [`OpenedEvent`](#type-openedevent): event 6: the socket result.
- [`SentEvent`](#type-sentevent): event 7: a send result.
- [`IdleEvent`](#type-idleevent): event 8: no datagram.
- [`SendAction`](#type-sendaction): action 1: send a datagram.
- [`NodeFoundAction`](#type-nodefoundaction): action 2: a record found.
- [`LookupDoneAction`](#type-lookupdoneaction): action 3: a lookup ended.
- [`EndpointAction`](#type-endpointaction): action 4: what a node saw.
- [`RecordAction`](#type-recordaction): action 5: the new local record.
- [`WakeupAction`](#type-wakeupaction): action 6: the next call.

### Constants

- `DISCV5_STATE_SIZE`: the size of `State`.
- `DISCV5_SCRATCH_SIZE`: the scratch of a step.
- `DISCV5_ACTIONS_BASE`: action room for a step.
- `DISCV5_ACTIONS_PER_EVENT`: action room for each event.
- `DISCV5_INVALID_EVENT`: status 3.

## Spec

- Document: [discv5-theory.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-theory.md) and [discv5-wire.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-wire.md), devp2p at commit 88f1c80.
- Section: Node Table, Lookup, Sessions, Protocol Messages.
- Parameters (`DISCV5_K`, `DISCV5_ALPHA`, timeouts and limits) follow go-ethereum v1.17.10 `p2p/discover`.

## Integration

| Item | Value |
|---|---|
| Startup | `discv5_shell_clock` gives the time and entropy for `discv5_init`; `discv5_shell_open` binds the socket |
| Event loop | The application owns it: it calls `discv5_step` with a fresh tick and the events since the last step |
| Actions | After a step returns 0, the application performs each SEND with `discv5_shell_send` and passes the SENT events to the next step |
| Wakeup | The application waits with `discv5_shell_receive` until the WAKEUP time or a datagram, and passes the event to the next step |
| Action room | `DISCV5_ACTIONS_BASE` + events × `DISCV5_ACTIONS_PER_EVENT` bytes after the 24-byte header |
| Bootnodes, lookups, record | ADD_NODE, LOOKUP, SET_ENDPOINT and SET_ENTRY events; NODE_FOUND, LOOKUP_DONE, ENDPOINT and RECORD actions |
| IP limits of the node table | The `discv5_init` config sets them: [Config](#type-config); all zero turns them off |
| Shutdown | `discv5_shell_close` |
| Concurrency | One thread at a time for a state and its shell context |

## Function `discv5_init`

Starts a node: its keys, its record and its timers.

### Signature

```
discv5_init(config, state) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `config` | input | `Config` |
| `state` | output | `State` |

### Returns

- `DISCV5_OK`: `state` holds the node.
- `DISCV5_INVALID_KEY`: The private key is 0, or n or more. Nothing is written.

### Caller must

- Pass a `state` of `DISCV5_STATE_SIZE` bytes.
- Pass 32 random bytes in `entropy`.
- Pass a sequence number of at least 1.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Zeroes `state`, then stores the key pair and the node ID.
- Seeds the DRBG with the entropy.
- Sets "id" = "v4", "secp256k1", and the address and port entries of the config.
- Keeps the IP limit fields of the config; a subnet length above the address size counts as the address size, and a nonzero `limit_lan` as 1.
- Signs the record at the sequence number.
- Sets the first liveness check one interval after `now`.

### Function never

- Writes more than `state` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Effects

- `state` holds the private key and the DRBG key.

### Limits

- Stack: 4344 bytes on x86-64 (return address included), 4448 bytes on ARM64, 4560 bytes on RISC-V, callees included.

### ABI

- Role: L2.
- Symbol: `discv5_init` (`_discv5_init` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `config`, `state`.

## Function `discv5_step`

Runs the node on a list of events at a time, and writes the actions that follow.

### Signature

```
discv5_step(state, tick, events, scratch, actions) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | `State` |
| `tick` | input | `Tick` |
| `events` | input | `EventList` |
| `scratch` | scratch | `StepScratch` |
| `actions` | output | `ActionList` |

### Returns

- `DISCV5_OK`: The events are handled and `actions` holds the actions, WAKEUP last.
- `DISCV5_BUFFER_TOO_SMALL`: `scratch` is below `DISCV5_SCRATCH_SIZE`, or the room of `actions` is below `DISCV5_ACTIONS_BASE` + events × `DISCV5_ACTIONS_PER_EVENT`. `state` is unchanged.
- `DISCV5_INVALID_EVENT`: An event breaks the rules of its kind. `state` is unchanged.

### Caller must

- Pass a state from `discv5_init` or an earlier step.
- Set the `size` fields of `scratch` and `actions`.
- Pass a `now` that never goes back, and 32 fresh random bytes, in `tick`.
- Call again by the time of the WAKEUP action, with the events that arrived.
- Keep every output and scratch buffer apart from the inputs and from each other.
- Pass buffers that start at a multiple of 8.

### Function does

- Checks the scratch, every event and the action room before it changes anything.
- Takes the time: the larger of `now` and the last time.
- Reseeds the DRBG: its key becomes SHA-256(key || entropy).
- Handles the events in order. A datagram that does not decode, and a shell result, change nothing.
- Ends requests past their deadline, checks one due table member every second, starts the refresh lookup when due, and moves lookups on.
- Writes WAKEUP last, with the earliest of the next check, the next refresh and the request deadlines.

### Function never

- Writes more than `state`, `scratch`, `actions` and its own stack.
- Keeps a pointer after it returns.
- Makes an OS call.

### Effects

- Every action in `actions` is for the shell to perform after the call returns 0.
- `scratch` holds session keys after the call.

### Limits

- Stack: 4616 bytes on x86-64 (return address included), 4848 bytes on ARM64, 5072 bytes on RISC-V, callees included.
- Events: as many as fit the action room the caller gives.
- Node table: 442 slots; sessions: 256; challenges: 32; requests: 32; lookups: 4.

### ABI

- Role: L2.
- Symbol: `discv5_step` (`_discv5_step` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `state`, `tick`, `events`, `scratch`, `actions`.

## Function `discv5_random`

Writes n bytes from the DRBG of the state.

### Signature

```
discv5_random(state, out, n) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | `State` |
| `out` | output | n bytes |
| `n` | input | u64 in a register |

### Function does

- Writes SHA-256(key || counter) blocks, the counter 8 bytes little endian, and adds 1 to the counter for each block.

### Function never

- Writes more than `out`, the DRBG counter and its own stack.
- Makes an OS call.

### Limits

- Stack of its own: 160 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_random`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `state`, `out`, `n`.

## Function `discv5_reseed`

Mixes 32 entropy bytes into the DRBG key.

### Signature

```
discv5_reseed(state, entropy) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | `State` |
| `entropy` | input | 32 bytes |

### Function does

- Sets the key to SHA-256(key || entropy).

### Function never

- Writes more than the DRBG key and its own stack.
- Makes an OS call.

### Limits

- Stack of its own: 160 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_reseed`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `state`, `entropy`.

## Function `discv5_log_distance`

Gives the log distance of two node IDs.

### Signature

```
discv5_log_distance(a, b) -> distance
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `a` | input | `NodeId` |
| `b` | input | `NodeId` |

### Function does

- Returns 0 for equal IDs, else 256 minus the leading zero bits of a XOR b.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_log_distance`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the distance, not a status.
- Argument order: `a`, `b`.

## Function `discv5_action`

Adds an action of a kind and size to the actions of the step.

### Signature

```
discv5_action(scratch, kind, size) -> action or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `kind` | input | u64 in a register |
| `size` | input | u64 in a register, a multiple of 8 |

### Function does

- Returns the new action, zeroed, with `size` and `kind` set, after the actions so far.
- Returns 0 and adds nothing when the room is short.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_action`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the action or 0, not a status.
- Argument order: `scratch`, `kind`, `size`.

## Function `discv5_send_packet`

Adds a SEND action with the packet in the scratch.

### Signature

```
discv5_send_packet(scratch, endpoint) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `endpoint` | input | `Endpoint` |

### Function does

- Copies the endpoint and the packet bytes into the action.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_send_packet`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `endpoint`.

## Function `discv5_enr_endpoint`

Reads the UDP endpoint of a checked record.

### Signature

```
discv5_enr_endpoint(enr, endpoint) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `enr` | input | [`Enr`](enr.md#type-enr) |
| `endpoint` | output | `Endpoint` |

### Function does

- Returns 1 and writes "ip" and "udp" when both are present with a port above 0, else "ip6" and "udp6" on the same terms; else returns 0.

### Function never

- Writes more than `endpoint`.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_enr_endpoint`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `enr`, `endpoint`.

## Function `discv5_session_find`

Finds the session of a node ID and endpoint.

### Signature

```
discv5_session_find(scratch, id, endpoint) -> session or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `id` | input | `NodeId` |
| `endpoint` | input | `Endpoint` |

### Function does

- Returns the session slot, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_session_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `id`, `endpoint`.

## Function `discv5_session_put`

Stores session keys for a node ID and endpoint.

### Signature

```
discv5_session_put(scratch, id, endpoint, write_key, read_key) -> session
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `id` | input | `NodeId` |
| `endpoint` | input | `Endpoint` |
| `write_key` | input | 16 bytes |
| `read_key` | input | 16 bytes |

### Function does

- Uses the slot of the same node and endpoint, else a free slot, else the slot used longest ago.
- Sets the message counter to 0 and the last use to now.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_session_put`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot, not a status.
- Argument order: `scratch`, `id`, `endpoint`, `write_key`, `read_key`.

## Function `discv5_challenge_find`

Finds the WHOAREYOU sent to a node ID and endpoint that is still valid.

### Signature

```
discv5_challenge_find(scratch, id, endpoint, any) -> challenge or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `id` | input | `NodeId` |
| `endpoint` | input | `Endpoint` |
| `any` | input | u64 in a register |

### Function does

- Frees challenges older than `DISCV5_CHALLENGE_TIMEOUT`.
- Returns the matching challenge; with `any` 1 and none, a free slot, else the oldest slot; else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_challenge_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `id`, `endpoint`, `any`.

## Function `discv5_challenge_new`

Makes a new WHOAREYOU for the sender of the packet received.

### Signature

```
discv5_challenge_new(scratch, challenge) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `challenge` | output | `ChallengeSlot` |

### Function does

- Stores the sender, the time, and the 63 bytes: a random IV, the static header with the packet nonce, a random ID nonce, and the sequence number of the sender in the table (0 when unknown).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_challenge_new`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `challenge`.

## Function `discv5_send_whoareyou`

Sends a stored WHOAREYOU.

### Signature

```
discv5_send_whoareyou(scratch, challenge) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `challenge` | input | `ChallengeSlot` |

### Function does

- Masks the bytes after the IV with the first 16 bytes of the challenged node ID and adds a SEND action.
- Sends the same bytes each time for the same challenge.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_send_whoareyou`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `challenge`.

## Function `discv5_request_find`

Finds the request whose last packet had a nonce.

### Signature

```
discv5_request_find(scratch, nonce) -> request or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `nonce` | input | 12 bytes |

### Function does

- Returns the request slot, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_request_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `nonce`.

## Function `discv5_request_match`

Finds the request a response answers.

### Signature

```
discv5_request_match(scratch, id, request_id, type) -> request or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `id` | input | `NodeId` |
| `request_id` | input | u64 in a register |
| `type` | input | u64 in a register |

### Function does

- Returns the request of this message type to the node, with this request ID, sent to the endpoint the response came from; else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_request_match`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `id`, `request_id`, `type`.

## Function `discv5_bucket`

Gives the table bucket of a node ID.

### Signature

```
discv5_bucket(state, id) -> bucket
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | input | `State` |
| `id` | input | `NodeId` |

### Function does

- Returns 0 for log distances up to 240, else the distance minus 240.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_bucket`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the bucket, not a status.
- Argument order: `state`, `id`.

## Function `discv5_node_find`

Finds the table slot of a node ID.

### Signature

```
discv5_node_find(scratch, id) -> slot or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `id` | input | `NodeId` |

### Function does

- Returns the member or replacement slot, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_node_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `id`.

## Function `discv5_node_count`

Counts the slots of a kind in a bucket.

### Signature

```
discv5_node_count(scratch, bucket, kind) -> count, free, oldest
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `bucket` | input | u64 in a register |
| `kind` | input | u64 in a register: 1 member, 2 replacement |

### Function does

- Returns the count, the first free slot of the table (0 when none) and the oldest slot of the kind in the bucket.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_node_count`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the count in the result register, the free slot in the second argument register and the oldest slot in the third (rdx and rcx on x86-64).
- Argument order: `scratch`, `bucket`, `kind`.

## Function `discv5_ip_lan`

Tests whether the address of an endpoint is on a local network.

### Signature

```
discv5_ip_lan(endpoint) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `endpoint` | input | `Endpoint` |

### Function does

- Returns 1 for loopback, private and link local addresses as Go's `net/netip` reports them, which geth's `AddrIsLAN` uses: 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7 and fe80::/10.
- Tests an IPv4-mapped IPv6 address (::ffff:a.b.c.d) as its IPv4 address.
- Returns 0 for any other address.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_ip_lan`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `endpoint`.

## Function `discv5_prefix_equal`

Compares the first bits of two byte strings.

### Signature

```
discv5_prefix_equal(a, b, bits) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `a` | input | bytes |
| `b` | input | bytes |
| `bits` | input | u64 in a register |

### Function does

- Returns 1 when the first `bits` bits of `a` and `b` are equal, else 0; 0 bits are always equal.
- Reads at most `bits` / 8 bytes, rounded up, of each.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_prefix_equal`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `a`, `b`, `bits`.

## Function `discv5_ip_fits`

Checks a node endpoint against the IP limits of the table and of a bucket.

### Signature

```
discv5_ip_fits(scratch, endpoint, bucket, exclude) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `endpoint` | input | `Endpoint` |
| `bucket` | input | u64 in a register |
| `exclude` | input | a `NodeSlot` not to count, or 0 |

### Function does

- Returns 1 when both limits are 0.
- Returns 1 for a local network address while `limit_lan` is 0.
- Counts the members and replacements other than `exclude` in the same subnet: the same family and the same first `subnet4` or `subnet6` bits; while `limit_lan` is 0, local network addresses do not count.
- Returns 0 when the table count reaches `table_ip_limit`, or the count in `bucket` reaches `bucket_ip_limit`; a limit of 0 does not apply.
- Else returns 1.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_ip_fits`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `scratch`, `endpoint`, `bucket`, `exclude`.

## Function `discv5_node_add`

Adds a checked record with a UDP endpoint to the table.

### Signature

```
discv5_node_add(scratch, enr, record) -> slot or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `enr` | input | [`Enr`](enr.md#type-enr) |
| `record` | input | [`ByteList`](enr.md#type-bytelist) |

### Function does

- Leaves out the local node and records with no UDP endpoint.
- Updates a known node when the record is newer.
- Leaves out a new node when `discv5_ip_fits` refuses its endpoint.
- Keeps the old record of a known node when `discv5_ip_fits` refuses the endpoint of the newer record, with the node itself not counted.
- Adds a member while its bucket has fewer than 16, else a replacement; with 10 replacements the oldest gives way.
- Sets the first refresh lookup one interval ahead when it adds the first node.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 128 bytes on ARM64, 144 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_node_add`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `enr`, `record`.

## Function `discv5_node_remove`

Frees a table slot.

### Signature

```
discv5_node_remove(scratch, slot) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `slot` | state | `NodeSlot` |

### Function does

- Gives the place of a member to the newest replacement of its bucket, which is checked at once.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_node_remove`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `slot`.

## Function `discv5_msg_finish`

Makes the message of the scratch from a type and an RLP payload.

### Signature

```
discv5_msg_finish(scratch, type, end) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `type` | input | u64 in a register |
| `end` | input | the end of the payload at SC_TMP |

### Function does

- Writes the type byte, a list header and the payload.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_msg_finish`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `type`, `end`.

## Function `discv5_send_message`

Sends the message of the scratch to a node.

### Signature

```
discv5_send_message(scratch, id, endpoint) -> nonce
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `id` | input | `NodeId` |
| `endpoint` | input | `Endpoint` |

### Function does

- With a session: seals the message under its write key, with the nonce: the message count (4 bytes big endian) and 8 random bytes.
- Without one: sends 20 random message bytes under a random key, with a random nonce, so the node answers with WHOAREYOU.
- Returns the nonce used.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_send_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns a pointer to the 12-byte nonce, not a status.
- Argument order: `scratch`, `id`, `endpoint`.

## Function `discv5_emit_record`

Adds a RECORD action with the local record.

### Signature

```
discv5_emit_record(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Copies the record into the action.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_emit_record`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_emit_found`

Adds a NODE_FOUND action with the record in the scratch.

### Signature

```
discv5_emit_found(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Copies the node ID and the record into the action.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_emit_found`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_emit_done`

Adds a LOOKUP_DONE action.

### Signature

```
discv5_emit_done(scratch, target, found) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `target` | input | `NodeId` |
| `found` | input | u64 in a register |

### Function does

- Writes the target and the count of records found.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_emit_done`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `target`, `found`.

## Function `discv5_request_message`

Writes the message of a request into the scratch.

### Signature

```
discv5_request_message(scratch, request) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `request` | input | `Request` |

### Function does

- Writes PING [request-id, enr-seq] or FINDNODE [request-id, [distance, ...]], the request ID as 8 bytes big endian.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_request_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `request`.

## Function `discv5_request_start`

Starts a PING or FINDNODE request to a node.

### Signature

```
discv5_request_start(scratch, node, kind, count, distances) -> request or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `node` | input | node ID, public key and endpoint: 104 bytes |
| `kind` | input | type | purpose << 8 | lookup << 16 |
| `count` | input | u64 in a register, at most 3 |
| `distances` | input | count u16 values in a register |

### Function does

- Takes a free request slot, the next request ID and a deadline of `DISCV5_REQUEST_TIMEOUT`.
- Sends the message and keeps its nonce.
- Returns 0 when every slot is busy.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_request_start`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the slot or 0, not a status.
- Argument order: `scratch`, `node`, `kind`, `count`, `distances`.

## Function `discv5_request_end`

Frees a request and uses its result.

### Signature

```
discv5_request_end(scratch, request, ok) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `request` | state | `Request` |
| `ok` | input | u64 in a register |

### Function does

- A check: marks the node live, or counts a failure; a node that is not live, or failed 3 times in a row, leaves the table.
- A lookup request: marks its candidate answered or failed, and moves the lookup on.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_request_end`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `request`, `ok`.

## Function `discv5_requests_resend`

Sends the other waiting requests to a node again after its handshake.

### Signature

```
discv5_requests_resend(scratch, request) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `request` | input | `Request` |

### Function does

- Sends each request waiting for the same node ID and endpoint through the new session, with a new nonce and deadline.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_requests_resend`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `request`.

## Function `discv5_candidate_find`

Finds a candidate of a lookup by node ID.

### Signature

```
discv5_candidate_find(lookup, id) -> candidate or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `lookup` | input | `Lookup` |
| `id` | input | `NodeId` |

### Function does

- Returns the candidate, or 0.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_candidate_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the candidate or 0, not a status.
- Argument order: `lookup`, `id`.

## Function `discv5_closer`

Tells whether one node ID is closer to a target than another.

### Signature

```
discv5_closer(a, b, target) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `a` | input | `NodeId` |
| `b` | input | `NodeId` |
| `target` | input | `NodeId` |

### Function does

- Returns 1 when a XOR target is below b XOR target, else 0.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_closer`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `a`, `b`, `target`.

## Function `discv5_candidate_insert`

Adds a node to the candidates of a lookup.

### Signature

```
discv5_candidate_insert(scratch, lookup, node) -> 1 or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `lookup` | state | `Lookup` |
| `node` | input | node ID, public key and endpoint: 104 bytes |

### Function does

- Keeps the 16 closest to the target, closest first.
- Leaves out the local node and known candidates.
- Returns 1 when the node joins.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_candidate_insert`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns 1 or 0, not a status.
- Argument order: `scratch`, `lookup`, `node`.

## Function `discv5_lookup_distances`

Picks the 3 distances to ask a node for in a lookup.

### Signature

```
discv5_lookup_distances(target, id) -> distances, count
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `target` | input | `NodeId` |
| `id` | input | `NodeId` |

### Function does

- Returns d, then d + 1 and d - 1, d + 2 and d - 2, and so on, keeping 1 to 256, with d the log distance of the target and the node: 3 u16 values and their count.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_lookup_distances`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the distances in the result register and the count in the second argument register (rdx on x86-64).
- Argument order: `target`, `id`.

## Function `discv5_lookup_advance`

Asks new candidates while fewer than 3 requests are pending.

### Signature

```
discv5_lookup_advance(scratch, lookup) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `lookup` | state | `Lookup` |

### Function does

- Asks the closest new candidates first.
- Ends the lookup with LOOKUP_DONE when nothing is pending and nothing is new.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_lookup_advance`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `lookup`.

## Function `discv5_lookup_start`

Starts a lookup of a target from the table members.

### Signature

```
discv5_lookup_start(scratch, target) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `target` | input | `NodeId` |

### Function does

- Ends at once with LOOKUP_DONE and 0 found when the 4 lookup slots are busy.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_lookup_start`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `target`.

## Function `discv5_msg_field`

Finds a field of the message list.

### Signature

```
discv5_msg_field(scratch, k) -> item or 0
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `k` | input | u64 in a register |

### Function does

- Returns the asm-rlp `Item` of field k (0 is the request ID), or 0 when the list is shorter.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_msg_field`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the item or 0, not a status.
- Argument order: `scratch`, `k`.

## Function `discv5_item_uint`

Reads a message field as a number.

### Signature

```
discv5_item_uint(scratch, item) -> value, ok
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `item` | input | asm-rlp `Item`, or 0 |

### Function does

- Returns the number and 1 for a canonical byte string of at most 8 bytes, else 0.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_item_uint`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the number in the result register and ok in the second argument register (rdx on x86-64).
- Argument order: `scratch`, `item`.

## Function `discv5_handle_message`

Handles a decrypted message from the sender of the packet.

### Signature

```
discv5_handle_message(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Decodes the RLP with `rlp_decode` and takes a request ID of at most 8 bytes.
- Hands PING, PONG, FINDNODE, NODES and TALKREQ to their handlers, and drops anything else.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_handle_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_reply`

Finishes the message and sends it to the sender of the packet received.

### Signature

```
discv5_reply(scratch, type, end) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `type` | input | u64 in a register |
| `end` | input | the end of the payload |

### Function does

- Calls `discv5_msg_finish`, then `discv5_send_message`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_reply`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `type`, `end`.

## Function `discv5_reqid_out`

Writes the request ID received at the start of a payload.

### Signature

```
discv5_reqid_out(scratch) -> position
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Returns the position after it.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_reqid_out`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the position, not a status.
- Argument order: `scratch`.

## Function `discv5_on_ping`

Answers PING [request-id, enr-seq] with PONG.

### Signature

```
discv5_on_ping(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Sends PONG [request-id, local sequence number, the IP (4 or 16 bytes) and port the PING came from].

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_ping`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_on_pong`

Takes PONG [request-id, enr-seq, ip, port] for a PING sent.

### Signature

```
discv5_on_pong(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Ends the check as passed.
- Adds an ENDPOINT action with the IP and port the node saw.
- Asks FINDNODE [0] for a newer record.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_pong`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_on_talkreq`

Answers TALKREQ with an empty TALKRESP.

### Signature

```
discv5_on_talkreq(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Sends TALKRESP [request-id, ""]: the node serves no talk protocol.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_talkreq`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_result_record`

Gives the record of a FINDNODE result.

### Signature

```
discv5_result_record(scratch, result) -> bytes, length
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `result` | input | a table slot, or 0 for the local record |

### Function does

- Returns the record bytes and their length.

### Function never

- Writes memory.
- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_result_record`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the bytes in the result register and the length in the second argument register (rdx on x86-64).
- Argument order: `scratch`, `result`.

## Function `discv5_nodes_send`

Sends one NODES message with some results.

### Signature

```
discv5_nodes_send(scratch, start, end, total, bytes) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `start` | input | u64 |
| `end` | input | u64 |
| `total` | input | u64 |
| `bytes` | input | u64 |

### Function does

- Sends NODES [request-id, total, [record, ...]] with results start to end.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_nodes_send`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `start`, `end`, `total`, `bytes`.

## Function `discv5_nodes_pack`

Packs the results into NODES packets.

### Signature

```
discv5_nodes_pack(scratch, count, send, total) -> packets
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `count` | input | u64 |
| `send` | input | u64 |
| `total` | input | u64 |

### Function does

- Fills each packet while its record bytes stay within 1000.
- Uses one empty packet for no results.
- With send 1, sends them.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_nodes_pack`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns the packet count, not a status.
- Argument order: `scratch`, `count`, `send`, `total`.

## Function `discv5_on_findnode`

Answers FINDNODE [request-id, [distance, ...]] with NODES.

### Signature

```
discv5_on_findnode(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Takes the first 16 distinct distances up to 256.
- Gives the local record for distance 0, else live members at exactly that log distance, up to 16 records.
- Sends 1 to 6 NODES packets that all announce the same total.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_findnode`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_nodes_record`

Takes one record of a NODES answer.

### Signature

```
discv5_nodes_record(scratch, item, request, lookup) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `item` | input | asm-rlp `Item` |
| `request` | input | `Request` |
| `lookup` | state | `Lookup`, or 0 |

### Function does

- Takes a valid record with a UDP port above 1024, at one of the distances asked from the answering node.
- For a lookup: a record new to it gives NODE_FOUND and joins the candidates.
- Adds the record to the table.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_nodes_record`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `item`, `request`, `lookup`.

## Function `discv5_on_nodes`

Takes NODES [request-id, total, [record, ...]] for a FINDNODE sent.

### Signature

```
discv5_on_nodes(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Ends the request after min(total, 5) packets, at least 1.
- Moves its deadline on after each packet.
- Ignores NODES that answer no request.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 80 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_nodes`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_on_message_packet`

Takes an ordinary message packet.

### Signature

```
discv5_on_message_packet(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Opens the message with the session of the sender node ID and endpoint, and handles it.
- Else answers with WHOAREYOU: the one still valid for that node and endpoint, unchanged, or a new one.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_message_packet`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_on_whoareyou`

Answers a WHOAREYOU for a waiting request with a handshake.

### Signature

```
discv5_on_whoareyou(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Matches the request by nonce; a request already answered once is left alone.
- Makes an ephemeral key, derives the keys with `discv5_derive_keys`, and signs the ID proof with `discv5_id_sign`.
- Adds the local record when the challenge sequence number is older.
- Sends the request again in a handshake packet, then the other waiting requests to the node.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_whoareyou`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_on_handshake`

Takes a handshake packet for a WHOAREYOU sent.

### Signature

```
discv5_on_handshake(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Takes the public key from the record in the packet (its node ID must match), else from the table.
- Checks the ID proof with `discv5_id_verify` and opens the message with the derived keys.
- Then stores the session, uses up the challenge, adds a record from the packet to the table, and handles the message.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_handshake`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_on_datagram`

Takes a received datagram.

### Signature

```
discv5_on_datagram(scratch, event) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `event` | input | `DatagramEvent` |

### Function does

- Keeps the sender endpoint with unused address bytes zero.
- Decodes the packet and hands it on by flag; drops a packet that does not decode.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_datagram`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `event`.

## Function `discv5_on_add_node`

Adds a record from an event to the table.

### Signature

```
discv5_on_add_node(scratch, event) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `event` | input | `AddNodeEvent` |

### Function does

- Adds a valid record with a UDP endpoint; ignores anything else.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_on_add_node`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `event`.

## Function `discv5_record_change`

Changes the local record for SET_ENDPOINT or SET_ENTRY.

### Signature

```
discv5_record_change(scratch, event) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |
| `event` | input | `SetEndpointEvent` or `SetEntryEvent` |

### Function does

- Sets the entries, adds 1 to the sequence number, signs the record again, and adds a RECORD action.
- Keeps the entries and sequence number as they were when the entries are full or the record would pass 300 bytes.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_record_change`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`, `event`.

## Function `discv5_timers`

Runs the timers of a step.

### Signature

```
discv5_timers(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Ends requests past their deadline: failed, or answered for a FINDNODE that got some NODES.
- Each second, pings the member whose check is most overdue.
- Starts the refresh lookup of the local node ID when due, then every 30 minutes.
- Moves every lookup on.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_timers`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Function `discv5_wakeup`

Adds the WAKEUP action.

### Signature

```
discv5_wakeup(scratch) -> nothing
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `scratch` | scratch | `StepScratch` |

### Function does

- Gives the earliest of the next check, the next refresh and the request deadlines.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 64 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `discv5_wakeup`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6). It returns no status.
- Argument order: `scratch`.

## Type `Config`

The input of `discv5_init`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `key` | 32 bytes | The private key |
| 32 | `seq` | u64 | The first record sequence number, at least 1 |
| 40 | `entropy` | 32 bytes | Random bytes for the DRBG |
| 72 | `now` | u64 | Milliseconds |
| 80 | `endpoint` | `Endpoint` | The address and port for the record; family 0 for none, port 0 for no port |
| 112 | `bucket_ip_limit` | u64 | The most table nodes of one bucket in one subnet; 0 for no limit |
| 120 | `table_ip_limit` | u64 | The most table nodes in one subnet; 0 for no limit |
| 128 | `subnet4` | u64 | The prefix length of an IPv4 subnet in bits; above 32 counts as 32 |
| 136 | `subnet6` | u64 | The prefix length of an IPv6 subnet in bits; above 128 counts as 128 |
| 144 | `limit_lan` | u64 | 0: local network addresses are left out of the limits; else they count |

### Rules

- Size: 152 bytes.
- The IP limits count members and replacements together.
- Both limits 0: no IP limit applies.
- go-ethereum v1.17.10 `p2p/discover`: 2, 10, 24, 24 and 0.
- nim-eth at 57da57b, `discoveryv5`: 2 and 10, with /24 IPv4 and /64 IPv6 subnets.
- sigp discv5 0.12.0 with `ip_limit`: 2 and 10 for IPv4 /24 subnets only, local addresses included.

## Type `Tick`

The time and fresh random bytes for a step.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `now` | u64 | Milliseconds, never decreasing |
| 8 | `entropy` | 32 bytes | Random bytes |

### Rules

- Size: 40 bytes.

## Type `Endpoint`

An IP address and UDP port.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `port` | u64 | The UDP port |
| 8 | `family` | u64 | 4 or 6 |
| 16 | `address` | 16 bytes | An IPv4 address uses the first 4; the rest are zero |

### Rules

- Size: 32 bytes.
- Endpoints are equal when all 32 bytes are equal.

## Type `State`

The node: keys, DRBG, record, timers and tables, at fixed offsets.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `private_key` | 32 bytes | Secret |
| 32 | `public_key` | 33 bytes | Compressed |
| 72 | `node_id` | 32 bytes | The node ID |
| 104 | `seq` | u64 | The local record sequence number |
| 112 | `drbg_key` | 32 bytes | Secret |
| 144 | `drbg_count` | u64 | DRBG blocks drawn |
| 152 | `now` | u64 | The time of the last step |
| 160 | `next_ping` | u64 | The next liveness check |
| 168 | `next_refresh` | u64 | The next refresh lookup; 0 until the table has a node |
| 176 | `req_id` | u64 | The last request ID |
| 184 | `record_len` | u64 | Record bytes |
| 192 | `record` | 300 bytes | The local record |
| 496 | `entry_count` | u64 | Entries in use |
| 504 | `entries` | [`LocalEntry`](enr.md#type-localentry) [16] | Sorted by key |
| 2056 | `bucket_ip_limit` | u64 | From the config |
| 2064 | `table_ip_limit` | u64 | From the config |
| 2072 | `subnet4` | u64 | From the config, at most 32 |
| 2080 | `subnet6` | u64 | From the config, at most 128 |
| 2088 | `limit_lan` | u64 | From the config, 0 or 1 |
| 2096 | `nodes` | `NodeSlot` [442] | The node table |
| 200112 | `sessions` | `Session` [256] | Session keys |
| 228784 | `challenges` | `ChallengeSlot` [32] | WHOAREYOU packets sent |
| 233136 | `requests` | `Request` [32] | Requests waiting |
| 238000 | `lookups` | `Lookup` [4] | Running lookups |

### Rules

- Size: 245392 bytes (`DISCV5_STATE_SIZE`).
- It holds no pointers and can be copied as one block.
- It holds secrets: the private key, the DRBG key and session keys.

## Type `NodeSlot`

A slot of the node table.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `id` | 32 bytes | The node ID |
| 32 | `pubkey` | 33 bytes | Compressed public key |
| 72 | `endpoint` | `Endpoint` | Its UDP endpoint |
| 104 | `state` | u8 | 0 free, 1 member, 2 replacement |
| 105 | `bucket` | u8 | 0 to 16 |
| 106 | `live` | u8 | 1 after a PONG |
| 107 | `fails` | u8 | Failed checks in a row |
| 108 | `pinging` | u8 | 1 while a check waits |
| 112 | `seq` | u64 | Record sequence number |
| 120 | `added` | u64 | When it was added |
| 128 | `check` | u64 | When to check it next |
| 136 | `record_len` | u64 | Record bytes |
| 144 | `record` | 300 bytes | The record |

### Rules

- Size: 448 bytes.
- 17 buckets of 16 members and 10 replacements.

## Type `Session`

Session keys for a node ID and endpoint.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `id` | 32 bytes | The node ID |
| 32 | `endpoint` | `Endpoint` | Its UDP endpoint |
| 64 | `used` | u64 | Last use plus 1; 0 marks a free slot |
| 72 | `write_key` | 16 bytes | Secret |
| 88 | `read_key` | 16 bytes | Secret |
| 104 | `counter` | u64 | Messages sent |

### Rules

- Size: 112 bytes.

## Type `ChallengeSlot`

A WHOAREYOU sent and not yet answered.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `id` | 32 bytes | The node ID |
| 32 | `endpoint` | `Endpoint` | Its UDP endpoint |
| 64 | `sent` | u64 | Time plus 1; 0 marks a free slot |
| 72 | `data` | 63 bytes | The unmasked WHOAREYOU |

### Rules

- Size: 136 bytes.
- Valid for `DISCV5_CHALLENGE_TIMEOUT`.

## Type `Request`

A PING or FINDNODE sent and waiting.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `id` | 32 bytes | The node ID |
| 32 | `pubkey` | 33 bytes | Compressed public key |
| 72 | `endpoint` | `Endpoint` | Its UDP endpoint |
| 104 | `req_id` | u64 | Sent as 8 bytes big endian |
| 112 | `nonce` | 12 bytes | Of the last packet sent |
| 124 | `state` | u8 | 0 free, 1 waiting, 2 handshake sent |
| 125 | `type` | u8 | PING or FINDNODE |
| 126 | `purpose` | u8 | 1 lookup, 2 check, 3 record refresh |
| 127 | `lookup` | u8 | The lookup slot |
| 128 | `deadline` | u64 | When it fails |
| 136 | `dist_count` | u8 | Distances asked |
| 137 | `got` | u8 | NODES packets received |
| 138 | `total` | u8 | NODES packets announced |
| 140 | `distances` | u16 [3] | The distances |

### Rules

- Size: 152 bytes.

## Type `Lookup`

A lookup and its candidates.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `target` | 32 bytes | The node ID looked up |
| 32 | `active` | u64 | 1 while running |
| 40 | `found` | u64 | Records found |
| 48 | `count` | u64 | Candidates |
| 56 | `candidates` | `Candidate` [16] | Closest first |

### Rules

- Size: 1848 bytes.

## Type `Candidate`

A node a lookup may ask.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `id` | 32 bytes | The node ID |
| 32 | `pubkey` | 33 bytes | Compressed public key |
| 72 | `endpoint` | `Endpoint` | Its UDP endpoint |
| 104 | `state` | u64 | 0 new, 1 asked, 2 answered, 3 failed |

### Rules

- Size: 112 bytes.

## Type `StepScratch`

The workspace of `discv5_step`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Total buffer size in bytes |

### Rules

- `size` is at least `DISCV5_SCRATCH_SIZE` (65536).
- The step lays out its own fields after `size`; they are not an interface.
- It holds session keys after a step.

## Type `EventList`

A `ByteList` of events, one after another.

### Rules

- Each event starts with `size` (a multiple of 8, at least 16) and `kind`.
- The sizes sum to `count`.
- The step handles them in order.

## Type `ActionList`

A `ByteList` of actions, one after another.

### Rules

- Each action starts with `size` (a multiple of 8) and `kind`.
- The step writes `offset` 24 and `count`.
- WAKEUP comes last, once.
- The shell performs them only after the step returns 0.

## Type `DatagramEvent`

Event kind 1: a datagram received.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `from` | `Endpoint` | The sender |
| 48 | `len` | u64 | At most 1280 |
| 56 | `data` | len bytes | The datagram |

### Rules

- `size` is at least 56 + `len`.
- Family 4 or 6.
- Duplicates and stale packets fail the nonce, session or challenge checks and change nothing.

## Type `AddNodeEvent`

Event kind 2: a record to add, such as a bootnode.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `len` | u64 | Record bytes |
| 24 | `data` | len bytes | The record |

### Rules

- `size` is at least 24 + `len`.
- A record that does not check is ignored.

## Type `LookupEvent`

Event kind 3: start a lookup.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `target` | 32 bytes | The node ID to look up |

### Rules

- `size` is at least 48.
- Its result is the NODE_FOUND actions and one LOOKUP_DONE with the target.

## Type `SetEndpointEvent`

Event kind 4: the address and port for the local record.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `endpoint` | `Endpoint` | The local endpoint |

### Rules

- `size` is at least 48.
- Family 4 or 6; port below 65536.
- Its result is a RECORD action when the record changes.

## Type `SetEntryEvent`

Event kind 5: a key and byte string value for the local record.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `key_len` | u64 | 1 to 16 |
| 24 | `key` | 16 bytes | The key |
| 40 | `value_len` | u64 | 0 to 64 |
| 48 | `value` | value_len bytes | The value |

### Rules

- `size` is at least 48 + `value_len`.
- The keys "id", "secp256k1", "ip", "udp", "ip6" and "udp6" are refused.
- Its result is a RECORD action when the record changes.

## Type `OpenedEvent`

Event kind 6: the result of `discv5_shell_open`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `error` | u64 | 0, or the OS error |
| 24 | `endpoint` | `Endpoint` | The bound endpoint |

### Rules

- `size` is at least 56.
- The step accepts it and changes nothing.

## Type `SentEvent`

Event kind 7: the result of `discv5_shell_send`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `error` | u64 | 0, or the OS error |

### Rules

- `size` is at least 24.
- The step accepts it and changes nothing: a lost datagram ends as a request timeout.

## Type `IdleEvent`

Event kind 8: `discv5_shell_receive` got no datagram.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `error` | u64 | 0 when the time passed, else the OS error |

### Rules

- `size` is at least 24.
- The step accepts it and changes nothing.

## Type `SendAction`

Action kind 1: send a datagram.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `to` | `Endpoint` | The destination |
| 48 | `len` | u64 | At most 1280 |
| 56 | `data` | len bytes | The datagram |

### Rules

- Its result is a `SentEvent`.

## Type `NodeFoundAction`

Action kind 2: a checked record a lookup found.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `id` | 32 bytes | The node ID |
| 48 | `len` | u64 | Record bytes |
| 56 | `data` | len bytes | The record |

### Rules

- A lookup reports each record once while it is among its candidates.

## Type `LookupDoneAction`

Action kind 3: a lookup ended.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `target` | 32 bytes | The node ID to look up |
| 48 | `found` | u64 | NODE_FOUND actions of the lookup |

### Rules

- Size: 56 bytes.

## Type `EndpointAction`

Action kind 4: the endpoint a node saw the local node at.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `seen` | `Endpoint` | The endpoint the node saw |
| 48 | `from` | 32 bytes | The node ID that reported it |

### Rules

- Size: 80 bytes.
- The application may answer with SET_ENDPOINT.

## Type `RecordAction`

Action kind 5: the local record changed.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `len` | u64 | Record bytes |
| 24 | `data` | len bytes | The record |

## Type `WakeupAction`

Action kind 6: call `discv5_step` again by this time.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 16 | `at` | u64 | Milliseconds |

### Rules

- Size: 24 bytes.

## Test vectors

- devp2p discv5 wire test vectors
  - File: [discv5-wire-test-vectors.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/discv5/discv5-wire-test-vectors.md), SHA-256 dbcb81f70bc963cad2d5b28fd7ef99e0c4b4ce4d03497f7c75d63ef752115170
- devp2p node record examples
  - File: [enr.md](https://github.com/ethereum/devp2p/blob/88f1c80800d622cc3a542a2125bbe33cc18c9f9c/enr.md), SHA-256 29260bceb96e289140dc08c1336e1f26e070613664a7ec6db72fffbfb85cc58d
- go-ethereum v1.17.10 (commit 1df30b18): records, packets, handshakes and keys built with its `enr`, `enode` and `v5wire` packages
  - Files: written by [tests/generator/](../../tests/generator/) and run by [tests/runner/](../../tests/runner/)
- go-ethereum v1.17.10 conformance suite: `devp2p discv5 test`
  - Run by: [tests/conformance/](../../tests/conformance/)

## Results

<!-- CI generates the tick table for each function here. -->

### `discv5_init`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_step`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_random`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_reseed`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_log_distance`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_action`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_send_packet`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_enr_endpoint`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_session_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_session_put`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_challenge_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_challenge_new`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_send_whoareyou`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_request_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_request_match`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_bucket`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_node_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_node_count`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_ip_lan`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_prefix_equal`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_ip_fits`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_node_add`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_node_remove`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_msg_finish`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_send_message`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_emit_record`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_emit_found`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_emit_done`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_request_message`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_request_start`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_request_end`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_requests_resend`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_candidate_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_closer`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_candidate_insert`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_lookup_distances`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_lookup_advance`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_lookup_start`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_msg_field`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_item_uint`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_handle_message`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_reply`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_reqid_out`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_ping`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_pong`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_talkreq`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_result_record`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_nodes_send`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_nodes_pack`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_findnode`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_nodes_record`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_nodes`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_message_packet`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_whoareyou`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_handshake`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_datagram`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_on_add_node`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_record_change`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_timers`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `discv5_wakeup`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
