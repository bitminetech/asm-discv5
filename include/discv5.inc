/*
 * asm-discv5 shared definitions, in assembler syntax.
 * Every core and shell file includes this file with .include.
 * The requirement entry for each function is in docs/reference/.
 */

/* ---------------------------------------------------------------- Status codes */

/* ARCHITECTURE.md section 6. */
.set DISCV5_OK, 0
.set DISCV5_BUFFER_TOO_SMALL, 1
.set DISCV5_INVALID_KEY, 2          /* a private key is 0, or n or more */
.set DISCV5_INVALID_EVENT, 3        /* an event in the list is not well formed */
.set DISCV5_INVALID_RECORD, 4       /* a node record breaks EIP-778 or the v4 scheme */
.set DISCV5_INVALID_TEXT, 5         /* text is not "enr:" and URL-safe base64 */
.set DISCV5_INVALID_PACKET, 6       /* a packet header breaks the wire format */
.set DISCV5_DECRYPT_FAIL, 7         /* a message does not authenticate */
.set DISCV5_OS_ERROR, 8             /* a shell call failed; the event holds the OS error */

/* ---------------------------------------------------------------- Byte lists */

.set DISCV5_BL_SIZE, 0
.set DISCV5_BL_OFFSET, 8
.set DISCV5_BL_COUNT, 16
.set DISCV5_BL_FIXED, 24

/* ---------------------------------------------------------------- Protocol numbers */

.set DISCV5_MAX_PACKET, 1280        /* largest packet, discv5-wire.md */
.set DISCV5_MIN_PACKET, 63          /* smallest packet */
.set DISCV5_MIN_MESSAGE_PACKET, 87  /* smallest packet that carries a message: 39 + 48 */
.set DISCV5_STATIC_HEADER, 23       /* "discv5", version, flag, nonce, authdata-size */
.set DISCV5_MASKED_START, 16        /* the header starts after the masking IV */
.set DISCV5_HEADER_START, 39        /* authdata starts after the IV and the static header */
.set DISCV5_CHALLENGE_SIZE, 63      /* a WHOAREYOU packet: IV, static header, 24 bytes of authdata */
.set DISCV5_MAX_RECORD, 300         /* largest node record, EIP-778 */
.set DISCV5_RANDOM_MESSAGE, 20      /* message bytes of a packet that starts a handshake */

.set DISCV5_FLAG_MESSAGE, 0
.set DISCV5_FLAG_WHOAREYOU, 1
.set DISCV5_FLAG_HANDSHAKE, 2

.set DISCV5_MSG_PING, 0x01
.set DISCV5_MSG_PONG, 0x02
.set DISCV5_MSG_FINDNODE, 0x03
.set DISCV5_MSG_NODES, 0x04
.set DISCV5_MSG_TALKREQ, 0x05
.set DISCV5_MSG_TALKRESP, 0x06

/* ---------------------------------------------------------------- Header value */

/*
 * A packet header, as discv5_packet_decode writes it and discv5_packet_encode
 * reads it. Fixed size. The record and the raw header are ByteList values.
 */
.set DISCV5_HDR_IV, 0               /* 16 bytes, the masking IV */
.set DISCV5_HDR_NONCE, 16           /* 12 bytes */
.set DISCV5_HDR_FLAG, 32            /* u64 */
.set DISCV5_HDR_SRC_ID, 40          /* 32 bytes: flags 0 and 2 */
.set DISCV5_HDR_ID_NONCE, 72        /* 16 bytes: flag 1 */
.set DISCV5_HDR_ENR_SEQ, 88         /* u64: flag 1 */
.set DISCV5_HDR_SIGNATURE, 96       /* 64 bytes: flag 2 */
.set DISCV5_HDR_EPH_KEY, 160        /* 33 bytes: flag 2 */
.set DISCV5_HDR_RECORD, 200         /* ByteList of 24 + 300 bytes: flag 2, count 0 when no record */
.set DISCV5_HDR_RECORD_SIZE, 324
.set DISCV5_HDR_HEADER, 528         /* ByteList of 24 + 512 bytes: the unmasked IV, static header and authdata */
.set DISCV5_HDR_HEADER_SIZE, 536
.set DISCV5_HDR_SIZE, 1064

/* ---------------------------------------------------------------- Record value */

/* A checked node record, as discv5_enr_decode writes it. Fixed size. */
.set DISCV5_ENR_NODE_ID, 0          /* 32 bytes, keccak256 of the public key's x and y */
.set DISCV5_ENR_PUBKEY, 32          /* 33 bytes, the "secp256k1" value */
.set DISCV5_ENR_SEQ, 72             /* u64 */
.set DISCV5_ENR_IP4, 80             /* 4 bytes */
.set DISCV5_ENR_UDP4, 88            /* u64 port */
.set DISCV5_ENR_IP6, 96             /* 16 bytes */
.set DISCV5_ENR_UDP6, 112           /* u64 port */
.set DISCV5_ENR_HAS, 120            /* u64: bit 0 ip, 1 udp, 2 ip6, 3 udp6 */
.set DISCV5_ENR_COUNT, 128          /* u64: key/value pairs */
.set DISCV5_ENR_PAIRS, 136          /* DISCV5_ENR_MAX_PAIRS entries of 24 bytes */
.set DISCV5_ENR_SIZE, 3208

.set DISCV5_ENR_MAX_PAIRS, 128      /* the most pairs that fit in 300 bytes is below 128 */
.set DISCV5_PAIR_KEY_OFFSET, 0      /* u32: the key bytes, from the record start */
.set DISCV5_PAIR_KEY_LEN, 4         /* u32 */
.set DISCV5_PAIR_VALUE_OFFSET, 8    /* u32: the value bytes, or the whole encoded list */
.set DISCV5_PAIR_VALUE_LEN, 12      /* u32 */
.set DISCV5_PAIR_VALUE_KIND, 16     /* u32: 1 byte string, 2 list */
.set DISCV5_PAIR_SIZE, 24

.set DISCV5_HAS_IP4, 1
.set DISCV5_HAS_UDP4, 2
.set DISCV5_HAS_IP6, 4
.set DISCV5_HAS_UDP6, 8

/* ---------------------------------------------------------------- Config and tick values */

/* discv5_init input. */
.set DISCV5_CFG_KEY, 0              /* 32 bytes, the private key */
.set DISCV5_CFG_SEQ, 32             /* u64, the first record sequence number, at least 1 */
.set DISCV5_CFG_ENTROPY, 40         /* 32 random bytes */
.set DISCV5_CFG_NOW, 72             /* u64, milliseconds */
.set DISCV5_CFG_PORT, 80            /* u64, the UDP port for the record, 0 for none */
.set DISCV5_CFG_FAMILY, 88          /* u64, 4 or 6, 0 for no address */
.set DISCV5_CFG_ADDRESS, 96         /* 16 bytes; an IPv4 address uses the first 4 */
.set DISCV5_CFG_BUCKET_IP_LIMIT, 112 /* u64, most table nodes of one bucket in one subnet, 0 for no limit */
.set DISCV5_CFG_TABLE_IP_LIMIT, 120 /* u64, most table nodes in one subnet, 0 for no limit */
.set DISCV5_CFG_SUBNET4, 128        /* u64, IPv4 subnet prefix bits; above 32 counts as 32 */
.set DISCV5_CFG_SUBNET6, 136        /* u64, IPv6 subnet prefix bits; above 128 counts as 128 */
.set DISCV5_CFG_LIMIT_LAN, 144      /* u64, 0 leaves local network addresses out of the limits */
.set DISCV5_CFG_SIZE, 152

/* discv5_step input: the time and fresh random bytes. */
.set DISCV5_TICK_NOW, 0             /* u64, milliseconds, never decreasing */
.set DISCV5_TICK_ENTROPY, 8         /* 32 random bytes */
.set DISCV5_TICK_SIZE, 40

/* An endpoint inside events and actions. */
.set DISCV5_EP_PORT, 0              /* u64 */
.set DISCV5_EP_FAMILY, 8            /* u64, 4 or 6 */
.set DISCV5_EP_ADDRESS, 16          /* 16 bytes; an IPv4 address uses the first 4 */
.set DISCV5_EP_SIZE, 32

/* ---------------------------------------------------------------- Events (shell to core) */

.set DISCV5_EV_SIZE, 0              /* u64, a multiple of 8 */
.set DISCV5_EV_KIND, 8              /* u64 */

.set DISCV5_EVENT_DATAGRAM, 1       /* a received UDP datagram */
.set DISCV5_EVENT_ADD_NODE, 2       /* a node record to add, such as a bootnode */
.set DISCV5_EVENT_LOOKUP, 3         /* start a lookup of a target */
.set DISCV5_EVENT_SET_ENDPOINT, 4   /* the local IP address and UDP port for the record */
.set DISCV5_EVENT_SET_ENTRY, 5      /* a key and byte string value for the local record */

/* DATAGRAM: the sender's endpoint, then the bytes. */
.set DISCV5_EV_DG_FROM, 16          /* endpoint, 32 bytes */
.set DISCV5_EV_DG_LEN, 48           /* u64 */
.set DISCV5_EV_DG_DATA, 56          /* the datagram */

/* ADD_NODE: the encoded record. */
.set DISCV5_EV_ADD_LEN, 16          /* u64 */
.set DISCV5_EV_ADD_DATA, 24

/* LOOKUP: the target. */
.set DISCV5_EV_LOOKUP_TARGET, 16    /* 32 bytes */
.set DISCV5_EV_LOOKUP_SIZE, 48

/* SET_ENDPOINT: the endpoint. */
.set DISCV5_EV_ENDPOINT, 16         /* endpoint, 32 bytes */
.set DISCV5_EV_ENDPOINT_SIZE, 48

/* SET_ENTRY: a key of 1 to 16 bytes and a value of 0 to 64 bytes. */
.set DISCV5_EV_ENTRY_KEY_LEN, 16    /* u64 */
.set DISCV5_EV_ENTRY_KEY, 24        /* 16 bytes */
.set DISCV5_EV_ENTRY_VALUE_LEN, 40  /* u64 */
.set DISCV5_EV_ENTRY_VALUE, 48
.set DISCV5_MAX_KEY, 16
.set DISCV5_MAX_VALUE, 64

/* Shell results. discv5_step accepts them and changes nothing. */
.set DISCV5_EVENT_OPENED, 6         /* discv5_shell_open: the socket is bound, or the OS error */
.set DISCV5_EVENT_SENT, 7           /* discv5_shell_send: the datagram went to the OS, or the OS error */
.set DISCV5_EVENT_IDLE, 8           /* discv5_shell_receive: no datagram by the time, or the OS error */
.set DISCV5_EV_ERROR, 16            /* u64: 0, or the OS error number */
.set DISCV5_EV_OPENED_ENDPOINT, 24  /* endpoint, 32 bytes: the bound endpoint */
.set DISCV5_EV_OPENED_SIZE, 56
.set DISCV5_EV_ERROR_SIZE, 24       /* SENT and IDLE */
.set DISCV5_EVENT_MAX, 1336         /* the largest event: a DATAGRAM of 1280 bytes */

/* ---------------------------------------------------------------- Actions (core to shell) */

.set DISCV5_ACT_SIZE, 0             /* u64, a multiple of 8 */
.set DISCV5_ACT_KIND, 8             /* u64 */

.set DISCV5_ACTION_SEND, 1          /* send a datagram */
.set DISCV5_ACTION_NODE_FOUND, 2    /* a checked record found by a lookup */
.set DISCV5_ACTION_LOOKUP_DONE, 3   /* a lookup ended */
.set DISCV5_ACTION_ENDPOINT, 4      /* a PONG said what endpoint it saw for us */
.set DISCV5_ACTION_RECORD, 5        /* the local record changed */
.set DISCV5_ACTION_WAKEUP, 6        /* call discv5_step again by this time */

/* SEND: the destination, then the bytes. */
.set DISCV5_ACT_SEND_TO, 16         /* endpoint, 32 bytes */
.set DISCV5_ACT_SEND_LEN, 48        /* u64 */
.set DISCV5_ACT_SEND_DATA, 56

/* NODE_FOUND: the node ID, then the record. */
.set DISCV5_ACT_FOUND_ID, 16        /* 32 bytes */
.set DISCV5_ACT_FOUND_LEN, 48       /* u64 */
.set DISCV5_ACT_FOUND_DATA, 56

/* LOOKUP_DONE: the target and the records found. */
.set DISCV5_ACT_DONE_TARGET, 16     /* 32 bytes */
.set DISCV5_ACT_DONE_FOUND, 48      /* u64 */
.set DISCV5_ACT_DONE_SIZE, 56

/* ENDPOINT: what the reporting node saw. */
.set DISCV5_ACT_EP_SEEN, 16         /* endpoint, 32 bytes */
.set DISCV5_ACT_EP_FROM, 48         /* 32 bytes, the reporting node */
.set DISCV5_ACT_EP_SIZE, 80

/* RECORD: the new local record. */
.set DISCV5_ACT_RECORD_LEN, 16      /* u64 */
.set DISCV5_ACT_RECORD_DATA, 24

/* WAKEUP: the time. */
.set DISCV5_ACT_WAKEUP_AT, 16       /* u64, milliseconds */
.set DISCV5_ACT_WAKEUP_SIZE, 24

/* ---------------------------------------------------------------- Shell resource context */

/* Native and opaque to the core: one UDP socket. */
.set DISCV5_SHELL_SOCKET, 0         /* u64: the socket descriptor or handle; all ones when closed */
.set DISCV5_SHELL_FAMILY, 8         /* u64: 4 or 6, the socket's address family */
.set DISCV5_SHELL_STARTED, 16       /* u64: 1 after WSAStartup (Windows) */
.set DISCV5_SHELL_SIZE, 64

/* ---------------------------------------------------------------- Sizes for callers */

.set DISCV5_ENR_SCRATCH, 10240      /* the scratch discv5_enr_decode needs */
.set DISCV5_SCRATCH_SIZE, 65536     /* the scratch every discv5_step call needs */
.set DISCV5_ACTIONS_BASE, 32768     /* action room for a step: this ... */
.set DISCV5_ACTIONS_PER_EVENT, 16384 /* ... plus this for each event */

/* ---------------------------------------------------------------- Protocol parameters */

.set DISCV5_K, 16                   /* bucket size and lookup result size */
.set DISCV5_ALPHA, 3                /* concurrent FINDNODE requests in a lookup */
.set DISCV5_BUCKETS, 17             /* distances up to 240 share bucket 0 */
.set DISCV5_REPLACEMENTS, 10        /* replacement slots for each bucket */
.set DISCV5_REQUEST_TIMEOUT, 1000   /* milliseconds */
.set DISCV5_CHALLENGE_TIMEOUT, 1000 /* milliseconds a WHOAREYOU stays valid */
.set DISCV5_PING_INTERVAL, 1000     /* milliseconds between liveness checks */
.set DISCV5_RECHECK_INTERVAL, 30000 /* milliseconds before a live node is checked again */
.set DISCV5_REFRESH_INTERVAL, 1800000 /* milliseconds between table refresh lookups */
.set DISCV5_MAX_FAILS, 3            /* failed checks that remove a live node */
.set DISCV5_RESULT_LIMIT, 16        /* records in a FINDNODE answer */
.set DISCV5_NODES_LIMIT, 5          /* NODES packets accepted for one request */
.set DISCV5_NODES_BYTES, 1000       /* record bytes in one NODES packet */
.set DISCV5_MAX_DISTANCES, 16       /* distances read from one FINDNODE */

/* ---------------------------------------------------------------- State value */

/*
 * The state: fixed size, DISCV5_STATE_SIZE bytes, 8-byte aligned. It holds
 * the local node, the DRBG, timers, and the tables below at fixed offsets.
 * It holds no pointers and can be copied as one block.
 */
.set DISCV5_ST_PRIVATE_KEY, 0       /* 32 bytes, secret */
.set DISCV5_ST_PUBLIC_KEY, 32       /* 33 bytes */
.set DISCV5_ST_NODE_ID, 72          /* 32 bytes */
.set DISCV5_ST_SEQ, 104             /* u64, the local record sequence number */
.set DISCV5_ST_DRBG_KEY, 112        /* 32 bytes, secret */
.set DISCV5_ST_DRBG_COUNT, 144      /* u64 */
.set DISCV5_ST_NOW, 152             /* u64, the time of the last step */
.set DISCV5_ST_NEXT_PING, 160       /* u64, next liveness check */
.set DISCV5_ST_NEXT_REFRESH, 168    /* u64, next refresh lookup; 0 until the table has a node */
.set DISCV5_ST_REQ_ID, 176          /* u64, the last request ID */
.set DISCV5_ST_RECORD_LEN, 184      /* u64 */
.set DISCV5_ST_RECORD, 192          /* 300 bytes, the local record */
.set DISCV5_ST_ENTRY_COUNT, 496     /* u64, local key/value pairs */
.set DISCV5_ST_ENTRIES, 504         /* DISCV5_MAX_ENTRIES local entries */
.set DISCV5_ST_BUCKET_IP_LIMIT, 2056 /* u64, from the config */
.set DISCV5_ST_TABLE_IP_LIMIT, 2064 /* u64, from the config */
.set DISCV5_ST_SUBNET4, 2072        /* u64, from the config, at most 32 */
.set DISCV5_ST_SUBNET6, 2080        /* u64, from the config, at most 128 */
.set DISCV5_ST_LIMIT_LAN, 2088      /* u64, from the config */
.set DISCV5_ST_NODES, 2096          /* the node table */

/* Local record entries, sorted by key. */
.set DISCV5_MAX_ENTRIES, 16
.set DISCV5_LE_KEY_LEN, 0           /* u8 */
.set DISCV5_LE_VALUE_LEN, 1         /* u8 */
.set DISCV5_LE_KEY, 8               /* 16 bytes */
.set DISCV5_LE_VALUE, 24            /* 64 bytes */
.set DISCV5_LE_SIZE, 96             /* 16 entries: 1536 bytes, then 16 spare */

/* Node table: DISCV5_NODE_SLOTS slots. */
.set DISCV5_NODE_SLOTS, 442         /* 17 buckets of 16 members and 10 replacements */
.set DISCV5_N_ID, 0                 /* 32 bytes */
.set DISCV5_N_PUBKEY, 32            /* 33 bytes */
.set DISCV5_N_EP, 72                /* endpoint, 32 bytes */
.set DISCV5_N_STATE, 104            /* u8: 0 free, 1 member, 2 replacement */
.set DISCV5_N_BUCKET, 105           /* u8 */
.set DISCV5_N_LIVE, 106             /* u8: 1 after a PONG */
.set DISCV5_N_FAILS, 107            /* u8: failed checks in a row */
.set DISCV5_N_PINGING, 108          /* u8: 1 while a check is pending */
.set DISCV5_N_SEQ, 112              /* u64, the record sequence number */
.set DISCV5_N_ADDED, 120            /* u64, when it was added or last seen */
.set DISCV5_N_CHECK, 128            /* u64, when to check it next */
.set DISCV5_N_RECORD_LEN, 136       /* u64 */
.set DISCV5_N_RECORD, 144           /* 300 bytes */
.set DISCV5_N_SIZE, 448
.set DISCV5_NODE_MEMBER, 1
.set DISCV5_NODE_REPLACEMENT, 2
.set DISCV5_ST_SESSIONS, DISCV5_ST_NODES + DISCV5_NODE_SLOTS * DISCV5_N_SIZE

/* Sessions: established keys, keyed by node ID and endpoint. */
.set DISCV5_SESSION_SLOTS, 256
.set DISCV5_S_ID, 0                 /* 32 bytes */
.set DISCV5_S_EP, 32                /* endpoint, 32 bytes */
.set DISCV5_S_USED, 64              /* u64, last use; 0 marks a free slot */
.set DISCV5_S_WRITE_KEY, 72         /* 16 bytes, secret */
.set DISCV5_S_READ_KEY, 88          /* 16 bytes, secret */
.set DISCV5_S_COUNTER, 104          /* u64, messages sent with the keys */
.set DISCV5_S_SIZE, 112
.set DISCV5_ST_CHALLENGES, DISCV5_ST_SESSIONS + DISCV5_SESSION_SLOTS * DISCV5_S_SIZE

/* Challenges: WHOAREYOU packets sent and not yet answered. */
.set DISCV5_CHALLENGE_SLOTS, 32
.set DISCV5_C_ID, 0                 /* 32 bytes, the node challenged */
.set DISCV5_C_EP, 32                /* endpoint, 32 bytes */
.set DISCV5_C_SENT, 64              /* u64; 0 marks a free slot */
.set DISCV5_C_DATA, 72              /* 63 bytes, the unmasked WHOAREYOU */
.set DISCV5_C_SIZE, 136
.set DISCV5_ST_REQUESTS, DISCV5_ST_CHALLENGES + DISCV5_CHALLENGE_SLOTS * DISCV5_C_SIZE

/* Requests: PING and FINDNODE sent and waiting for answers. */
.set DISCV5_REQUEST_SLOTS, 32
.set DISCV5_R_ID, 0                 /* 32 bytes, the node asked */
.set DISCV5_R_PUBKEY, 32            /* 33 bytes */
.set DISCV5_R_EP, 72                /* endpoint, 32 bytes */
.set DISCV5_R_REQ_ID, 104           /* u64, 8 bytes sent big endian */
.set DISCV5_R_NONCE, 112            /* 12 bytes, the nonce of the last packet sent */
.set DISCV5_R_STATE, 124            /* u8: 0 free, 1 waiting, 2 handshake sent */
.set DISCV5_R_TYPE, 125             /* u8: DISCV5_MSG_PING or DISCV5_MSG_FINDNODE */
.set DISCV5_R_PURPOSE, 126          /* u8: 1 lookup, 2 check, 3 record refresh */
.set DISCV5_R_LOOKUP, 127           /* u8: the lookup slot */
.set DISCV5_R_DEADLINE, 128         /* u64 */
.set DISCV5_R_DIST_COUNT, 136       /* u8 */
.set DISCV5_R_GOT, 137              /* u8: NODES packets received */
.set DISCV5_R_TOTAL, 138            /* u8: NODES packets announced, 0 before the first */
.set DISCV5_R_DISTANCES, 140        /* 3 u16 */
.set DISCV5_R_SIZE, 152
.set DISCV5_REQ_WAITING, 1
.set DISCV5_REQ_HANDSHAKE, 2
.set DISCV5_PURPOSE_LOOKUP, 1
.set DISCV5_PURPOSE_CHECK, 2
.set DISCV5_PURPOSE_REFRESH, 3
.set DISCV5_ST_LOOKUPS, DISCV5_ST_REQUESTS + DISCV5_REQUEST_SLOTS * DISCV5_R_SIZE

/* Lookups. */
.set DISCV5_LOOKUP_SLOTS, 4
.set DISCV5_L_TARGET, 0             /* 32 bytes */
.set DISCV5_L_ACTIVE, 32            /* u64: 1 while running */
.set DISCV5_L_FOUND, 40             /* u64: records found */
.set DISCV5_L_COUNT, 48             /* u64: candidates */
.set DISCV5_L_CANDIDATES, 56        /* DISCV5_K candidates, closest first */
.set DISCV5_LC_ID, 0                /* 32 bytes */
.set DISCV5_LC_PUBKEY, 32           /* 33 bytes */
.set DISCV5_LC_EP, 72               /* endpoint, 32 bytes */
.set DISCV5_LC_STATE, 104           /* u64: 0 new, 1 asked, 2 answered, 3 failed */
.set DISCV5_LC_SIZE, 112
.set DISCV5_LC_NEW, 0
.set DISCV5_LC_ASKED, 1
.set DISCV5_LC_ANSWERED, 2
.set DISCV5_LC_FAILED, 3
.set DISCV5_L_SIZE, DISCV5_L_CANDIDATES + DISCV5_K * DISCV5_LC_SIZE
.set DISCV5_STATE_SIZE, DISCV5_ST_LOOKUPS + DISCV5_LOOKUP_SLOTS * DISCV5_L_SIZE
