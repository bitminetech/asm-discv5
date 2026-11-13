/*
 * asm-discv5 for ARM64 (AAPCS64): Node Discovery Protocol v5.1.
 * Requirements: docs/reference/. Layouts: include/discv5.inc.
 *
 * Pointer arguments, status in x0. Hashes, ciphers and curve operations go
 * through asm-crypto; RLP decoding goes through asm-rlp. x18 is never used.
 * Every function that calls keeps an x29 frame record.
 */
.set ISA_ARM64, 1
.include "crypto.inc"
.include "keccak.inc"
.include "hmac.inc"
.include "aes.inc"
.include "secp256k1.inc"
.include "rlp.inc"
.include "discv5.inc"
.include "platform.inc"

/* ---------------------------------------------------------------- Frames */

/*
 * Frame of a non-leaf function: x29, x30, x19-x28, then locals at sp + 96.
 * extra bytes of locals sit below at sp; then the frame record is at sp + extra.
 */
.macro ENTER locals, extra=0
    stp     x29, x30, [sp, #-(96 + \locals)]!
    UNWIND_SAVE_FPLR_X (96 + \locals)
    mov     x29, sp
    UNWIND_SET_FP
    stp     x19, x20, [sp, #16]
    UNWIND_SAVE_REGP x19, x20, 16, (96 + \locals)
    stp     x21, x22, [sp, #32]
    UNWIND_SAVE_REGP x21, x22, 32, (96 + \locals)
    stp     x23, x24, [sp, #48]
    UNWIND_SAVE_REGP x23, x24, 48, (96 + \locals)
    stp     x25, x26, [sp, #64]
    UNWIND_SAVE_REGP x25, x26, 64, (96 + \locals)
    stp     x27, x28, [sp, #80]
    UNWIND_SAVE_REGP x27, x28, 80, (96 + \locals)
    .if \extra
    sub     sp, sp, #\extra
    UNWIND_ALLOC \extra
    .endif
    UNWIND_END_PROLOGUE
.endm

.macro LEAVE locals, extra=0
    UNWIND_BEGIN_EPILOGUE
    .if \extra
    add     sp, sp, #\extra
    UNWIND_FREE \extra
    .endif
    ldp     x27, x28, [sp, #80]
    UNWIND_RESTORE_REGP x27, x28, 80
    ldp     x25, x26, [sp, #64]
    UNWIND_RESTORE_REGP x25, x26, 64
    ldp     x23, x24, [sp, #48]
    UNWIND_RESTORE_REGP x23, x24, 48
    ldp     x21, x22, [sp, #32]
    UNWIND_RESTORE_REGP x21, x22, 32
    ldp     x19, x20, [sp, #16]
    UNWIND_RESTORE_REGP x19, x20, 16
    ldp     x29, x30, [sp], #(96 + \locals)
    UNWIND_RESTORE_FPLR_X (96 + \locals)
    UNWIND_END_EPILOGUE
    ret
.endm

/* reg = the 64-bit constant v. */
.macro MOV64 reg, v
    movz    \reg, #((\v) & 0xFFFF)
    movk    \reg, #(((\v) >> 16) & 0xFFFF), lsl #16
    movk    \reg, #(((\v) >> 32) & 0xFFFF), lsl #32
    movk    \reg, #(((\v) >> 48) & 0xFFFF), lsl #48
.endm

/* A ByteList header at base + off: size, offset 24, count. Uses x17; count is not x17. */
.macro BYTELIST base, off, size, count
    str     \count, [\base, #\off + 16]
    mov     x17, #\size
    str     x17, [\base, #\off]
    mov     x17, #DISCV5_BL_FIXED
    str     x17, [\base, #\off + 8]
.endm

/* ---------------------------------------------------------------- Byte helpers */

/* discv5_copy(dst, src, n) -> dst + n. The regions do not overlap. */
LOCAL_FUNCTION discv5_copy
    UNWIND_END_PROLOGUE
1:  cmp     x2, #8
    b.lo    2f
    ldr     x3, [x1], #8
    str     x3, [x0], #8
    sub     x2, x2, #8
    b       1b
2:  cbz     x2, 3f
    ldrb    w3, [x1], #1
    strb    w3, [x0], #1
    sub     x2, x2, #1
    b       2b
3:  ret
END_FUNCTION discv5_copy

/* discv5_zero(dst, n) -> dst + n. */
LOCAL_FUNCTION discv5_zero
    UNWIND_END_PROLOGUE
1:  cmp     x1, #8
    b.lo    2f
    str     xzr, [x0], #8
    sub     x1, x1, #8
    b       1b
2:  cbz     x1, 3f
    strb    wzr, [x0], #1
    sub     x1, x1, #1
    b       2b
3:  ret
END_FUNCTION discv5_zero

/* discv5_equal(a, b, n) -> 1 when the n bytes at a and b are equal, else 0. */
LOCAL_FUNCTION discv5_equal
    UNWIND_END_PROLOGUE
    mov     x4, #0
1:  cbz     x2, 2f
    ldrb    w3, [x0], #1
    ldrb    w5, [x1], #1
    eor     w3, w3, w5
    orr     x4, x4, x3
    sub     x2, x2, #1
    b       1b
2:  cmp     x4, #0
    cset    x0, eq
    ret
END_FUNCTION discv5_equal

/* discv5_log_distance(a, b) -> 0 when the 32-byte IDs are equal, else 256 minus the leading zero bits of a XOR b. */
LOCAL_FUNCTION discv5_log_distance
    UNWIND_END_PROLOGUE
    mov     x4, #256
    mov     x5, #0
1:  ldr     x2, [x0, x5]
    ldr     x3, [x1, x5]
    eor     x2, x2, x3
    rev     x2, x2
    cbnz    x2, 2f
    sub     x4, x4, #64
    add     x5, x5, #8
    cmp     x5, #32
    b.lo    1b
    mov     x0, #0
    ret
2:  clz     x2, x2
    sub     x0, x4, x2
    ret
END_FUNCTION discv5_log_distance

/* discv5_load_be(p, n) -> the n bytes at p (n at most 8) as a big-endian number. */
LOCAL_FUNCTION discv5_load_be
    UNWIND_END_PROLOGUE
    mov     x2, #0
1:  cbz     x1, 2f
    ldrb    w3, [x0], #1
    orr     x2, x3, x2, lsl #8
    sub     x1, x1, #1
    b       1b
2:  mov     x0, x2
    ret
END_FUNCTION discv5_load_be

/* discv5_store_be(p, v, n): the low n bytes of v (n at most 8) at p, big endian. */
LOCAL_FUNCTION discv5_store_be
    UNWIND_END_PROLOGUE
    lsl     x3, x2, #3
1:  cbz     x3, 2f
    sub     x3, x3, #8
    lsr     x4, x1, x3
    strb    w4, [x0], #1
    b       1b
2:  ret
END_FUNCTION discv5_store_be

/* ---------------------------------------------------------------- RLP writers */

/* x4 = bytes of the number x1, which is not 0. Uses x3. */
.macro BYTES_OF
    clz     x3, x1
    mov     x4, #64
    sub     x4, x4, x3
    add     x4, x4, #7
    lsr     x4, x4, #3
.endm

/* Write the n (x4) bytes of x1 big endian at x0, moving x0. Uses x5, x6. */
.macro WRITE_BE
    lsl     x5, x4, #3
97: sub     x5, x5, #8
    lsr     x6, x1, x5
    strb    w6, [x0], #1
    cbnz    x5, 97b
.endm

/* discv5_rlp_header(out, length, base) -> out after the header: base 0x80 for a byte string, 0xC0 for a list. */
LOCAL_FUNCTION discv5_rlp_header
    UNWIND_END_PROLOGUE
    cmp     x1, #55
    b.hi    1f
    add     x2, x2, x1
    strb    w2, [x0], #1
    ret
1:  BYTES_OF
    add     x2, x2, #55
    add     x2, x2, x4
    strb    w2, [x0], #1
    WRITE_BE
    ret
END_FUNCTION discv5_rlp_header

/* discv5_rlp_bytes(out, data, len) -> out after the byte string encoding. A byte below 0x80 is itself. */
LOCAL_FUNCTION discv5_rlp_bytes
    UNWIND_END_PROLOGUE
    cmp     x2, #1
    b.ne    1f
    ldrb    w3, [x1]
    cmp     w3, #0x80
    b.hs    1f
    strb    w3, [x0], #1
    ret
1:  mov     x7, x1
    mov     x1, x2
    cmp     x1, #55
    b.hi    2f
    add     x3, x1, #0x80
    strb    w3, [x0], #1
    b       3f
2:  BYTES_OF
    add     x3, x4, #0xB7
    strb    w3, [x0], #1
    WRITE_BE
3:  cbz     x2, 4f
    ldrb    w3, [x7], #1
    strb    w3, [x0], #1
    sub     x2, x2, #1
    b       3b
4:  ret
END_FUNCTION discv5_rlp_bytes

/* discv5_rlp_uint(out, value) -> out after the value as a byte string, big endian with no leading zero. */
LOCAL_FUNCTION discv5_rlp_uint
    UNWIND_END_PROLOGUE
    cbnz    x1, 1f
    mov     w2, #0x80
    strb    w2, [x0], #1
    ret
1:  cmp     x1, #0x80
    b.hs    2f
    strb    w1, [x0], #1
    ret
2:  BYTES_OF
    add     x3, x4, #0x80
    strb    w3, [x0], #1
    WRITE_BE
    ret
END_FUNCTION discv5_rlp_uint

/* ---------------------------------------------------------------- Hashes and the DRBG */

/*
 * discv5_hash(data, len, digest, keccak): SHA-256 (keccak 0) or Keccak-256
 * (keccak 1) of len bytes, len at most 304. The bytes go into a ByteList on
 * the stack first.
 */
LOCAL_FUNCTION discv5_hash
    ENTER   0, 336
    mov     x19, x2
    mov     x20, x3
    mov     x9, #328
    str     x9, [sp]
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [sp, #8]
    str     x1, [sp, #16]
    mov     x2, x1
    mov     x1, x0
    add     x0, sp, #24
    bl      discv5_copy
    mov     x0, sp
    mov     x1, x19
    cbnz    x20, 1f
    CALL_GLOBAL crypto_sha256
    b       2f
1:  CALL_GLOBAL crypto_keccak256
2:  LEAVE   0, 336
END_FUNCTION discv5_hash

/*
 * discv5_random(state, out, n): n bytes from the DRBG. Each 32-byte block is
 * SHA-256(key || counter), the counter as 8 bytes little endian; the counter
 * then goes up by 1.
 */
LOCAL_FUNCTION discv5_random
    ENTER   0, 96
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
1:  cbz     x21, 9f
    mov     x9, #64
    str     x9, [sp]
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [sp, #8]
    mov     x9, #40
    str     x9, [sp, #16]
    ldp     x9, x10, [x19, #DISCV5_ST_DRBG_KEY]
    stp     x9, x10, [sp, #24]
    ldp     x9, x10, [x19, #DISCV5_ST_DRBG_KEY + 16]
    stp     x9, x10, [sp, #40]
    ldr     x9, [x19, #DISCV5_ST_DRBG_COUNT]
    str     x9, [sp, #56]
    add     x9, x9, #1
    str     x9, [x19, #DISCV5_ST_DRBG_COUNT]
    mov     x0, sp
    add     x1, sp, #64
    CALL_GLOBAL crypto_sha256
    mov     x2, #32
    cmp     x21, x2
    csel    x2, x21, x2, lo
    sub     x21, x21, x2
    mov     x0, x20
    add     x1, sp, #64
    bl      discv5_copy
    mov     x20, x0
    b       1b
9:  LEAVE   0, 96
END_FUNCTION discv5_random

/* discv5_reseed(state, entropy): the DRBG key becomes SHA-256(key || the 32 entropy bytes). */
LOCAL_FUNCTION discv5_reseed
    ENTER   0, 96
    mov     x19, x0
    mov     x9, #88
    str     x9, [sp]
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [sp, #8]
    mov     x9, #64
    str     x9, [sp, #16]
    ldp     x9, x10, [x19, #DISCV5_ST_DRBG_KEY]
    stp     x9, x10, [sp, #24]
    ldp     x9, x10, [x19, #DISCV5_ST_DRBG_KEY + 16]
    stp     x9, x10, [sp, #40]
    ldp     x9, x10, [x1]
    stp     x9, x10, [sp, #56]
    ldp     x9, x10, [x1, #16]
    stp     x9, x10, [sp, #72]
    mov     x0, sp
    add     x1, x19, #DISCV5_ST_DRBG_KEY
    CALL_GLOBAL crypto_sha256
    LEAVE   0, 96
END_FUNCTION discv5_reseed

/* ---------------------------------------------------------------- Node records (EIP-778, v4 scheme) */

/* discv5_enr_decode scratch: the signature, the record content, the point, its hash, the Items value. */
.set ES_SIG, 8                      /* 64 bytes, the signature copied to an aligned buffer */
.set ES_CONTENT, 72                 /* up to 303 bytes */
.set ES_POINT, 376                  /* 64 bytes */
.set ES_HASH, 440                   /* 32 bytes */
.set ES_VALID, 472                  /* u64 */
.set ES_ITEMS, 480                  /* the Items value: 24 + 32 * 300 bytes */
.set ES_ITEMS_SIZE, 24 + 32 * 300

/* x12 = the item at index x13: x23 + 32 * x13. */
.macro ITEM_AT
    add     x12, x23, x13, lsl #RLP_ITEM_SHIFT
.endm

/* Branch to label unless the byte string at x10 (x11 bytes) is a canonical number of at most n bytes. Uses x9. */
.macro CHECK_UINT n, label
    cmp     x11, #\n
    b.hi    \label
    cbz     x11, 96f
    ldrb    w9, [x10]
    cbz     w9, \label
96:
.endm

/*
 * discv5_enr_decode(record, scratch, enr) -> status
 * x19 record, x20 scratch, x21 enr, x22 record bytes, x23 items, x24 item
 * count, x25 child index, x26 previous key (pointer), x27 pairs, x28 flags:
 * bit 0 id is v4, bit 1 secp256k1 seen. Locals: sp + 96 the previous key
 * length, sp + 104 the signature item.
 */
FUNCTION discv5_enr_decode
    ENTER   16
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x0, #DISCV5_BUFFER_TOO_SMALL
    ldr     x9, [x20]
    mov     x10, #DISCV5_ENR_SCRATCH
    cmp     x9, x10
    b.lo    99f
    mov     x0, x21
    mov     x1, #DISCV5_ENR_SIZE
    bl      discv5_zero
    mov     x0, #DISCV5_INVALID_RECORD
    ldr     x9, [x19, #DISCV5_BL_COUNT]
    cbz     x9, 99f
    cmp     x9, #DISCV5_MAX_RECORD
    b.hi    99f
    ldr     x22, [x19, #DISCV5_BL_OFFSET]
    add     x22, x19, x22
    add     x1, x20, #ES_ITEMS
    mov     x9, #ES_ITEMS_SIZE
    str     x9, [x1]
    mov     x0, x19
    CALL_GLOBAL rlp_decode
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_RECORD
    cbnz    x9, 99f
    add     x10, x20, #ES_ITEMS
    ldr     x11, [x10, #RLP_ITEMS_OFFSET]
    add     x23, x10, x11
    ldr     x24, [x10, #RLP_ITEMS_COUNT]
    ldr     x9, [x23, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_LIST
    b.ne    99f

    /* The signature: 64 bytes. */
    mov     x13, #1
    cmp     x13, x24
    b.hs    99f
    ITEM_AT
    ldr     x9, [x12, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_BYTES
    b.ne    99f
    ldr     x9, [x12, #RLP_ITEM_LENGTH]
    cmp     x9, #64
    b.ne    99f
    str     x12, [sp, #104]

    /* The sequence number. */
    mov     x13, #2
    cmp     x13, x24
    b.hs    99f
    ITEM_AT
    ldr     x9, [x12, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_BYTES
    b.ne    99f
    ldr     x10, [x12, #RLP_ITEM_OFFSET]
    add     x10, x22, x10
    ldr     x11, [x12, #RLP_ITEM_LENGTH]
    CHECK_UINT 8, 99f
    mov     x0, x10
    mov     x1, x11
    bl      discv5_load_be
    str     x0, [x21, #DISCV5_ENR_SEQ]
    mov     x0, #DISCV5_INVALID_RECORD

    /* Key/value pairs, keys sorted and unique. */
    mov     x25, #3
    mov     x26, #0
    mov     x27, #0
    mov     x28, #0
1:  cmp     x25, x24
    b.hs    5f
    mov     x13, x25
    ITEM_AT
    ldr     x9, [x12, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_BYTES
    b.ne    99f
    ldr     x14, [x12, #RLP_ITEM_OFFSET]
    add     x14, x22, x14                   /* key */
    ldr     x15, [x12, #RLP_ITEM_LENGTH]    /* key length */
    cbz     x26, 3f
    ldr     x16, [sp, #96]                  /* previous key length */
    mov     x9, #0
2:  cmp     x9, x16
    b.lo    21f
    cmp     x15, x16                        /* the previous key is a prefix: increasing when the new key is longer */
    b.hi    3f
    b       99f
21: cmp     x9, x15
    b.hs    99f                             /* the new key is a prefix of the previous one */
    ldrb    w10, [x26, x9]
    ldrb    w11, [x14, x9]
    cmp     w10, w11
    b.lo    3f
    b.hi    99f
    add     x9, x9, #1
    b       2b
3:  mov     x26, x14
    str     x15, [sp, #96]
    cmp     x27, #DISCV5_ENR_MAX_PAIRS
    b.hs    99f
    add     x13, x25, #1                    /* the value */
    cmp     x13, x24
    b.hs    99f
    ITEM_AT
    mov     x9, #DISCV5_PAIR_SIZE
    mul     x9, x27, x9
    add     x17, x21, #DISCV5_ENR_PAIRS
    add     x17, x17, x9
    sub     x9, x14, x22
    str     w9, [x17, #DISCV5_PAIR_KEY_OFFSET]
    str     w15, [x17, #DISCV5_PAIR_KEY_LEN]
    ldr     x9, [x12, #RLP_ITEM_KIND]
    str     w9, [x17, #DISCV5_PAIR_VALUE_KIND]
    ldr     x10, [x12, #RLP_ITEM_OFFSET]
    ldr     x11, [x12, #RLP_ITEM_LENGTH]
    cmp     x9, #RLP_KIND_BYTES
    b.eq    4f
    mov     x9, #1                          /* a list: the whole encoding, header included */
    cmp     x11, #55
    b.ls    31f
    clz     x9, x11
    mov     x16, #71
    sub     x9, x16, x9
    lsr     x9, x9, #3
    add     x9, x9, #1
31: sub     x10, x10, x9
    add     x11, x11, x9
    str     w10, [x17, #DISCV5_PAIR_VALUE_OFFSET]
    str     w11, [x17, #DISCV5_PAIR_VALUE_LEN]
    b       45f
4:  str     w10, [x17, #DISCV5_PAIR_VALUE_OFFSET]
    str     w11, [x17, #DISCV5_PAIR_VALUE_LEN]
    add     x10, x22, x10                   /* value bytes */
    adr     x16, 400f
    cmp     x15, #2                         /* "id" and "ip" */
    b.ne    41f
    ldrh    w9, [x14]
    ldrh    w8, [x16]
    cmp     w9, w8
    b.ne    40f
    cmp     x11, #2                         /* "id" = "v4" */
    b.ne    99f
    ldrh    w9, [x10]
    ldrh    w8, [x16, #2]
    cmp     w9, w8
    b.ne    99f
    orr     x28, x28, #1
    b       45f
40: ldrh    w8, [x16, #4]                   /* "ip": 4 bytes */
    cmp     w9, w8
    b.ne    45f
    cmp     x11, #4
    b.ne    45f
    ldr     w9, [x10]
    str     w9, [x21, #DISCV5_ENR_IP4]
    ldr     x9, [x21, #DISCV5_ENR_HAS]
    orr     x9, x9, #DISCV5_HAS_IP4
    str     x9, [x21, #DISCV5_ENR_HAS]
    b       45f
41: cmp     x15, #3                         /* "udp" and "ip6" */
    b.ne    43f
    ldrh    w9, [x14]
    ldrb    w8, [x14, #2]
    orr     w9, w9, w8, lsl #16
    ldr     w8, [x16, #8]                   /* "udp" */
    cmp     w9, w8
    b.ne    42f
    CHECK_UINT 2, 45f
    mov     x0, x10
    mov     x1, x11
    bl      discv5_load_be
    str     x0, [x21, #DISCV5_ENR_UDP4]
    ldr     x9, [x21, #DISCV5_ENR_HAS]
    orr     x9, x9, #DISCV5_HAS_UDP4
    str     x9, [x21, #DISCV5_ENR_HAS]
    mov     x0, #DISCV5_INVALID_RECORD
    b       45f
42: ldr     w8, [x16, #12]                  /* "ip6": 16 bytes */
    cmp     w9, w8
    b.ne    45f
    cmp     x11, #16
    b.ne    45f
    ldp     x8, x9, [x10]
    stp     x8, x9, [x21, #DISCV5_ENR_IP6]
    ldr     x9, [x21, #DISCV5_ENR_HAS]
    orr     x9, x9, #DISCV5_HAS_IP6
    str     x9, [x21, #DISCV5_ENR_HAS]
    b       45f
43: cmp     x15, #4                         /* "udp6" */
    b.ne    44f
    ldr     w9, [x14]
    ldr     w8, [x16, #16]
    cmp     w9, w8
    b.ne    45f
    CHECK_UINT 2, 45f
    mov     x0, x10
    mov     x1, x11
    bl      discv5_load_be
    str     x0, [x21, #DISCV5_ENR_UDP6]
    ldr     x9, [x21, #DISCV5_ENR_HAS]
    orr     x9, x9, #DISCV5_HAS_UDP6
    str     x9, [x21, #DISCV5_ENR_HAS]
    mov     x0, #DISCV5_INVALID_RECORD
    b       45f
44: cmp     x15, #9                         /* "secp256k1": 33 bytes */
    b.ne    45f
    ldr     x9, [x14]
    ldr     x8, [x16, #24]
    cmp     x9, x8
    b.ne    45f
    ldrb    w9, [x14, #8]
    ldrb    w8, [x16, #32]
    cmp     w9, w8
    b.ne    45f
    cmp     x11, #33
    b.ne    99f
    add     x0, x21, #DISCV5_ENR_PUBKEY
    mov     x1, x10
    mov     x2, #33
    bl      discv5_copy
    orr     x28, x28, #2
    mov     x0, #DISCV5_INVALID_RECORD
45: add     x27, x27, #1
    add     x13, x25, #1
    ITEM_AT
    ldr     x9, [x12, #RLP_ITEM_ITEMS]
    add     x25, x13, x9
    b       1b

    /* The v4 scheme: the id, the key, the node ID and the signature. */
5:  cmp     x28, #3
    b.ne    99f
    str     x27, [x21, #DISCV5_ENR_COUNT]
    add     x0, x21, #DISCV5_ENR_PUBKEY
    add     x1, x20, #ES_POINT
    CALL_GLOBAL crypto_secp256k1_decompress
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_RECORD
    cbnz    x9, 99f
    add     x0, x20, #ES_POINT
    mov     x1, #64
    add     x2, x21, #DISCV5_ENR_NODE_ID
    mov     x3, #1
    bl      discv5_hash

    /* The content [seq, k, v, ...]: a new list header, then the record bytes after the signature. */
    ldr     x12, [sp, #104]
    ldr     x9, [x12, #RLP_ITEM_OFFSET]
    add     x1, x22, x9
    add     x0, x20, #ES_SIG
    mov     x2, #64
    bl      discv5_copy
    ldr     x12, [sp, #104]
    ldr     x25, [x12, #RLP_ITEM_OFFSET]
    add     x25, x25, #64                   /* the content payload starts after the signature */
    ldr     x9, [x23, #RLP_ITEM_OFFSET]
    ldr     x10, [x23, #RLP_ITEM_LENGTH]
    add     x26, x9, x10                    /* and ends with the record */
    sub     x26, x26, x25
    add     x0, x20, #ES_CONTENT
    mov     x1, x26
    mov     x2, #0xC0
    bl      discv5_rlp_header
    add     x1, x22, x25
    mov     x2, x26
    bl      discv5_copy
    add     x1, x20, #ES_CONTENT
    sub     x1, x0, x1
    add     x0, x20, #ES_CONTENT
    add     x2, x20, #ES_HASH
    mov     x3, #1
    bl      discv5_hash
    add     x0, x21, #DISCV5_ENR_PUBKEY
    add     x1, x20, #ES_HASH
    add     x2, x20, #ES_SIG
    add     x3, x20, #ES_VALID
    CALL_GLOBAL crypto_secp256k1_verify
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_RECORD
    cbnz    x9, 99f
    ldr     x9, [x20, #ES_VALID]
    cbz     x9, 99f
    mov     x0, #DISCV5_OK
99: LEAVE   16
END_FUNCTION discv5_enr_decode

/* Key names, for the comparisons in discv5_enr_decode. */
    .p2align 3
400:
    .ascii  "idv4ip"
    .byte   0, 0
    .ascii  "udp"
    .byte   0
    .ascii  "ip6"
    .byte   0
    .ascii  "udp6"
    .byte   0, 0, 0, 0
    .ascii  "secp256k1"
    .p2align 3

/*
 * discv5_enr_text_decode(text, record) -> status: "enr:" then URL-safe base64
 * with no padding. x19 text bytes, x20 record, x21 characters left, x22
 * output, x23 bits, x24 bits held.
 */
FUNCTION discv5_enr_text_decode
    UNWIND_END_PROLOGUE
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_TEXT
    ldr     x3, [x9, #DISCV5_BL_COUNT]
    cmp     x3, #4
    b.lo    99f
    ldr     x2, [x9, #DISCV5_BL_OFFSET]
    add     x2, x9, x2
    ldr     w10, [x2], #4
    MOV64   x11, 0x3a726e65                 /* "enr:" */
    cmp     w10, w11
    b.ne    99f
    sub     x3, x3, #4
    and     x9, x3, #3
    cmp     x9, #1
    b.eq    99f
    mov     x10, #0                         /* every character must be in the alphabet */
11: cmp     x10, x3
    b.hs    12f
    ldrb    w11, [x2, x10]
    add     x10, x10, #1
    sub     w12, w11, #'A'
    cmp     w12, #26
    b.lo    11b
    sub     w12, w11, #'a'
    cmp     w12, #26
    b.lo    11b
    sub     w12, w11, #'0'
    cmp     w12, #10
    b.lo    11b
    cmp     w11, #'-'
    b.eq    11b
    cmp     w11, #'_'
    b.eq    11b
    b       99f
12: mov     x9, #3
    mul     x9, x3, x9
    lsr     x9, x9, #2                      /* output bytes */
    mov     x0, #DISCV5_BUFFER_TOO_SMALL
    ldr     x10, [x1, #DISCV5_BL_SIZE]
    subs    x10, x10, #DISCV5_BL_FIXED
    b.lo    99f
    cmp     x10, x9
    b.lo    99f
    mov     x0, #DISCV5_INVALID_TEXT
    add     x4, x1, #DISCV5_BL_FIXED
    mov     x5, #0
    mov     x6, #0
1:  cbz     x3, 8f
    ldrb    w10, [x2], #1
    sub     x3, x3, #1
    sub     w11, w10, #'A'
    cmp     w11, #26
    b.lo    2f
    sub     w11, w10, #'a'
    cmp     w11, #26
    add     w11, w11, #26
    b.lo    2f
    sub     w11, w10, #'0'
    cmp     w11, #10
    add     w11, w11, #52
    b.lo    2f
    mov     w11, #62
    cmp     w10, #'-'
    b.eq    2f
    mov     w11, #63
    cmp     w10, #'_'
    b.ne    99f
2:  orr     x5, x11, x5, lsl #6
    add     x6, x6, #6
    cmp     x6, #8
    b.lo    1b
    sub     x6, x6, #8
    lsr     x10, x5, x6
    strb    w10, [x4], #1
    b       1b
8:  mov     x9, #DISCV5_BL_FIXED
    str     x9, [x1, #DISCV5_BL_OFFSET]
    add     x9, x1, #DISCV5_BL_FIXED
    sub     x9, x4, x9
    str     x9, [x1, #DISCV5_BL_COUNT]
    mov     x0, #DISCV5_OK
99: ret
END_FUNCTION discv5_enr_text_decode

/* discv5_local_record(state, record) -> status: a copy of the local record. */
FUNCTION discv5_local_record
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x0, #DISCV5_BUFFER_TOO_SMALL
    ldr     x21, [x19, #DISCV5_ST_RECORD_LEN]
    ldr     x9, [x20, #DISCV5_BL_SIZE]
    subs    x9, x9, #DISCV5_BL_FIXED
    b.lo    9f
    cmp     x9, x21
    b.lo    9f
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [x20, #DISCV5_BL_OFFSET]
    str     x21, [x20, #DISCV5_BL_COUNT]
    add     x0, x20, #DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_ST_RECORD
    mov     x2, x21
    bl      discv5_copy
    mov     x0, #DISCV5_OK
9:  LEAVE   0
END_FUNCTION discv5_local_record

/* ---------------------------------------------------------------- Packets (discv5-wire.md) */

/* discv5_packet_decode stack: the masked bytes and the unmasked bytes, as ByteLists. */
.set PD_IN, 0
.set PD_OUT, 520
.set PD_UNMASK, 496                 /* most bytes unmasked: the static header and 473 bytes of authdata */

/*
 * discv5_packet_decode(packet, local_id, header) -> status
 * x19 packet, x20 local_id, x21 header, x22 packet bytes, x23 length,
 * x24 unmasked bytes, x25 flag, x26 authdata size.
 */
FUNCTION discv5_packet_decode
    ENTER   0, 1040
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x0, #DISCV5_INVALID_PACKET
    ldr     x23, [x19, #DISCV5_BL_COUNT]
    cmp     x23, #DISCV5_MIN_PACKET
    b.lo    99f
    cmp     x23, #DISCV5_MAX_PACKET
    b.hi    99f
    ldr     x22, [x19, #DISCV5_BL_OFFSET]
    add     x22, x19, x22
    ldp     x9, x10, [x22]
    stp     x9, x10, [x21, #DISCV5_HDR_IV]
    sub     x9, x23, #DISCV5_MASKED_START
    mov     x10, #PD_UNMASK
    cmp     x9, x10
    csel    x9, x9, x10, lo
    BYTELIST sp, PD_IN, 520, x9
    BYTELIST sp, PD_OUT, 520, xzr
    add     x0, sp, #PD_IN + DISCV5_BL_FIXED
    add     x1, x22, #DISCV5_MASKED_START
    mov     x2, x9
    bl      discv5_copy
    mov     x0, x20
    add     x1, x21, #DISCV5_HDR_IV
    add     x2, sp, #PD_IN
    add     x3, sp, #PD_OUT
    CALL_GLOBAL crypto_aes128_ctr
    add     x24, sp, #PD_OUT + DISCV5_BL_FIXED
    mov     x0, #DISCV5_INVALID_PACKET

    /* The static header: "discv5", version at least 1, flag, nonce, authdata size. */
    adr     x16, 410f
    ldr     w9, [x24]
    ldr     w10, [x16]
    cmp     w9, w10
    b.ne    99f
    ldrh    w9, [x24, #4]
    ldrh    w10, [x16, #4]
    cmp     w9, w10
    b.ne    99f
    ldrb    w9, [x24, #6]
    ldrb    w10, [x24, #7]
    orr     w9, w10, w9, lsl #8
    cbz     w9, 99f
    ldrb    w25, [x24, #8]
    str     x25, [x21, #DISCV5_HDR_FLAG]
    add     x0, x21, #DISCV5_HDR_NONCE
    add     x1, x24, #9
    mov     x2, #12
    bl      discv5_copy
    mov     x0, #DISCV5_INVALID_PACKET
    ldrb    w9, [x24, #21]
    ldrb    w10, [x24, #22]
    orr     w26, w10, w9, lsl #8
    sub     x9, x23, #DISCV5_HEADER_START   /* bytes after the static header */
    cmp     x25, #DISCV5_FLAG_WHOAREYOU
    b.eq    1f
    cmp     x9, #48
    b.lo    99f
1:  cmp     x26, x9
    b.hi    99f
    cmp     x26, #(PD_UNMASK - DISCV5_STATIC_HEADER)
    b.hi    99f

    /* The unmasked header, kept for the message's associated data. */
    add     x9, x26, #DISCV5_HEADER_START
    add     x10, x21, #DISCV5_HDR_HEADER
    BYTELIST x10, 0, DISCV5_HDR_HEADER_SIZE, x9
    add     x0, x21, #DISCV5_HDR_HEADER + DISCV5_BL_FIXED
    add     x1, x21, #DISCV5_HDR_IV
    mov     x2, #16
    bl      discv5_copy
    mov     x1, x24
    add     x2, x26, #DISCV5_STATIC_HEADER
    bl      discv5_copy
    add     x10, x21, #DISCV5_HDR_RECORD
    BYTELIST x10, 0, DISCV5_HDR_RECORD_SIZE, xzr
    mov     x0, #DISCV5_INVALID_PACKET
    add     x24, x24, #DISCV5_STATIC_HEADER /* authdata */
    cmp     x25, #DISCV5_FLAG_MESSAGE
    b.ne    2f
    cmp     x26, #32
    b.ne    99f
    add     x0, x21, #DISCV5_HDR_SRC_ID
    mov     x1, x24
    mov     x2, #32
    bl      discv5_copy
    b       8f
2:  cmp     x25, #DISCV5_FLAG_WHOAREYOU
    b.ne    3f
    cmp     x26, #24
    b.ne    99f
    add     x0, x21, #DISCV5_HDR_ID_NONCE
    mov     x1, x24
    mov     x2, #16
    bl      discv5_copy
    add     x0, x24, #16
    mov     x1, #8
    bl      discv5_load_be
    str     x0, [x21, #DISCV5_HDR_ENR_SEQ]
    b       8f
3:  cmp     x25, #DISCV5_FLAG_HANDSHAKE
    b.ne    99f
    cmp     x26, #(34 + 64 + 33)
    b.lo    99f
    ldrb    w9, [x24, #32]
    cmp     w9, #64
    b.ne    99f
    ldrb    w9, [x24, #33]
    cmp     w9, #33
    b.ne    99f
    sub     x9, x26, #(34 + 64 + 33)
    cmp     x9, #DISCV5_MAX_RECORD
    b.hi    99f
    str     x9, [x21, #DISCV5_HDR_RECORD + DISCV5_BL_COUNT]
    add     x0, x21, #DISCV5_HDR_SRC_ID
    mov     x1, x24
    mov     x2, #32
    bl      discv5_copy
    add     x0, x21, #DISCV5_HDR_SIGNATURE
    add     x1, x24, #34
    mov     x2, #64
    bl      discv5_copy
    add     x0, x21, #DISCV5_HDR_EPH_KEY
    add     x1, x24, #98
    mov     x2, #33
    bl      discv5_copy
    add     x0, x21, #DISCV5_HDR_RECORD + DISCV5_BL_FIXED
    add     x1, x24, #131
    ldr     x2, [x21, #DISCV5_HDR_RECORD + DISCV5_BL_COUNT]
    bl      discv5_copy
8:  mov     x0, #DISCV5_OK
99: LEAVE   0, 1040
END_FUNCTION discv5_packet_decode

/*
 * discv5_message_decrypt(header, key, packet, message) -> status: AES-GCM
 * open of the bytes after the header, with the header nonce and the
 * unmasked header as associated data. The sealed bytes at sp.
 */
FUNCTION discv5_message_decrypt
    ENTER   0, 1312
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x0, #DISCV5_DECRYPT_FAIL
    ldr     x23, [x19, #DISCV5_HDR_HEADER + DISCV5_BL_COUNT]
    ldr     x24, [x21, #DISCV5_BL_COUNT]
    subs    x24, x24, x23
    b.lo    99f
    cmp     x24, #(CRYPTO_GCM_TAG_SIZE + 1)
    b.lo    99f
    mov     x9, #1304
    cmp     x24, x9
    b.hi    99f
    BYTELIST sp, 0, 1304, x24
    ldr     x9, [x21, #DISCV5_BL_OFFSET]
    add     x1, x21, x9
    add     x1, x1, x23
    add     x0, sp, #DISCV5_BL_FIXED
    mov     x2, x24
    bl      discv5_copy
    mov     x0, x20
    add     x1, x19, #DISCV5_HDR_NONCE
    mov     x2, sp
    add     x3, x19, #DISCV5_HDR_HEADER
    mov     x4, x22
    CALL_GLOBAL crypto_aes128_gcm_ad
    cmp     x0, #CRYPTO_GCM_FAIL
    b.ne    99f
    mov     x0, #DISCV5_DECRYPT_FAIL
99: LEAVE   0, 1312
END_FUNCTION discv5_message_decrypt

/* discv5_packet_encode stack: the header to mask, the masked header, the sealed message. */
.set PE_IN, 0
.set PE_OUT, 520
.set PE_SEALED, 1040

/*
 * discv5_packet_encode(header, dest_id, key, message, packet) -> status
 * x19 header, x20 dest_id, x21 key, x22 message, x23 packet, x24 flag,
 * x25 header length, x26 total length, x27 write position.
 */
FUNCTION discv5_packet_encode
    ENTER   0, 2352
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    ldr     x24, [x19, #DISCV5_HDR_FLAG]

    /* The unmasked header: IV, "discv5", version 1, flag, nonce, authdata size, authdata. */
    add     x27, x19, #DISCV5_HDR_HEADER + DISCV5_BL_FIXED
    mov     x0, x27
    add     x1, x19, #DISCV5_HDR_IV
    mov     x2, #16
    bl      discv5_copy
    adr     x1, 410f
    mov     x2, #6
    bl      discv5_copy
    mov     w9, #0
    strb    w9, [x0], #1
    mov     w9, #1
    strb    w9, [x0], #1
    strb    w24, [x0], #1
    add     x1, x19, #DISCV5_HDR_NONCE
    mov     x2, #12
    bl      discv5_copy
    mov     x27, x0
    mov     x0, #DISCV5_INVALID_PACKET
    cmp     x24, #DISCV5_FLAG_MESSAGE
    b.ne    1f
    mov     x9, #32
    b       4f
1:  cmp     x24, #DISCV5_FLAG_WHOAREYOU
    b.ne    2f
    mov     x9, #24
    b       4f
2:  cmp     x24, #DISCV5_FLAG_HANDSHAKE
    b.ne    99f
    ldr     x9, [x19, #DISCV5_HDR_RECORD + DISCV5_BL_COUNT]
    cmp     x9, #DISCV5_MAX_RECORD
    b.hi    99f
    add     x9, x9, #(34 + 64 + 33)
4:  lsr     x10, x9, #8
    strb    w10, [x27], #1
    strb    w9, [x27], #1
    add     x25, x9, #DISCV5_HEADER_START
    mov     x0, x27
    cmp     x24, #DISCV5_FLAG_WHOAREYOU
    b.eq    5f
    add     x1, x19, #DISCV5_HDR_SRC_ID
    mov     x2, #32
    bl      discv5_copy
    cmp     x24, #DISCV5_FLAG_HANDSHAKE
    b.ne    6f
    mov     w9, #64
    strb    w9, [x0], #1
    mov     w9, #33
    strb    w9, [x0], #1
    add     x1, x19, #DISCV5_HDR_SIGNATURE
    mov     x2, #64
    bl      discv5_copy
    add     x1, x19, #DISCV5_HDR_EPH_KEY
    mov     x2, #33
    bl      discv5_copy
    add     x1, x19, #DISCV5_HDR_RECORD + DISCV5_BL_FIXED
    ldr     x2, [x19, #DISCV5_HDR_RECORD + DISCV5_BL_COUNT]
    bl      discv5_copy
    b       6f
5:  add     x1, x19, #DISCV5_HDR_ID_NONCE
    mov     x2, #16
    bl      discv5_copy
    ldr     x1, [x19, #DISCV5_HDR_ENR_SEQ]
    mov     x2, #8
    bl      discv5_store_be
6:  str     x25, [x19, #DISCV5_HDR_HEADER + DISCV5_BL_COUNT]
    mov     x9, #DISCV5_HDR_HEADER_SIZE
    str     x9, [x19, #DISCV5_HDR_HEADER + DISCV5_BL_SIZE]
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [x19, #DISCV5_HDR_HEADER + DISCV5_BL_OFFSET]

    /* Sizes: the header, then the sealed message unless this is WHOAREYOU. */
    mov     x26, x25
    cmp     x24, #DISCV5_FLAG_WHOAREYOU
    b.eq    7f
    ldr     x9, [x22, #DISCV5_BL_COUNT]
    add     x9, x9, #CRYPTO_GCM_TAG_SIZE
    add     x26, x26, x9
7:  mov     x0, #DISCV5_INVALID_PACKET
    cmp     x26, #DISCV5_MAX_PACKET
    b.hi    99f
    mov     x0, #DISCV5_BUFFER_TOO_SMALL
    ldr     x9, [x23, #DISCV5_BL_SIZE]
    subs    x9, x9, #DISCV5_BL_FIXED
    b.lo    99f
    cmp     x9, x26
    b.lo    99f

    /* Mask: AES-CTR with the first 16 bytes of the destination ID, the IV as counter. */
    sub     x9, x25, #DISCV5_MASKED_START
    BYTELIST sp, PE_IN, 520, x9
    BYTELIST sp, PE_OUT, 520, xzr
    add     x0, sp, #PE_IN + DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_HDR_HEADER + DISCV5_BL_FIXED + DISCV5_MASKED_START
    sub     x2, x25, #DISCV5_MASKED_START
    bl      discv5_copy
    mov     x0, x20
    add     x1, x19, #DISCV5_HDR_IV
    add     x2, sp, #PE_IN
    add     x3, sp, #PE_OUT
    CALL_GLOBAL crypto_aes128_ctr
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [x23, #DISCV5_BL_OFFSET]
    str     x26, [x23, #DISCV5_BL_COUNT]
    add     x0, x23, #DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_HDR_IV
    mov     x2, #16
    bl      discv5_copy
    add     x1, sp, #PE_OUT + DISCV5_BL_FIXED
    sub     x2, x25, #DISCV5_MASKED_START
    bl      discv5_copy
    mov     x27, x0
    cmp     x24, #DISCV5_FLAG_WHOAREYOU
    b.eq    8f

    /* The message: AES-GCM with the nonce, the unmasked header as associated data. */
    add     x9, sp, #PE_SEALED
    BYTELIST x9, 0, 1304, xzr
    mov     x0, x21
    add     x1, x19, #DISCV5_HDR_NONCE
    mov     x2, x22
    add     x3, x19, #DISCV5_HDR_HEADER
    add     x4, sp, #PE_SEALED
    CALL_GLOBAL crypto_aes128_gcm_ae
    mov     x0, x27
    add     x1, sp, #PE_SEALED + DISCV5_BL_FIXED
    add     x9, sp, #PE_SEALED
    ldr     x2, [x9, #DISCV5_BL_COUNT]
    bl      discv5_copy
8:  mov     x0, #DISCV5_OK
99: LEAVE   0, 2352
END_FUNCTION discv5_packet_encode

/* Protocol strings. */
    .p2align 3
410:
    .ascii  "discv5"
    .p2align 3
411:
    .ascii  "discovery v5 key agreement"
    .p2align 3
412:
    .ascii  "discovery v5 identity proof"
    .p2align 3

/* ---------------------------------------------------------------- Handshake (discv5-theory.md) */

/* discv5_derive_keys stack: ByteLists and scratch for the HKDF calls. */
.set DK_IKM, 0                      /* 24 + 40: the ECDH secret, 33 bytes */
.set DK_SALT, 64                    /* 24 + 64: the challenge, 63 bytes */
.set DK_SCRATCH1, 152               /* 136: HKDF-Extract scratch */
.set DK_PRK, 288                    /* 24 + 32 */
.set DK_INFO, 344                   /* 24 + 96: 26 + 64 bytes */
.set DK_LENGTH, 464                 /* u64: 32 */
.set DK_SCRATCH2, 472               /* 224: HKDF-Expand scratch */
.set DK_OKM, 696                    /* 24 + 32 */
.set DK_FRAME, 752

/*
 * discv5_derive_keys(private_key, public_key, challenge, ids, keys) -> status
 * secret = ecdh(public_key, private_key); prk = HKDF-Extract(challenge,
 * secret); keys = HKDF-Expand(prk, "discovery v5 key agreement" || ids, 32):
 * the initiator key, then the recipient key. ids: node ID A, then node ID B.
 */
FUNCTION discv5_derive_keys
    ENTER   0, DK_FRAME
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x9, #33
    BYTELIST sp, DK_IKM, 64, x9
    mov     x0, x20
    mov     x1, x19
    add     x2, sp, #DK_IKM + DISCV5_BL_FIXED
    CALL_GLOBAL crypto_secp256k1_ecdh
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_KEY
    cbnz    x9, 99f
    mov     x9, #DISCV5_CHALLENGE_SIZE
    BYTELIST sp, DK_SALT, 88, x9
    add     x0, sp, #DK_SALT + DISCV5_BL_FIXED
    mov     x1, x21
    mov     x2, #DISCV5_CHALLENGE_SIZE
    bl      discv5_copy
    mov     x9, #136
    str     x9, [sp, #DK_SCRATCH1]
    mov     x9, #32
    BYTELIST sp, DK_PRK, 56, x9
    add     x0, sp, #DK_SALT
    add     x1, sp, #DK_IKM
    add     x2, sp, #DK_SCRATCH1
    add     x3, sp, #DK_PRK + DISCV5_BL_FIXED
    CALL_GLOBAL crypto_hkdf_extract
    mov     x9, #90
    BYTELIST sp, DK_INFO, 120, x9
    add     x0, sp, #DK_INFO + DISCV5_BL_FIXED
    adr     x1, 411b
    mov     x2, #26
    bl      discv5_copy
    mov     x1, x22
    mov     x2, #64
    bl      discv5_copy
    mov     x9, #32
    str     x9, [sp, #DK_LENGTH]
    mov     x9, #224
    str     x9, [sp, #DK_SCRATCH2]
    add     x9, sp, #DK_OKM
    BYTELIST x9, 0, 56, xzr
    add     x0, sp, #DK_PRK
    add     x1, sp, #DK_INFO
    add     x2, sp, #DK_LENGTH
    add     x3, sp, #DK_SCRATCH2
    add     x4, sp, #DK_OKM
    CALL_GLOBAL crypto_hkdf_expand
    add     x9, sp, #DK_OKM + DISCV5_BL_FIXED
    ldp     x10, x11, [x9]
    stp     x10, x11, [x23]
    ldp     x10, x11, [x9, #16]
    stp     x10, x11, [x23, #16]
    mov     x0, #DISCV5_OK
99: LEAVE   0, DK_FRAME
END_FUNCTION discv5_derive_keys

/*
 * The ID signature hash at sp + 160: SHA-256("discovery v5 identity proof"
 * || challenge || ephemeral key || destination ID). Input: x21 challenge,
 * x22 ephemeral key, x23 destination ID. The 155 input bytes at sp.
 */
.macro ID_HASH
    mov     x0, sp
    adr     x1, 412b
    mov     x2, #27
    bl      discv5_copy
    mov     x1, x21
    mov     x2, #DISCV5_CHALLENGE_SIZE
    bl      discv5_copy
    mov     x1, x22
    mov     x2, #33
    bl      discv5_copy
    mov     x1, x23
    mov     x2, #32
    bl      discv5_copy
    mov     x0, sp
    mov     x1, #155
    add     x2, sp, #160
    mov     x3, #0
    bl      discv5_hash
.endm

/* discv5_id_sign(private_key, challenge, ephemeral_key, dest_id, signature) -> status */
FUNCTION discv5_id_sign
    ENTER   0, 192
    mov     x19, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x24, x4
    ID_HASH
    mov     x0, x19
    add     x1, sp, #160
    mov     x2, x24
    CALL_GLOBAL crypto_secp256k1_sign
    cbz     x0, 9f
    mov     x0, #DISCV5_INVALID_KEY
9:  LEAVE   0, 192
END_FUNCTION discv5_id_sign

/*
 * discv5_id_verify(public_key, challenge, header, dest_id, valid) -> status:
 * checks the signature and ephemeral key held in header.
 */
FUNCTION discv5_id_verify
    ENTER   0, 192
    mov     x19, x0
    mov     x21, x1
    mov     x20, x2
    add     x22, x2, #DISCV5_HDR_EPH_KEY
    mov     x23, x3
    mov     x24, x4
    ID_HASH
    mov     x0, x19
    add     x1, sp, #160
    add     x2, x20, #DISCV5_HDR_SIGNATURE
    mov     x3, x24
    CALL_GLOBAL crypto_secp256k1_verify
    cbz     x0, 9f
    mov     x0, #DISCV5_INVALID_KEY
9:  LEAVE   0, 192
END_FUNCTION discv5_id_verify

/* ---------------------------------------------------------------- The local record */

/*
 * discv5_entry_set(state, key, key_len, value, value_len) -> 0, or 1 when the
 * 16 entries are full: sets one entry of the local record, keeping the keys
 * sorted. key_len 1 to 16, value_len 0 to 64.
 * x19 state, x20 key, x21 key length, x22 value, x23 value length,
 * x24 entry index, x25 entry count.
 */
LOCAL_FUNCTION discv5_entry_set
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    ldr     x25, [x19, #DISCV5_ST_ENTRY_COUNT]
    mov     x24, #0
1:  cmp     x24, x25
    b.hs    4f                              /* after every key: append */
    mov     x9, #DISCV5_LE_SIZE
    mul     x9, x24, x9
    add     x10, x19, #DISCV5_ST_ENTRIES
    add     x10, x10, x9                    /* the entry */
    ldrb    w11, [x10, #DISCV5_LE_KEY_LEN]
    add     x12, x10, #DISCV5_LE_KEY
    mov     x13, #0
2:  cmp     x13, x11                        /* compare the entry key with the key */
    b.hs    21f
    cmp     x13, x21
    b.hs    5f                              /* the key is a prefix of the entry key: insert before */
    ldrb    w14, [x12, x13]
    ldrb    w15, [x20, x13]
    cmp     w14, w15
    b.lo    3f                              /* the entry key is smaller: go on */
    b.hi    5f                              /* larger: insert before */
    add     x13, x13, #1
    b       2b
21: cmp     x11, x21
    b.eq    6f                              /* the same key: replace the value */
3:  add     x24, x24, #1
    b       1b
4:  cmp     x25, #DISCV5_MAX_ENTRIES
    b.hs    8f
    b       7f
5:  cmp     x25, #DISCV5_MAX_ENTRIES        /* insert at x24: move entries x24.. up by one */
    b.hs    8f
    mov     x26, x25
51: cmp     x26, x24
    b.ls    7f
    mov     x9, #DISCV5_LE_SIZE
    mul     x9, x26, x9
    add     x0, x19, #DISCV5_ST_ENTRIES
    add     x0, x0, x9
    sub     x1, x0, #DISCV5_LE_SIZE
    mov     x2, #DISCV5_LE_SIZE
    bl      discv5_copy
    sub     x26, x26, #1
    b       51b
7:  add     x25, x25, #1
    str     x25, [x19, #DISCV5_ST_ENTRY_COUNT]
6:  mov     x9, #DISCV5_LE_SIZE
    mul     x9, x24, x9
    add     x26, x19, #DISCV5_ST_ENTRIES
    add     x26, x26, x9
    strb    w21, [x26, #DISCV5_LE_KEY_LEN]
    strb    w23, [x26, #DISCV5_LE_VALUE_LEN]
    add     x0, x26, #DISCV5_LE_KEY
    mov     x1, x20
    mov     x2, x21
    bl      discv5_copy
    add     x0, x26, #DISCV5_LE_VALUE
    mov     x1, x22
    mov     x2, x23
    bl      discv5_copy
    mov     x0, #0
    b       9f
8:  mov     x0, #1
9:  LEAVE   0
END_FUNCTION discv5_entry_set

/* discv5_record_build stack: the payload, the content, the signature, the hash, the record. */
.set RB_PAYLOAD, 0                  /* up to 1400 bytes */
.set RB_CONTENT, 1408               /* up to 304 bytes */
.set RB_SIG, 1712                   /* 64 bytes */
.set RB_HASH, 1776                  /* 32 bytes */
.set RB_RECORD, 1808                /* up to 304 bytes */
.set RB_FRAME, 2112

/*
 * discv5_record_build(state) -> 0, or 1 when the record would pass 300 bytes:
 * signs [seq, k, v, ...] of the entries and writes the record to the state.
 * x19 state, x20 payload length, x21 entry index, x22 content length.
 */
LOCAL_FUNCTION discv5_record_build
    ENTER   0, RB_FRAME
    mov     x19, x0
    add     x0, sp, #RB_PAYLOAD
    ldr     x1, [x19, #DISCV5_ST_SEQ]
    bl      discv5_rlp_uint
    mov     x21, #0
1:  ldr     x9, [x19, #DISCV5_ST_ENTRY_COUNT]
    cmp     x21, x9
    b.hs    2f
    mov     x9, #DISCV5_LE_SIZE
    mul     x9, x21, x9
    add     x10, x19, #DISCV5_ST_ENTRIES
    add     x22, x10, x9
    add     x1, x22, #DISCV5_LE_KEY
    ldrb    w2, [x22, #DISCV5_LE_KEY_LEN]
    bl      discv5_rlp_bytes
    add     x1, x22, #DISCV5_LE_VALUE
    ldrb    w2, [x22, #DISCV5_LE_VALUE_LEN]
    bl      discv5_rlp_bytes
    add     x21, x21, #1
    b       1b
2:  mov     x9, sp
    sub     x20, x0, x9                     /* payload length */
    mov     x0, #1
    cmp     x20, #(DISCV5_MAX_RECORD - 67)  /* the signature takes 66 bytes, the header 1 or more */
    b.hi    9f
    add     x0, sp, #RB_CONTENT
    mov     x1, x20
    mov     x2, #0xC0
    bl      discv5_rlp_header
    add     x1, sp, #RB_PAYLOAD
    mov     x2, x20
    bl      discv5_copy
    add     x22, sp, #RB_CONTENT
    sub     x22, x0, x22
    add     x0, sp, #RB_CONTENT
    mov     x1, x22
    add     x2, sp, #RB_HASH
    mov     x3, #1
    bl      discv5_hash
    add     x0, x19, #DISCV5_ST_PRIVATE_KEY
    add     x1, sp, #RB_HASH
    add     x2, sp, #RB_SIG
    CALL_GLOBAL crypto_secp256k1_sign
    add     x0, sp, #RB_RECORD
    add     x1, x20, #66
    mov     x2, #0xC0
    bl      discv5_rlp_header
    add     x1, sp, #RB_SIG
    mov     x2, #64
    bl      discv5_rlp_bytes
    add     x1, sp, #RB_PAYLOAD
    mov     x2, x20
    bl      discv5_copy
    add     x2, sp, #RB_RECORD
    sub     x2, x0, x2
    mov     x9, x0
    mov     x0, #1
    cmp     x2, #DISCV5_MAX_RECORD
    b.hi    9f
    str     x2, [x19, #DISCV5_ST_RECORD_LEN]
    add     x0, x19, #DISCV5_ST_RECORD
    add     x1, sp, #RB_RECORD
    bl      discv5_copy
    mov     x0, #0
9:  LEAVE   0, RB_FRAME
END_FUNCTION discv5_record_build

/*
 * discv5_set_endpoint(state, endpoint): the "ip" and "udp" entries, or "ip6"
 * and "udp6", from the endpoint. A port of 0 sets no port entry. Returns 0,
 * or 1 when the entries are full. x19 state, x20 endpoint, x24 result.
 * The port bytes at sp + 96.
 */
LOCAL_FUNCTION discv5_set_endpoint
    ENTER   16
    mov     x19, x0
    mov     x20, x1
    mov     x24, #0
    ldr     x9, [x20, #DISCV5_EP_FAMILY]
    cmp     x9, #4
    b.ne    1f
    mov     x0, x19
    adr     x1, 400b + 4                    /* "ip" */
    mov     x2, #2
    add     x3, x20, #DISCV5_EP_ADDRESS
    mov     x4, #4
    bl      discv5_entry_set
    orr     x24, x24, x0
    adr     x21, 400b + 8                   /* "udp" */
    mov     x22, #3
    b       2f
1:  cmp     x9, #6
    b.ne    9f
    mov     x0, x19
    adr     x1, 400b + 12                   /* "ip6" */
    mov     x2, #3
    add     x3, x20, #DISCV5_EP_ADDRESS
    mov     x4, #16
    bl      discv5_entry_set
    orr     x24, x24, x0
    adr     x21, 400b + 16                  /* "udp6" */
    mov     x22, #4
2:  ldr     x9, [x20, #DISCV5_EP_PORT]
    cbz     x9, 9f
    mov     x10, #2                         /* the port without leading zero bytes */
    mov     x11, #1
    cmp     x9, #0x100
    csel    x23, x11, x10, lo
    add     x0, sp, #96
    mov     x1, x9
    mov     x2, x23
    bl      discv5_store_be
    mov     x0, x19
    mov     x1, x21
    mov     x2, x22
    add     x3, sp, #96
    mov     x4, x23
    bl      discv5_entry_set
    orr     x24, x24, x0
9:  mov     x0, x24
    LEAVE   16
END_FUNCTION discv5_set_endpoint

/*
 * discv5_init(config, state) -> status
 * x19 config, x20 state. The public key and point at sp.
 */
FUNCTION discv5_init
    ENTER   0, 112
    mov     x19, x0
    mov     x20, x1
    mov     x0, x19
    mov     x1, sp
    CALL_GLOBAL crypto_secp256k1_public_key
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_KEY
    cbnz    x9, 9f
    mov     x0, x20
    MOV64   x1, DISCV5_STATE_SIZE
    bl      discv5_zero
    add     x0, x20, #DISCV5_ST_PRIVATE_KEY
    mov     x1, x19
    mov     x2, #32
    bl      discv5_copy
    add     x0, x20, #DISCV5_ST_PUBLIC_KEY
    mov     x1, sp
    mov     x2, #33
    bl      discv5_copy
    mov     x0, sp
    add     x1, sp, #48
    CALL_GLOBAL crypto_secp256k1_decompress
    add     x0, sp, #48
    mov     x1, #64
    add     x2, x20, #DISCV5_ST_NODE_ID
    mov     x3, #1
    bl      discv5_hash
    ldr     x9, [x19, #DISCV5_CFG_SEQ]
    str     x9, [x20, #DISCV5_ST_SEQ]
    mov     x0, x20
    add     x1, x19, #DISCV5_CFG_ENTROPY
    bl      discv5_reseed
    ldr     x9, [x19, #DISCV5_CFG_NOW]
    str     x9, [x20, #DISCV5_ST_NOW]
    add     x9, x9, #DISCV5_PING_INTERVAL
    str     x9, [x20, #DISCV5_ST_NEXT_PING]
    mov     x0, x20
    adr     x1, 400b                        /* "id" = "v4" */
    mov     x2, #2
    adr     x3, 400b + 2
    mov     x4, #2
    bl      discv5_entry_set
    mov     x0, x20
    adr     x1, 400b + 24                   /* "secp256k1" */
    mov     x2, #9
    add     x3, x20, #DISCV5_ST_PUBLIC_KEY
    mov     x4, #33
    bl      discv5_entry_set
    mov     x0, x20
    add     x1, x19, #DISCV5_CFG_PORT
    bl      discv5_set_endpoint
    mov     x0, x20
    bl      discv5_record_build
    mov     x0, #DISCV5_OK
9:  LEAVE   0, 112
END_FUNCTION discv5_init

/* ---------------------------------------------------------------- The state machine: layout */

/*
 * discv5_step scratch, from its start. Every step helper takes the scratch
 * start as its first argument and keeps it in x28; the context block holds
 * the state, the actions, the time and the sender of the current datagram.
 */
.set SC_CTX, 8
.set CTX_STATE, 0
.set CTX_ACTIONS, 8
.set CTX_NOW, 16
.set CTX_FROM, 24                   /* endpoint, 32 bytes: the sender of the datagram */
.set CTX_REQID, 56                  /* 8 bytes: the request ID of the message */
.set CTX_REQID_LEN, 64              /* u64 */
.set SC_HDR, 136                    /* Header of the packet received */
.set SC_HDR2, 1200                  /* Header of the packet sent */
.set SC_ENR, 2264                   /* Enr */
.set SC_MSG, 5472                   /* ByteList 24 + 1280: a message */
.set SC_PKT, 6776                   /* ByteList 24 + 1280: the packet sent */
.set SC_IN, 8080                    /* ByteList 24 + 1280: the packet received */
.set SC_RLP, 9384                   /* ByteList 24 + 1280: the message RLP, after the type byte */
.set SC_REC, 10688                  /* ByteList 24 + 304: a record */
.set SC_TMP, 11016                  /* 2048 bytes */
.set SC_KEYS, 13064                 /* 32 bytes, session keys */
.set SC_EPH, 13096                  /* 32 + 40 bytes: an ephemeral key pair */
.set SC_VIEW, 13168                 /* 104 bytes: ID, public key, endpoint of a found node */
.set SC_DIST, 13280                 /* 16 u64: distances asked by a FINDNODE */
.set SC_RESULT, 13408               /* 16 u64: records for a NODES answer; 0 is the local record */
.set SC_ENR_SCRATCH, 13536          /* 10240 bytes: discv5_enr_decode scratch */
.set SC_ITEMS, 23776                /* Items: 24 + 32 * 1280 bytes */
.set SC_ITEMS_SIZE, 24 + 32 * 1280
.set BL_PACKET_SIZE, 24 + 1280

/* reg = x28 + off, for any offset in the scratch. */
.macro SCR reg, off
    mov     \reg, #(\off)
    add     \reg, x28, \reg
.endm

/* reg = the state. */
.macro STATE reg
    ldr     \reg, [x28, #SC_CTX + CTX_STATE]
.endm

/* reg = the time. */
.macro NOW reg
    ldr     \reg, [x28, #SC_CTX + CTX_NOW]
.endm

/* ---------------------------------------------------------------- Actions */

/*
 * discv5_action(scratch, kind, size) -> the new action, zeroed, with size
 * and kind set; 0 when the actions have no room. size is a multiple of 8.
 */
LOCAL_FUNCTION discv5_action
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    ldr     x21, [x28, #SC_CTX + CTX_ACTIONS]
    ldr     x9, [x21, #DISCV5_BL_COUNT]
    ldr     x10, [x21, #DISCV5_BL_SIZE]
    sub     x10, x10, #DISCV5_BL_FIXED
    sub     x10, x10, x9
    mov     x0, #0
    cmp     x10, x20
    b.lo    9f
    add     x22, x21, #DISCV5_BL_FIXED
    add     x22, x22, x9
    add     x9, x9, x20
    str     x9, [x21, #DISCV5_BL_COUNT]
    mov     x0, x22
    mov     x1, x20
    bl      discv5_zero
    str     x20, [x22, #DISCV5_ACT_SIZE]
    str     x19, [x22, #DISCV5_ACT_KIND]
    mov     x0, x22
9:  LEAVE   0
END_FUNCTION discv5_action

/* discv5_send_packet(scratch, endpoint): a SEND action with the packet in the scratch. */
LOCAL_FUNCTION discv5_send_packet
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    SCR     x20, SC_PKT
    ldr     x21, [x20, #DISCV5_BL_COUNT]
    add     x2, x21, #(DISCV5_ACT_SEND_DATA + 7)
    and     x2, x2, #~7
    mov     x1, #DISCV5_ACTION_SEND
    bl      discv5_action
    cbz     x0, 9f
    mov     x22, x0
    add     x0, x22, #DISCV5_ACT_SEND_TO
    mov     x1, x19
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_copy
    str     x21, [x22, #DISCV5_ACT_SEND_LEN]
    add     x0, x22, #DISCV5_ACT_SEND_DATA
    add     x1, x20, #DISCV5_BL_FIXED
    mov     x2, x21
    bl      discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_send_packet

/*
 * discv5_enr_endpoint(enr, endpoint) -> 1 when the record has a UDP endpoint:
 * "ip" and "udp", else "ip6" and "udp6", with a port above 0.
 */
LOCAL_FUNCTION discv5_enr_endpoint
    UNWIND_END_PROLOGUE
    stp     xzr, xzr, [x1]
    stp     xzr, xzr, [x1, #16]
    ldr     x9, [x0, #DISCV5_ENR_HAS]
    and     x10, x9, #(DISCV5_HAS_IP4 | DISCV5_HAS_UDP4)
    cmp     x10, #(DISCV5_HAS_IP4 | DISCV5_HAS_UDP4)
    b.ne    1f
    ldr     x10, [x0, #DISCV5_ENR_UDP4]
    cbz     x10, 1f
    str     x10, [x1, #DISCV5_EP_PORT]
    mov     x10, #4
    str     x10, [x1, #DISCV5_EP_FAMILY]
    ldr     w10, [x0, #DISCV5_ENR_IP4]
    str     w10, [x1, #DISCV5_EP_ADDRESS]
    mov     x0, #1
    ret
1:  and     x10, x9, #(DISCV5_HAS_IP6 | DISCV5_HAS_UDP6)
    cmp     x10, #(DISCV5_HAS_IP6 | DISCV5_HAS_UDP6)
    b.ne    2f
    ldr     x10, [x0, #DISCV5_ENR_UDP6]
    cbz     x10, 2f
    str     x10, [x1, #DISCV5_EP_PORT]
    mov     x10, #6
    str     x10, [x1, #DISCV5_EP_FAMILY]
    ldp     x10, x11, [x0, #DISCV5_ENR_IP6]
    stp     x10, x11, [x1, #DISCV5_EP_ADDRESS]
    mov     x0, #1
    ret
2:  mov     x0, #0
    ret
END_FUNCTION discv5_enr_endpoint

/* ---------------------------------------------------------------- Sessions and challenges */

/*
 * discv5_session_find(scratch, id, endpoint) -> the session for the node ID
 * and endpoint, or 0. x19 id, x20 endpoint, x21 slot, x22 slots left.
 */
LOCAL_FUNCTION discv5_session_find
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    STATE   x21
    MOV64   x9, DISCV5_ST_SESSIONS
    add     x21, x21, x9
    mov     x22, #DISCV5_SESSION_SLOTS
1:  ldr     x9, [x21, #DISCV5_S_USED]
    cbz     x9, 2f
    mov     x0, x21
    mov     x1, x19
    mov     x2, #32
    bl      discv5_equal
    cbz     x0, 2f
    add     x0, x21, #DISCV5_S_EP
    mov     x1, x20
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_equal
    cbz     x0, 2f
    mov     x0, x21
    b       9f
2:  add     x21, x21, #DISCV5_S_SIZE
    subs    x22, x22, #1
    b.ne    1b
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_session_find

/*
 * discv5_session_put(scratch, id, endpoint, write_key, read_key) -> the
 * session: the slot of the same node and endpoint, else a free slot, else
 * the one used longest ago. x19 id, x20 endpoint, x21 write key, x22 read
 * key, x23 slot, x24 slots left, x25 the oldest.
 */
LOCAL_FUNCTION discv5_session_put
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    mov     x22, x4
    mov     x0, x28
    mov     x1, x19
    mov     x2, x20
    bl      discv5_session_find
    mov     x23, x0
    cbnz    x23, 5f
    STATE   x9
    MOV64   x10, DISCV5_ST_SESSIONS
    add     x23, x9, x10
    mov     x25, x23
    mov     x24, #DISCV5_SESSION_SLOTS
1:  ldr     x9, [x23, #DISCV5_S_USED]
    cbz     x9, 5f
    ldr     x10, [x25, #DISCV5_S_USED]
    cmp     x9, x10
    csel    x25, x23, x25, lo
    add     x23, x23, #DISCV5_S_SIZE
    subs    x24, x24, #1
    b.ne    1b
    mov     x23, x25
5:  mov     x0, x23
    mov     x1, x19
    mov     x2, #32
    bl      discv5_copy
    add     x0, x23, #DISCV5_S_EP
    mov     x1, x20
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_copy
    ldp     x9, x10, [x21]
    stp     x9, x10, [x23, #DISCV5_S_WRITE_KEY]
    ldp     x9, x10, [x22]
    stp     x9, x10, [x23, #DISCV5_S_READ_KEY]
    str     xzr, [x23, #DISCV5_S_COUNTER]
    NOW     x9
    add     x9, x9, #1
    str     x9, [x23, #DISCV5_S_USED]
    mov     x0, x23
    LEAVE   0
END_FUNCTION discv5_session_put

/*
 * discv5_challenge_find(scratch, id, endpoint, any) -> the WHOAREYOU sent to
 * the node ID and endpoint and still valid, or 0. With any 1 and no match: a
 * free slot, else the oldest slot. Expired slots become free. C_SENT holds
 * the time plus 1. x19 id, x20 endpoint, x21 any, x22 slot, x23 slots left,
 * x24 spare, x25 the time plus 1.
 */
LOCAL_FUNCTION discv5_challenge_find
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    NOW     x25
    add     x25, x25, #1
    STATE   x9
    MOV64   x10, DISCV5_ST_CHALLENGES
    add     x22, x9, x10
    mov     x24, #0
    mov     x23, #DISCV5_CHALLENGE_SLOTS
1:  ldr     x9, [x22, #DISCV5_C_SENT]
    cbz     x9, 3f
    add     x10, x9, #DISCV5_CHALLENGE_TIMEOUT
    cmp     x10, x25
    b.hi    2f
    str     xzr, [x22, #DISCV5_C_SENT]      /* expired */
    b       3f
2:  mov     x0, x22
    mov     x1, x19
    mov     x2, #32
    bl      discv5_equal
    cbz     x0, 4f
    add     x0, x22, #DISCV5_C_EP
    mov     x1, x20
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_equal
    cbz     x0, 4f
    mov     x0, x22
    b       9f
4:  cbz     x24, 41f                        /* a valid slot: the spare when it is the oldest */
    ldr     x10, [x24, #DISCV5_C_SENT]
    cbz     x10, 5f
    ldr     x9, [x22, #DISCV5_C_SENT]
    cmp     x9, x10
    b.hs    5f
41: mov     x24, x22
    b       5f
3:  cbz     x24, 31f                        /* a free slot: the spare unless one is free already */
    ldr     x10, [x24, #DISCV5_C_SENT]
    cbz     x10, 5f
31: mov     x24, x22
5:  add     x22, x22, #DISCV5_C_SIZE
    subs    x23, x23, #1
    b.ne    1b
    mov     x0, #0
    cbz     x21, 9f
    mov     x0, x24
9:  LEAVE   0
END_FUNCTION discv5_challenge_find

/* ---------------------------------------------------------------- Requests */

/*
 * discv5_request_find(scratch, nonce) -> the waiting request whose last
 * packet had this nonce, or 0. x19 nonce, x20 slot, x21 slots left.
 */
LOCAL_FUNCTION discv5_request_find
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    STATE   x9
    MOV64   x10, DISCV5_ST_REQUESTS
    add     x20, x9, x10
    mov     x21, #DISCV5_REQUEST_SLOTS
1:  ldrb    w9, [x20, #DISCV5_R_STATE]
    cbz     w9, 2f
    add     x0, x20, #DISCV5_R_NONCE
    mov     x1, x19
    mov     x2, #12
    bl      discv5_equal
    cbz     x0, 2f
    mov     x0, x20
    b       9f
2:  add     x20, x20, #DISCV5_R_SIZE
    subs    x21, x21, #1
    b.ne    1b
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_request_find

/*
 * discv5_request_match(scratch, id, request_id, type) -> the waiting request
 * of this type to the node ID, from the sender's endpoint, with this request
 * ID, or 0. request_id: the 8 bytes sent. x19 id, x20 request ID, x21 type,
 * x22 slot, x23 slots left.
 */
LOCAL_FUNCTION discv5_request_match
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    STATE   x9
    MOV64   x10, DISCV5_ST_REQUESTS
    add     x22, x9, x10
    mov     x23, #DISCV5_REQUEST_SLOTS
1:  ldrb    w9, [x22, #DISCV5_R_STATE]
    cbz     w9, 2f
    ldrb    w9, [x22, #DISCV5_R_TYPE]
    cmp     x9, x21
    b.ne    2f
    ldr     x9, [x22, #DISCV5_R_REQ_ID]
    cmp     x9, x20
    b.ne    2f
    mov     x0, x22
    mov     x1, x19
    mov     x2, #32
    bl      discv5_equal
    cbz     x0, 2f
    add     x0, x22, #DISCV5_R_EP
    SCR     x1, SC_CTX + CTX_FROM
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_equal
    cbz     x0, 2f
    mov     x0, x22
    b       9f
2:  add     x22, x22, #DISCV5_R_SIZE
    subs    x23, x23, #1
    b.ne    1b
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_request_match

/* ---------------------------------------------------------------- The node table */

/* discv5_bucket(state, id) -> the bucket: 0 for log distances up to 240, else the distance minus 240. */
LOCAL_FUNCTION discv5_bucket
    ENTER   0
    add     x0, x0, #DISCV5_ST_NODE_ID
    bl      discv5_log_distance
    subs    x0, x0, #240
    csel    x0, x0, xzr, hi
    LEAVE   0
END_FUNCTION discv5_bucket

/* discv5_node_find(scratch, id) -> the table slot of the node ID, member or replacement, or 0. */
LOCAL_FUNCTION discv5_node_find
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    STATE   x9
    add     x20, x9, #DISCV5_ST_NODES
    mov     x21, #DISCV5_NODE_SLOTS
1:  ldrb    w9, [x20, #DISCV5_N_STATE]
    cbz     w9, 2f
    mov     x0, x20
    mov     x1, x19
    mov     x2, #32
    bl      discv5_equal
    cbz     x0, 2f
    mov     x0, x20
    b       9f
2:  add     x20, x20, #DISCV5_N_SIZE
    subs    x21, x21, #1
    b.ne    1b
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_node_find

/*
 * discv5_node_count(scratch, bucket, kind) -> the slots of this kind (1
 * member, 2 replacement) in the bucket, and in x1 the free slot found first
 * (0 when none), in x2 the oldest slot of the kind in the bucket. A leaf:
 * x10 slot, x11 slots left, x12 free, x13 oldest.
 */
LOCAL_FUNCTION discv5_node_count
    UNWIND_END_PROLOGUE
    ldr     x9, [x0, #SC_CTX + CTX_STATE]
    add     x10, x9, #DISCV5_ST_NODES
    mov     x11, #DISCV5_NODE_SLOTS
    mov     x0, #0                          /* count */
    mov     x12, #0
    mov     x13, #0
1:  ldrb    w9, [x10, #DISCV5_N_STATE]
    cbnz    w9, 2f
    cbnz    x12, 3f
    mov     x12, x10
    b       3f
2:  cmp     x9, x2
    b.ne    3f
    ldrb    w9, [x10, #DISCV5_N_BUCKET]
    cmp     x9, x1
    b.ne    3f
    add     x0, x0, #1
    cbz     x13, 21f
    ldr     x9, [x10, #DISCV5_N_ADDED]
    ldr     x14, [x13, #DISCV5_N_ADDED]
    cmp     x9, x14
    b.hs    3f
21: mov     x13, x10
3:  add     x10, x10, #DISCV5_N_SIZE
    subs    x11, x11, #1
    b.ne    1b
    mov     x1, x12
    mov     x2, x13
    ret
END_FUNCTION discv5_node_count

/*
 * discv5_node_add(scratch, enr, record) -> the slot, or 0: adds a checked
 * record with a UDP endpoint to the table, or updates its slot when the
 * record is newer. A full bucket takes it as a replacement; a full
 * replacement list drops its oldest. x19 enr, x20 record, x21 slot,
 * x22 bucket, x23 the endpoint (in the slot).
 */
LOCAL_FUNCTION discv5_node_add
    ENTER   32
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x0, x19
    add     x1, sp, #96
    bl      discv5_enr_endpoint
    cbz     x0, 9f
    STATE   x9
    add     x0, x9, #DISCV5_ST_NODE_ID
    mov     x1, x19
    mov     x2, #32
    bl      discv5_equal
    mov     x9, x0
    mov     x0, #0
    cbnz    x9, 9f                          /* ourselves */
    mov     x0, x28
    mov     x1, x19
    bl      discv5_node_find
    mov     x21, x0
    cbz     x21, 1f
    ldr     x9, [x21, #DISCV5_N_SEQ]        /* known: keep the newer record */
    ldr     x10, [x19, #DISCV5_ENR_SEQ]
    cmp     x10, x9
    b.ls    9f
    b       6f
1:  STATE   x0
    mov     x1, x19
    bl      discv5_bucket
    mov     x22, x0
    mov     x0, x28
    mov     x1, x22
    mov     x2, #1
    bl      discv5_node_count
    mov     x21, x1
    cmp     x0, #DISCV5_K
    b.hs    2f
    mov     w23, #1                         /* a member */
    b       5f
2:  mov     x0, x28
    mov     x1, x22
    mov     x2, #2
    bl      discv5_node_count
    mov     x21, x1
    cmp     x0, #DISCV5_REPLACEMENTS
    b.lo    3f
    mov     x21, x2                         /* replace the oldest replacement */
3:  mov     w23, #2
5:  mov     x0, #0
    cbz     x21, 9f
    mov     x0, x21
    mov     x1, #DISCV5_N_SIZE
    bl      discv5_zero
    strb    w23, [x21, #DISCV5_N_STATE]
    strb    w22, [x21, #DISCV5_N_BUCKET]
    NOW     x9
    str     x9, [x21, #DISCV5_N_ADDED]
    str     x9, [x21, #DISCV5_N_CHECK]
    STATE   x10
    ldr     x11, [x10, #DISCV5_ST_NEXT_REFRESH]
    cbnz    x11, 6f
    add     x9, x9, #DISCV5_PING_INTERVAL   /* the first node: look up our own ID soon */
    str     x9, [x10, #DISCV5_ST_NEXT_REFRESH]
6:  mov     x0, x21
    mov     x1, x19
    mov     x2, #32
    bl      discv5_copy
    add     x0, x21, #DISCV5_N_PUBKEY
    add     x1, x19, #DISCV5_ENR_PUBKEY
    mov     x2, #33
    bl      discv5_copy
    add     x0, x21, #DISCV5_N_EP
    add     x1, sp, #96
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_copy
    ldr     x9, [x19, #DISCV5_ENR_SEQ]
    str     x9, [x21, #DISCV5_N_SEQ]
    ldr     x2, [x20, #DISCV5_BL_COUNT]
    str     x2, [x21, #DISCV5_N_RECORD_LEN]
    ldr     x9, [x20, #DISCV5_BL_OFFSET]
    add     x1, x20, x9
    add     x0, x21, #DISCV5_N_RECORD
    bl      discv5_copy
    mov     x0, x21
9:  LEAVE   32
END_FUNCTION discv5_node_add

/*
 * discv5_node_remove(scratch, slot): frees the slot. A member's place goes
 * to the newest replacement of its bucket. A leaf: x3 kind, x4 bucket,
 * x10 slot, x11 slots left, x12 the newest replacement.
 */
LOCAL_FUNCTION discv5_node_remove
    UNWIND_END_PROLOGUE
    ldrb    w3, [x1, #DISCV5_N_STATE]
    ldrb    w4, [x1, #DISCV5_N_BUCKET]
    strb    wzr, [x1, #DISCV5_N_STATE]
    cmp     w3, #DISCV5_NODE_MEMBER
    b.ne    9f
    ldr     x9, [x0, #SC_CTX + CTX_STATE]
    add     x10, x9, #DISCV5_ST_NODES
    mov     x11, #DISCV5_NODE_SLOTS
    mov     x12, #0
1:  ldrb    w9, [x10, #DISCV5_N_STATE]
    cmp     w9, #DISCV5_NODE_REPLACEMENT
    b.ne    2f
    ldrb    w9, [x10, #DISCV5_N_BUCKET]
    cmp     w9, w4
    b.ne    2f
    cbz     x12, 11f
    ldr     x9, [x10, #DISCV5_N_ADDED]
    ldr     x13, [x12, #DISCV5_N_ADDED]
    cmp     x9, x13
    b.lo    2f
11: mov     x12, x10
2:  add     x10, x10, #DISCV5_N_SIZE
    subs    x11, x11, #1
    b.ne    1b
    cbz     x12, 9f
    mov     w9, #DISCV5_NODE_MEMBER
    strb    w9, [x12, #DISCV5_N_STATE]
    strb    wzr, [x12, #DISCV5_N_LIVE]
    strb    wzr, [x12, #DISCV5_N_FAILS]
    ldr     x9, [x0, #SC_CTX + CTX_NOW]
    str     x9, [x12, #DISCV5_N_CHECK]
9:  ret
END_FUNCTION discv5_node_remove

/* ---------------------------------------------------------------- Messages out */

/* reg = the payload of RLP item item, a pointer to its Item record in the message. Uses x17. */
.macro ITEM_DATA reg, item
    ldr     \reg, [\item, #RLP_ITEM_OFFSET]
    mov     x17, #(SC_RLP + DISCV5_BL_FIXED)
    add     \reg, \reg, x17
    add     \reg, \reg, x28
.endm

/*
 * discv5_msg_finish(scratch, type, end): the message in the scratch becomes
 * the type byte, then an RLP list of the payload from SC_TMP up to end.
 * x19 type, x20 payload length, x21 message.
 */
LOCAL_FUNCTION discv5_msg_finish
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    SCR     x9, SC_TMP
    sub     x20, x2, x9
    SCR     x21, SC_MSG
    BYTELIST x21, 0, BL_PACKET_SIZE, xzr
    add     x0, x21, #DISCV5_BL_FIXED
    strb    w19, [x0], #1
    mov     x1, x20
    mov     x2, #0xC0
    bl      discv5_rlp_header
    SCR     x1, SC_TMP
    mov     x2, x20
    bl      discv5_copy
    add     x9, x21, #DISCV5_BL_FIXED
    sub     x9, x0, x9
    str     x9, [x21, #DISCV5_BL_COUNT]
    LEAVE   0
END_FUNCTION discv5_msg_finish

/*
 * discv5_send_message(scratch, id, endpoint) -> the nonce used, 12 bytes in
 * the scratch. Sends the message in the scratch to the node. With a session
 * for the node ID and endpoint it goes as an ordinary message; else the
 * packet carries 20 random message bytes, so that the node answers with
 * WHOAREYOU. x19 id, x20 endpoint, x21 session, x22 header, x23 state,
 * x24 the random message.
 */
LOCAL_FUNCTION discv5_send_message
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    STATE   x23
    SCR     x22, SC_HDR2
    mov     x9, #DISCV5_FLAG_MESSAGE
    str     x9, [x22, #DISCV5_HDR_FLAG]
    mov     x0, x23
    add     x1, x22, #DISCV5_HDR_IV
    mov     x2, #16
    bl      discv5_random
    add     x0, x22, #DISCV5_HDR_SRC_ID
    add     x1, x23, #DISCV5_ST_NODE_ID
    mov     x2, #32
    bl      discv5_copy
    mov     x0, x28
    mov     x1, x19
    mov     x2, x20
    bl      discv5_session_find
    mov     x21, x0
    cbz     x21, 1f

    /* The nonce: the message count, 4 bytes big endian, then 8 random bytes. */
    ldr     x9, [x21, #DISCV5_S_COUNTER]
    add     x9, x9, #1
    str     x9, [x21, #DISCV5_S_COUNTER]
    NOW     x10
    add     x10, x10, #1
    str     x10, [x21, #DISCV5_S_USED]
    add     x0, x22, #DISCV5_HDR_NONCE
    mov     x1, x9
    mov     x2, #4
    bl      discv5_store_be
    mov     x0, x23
    add     x1, x22, #DISCV5_HDR_NONCE + 4
    mov     x2, #8
    bl      discv5_random
    add     x2, x21, #DISCV5_S_WRITE_KEY
    SCR     x3, SC_MSG
    b       2f

    /* No session: a random nonce, and 4 random bytes sealed under a random key. */
1:  mov     x0, x23
    add     x1, x22, #DISCV5_HDR_NONCE
    mov     x2, #12
    bl      discv5_random
    mov     x0, x23
    SCR     x1, SC_KEYS
    mov     x2, #16
    bl      discv5_random
    SCR     x24, SC_EPH
    mov     x9, #(DISCV5_RANDOM_MESSAGE - CRYPTO_GCM_TAG_SIZE)
    BYTELIST x24, 0, 48, x9
    mov     x0, x23
    add     x1, x24, #DISCV5_BL_FIXED
    mov     x2, #(DISCV5_RANDOM_MESSAGE - CRYPTO_GCM_TAG_SIZE)
    bl      discv5_random
    SCR     x2, SC_KEYS
    mov     x3, x24
2:  SCR     x4, SC_PKT
    BYTELIST x4, 0, BL_PACKET_SIZE, xzr
    mov     x0, x22
    mov     x1, x19
    CALL_GLOBAL discv5_packet_encode
    cbnz    x0, 9f
    mov     x0, x28
    mov     x1, x20
    bl      discv5_send_packet
9:  add     x0, x22, #DISCV5_HDR_NONCE
    LEAVE   0
END_FUNCTION discv5_send_message

/*
 * discv5_challenge_new(scratch, challenge): a new WHOAREYOU for the sender
 * of the packet received, answering its nonce, in the challenge slot. The
 * enr-seq is the sequence number of the sender's record in the table, else
 * 0. x19 challenge, x20 write position, x21 state, x22 header received.
 */
LOCAL_FUNCTION discv5_challenge_new
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    STATE   x21
    add     x22, x28, #SC_HDR
    mov     x0, x19
    add     x1, x22, #DISCV5_HDR_SRC_ID
    mov     x2, #32
    bl      discv5_copy
    add     x0, x19, #DISCV5_C_EP
    add     x1, x28, #SC_CTX + CTX_FROM
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_copy
    NOW     x9
    add     x9, x9, #1
    str     x9, [x19, #DISCV5_C_SENT]
    mov     x0, x21
    add     x1, x19, #DISCV5_C_DATA
    mov     x2, #16
    bl      discv5_random
    add     x0, x19, #DISCV5_C_DATA + DISCV5_MASKED_START
    adr     x1, 410b
    mov     x2, #6
    bl      discv5_copy
    mov     w9, #0
    strb    w9, [x0], #1
    mov     w9, #1
    strb    w9, [x0], #1
    strb    w9, [x0], #1                    /* flag 1 */
    add     x1, x22, #DISCV5_HDR_NONCE
    mov     x2, #12
    bl      discv5_copy
    mov     w9, #0
    strb    w9, [x0], #1
    mov     w9, #24
    strb    w9, [x0], #1
    mov     x20, x0
    mov     x0, x21
    mov     x1, x20
    mov     x2, #16
    bl      discv5_random                   /* id-nonce */
    mov     x0, x28
    add     x1, x22, #DISCV5_HDR_SRC_ID
    bl      discv5_node_find
    cbz     x0, 1f
    ldr     x0, [x0, #DISCV5_N_SEQ]
1:  mov     x1, x0
    add     x0, x20, #16
    mov     x2, #8
    bl      discv5_store_be
    LEAVE   0
END_FUNCTION discv5_challenge_new

/*
 * discv5_send_whoareyou(scratch, challenge): sends the stored WHOAREYOU: its
 * IV, then the rest masked with AES-CTR under the first 16 bytes of the
 * challenged node ID, the IV as counter. x19 challenge, x20 masking input,
 * x21 masking output, x22 packet.
 */
LOCAL_FUNCTION discv5_send_whoareyou
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    SCR     x20, SC_TMP
    add     x21, x20, #80
    mov     x9, #(DISCV5_CHALLENGE_SIZE - DISCV5_MASKED_START)
    BYTELIST x20, 0, 72, x9
    BYTELIST x21, 0, 72, xzr
    add     x0, x20, #DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_C_DATA + DISCV5_MASKED_START
    mov     x2, #(DISCV5_CHALLENGE_SIZE - DISCV5_MASKED_START)
    bl      discv5_copy
    mov     x0, x19
    add     x1, x19, #DISCV5_C_DATA
    mov     x2, x20
    mov     x3, x21
    CALL_GLOBAL crypto_aes128_ctr
    SCR     x22, SC_PKT
    mov     x9, #DISCV5_CHALLENGE_SIZE
    BYTELIST x22, 0, BL_PACKET_SIZE, x9
    add     x0, x22, #DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_C_DATA
    mov     x2, #DISCV5_MASKED_START
    bl      discv5_copy
    add     x1, x21, #DISCV5_BL_FIXED
    mov     x2, #(DISCV5_CHALLENGE_SIZE - DISCV5_MASKED_START)
    bl      discv5_copy
    mov     x0, x28
    add     x1, x19, #DISCV5_C_EP
    bl      discv5_send_packet
    LEAVE   0
END_FUNCTION discv5_send_whoareyou

/* ---------------------------------------------------------------- Actions with records */

/* discv5_emit_record(scratch): a RECORD action with the local record. x19 state, x20 length. */
LOCAL_FUNCTION discv5_emit_record
    ENTER   0
    mov     x28, x0
    STATE   x19
    ldr     x20, [x19, #DISCV5_ST_RECORD_LEN]
    add     x2, x20, #(DISCV5_ACT_RECORD_DATA + 7)
    and     x2, x2, #~7
    mov     x1, #DISCV5_ACTION_RECORD
    bl      discv5_action
    cbz     x0, 9f
    str     x20, [x0, #DISCV5_ACT_RECORD_LEN]
    add     x0, x0, #DISCV5_ACT_RECORD_DATA
    add     x1, x19, #DISCV5_ST_RECORD
    mov     x2, x20
    bl      discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_emit_record

/* discv5_emit_found(scratch): a NODE_FOUND action with the checked record in the scratch. x19 record, x20 length, x21 action. */
LOCAL_FUNCTION discv5_emit_found
    ENTER   0
    mov     x28, x0
    SCR     x19, SC_REC
    ldr     x20, [x19, #DISCV5_BL_COUNT]
    add     x2, x20, #(DISCV5_ACT_FOUND_DATA + 7)
    and     x2, x2, #~7
    mov     x1, #DISCV5_ACTION_NODE_FOUND
    bl      discv5_action
    cbz     x0, 9f
    mov     x21, x0
    str     x20, [x21, #DISCV5_ACT_FOUND_LEN]
    add     x0, x21, #DISCV5_ACT_FOUND_ID
    SCR     x1, SC_ENR + DISCV5_ENR_NODE_ID
    mov     x2, #32
    bl      discv5_copy
    add     x0, x21, #DISCV5_ACT_FOUND_DATA
    ldr     x9, [x19, #DISCV5_BL_OFFSET]
    add     x1, x19, x9
    mov     x2, x20
    bl      discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_emit_found

/* discv5_emit_done(scratch, target, found): a LOOKUP_DONE action. x19 target, x20 found. */
LOCAL_FUNCTION discv5_emit_done
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x1, #DISCV5_ACTION_LOOKUP_DONE
    mov     x2, #DISCV5_ACT_DONE_SIZE
    bl      discv5_action
    cbz     x0, 9f
    str     x20, [x0, #DISCV5_ACT_DONE_FOUND]
    add     x0, x0, #DISCV5_ACT_DONE_TARGET
    mov     x1, x19
    mov     x2, #32
    bl      discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_emit_done

/* ---------------------------------------------------------------- Requests out */

/*
 * discv5_request_message(scratch, request): the request's message in the
 * scratch: PING [request-id, enr-seq] or FINDNODE [request-id, [distance,
 * ...]]. The request ID is 8 bytes, big endian. x19 request, x20 write
 * position, x21 distance list header, x22 distance index.
 */
LOCAL_FUNCTION discv5_request_message
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    SCR     x20, SC_TMP
    mov     w9, #0x88
    strb    w9, [x20], #1
    mov     x0, x20
    ldr     x1, [x19, #DISCV5_R_REQ_ID]
    mov     x2, #8
    bl      discv5_store_be
    add     x20, x20, #8
    ldrb    w9, [x19, #DISCV5_R_TYPE]
    cmp     w9, #DISCV5_MSG_PING
    b.ne    1f
    mov     x0, x20
    STATE   x9
    ldr     x1, [x9, #DISCV5_ST_SEQ]
    bl      discv5_rlp_uint
    mov     x2, x0
    mov     x1, #DISCV5_MSG_PING
    b       8f
1:  mov     x21, x20
    add     x20, x20, #1
    mov     x22, #0
2:  ldrb    w9, [x19, #DISCV5_R_DIST_COUNT]
    cmp     x22, x9
    b.hs    3f
    add     x9, x19, #DISCV5_R_DISTANCES
    ldrh    w1, [x9, x22, lsl #1]
    mov     x0, x20
    bl      discv5_rlp_uint
    mov     x20, x0
    add     x22, x22, #1
    b       2b
3:  sub     x9, x20, x21                    /* at most 3 distances: a one-byte list header */
    sub     x9, x9, #1
    add     x9, x9, #0xC0
    strb    w9, [x21]
    mov     x2, x20
    mov     x1, #DISCV5_MSG_FINDNODE
8:  mov     x0, x28
    bl      discv5_msg_finish
    LEAVE   0
END_FUNCTION discv5_request_message

/*
 * discv5_request_start(scratch, node, kind, count, distances) -> the request,
 * or 0 when every request slot is busy. node: ID, public key and endpoint,
 * the first 104 bytes of a table slot or lookup candidate. kind: the message
 * type, the purpose << 8, the lookup slot << 16. distances: count u16
 * values, the first in the low bits. x19 node, x20 kind, x21 count,
 * x22 distances, x23 slot, x24 slots left.
 */
LOCAL_FUNCTION discv5_request_start
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    mov     x22, x4
    STATE   x9
    MOV64   x10, DISCV5_ST_REQUESTS
    add     x23, x9, x10
    mov     x24, #DISCV5_REQUEST_SLOTS
1:  ldrb    w9, [x23, #DISCV5_R_STATE]
    cbz     w9, 2f
    add     x23, x23, #DISCV5_R_SIZE
    subs    x24, x24, #1
    b.ne    1b
    mov     x0, #0
    b       9f
2:  mov     x0, x23
    mov     x1, #DISCV5_R_SIZE
    bl      discv5_zero
    mov     x0, x23
    mov     x1, x19
    mov     x2, #104
    bl      discv5_copy
    STATE   x9
    ldr     x10, [x9, #DISCV5_ST_REQ_ID]
    add     x10, x10, #1
    str     x10, [x9, #DISCV5_ST_REQ_ID]
    str     x10, [x23, #DISCV5_R_REQ_ID]
    mov     w9, #DISCV5_REQ_WAITING
    strb    w9, [x23, #DISCV5_R_STATE]
    strb    w20, [x23, #DISCV5_R_TYPE]
    lsr     x9, x20, #8
    strb    w9, [x23, #DISCV5_R_PURPOSE]
    lsr     x9, x20, #16
    strb    w9, [x23, #DISCV5_R_LOOKUP]
    NOW     x9
    add     x9, x9, #DISCV5_REQUEST_TIMEOUT
    str     x9, [x23, #DISCV5_R_DEADLINE]
    strb    w21, [x23, #DISCV5_R_DIST_COUNT]
    str     w22, [x23, #DISCV5_R_DISTANCES]
    lsr     x9, x22, #32
    strh    w9, [x23, #DISCV5_R_DISTANCES + 4]
    mov     x0, x28
    mov     x1, x23
    bl      discv5_request_message
    mov     x0, x28
    mov     x1, x23
    add     x2, x23, #DISCV5_R_EP
    bl      discv5_send_message
    mov     x1, x0
    add     x0, x23, #DISCV5_R_NONCE
    mov     x2, #12
    bl      discv5_copy
    mov     x0, x23
9:  LEAVE   0
END_FUNCTION discv5_request_start

/*
 * discv5_request_end(scratch, request, ok): frees the request and uses the
 * result. A check marks the node live, or counts a failure: a node that is
 * not live, or failed DISCV5_MAX_FAILS times in a row, leaves the table. A
 * lookup request marks its candidate answered or failed and moves the
 * lookup on. x19 request, x20 ok, x21 purpose, x22 node or lookup.
 */
LOCAL_FUNCTION discv5_request_end
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    strb    wzr, [x19, #DISCV5_R_STATE]
    ldrb    w21, [x19, #DISCV5_R_PURPOSE]
    cmp     w21, #DISCV5_PURPOSE_CHECK
    b.ne    3f
    mov     x0, x28
    mov     x1, x19
    bl      discv5_node_find
    cbz     x0, 9f
    mov     x22, x0
    strb    wzr, [x22, #DISCV5_N_PINGING]
    cbz     x20, 1f
    mov     w9, #1
    strb    w9, [x22, #DISCV5_N_LIVE]
    strb    wzr, [x22, #DISCV5_N_FAILS]
    b       9f
1:  ldrb    w9, [x22, #DISCV5_N_FAILS]
    add     w9, w9, #1
    strb    w9, [x22, #DISCV5_N_FAILS]
    NOW     x10
    str     x10, [x22, #DISCV5_N_CHECK]     /* check again soon */
    ldrb    w10, [x22, #DISCV5_N_LIVE]
    cbz     w10, 2f
    cmp     w9, #DISCV5_MAX_FAILS
    b.lo    9f
2:  mov     x0, x28
    mov     x1, x22
    bl      discv5_node_remove
    b       9f
3:  cmp     w21, #DISCV5_PURPOSE_LOOKUP
    b.ne    9f
    ldrb    w9, [x19, #DISCV5_R_LOOKUP]
    mov     x10, #DISCV5_L_SIZE
    mul     x9, x9, x10
    STATE   x10
    MOV64   x11, DISCV5_ST_LOOKUPS
    add     x10, x10, x11
    add     x22, x10, x9
    ldr     x9, [x22, #DISCV5_L_ACTIVE]
    cbz     x9, 9f
    mov     x0, x22
    mov     x1, x19
    bl      discv5_candidate_find
    cbz     x0, 5f
    mov     x9, #DISCV5_LC_FAILED
    mov     x10, #DISCV5_LC_ANSWERED
    cmp     x20, #0
    csel    x9, x10, x9, ne
    str     x9, [x0, #DISCV5_LC_STATE]
5:  mov     x0, x28
    mov     x1, x22
    bl      discv5_lookup_advance
9:  LEAVE   0
END_FUNCTION discv5_request_end

/* ---------------------------------------------------------------- Lookups */

/* reg = candidate index of the lookup in x19. Uses x17. */
.macro CANDIDATE reg, index
    mov     x17, #DISCV5_LC_SIZE
    madd    \reg, \index, x17, x19
    add     \reg, \reg, #DISCV5_L_CANDIDATES
.endm

/* discv5_candidate_find(lookup, id) -> the lookup's candidate with the node ID, or 0. x19 lookup, x20 id, x21 index, x22 candidate. */
LOCAL_FUNCTION discv5_candidate_find
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, #0
1:  ldr     x9, [x19, #DISCV5_L_COUNT]
    cmp     x21, x9
    b.hs    8f
    CANDIDATE x22, x21
    mov     x0, x22
    mov     x1, x20
    mov     x2, #32
    bl      discv5_equal
    cbnz    x0, 2f
    add     x21, x21, #1
    b       1b
2:  mov     x0, x22
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_candidate_find

/* discv5_closer(a, b, target) -> 1 when ID a is closer to the target than ID b: a XOR target is below b XOR target. */
LOCAL_FUNCTION discv5_closer
    UNWIND_END_PROLOGUE
    mov     x3, #0
1:  ldr     x4, [x0, x3]
    ldr     x5, [x1, x3]
    ldr     x6, [x2, x3]
    eor     x4, x4, x6
    eor     x5, x5, x6
    rev     x4, x4
    rev     x5, x5
    cmp     x4, x5
    b.ne    2f
    add     x3, x3, #8
    cmp     x3, #32
    b.lo    1b
    mov     x0, #0
    ret
2:  cset    x0, lo
    ret
END_FUNCTION discv5_closer

/*
 * discv5_candidate_insert(scratch, lookup, node) -> 1 when the node joins the
 * candidates. They stay sorted by distance to the target, closest first, and
 * keep the DISCV5_K closest; the local node and known candidates are left
 * out. node: ID, public key and endpoint, 104 bytes. x19 lookup, x20 node,
 * x21 position, x22 count, x23 candidate.
 */
LOCAL_FUNCTION discv5_candidate_insert
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    STATE   x9
    add     x0, x9, #DISCV5_ST_NODE_ID
    mov     x1, x20
    mov     x2, #32
    bl      discv5_equal
    cbnz    x0, 8f
    mov     x0, x19
    mov     x1, x20
    bl      discv5_candidate_find
    cbnz    x0, 8f
    ldr     x22, [x19, #DISCV5_L_COUNT]
    mov     x21, #0
1:  cmp     x21, x22
    b.hs    2f
    CANDIDATE x1, x21
    mov     x0, x20
    mov     x2, x19                         /* the target */
    bl      discv5_closer
    cbnz    x0, 2f
    add     x21, x21, #1
    b       1b
2:  cmp     x21, #DISCV5_K
    b.hs    8f
    cmp     x22, #DISCV5_K                  /* full: the last one drops out */
    b.lo    3f
    mov     x22, #(DISCV5_K - 1)
3:  cmp     x22, x21                        /* move position to count - 1 down by one, from the end */
    b.ls    4f
    sub     x22, x22, #1
    CANDIDATE x1, x22
    add     x0, x1, #DISCV5_LC_SIZE
    mov     x2, #DISCV5_LC_SIZE
    bl      discv5_copy
    b       3b
4:  CANDIDATE x23, x21
    mov     x0, x23
    mov     x1, x20
    mov     x2, #104
    bl      discv5_copy
    mov     x9, #DISCV5_LC_NEW
    str     x9, [x23, #DISCV5_LC_STATE]
    ldr     x9, [x19, #DISCV5_L_COUNT]
    add     x9, x9, #1
    mov     x10, #DISCV5_K
    cmp     x9, x10
    csel    x9, x9, x10, ls
    str     x9, [x19, #DISCV5_L_COUNT]
    mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_candidate_insert

/*
 * discv5_lookup_distances(target, id) -> in x0 the distances to ask the node
 * for, in x1 their count: d, then d + 1 and d - 1, d + 2 and d - 2, ... up
 * to 3, keeping 1 to 256, with d the log distance of the target and the
 * node. Packed as u16 values, the first in the low bits.
 * x19 d, x20 packed, x21 count, x22 step.
 */
LOCAL_FUNCTION discv5_lookup_distances
    ENTER   0
    bl      discv5_log_distance
    mov     x19, x0
    mov     x20, x0
    mov     x21, #1
    mov     x22, #1
1:  cmp     x21, #3
    b.hs    9f
    add     x9, x19, x22
    cmp     x9, #256
    b.hi    2f
    lsl     x10, x21, #4
    lsl     x9, x9, x10
    orr     x20, x20, x9
    add     x21, x21, #1
2:  cmp     x21, #3
    b.hs    9f
    subs    x9, x19, x22
    b.le    3f
    lsl     x10, x21, #4
    lsl     x9, x9, x10
    orr     x20, x20, x9
    add     x21, x21, #1
3:  add     x22, x22, #1
    b       1b
9:  mov     x0, x20
    mov     x1, x21
    LEAVE   0
END_FUNCTION discv5_lookup_distances

/*
 * discv5_lookup_advance(scratch, lookup): asks new candidates, closest
 * first, while fewer than DISCV5_ALPHA requests are pending. With nothing
 * pending and nothing new, the lookup ends with a LOOKUP_DONE action.
 * x19 lookup, x20 pending, x21 index, x22 candidate, x23 new candidates
 * not asked, x24 lookup slot number.
 */
LOCAL_FUNCTION discv5_lookup_advance
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    ldr     x9, [x19, #DISCV5_L_ACTIVE]
    cbz     x9, 9f
    STATE   x9
    MOV64   x10, DISCV5_ST_LOOKUPS
    add     x9, x9, x10
    sub     x9, x19, x9
    mov     x10, #DISCV5_L_SIZE
    udiv    x24, x9, x10
    mov     x20, #0
    mov     x21, #0
1:  ldr     x9, [x19, #DISCV5_L_COUNT]
    cmp     x21, x9
    b.hs    2f
    CANDIDATE x22, x21
    ldr     x10, [x22, #DISCV5_LC_STATE]
    cmp     x10, #DISCV5_LC_ASKED
    cinc    x20, x20, eq
    add     x21, x21, #1
    b       1b
2:  mov     x21, #0
    mov     x23, #0
3:  ldr     x9, [x19, #DISCV5_L_COUNT]
    cmp     x21, x9
    b.hs    5f
    CANDIDATE x22, x21
    ldr     x10, [x22, #DISCV5_LC_STATE]
    cmp     x10, #DISCV5_LC_NEW
    b.ne    4f
    cmp     x20, #DISCV5_ALPHA
    b.hs    41f
    mov     x0, x19
    mov     x1, x22
    bl      discv5_lookup_distances
    mov     x3, x1
    mov     x4, x0
    mov     x9, #(DISCV5_MSG_FINDNODE | (DISCV5_PURPOSE_LOOKUP << 8))
    orr     x2, x9, x24, lsl #16
    mov     x0, x28
    mov     x1, x22
    bl      discv5_request_start
    cbz     x0, 41f
    mov     x9, #DISCV5_LC_ASKED
    str     x9, [x22, #DISCV5_LC_STATE]
    add     x20, x20, #1
    b       4f
41: add     x23, x23, #1
4:  add     x21, x21, #1
    b       3b
5:  orr     x9, x20, x23
    cbnz    x9, 9f
    str     xzr, [x19, #DISCV5_L_ACTIVE]
    mov     x0, x28
    mov     x1, x19
    ldr     x2, [x19, #DISCV5_L_FOUND]
    bl      discv5_emit_done
9:  LEAVE   0
END_FUNCTION discv5_lookup_advance

/*
 * discv5_lookup_start(scratch, target): starts a lookup of the target from
 * the table members. With every lookup slot busy it ends at once with
 * LOOKUP_DONE and 0 found. x19 target, x20 lookup, x21 slots left,
 * x22 node slot, x23 nodes left.
 */
LOCAL_FUNCTION discv5_lookup_start
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    STATE   x9
    MOV64   x10, DISCV5_ST_LOOKUPS
    add     x20, x9, x10
    mov     x21, #DISCV5_LOOKUP_SLOTS
1:  ldr     x9, [x20, #DISCV5_L_ACTIVE]
    cbz     x9, 2f
    add     x20, x20, #DISCV5_L_SIZE
    subs    x21, x21, #1
    b.ne    1b
    mov     x0, x28
    mov     x1, x19
    mov     x2, #0
    bl      discv5_emit_done
    b       9f
2:  mov     x0, x20
    mov     x1, #DISCV5_L_SIZE
    bl      discv5_zero
    mov     x0, x20
    mov     x1, x19
    mov     x2, #32
    bl      discv5_copy
    mov     x9, #1
    str     x9, [x20, #DISCV5_L_ACTIVE]
    STATE   x9
    add     x22, x9, #DISCV5_ST_NODES
    mov     x23, #DISCV5_NODE_SLOTS
3:  ldrb    w9, [x22, #DISCV5_N_STATE]
    cmp     w9, #DISCV5_NODE_MEMBER
    b.ne    4f
    mov     x0, x28
    mov     x1, x20
    mov     x2, x22
    bl      discv5_candidate_insert
4:  add     x22, x22, #DISCV5_N_SIZE
    subs    x23, x23, #1
    b.ne    3b
    mov     x0, x28
    mov     x1, x20
    bl      discv5_lookup_advance
9:  LEAVE   0
END_FUNCTION discv5_lookup_start

/* ---------------------------------------------------------------- Messages in */

/*
 * discv5_msg_field(scratch, k) -> the Item record of field k of the message
 * list (field 0 is the request ID), or 0 when the list is shorter.
 * x9 items, x10 index, x11 list end.
 */
LOCAL_FUNCTION discv5_msg_field
    UNWIND_END_PROLOGUE
    mov     x9, #SC_ITEMS
    add     x9, x0, x9
    ldr     x10, [x9, #RLP_ITEMS_OFFSET]
    add     x9, x9, x10
    ldr     x11, [x9, #RLP_ITEM_ITEMS]
    mov     x10, #1
1:  cmp     x10, x11
    b.hs    8f
    add     x12, x9, x10, lsl #RLP_ITEM_SHIFT
    cbz     x1, 9f
    sub     x1, x1, #1
    ldr     x13, [x12, #RLP_ITEM_ITEMS]
    add     x10, x10, x13
    b       1b
8:  mov     x0, #0
    ret
9:  mov     x0, x12
    ret
END_FUNCTION discv5_msg_field

/*
 * discv5_item_uint(scratch, item) -> in x0 the number, in x1 1 when the
 * message item is a canonical number of at most 8 bytes, else 0. item may
 * be 0 (a missing field).
 */
LOCAL_FUNCTION discv5_item_uint
    UNWIND_END_PROLOGUE
    mov     x2, x1
    mov     x1, #0
    cbz     x2, 9f
    ldr     x9, [x2, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_BYTES
    b.ne    9f
    ldr     x10, [x2, #RLP_ITEM_LENGTH]
    cmp     x10, #8
    b.hi    9f
    ldr     x11, [x2, #RLP_ITEM_OFFSET]
    mov     x12, #(SC_RLP + DISCV5_BL_FIXED)
    add     x12, x0, x12
    add     x12, x12, x11
    mov     x0, #0
    cbz     x10, 2f
    ldrb    w13, [x12]
    cbz     w13, 9f                         /* a leading zero */
1:  ldrb    w13, [x12], #1
    orr     x0, x13, x0, lsl #8
    subs    x10, x10, #1
    b.ne    1b
2:  mov     x1, #1
9:  ret
END_FUNCTION discv5_item_uint

/*
 * discv5_handle_message(scratch): the decrypted message in the scratch, from
 * the sender of the packet: a type byte, then an RLP list whose first field
 * is a request ID of at most 8 bytes. Anything else is dropped.
 * x19 message bytes, x20 length, x21 RLP ByteList, x22 type, x23 item.
 */
LOCAL_FUNCTION discv5_handle_message
    ENTER   0
    mov     x28, x0
    SCR     x19, SC_MSG
    ldr     x20, [x19, #DISCV5_BL_COUNT]
    cmp     x20, #2
    b.lo    9f
    ldr     x9, [x19, #DISCV5_BL_OFFSET]
    add     x19, x19, x9
    ldrb    w22, [x19]
    SCR     x21, SC_RLP
    sub     x9, x20, #1
    BYTELIST x21, 0, BL_PACKET_SIZE, x9
    add     x0, x21, #DISCV5_BL_FIXED
    add     x1, x19, #1
    sub     x2, x20, #1
    bl      discv5_copy
    SCR     x1, SC_ITEMS
    mov     x9, #SC_ITEMS_SIZE
    str     x9, [x1, #RLP_ITEMS_SIZE]
    mov     x0, x21
    CALL_GLOBAL rlp_decode
    cbnz    x0, 9f
    SCR     x9, SC_ITEMS
    ldr     x10, [x9, #RLP_ITEMS_OFFSET]
    add     x9, x9, x10
    ldr     x10, [x9, #RLP_ITEM_KIND]
    cmp     x10, #RLP_KIND_LIST
    b.ne    9f
    mov     x0, x28
    mov     x1, #0
    bl      discv5_msg_field
    cbz     x0, 9f
    mov     x23, x0
    ldr     x9, [x23, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_BYTES
    b.ne    9f
    ldr     x20, [x23, #RLP_ITEM_LENGTH]
    cmp     x20, #8
    b.hi    9f
    str     x20, [x28, #SC_CTX + CTX_REQID_LEN]
    str     xzr, [x28, #SC_CTX + CTX_REQID]
    add     x0, x28, #SC_CTX + CTX_REQID
    ITEM_DATA x1, x23
    mov     x2, x20
    bl      discv5_copy
    mov     x0, x28
    cmp     w22, #DISCV5_MSG_PING
    b.ne    1f
    bl      discv5_on_ping
    b       9f
1:  cmp     w22, #DISCV5_MSG_PONG
    b.ne    2f
    bl      discv5_on_pong
    b       9f
2:  cmp     w22, #DISCV5_MSG_FINDNODE
    b.ne    3f
    bl      discv5_on_findnode
    b       9f
3:  cmp     w22, #DISCV5_MSG_NODES
    b.ne    4f
    bl      discv5_on_nodes
    b       9f
4:  cmp     w22, #DISCV5_MSG_TALKREQ
    b.ne    9f
    bl      discv5_on_talkreq
9:  LEAVE   0
END_FUNCTION discv5_handle_message

/* discv5_reply(scratch, type, end): finishes the message and sends it to the sender of the packet received. */
LOCAL_FUNCTION discv5_reply
    ENTER   0
    mov     x28, x0
    bl      discv5_msg_finish
    mov     x0, x28
    add     x1, x28, #SC_HDR + DISCV5_HDR_SRC_ID
    add     x2, x28, #SC_CTX + CTX_FROM
    bl      discv5_send_message
    LEAVE   0
END_FUNCTION discv5_reply

/* discv5_reqid_out(scratch) -> the write position after the request ID received, written at SC_TMP. */
LOCAL_FUNCTION discv5_reqid_out
    ENTER   0
    mov     x28, x0
    SCR     x0, SC_TMP
    add     x1, x28, #SC_CTX + CTX_REQID
    ldr     x2, [x28, #SC_CTX + CTX_REQID_LEN]
    bl      discv5_rlp_bytes
    LEAVE   0
END_FUNCTION discv5_reqid_out

/*
 * discv5_on_ping(scratch): PING [request-id, enr-seq] -> PONG [request-id,
 * enr-seq, ip, port], with the local sequence number and the endpoint the
 * PING came from. x20 the sender's endpoint.
 */
LOCAL_FUNCTION discv5_on_ping
    ENTER   0
    mov     x28, x0
    mov     x1, #1
    bl      discv5_msg_field
    mov     x1, x0
    mov     x0, x28
    bl      discv5_item_uint
    cbz     x1, 9f
    add     x20, x28, #SC_CTX + CTX_FROM
    mov     x0, x28
    bl      discv5_reqid_out
    STATE   x9
    ldr     x1, [x9, #DISCV5_ST_SEQ]
    bl      discv5_rlp_uint
    add     x1, x20, #DISCV5_EP_ADDRESS
    ldr     x9, [x20, #DISCV5_EP_FAMILY]
    mov     x2, #4
    mov     x10, #16
    cmp     x9, #4
    csel    x2, x2, x10, eq
    bl      discv5_rlp_bytes
    ldr     x1, [x20, #DISCV5_EP_PORT]
    bl      discv5_rlp_uint
    mov     x2, x0
    mov     x0, x28
    mov     x1, #DISCV5_MSG_PONG
    bl      discv5_reply
9:  LEAVE   0
END_FUNCTION discv5_on_ping

/* discv5_on_talkreq(scratch): TALKREQ [request-id, protocol, request] -> TALKRESP [request-id, ""]: no protocol is served. */
LOCAL_FUNCTION discv5_on_talkreq
    ENTER   0
    mov     x28, x0
    bl      discv5_reqid_out
    mov     w9, #0x80
    strb    w9, [x0], #1
    mov     x2, x0
    mov     x0, x28
    mov     x1, #DISCV5_MSG_TALKRESP
    bl      discv5_reply
    LEAVE   0
END_FUNCTION discv5_on_talkreq

/*
 * discv5_on_pong(scratch): PONG [request-id, enr-seq, ip, port] answering a
 * PING sent ends the check. An ENDPOINT action reports the endpoint the node
 * saw; a newer record is fetched with FINDNODE [0].
 * x19 request, x20 enr-seq, x21 node, x22 action, x23 ip item, x24 ip
 * length, x25 port.
 */
LOCAL_FUNCTION discv5_on_pong
    ENTER   0
    mov     x28, x0
    ldr     x9, [x28, #SC_CTX + CTX_REQID_LEN]
    cmp     x9, #8
    b.ne    9f
    mov     x1, #1
    bl      discv5_msg_field
    mov     x1, x0
    mov     x0, x28
    bl      discv5_item_uint
    cbz     x1, 9f
    mov     x20, x0
    add     x0, x28, #SC_CTX + CTX_REQID
    mov     x1, #8
    bl      discv5_load_be
    mov     x2, x0
    mov     x0, x28
    add     x1, x28, #SC_HDR + DISCV5_HDR_SRC_ID
    mov     x3, #DISCV5_MSG_PING
    bl      discv5_request_match
    cbz     x0, 9f
    mov     x19, x0

    /* ENDPOINT: ip of 4 or 16 bytes and a port. */
    mov     x0, x28
    mov     x1, #2
    bl      discv5_msg_field
    cbz     x0, 5f
    mov     x23, x0
    ldr     x9, [x23, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_BYTES
    b.ne    5f
    ldr     x24, [x23, #RLP_ITEM_LENGTH]
    cmp     x24, #4
    b.eq    1f
    cmp     x24, #16
    b.ne    5f
1:  mov     x0, x28
    mov     x1, #3
    bl      discv5_msg_field
    mov     x1, x0
    mov     x0, x28
    bl      discv5_item_uint
    cbz     x1, 5f
    mov     x25, x0
    cmp     x25, #0x10000
    b.hs    5f
    mov     x0, x28
    mov     x1, #DISCV5_ACTION_ENDPOINT
    mov     x2, #DISCV5_ACT_EP_SIZE
    bl      discv5_action
    cbz     x0, 5f
    mov     x22, x0
    str     x25, [x22, #DISCV5_ACT_EP_SEEN + DISCV5_EP_PORT]
    mov     x9, #4
    mov     x10, #6
    cmp     x24, #4
    csel    x9, x9, x10, eq
    str     x9, [x22, #DISCV5_ACT_EP_SEEN + DISCV5_EP_FAMILY]
    add     x0, x22, #DISCV5_ACT_EP_SEEN + DISCV5_EP_ADDRESS
    ITEM_DATA x1, x23
    mov     x2, x24
    bl      discv5_copy
    add     x0, x22, #DISCV5_ACT_EP_FROM
    add     x1, x28, #SC_HDR + DISCV5_HDR_SRC_ID
    mov     x2, #32
    bl      discv5_copy

    /* The check succeeded; fetch a newer record. */
5:  mov     x0, x28
    mov     x1, x19
    mov     x2, #1
    bl      discv5_request_end
    mov     x0, x28
    mov     x1, x19
    bl      discv5_node_find
    cbz     x0, 9f
    mov     x21, x0
    ldr     x9, [x21, #DISCV5_N_SEQ]
    cmp     x20, x9
    b.ls    9f
    mov     x0, x28
    mov     x1, x21
    mov     x2, #(DISCV5_MSG_FINDNODE | (DISCV5_PURPOSE_REFRESH << 8))
    mov     x3, #1
    mov     x4, #0
    bl      discv5_request_start
9:  LEAVE   0
END_FUNCTION discv5_on_pong

/* discv5_result_record(scratch, result) -> in x0 the bytes, in x1 the length of a FINDNODE result: a table slot, or 0 for the local record. */
LOCAL_FUNCTION discv5_result_record
    UNWIND_END_PROLOGUE
    cbnz    x1, 1f
    ldr     x9, [x0, #SC_CTX + CTX_STATE]
    ldr     x1, [x9, #DISCV5_ST_RECORD_LEN]
    add     x0, x9, #DISCV5_ST_RECORD
    ret
1:  add     x0, x1, #DISCV5_N_RECORD
    ldr     x1, [x1, #DISCV5_N_RECORD_LEN]
    ret
END_FUNCTION discv5_result_record

/*
 * discv5_nodes_send(scratch, start, end, total, bytes): NODES [request-id,
 * total, [record, ...]] with the results from start to end (bytes record
 * bytes in all), to the sender of the FINDNODE. x19 index, x20 end,
 * x21 total, x22 bytes, x23 write position.
 */
LOCAL_FUNCTION discv5_nodes_send
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    mov     x22, x4
    bl      discv5_reqid_out
    mov     x1, x21
    bl      discv5_rlp_uint
    mov     x1, x22
    mov     x2, #0xC0
    bl      discv5_rlp_header
    mov     x23, x0
1:  cmp     x19, x20
    b.hs    2f
    SCR     x9, SC_RESULT
    ldr     x1, [x9, x19, lsl #3]
    mov     x0, x28
    bl      discv5_result_record
    mov     x2, x1
    mov     x1, x0
    mov     x0, x23
    bl      discv5_copy
    mov     x23, x0
    add     x19, x19, #1
    b       1b
2:  mov     x0, x28
    mov     x1, #DISCV5_MSG_NODES
    mov     x2, x23
    bl      discv5_reply
    LEAVE   0
END_FUNCTION discv5_nodes_send

/*
 * discv5_nodes_pack(scratch, count, send, total) -> the NODES packets needed
 * for the count results: each holds records while their bytes stay within
 * DISCV5_NODES_BYTES, and no results take one empty packet. With send 1 the
 * packets go out, each announcing total. x19 count, x20 send, x21 total,
 * x22 index, x23 packets, x24 packet start, x25 record bytes.
 */
LOCAL_FUNCTION discv5_nodes_pack
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    mov     x22, #0
    mov     x23, #0
1:  mov     x24, x22
    mov     x25, #0
2:  cmp     x22, x19
    b.hs    3f
    SCR     x9, SC_RESULT
    ldr     x1, [x9, x22, lsl #3]
    mov     x0, x28
    bl      discv5_result_record
    add     x9, x25, x1
    cmp     x9, #DISCV5_NODES_BYTES
    b.hi    3f
    mov     x25, x9
    add     x22, x22, #1
    b       2b
3:  add     x23, x23, #1
    cbz     x20, 4f
    mov     x0, x28
    mov     x1, x24
    mov     x2, x22
    mov     x3, x21
    mov     x4, x25
    bl      discv5_nodes_send
4:  cmp     x22, x19
    b.lo    1b
    mov     x0, x23
    LEAVE   0
END_FUNCTION discv5_nodes_pack

/*
 * discv5_on_findnode(scratch): FINDNODE [request-id, [distance, ...]] ->
 * NODES packets with up to DISCV5_RESULT_LIMIT records: the local record for
 * distance 0, else live table members at exactly that log distance from the
 * local node. Distances past 256 and repeats are skipped; the first
 * DISCV5_MAX_DISTANCES distinct distances count. x19 list item, x20 item
 * index, x21 list end, x22 distances, x23 results, x24 distance, x25 node
 * slot, x26 slots left, x27 items, then distance index.
 */
LOCAL_FUNCTION discv5_on_findnode
    ENTER   0
    mov     x28, x0
    mov     x1, #1
    bl      discv5_msg_field
    cbz     x0, 9f
    mov     x19, x0
    ldr     x9, [x19, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_LIST
    b.ne    9f
    SCR     x27, SC_ITEMS
    ldr     x10, [x27, #RLP_ITEMS_OFFSET]
    add     x27, x27, x10
    sub     x20, x19, x27
    lsr     x20, x20, #RLP_ITEM_SHIFT
    ldr     x21, [x19, #RLP_ITEM_ITEMS]
    add     x21, x20, x21
    add     x20, x20, #1
    mov     x22, #0

    /* The distances. */
1:  cmp     x20, x21
    b.hs    3f
    add     x1, x27, x20, lsl #RLP_ITEM_SHIFT
    ldr     x9, [x1, #RLP_ITEM_ITEMS]
    add     x20, x20, x9
    mov     x0, x28
    bl      discv5_item_uint
    cbz     x1, 9f
    mov     x24, x0
    cmp     x24, #256
    b.hi    1b
    cmp     x22, #DISCV5_MAX_DISTANCES
    b.hs    1b
    SCR     x10, SC_DIST
    mov     x11, #0
2:  cmp     x11, x22
    b.hs    21f
    ldr     x12, [x10, x11, lsl #3]
    cmp     x12, x24
    b.eq    1b
    add     x11, x11, #1
    b       2b
21: str     x24, [x10, x22, lsl #3]
    add     x22, x22, #1
    b       1b

    /* The results. */
3:  mov     x23, #0
    mov     x27, #0
4:  cmp     x27, x22
    b.hs    7f
    cmp     x23, #DISCV5_RESULT_LIMIT
    b.hs    7f
    SCR     x9, SC_DIST
    ldr     x24, [x9, x27, lsl #3]
    add     x27, x27, #1
    cbnz    x24, 5f
    SCR     x9, SC_RESULT
    str     xzr, [x9, x23, lsl #3]
    add     x23, x23, #1
    b       4b
5:  STATE   x9
    add     x25, x9, #DISCV5_ST_NODES
    mov     x26, #DISCV5_NODE_SLOTS
6:  cmp     x23, #DISCV5_RESULT_LIMIT
    b.hs    4b
    ldrb    w9, [x25, #DISCV5_N_STATE]
    cmp     w9, #DISCV5_NODE_MEMBER
    b.ne    61f
    ldrb    w9, [x25, #DISCV5_N_LIVE]
    cbz     w9, 61f
    STATE   x9
    add     x0, x9, #DISCV5_ST_NODE_ID
    mov     x1, x25
    bl      discv5_log_distance
    cmp     x0, x24
    b.ne    61f
    SCR     x9, SC_RESULT
    str     x25, [x9, x23, lsl #3]
    add     x23, x23, #1
61: add     x25, x25, #DISCV5_N_SIZE
    subs    x26, x26, #1
    b.ne    6b
    b       4b

    /* Count the packets, then send them. */
7:  mov     x0, x28
    mov     x1, x23
    mov     x2, #0
    mov     x3, #0
    bl      discv5_nodes_pack
    mov     x3, x0
    mov     x0, x28
    mov     x1, x23
    mov     x2, #1
    bl      discv5_nodes_pack
9:  LEAVE   0
END_FUNCTION discv5_on_findnode

/*
 * discv5_nodes_record(scratch, item, request, lookup): one record of a NODES
 * answer to the request. It must be a valid record with a UDP port above
 * 1024, at one of the distances asked from the answering node. For a lookup
 * (lookup not 0) a record new to it gives NODE_FOUND and becomes a
 * candidate; every good record goes to the table. x19 item, x20 request,
 * x21 lookup, x22 record, then the node view, x23 header length, x24 length.
 */
LOCAL_FUNCTION discv5_nodes_record
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    ldr     x9, [x19, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_LIST
    b.ne    9f
    ldr     x11, [x19, #RLP_ITEM_LENGTH]
    mov     x23, #1
    cmp     x11, #55
    b.ls    1f
    clz     x9, x11
    mov     x10, #71
    sub     x9, x10, x9
    lsr     x9, x9, #3
    add     x23, x9, #1
1:  add     x24, x11, x23
    cmp     x24, #DISCV5_MAX_RECORD
    b.hi    9f
    SCR     x22, SC_REC
    BYTELIST x22, 0, 328, x24
    ITEM_DATA x1, x19
    sub     x1, x1, x23
    add     x0, x22, #DISCV5_BL_FIXED
    mov     x2, x24
    bl      discv5_copy
    SCR     x1, SC_ENR_SCRATCH
    mov     x9, #DISCV5_ENR_SCRATCH
    str     x9, [x1]
    mov     x0, x22
    SCR     x2, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    cbnz    x0, 9f
    SCR     x0, SC_ENR
    SCR     x1, SC_VIEW + DISCV5_N_EP
    bl      discv5_enr_endpoint
    cbz     x0, 9f
    SCR     x9, SC_VIEW + DISCV5_N_EP
    ldr     x9, [x9, #DISCV5_EP_PORT]
    cmp     x9, #1024
    b.ls    9f
    mov     x0, x20
    SCR     x1, SC_ENR + DISCV5_ENR_NODE_ID
    bl      discv5_log_distance
    ldrb    w10, [x20, #DISCV5_R_DIST_COUNT]
    add     x11, x20, #DISCV5_R_DISTANCES
2:  cbz     x10, 9f
    ldrh    w12, [x11], #2
    cmp     x12, x0
    b.eq    3f
    sub     x10, x10, #1
    b       2b
3:  STATE   x9
    add     x0, x9, #DISCV5_ST_NODE_ID
    SCR     x1, SC_ENR + DISCV5_ENR_NODE_ID
    mov     x2, #32
    bl      discv5_equal
    cbnz    x0, 9f
    SCR     x22, SC_VIEW
    mov     x0, x22
    SCR     x1, SC_ENR + DISCV5_ENR_NODE_ID
    mov     x2, #32
    bl      discv5_copy
    add     x0, x22, #DISCV5_N_PUBKEY
    SCR     x1, SC_ENR + DISCV5_ENR_PUBKEY
    mov     x2, #33
    bl      discv5_copy
    cbz     x21, 4f
    mov     x0, x21
    mov     x1, x22
    bl      discv5_candidate_find
    cbnz    x0, 4f
    mov     x0, x28
    bl      discv5_emit_found
    ldr     x9, [x21, #DISCV5_L_FOUND]
    add     x9, x9, #1
    str     x9, [x21, #DISCV5_L_FOUND]
    mov     x0, x28
    mov     x1, x21
    mov     x2, x22
    bl      discv5_candidate_insert
4:  mov     x0, x28
    SCR     x1, SC_ENR
    SCR     x2, SC_REC
    bl      discv5_node_add
9:  LEAVE   0
END_FUNCTION discv5_nodes_record

/*
 * discv5_on_nodes(scratch): NODES [request-id, total, [record, ...]]
 * answering a FINDNODE sent. The request ends after min(total,
 * DISCV5_NODES_LIMIT) packets, at least 1; each packet moves its deadline
 * on. x19 request, x20 child index, x21 list end, x22 items, x23 lookup,
 * x24 item, x25 total.
 */
LOCAL_FUNCTION discv5_on_nodes
    ENTER   0
    mov     x28, x0
    ldr     x9, [x28, #SC_CTX + CTX_REQID_LEN]
    cmp     x9, #8
    b.ne    9f
    mov     x1, #1
    bl      discv5_msg_field
    mov     x1, x0
    mov     x0, x28
    bl      discv5_item_uint
    cbz     x1, 9f
    mov     x25, x0
    mov     x0, x28
    mov     x1, #2
    bl      discv5_msg_field
    cbz     x0, 9f
    mov     x24, x0
    ldr     x9, [x24, #RLP_ITEM_KIND]
    cmp     x9, #RLP_KIND_LIST
    b.ne    9f
    add     x0, x28, #SC_CTX + CTX_REQID
    mov     x1, #8
    bl      discv5_load_be
    mov     x2, x0
    mov     x0, x28
    add     x1, x28, #SC_HDR + DISCV5_HDR_SRC_ID
    mov     x3, #DISCV5_MSG_FINDNODE
    bl      discv5_request_match
    cbz     x0, 9f
    mov     x19, x0
    mov     x23, #0
    ldrb    w9, [x19, #DISCV5_R_PURPOSE]
    cmp     w9, #DISCV5_PURPOSE_LOOKUP
    b.ne    1f
    ldrb    w9, [x19, #DISCV5_R_LOOKUP]
    mov     x10, #DISCV5_L_SIZE
    mul     x9, x9, x10
    STATE   x10
    MOV64   x11, DISCV5_ST_LOOKUPS
    add     x10, x10, x11
    add     x23, x10, x9
    ldr     x9, [x23, #DISCV5_L_ACTIVE]
    cmp     x9, #0
    csel    x23, x23, xzr, ne
1:  SCR     x22, SC_ITEMS
    ldr     x9, [x22, #RLP_ITEMS_OFFSET]
    add     x22, x22, x9
    sub     x20, x24, x22
    lsr     x20, x20, #RLP_ITEM_SHIFT
    ldr     x21, [x24, #RLP_ITEM_ITEMS]
    add     x21, x20, x21
    add     x20, x20, #1
2:  cmp     x20, x21
    b.hs    5f
    add     x24, x22, x20, lsl #RLP_ITEM_SHIFT
    ldr     x9, [x24, #RLP_ITEM_ITEMS]
    add     x20, x20, x9
    mov     x0, x28
    mov     x1, x24
    mov     x2, x19
    mov     x3, x23
    bl      discv5_nodes_record
    b       2b
5:  ldrb    w9, [x19, #DISCV5_R_TOTAL]
    cbnz    w9, 6f
    mov     x9, #DISCV5_NODES_LIMIT
    cmp     x25, x9
    csel    x9, x25, x9, lo
    mov     x10, #1
    cmp     x9, #0
    csel    x9, x9, x10, ne
    strb    w9, [x19, #DISCV5_R_TOTAL]
6:  ldrb    w10, [x19, #DISCV5_R_GOT]
    add     w10, w10, #1
    strb    w10, [x19, #DISCV5_R_GOT]
    cmp     w10, w9
    b.lo    7f
    mov     x0, x28
    mov     x1, x19
    mov     x2, #1
    bl      discv5_request_end
    b       9f
7:  NOW     x9
    add     x9, x9, #DISCV5_REQUEST_TIMEOUT
    str     x9, [x19, #DISCV5_R_DEADLINE]
9:  LEAVE   0
END_FUNCTION discv5_on_nodes

/* ---------------------------------------------------------------- Packets in */

/*
 * discv5_on_message_packet(scratch): an ordinary message packet. With a
 * session for the sender's node ID and endpoint whose key opens it, the
 * message is handled. Else the sender gets WHOAREYOU: the one still valid
 * for that node and endpoint, sent again unchanged, or a new one.
 * x19 source ID, x20 endpoint, x21 session or challenge.
 */
LOCAL_FUNCTION discv5_on_message_packet
    ENTER   0
    mov     x28, x0
    add     x19, x28, #SC_HDR + DISCV5_HDR_SRC_ID
    add     x20, x28, #SC_CTX + CTX_FROM
    mov     x1, x19
    mov     x2, x20
    bl      discv5_session_find
    cbz     x0, 2f
    mov     x21, x0
    add     x0, x28, #SC_HDR
    add     x1, x21, #DISCV5_S_READ_KEY
    SCR     x2, SC_IN
    SCR     x3, SC_MSG
    CALL_GLOBAL discv5_message_decrypt
    cbnz    x0, 2f
    NOW     x9
    add     x9, x9, #1
    str     x9, [x21, #DISCV5_S_USED]
    mov     x0, x28
    bl      discv5_handle_message
    b       9f
2:  mov     x0, x28
    mov     x1, x19
    mov     x2, x20
    mov     x3, #0
    bl      discv5_challenge_find
    mov     x21, x0
    cbnz    x21, 3f
    mov     x0, x28
    mov     x1, x19
    mov     x2, x20
    mov     x3, #1
    bl      discv5_challenge_find
    mov     x21, x0
    mov     x1, x21
    mov     x0, x28
    bl      discv5_challenge_new
3:  mov     x0, x28
    mov     x1, x21
    bl      discv5_send_whoareyou
9:  LEAVE   0
END_FUNCTION discv5_on_message_packet

/*
 * discv5_on_whoareyou(scratch): a WHOAREYOU answering a request that waits
 * (matched by the nonce sent). A new ephemeral key gives the session keys;
 * the ID proof signs the challenge; the request goes again in a handshake
 * packet, with the local record when the challenge's enr-seq is older.
 * x19 request, x20 state, x21 header out, x22 session, x23 challenge data.
 */
LOCAL_FUNCTION discv5_on_whoareyou
    ENTER   0
    mov     x28, x0
    add     x1, x28, #SC_HDR + DISCV5_HDR_NONCE
    bl      discv5_request_find
    cbz     x0, 9f
    mov     x19, x0
    ldrb    w9, [x19, #DISCV5_R_STATE]
    cmp     w9, #DISCV5_REQ_WAITING
    b.ne    9f
    STATE   x20
    add     x23, x28, #SC_HDR + DISCV5_HDR_HEADER + DISCV5_BL_FIXED
1:  mov     x0, x20
    SCR     x1, SC_EPH
    mov     x2, #32
    bl      discv5_random
    SCR     x0, SC_EPH
    SCR     x1, SC_EPH + 32
    CALL_GLOBAL crypto_secp256k1_public_key
    cbnz    x0, 1b

    /* Keys: the IDs are the local node's (initiator), then the remote's. */
    SCR     x0, SC_TMP
    add     x1, x20, #DISCV5_ST_NODE_ID
    mov     x2, #32
    bl      discv5_copy
    mov     x1, x19
    mov     x2, #32
    bl      discv5_copy
    SCR     x0, SC_EPH
    add     x1, x19, #DISCV5_R_PUBKEY
    mov     x2, x23
    SCR     x3, SC_TMP
    SCR     x4, SC_KEYS
    CALL_GLOBAL discv5_derive_keys
    cbnz    x0, 9f
    SCR     x21, SC_HDR2
    add     x0, x20, #DISCV5_ST_PRIVATE_KEY
    mov     x1, x23
    SCR     x2, SC_EPH + 32
    mov     x3, x19
    add     x4, x21, #DISCV5_HDR_SIGNATURE
    CALL_GLOBAL discv5_id_sign
    cbnz    x0, 9f
    add     x0, x21, #DISCV5_HDR_EPH_KEY
    SCR     x1, SC_EPH + 32
    mov     x2, #33
    bl      discv5_copy
    mov     x0, x28
    mov     x1, x19
    add     x2, x19, #DISCV5_R_EP
    SCR     x3, SC_KEYS
    SCR     x4, SC_KEYS + 16
    bl      discv5_session_put
    mov     x22, x0
    mov     x9, #1
    str     x9, [x22, #DISCV5_S_COUNTER]

    /* The header: flag 2, the first nonce of the session. */
    mov     x9, #DISCV5_FLAG_HANDSHAKE
    str     x9, [x21, #DISCV5_HDR_FLAG]
    mov     x0, x20
    add     x1, x21, #DISCV5_HDR_IV
    mov     x2, #16
    bl      discv5_random
    add     x0, x21, #DISCV5_HDR_SRC_ID
    add     x1, x20, #DISCV5_ST_NODE_ID
    mov     x2, #32
    bl      discv5_copy
    add     x0, x21, #DISCV5_HDR_NONCE
    mov     x1, #1
    mov     x2, #4
    bl      discv5_store_be
    mov     x0, x20
    add     x1, x21, #DISCV5_HDR_NONCE + 4
    mov     x2, #8
    bl      discv5_random
    add     x9, x21, #DISCV5_HDR_RECORD
    BYTELIST x9, 0, DISCV5_HDR_RECORD_SIZE, xzr
    ldr     x9, [x28, #SC_HDR + DISCV5_HDR_ENR_SEQ]
    ldr     x10, [x20, #DISCV5_ST_SEQ]
    cmp     x9, x10
    b.hs    2f
    ldr     x2, [x20, #DISCV5_ST_RECORD_LEN]
    str     x2, [x21, #DISCV5_HDR_RECORD + DISCV5_BL_COUNT]
    add     x0, x21, #DISCV5_HDR_RECORD + DISCV5_BL_FIXED
    add     x1, x20, #DISCV5_ST_RECORD
    bl      discv5_copy

    /* The request again. */
2:  mov     x0, x28
    mov     x1, x19
    bl      discv5_request_message
    SCR     x9, SC_PKT
    BYTELIST x9, 0, BL_PACKET_SIZE, xzr
    mov     x0, x21
    mov     x1, x19
    add     x2, x22, #DISCV5_S_WRITE_KEY
    SCR     x3, SC_MSG
    SCR     x4, SC_PKT
    CALL_GLOBAL discv5_packet_encode
    cbnz    x0, 9f
    mov     x0, x28
    add     x1, x19, #DISCV5_R_EP
    bl      discv5_send_packet
    add     x0, x19, #DISCV5_R_NONCE
    add     x1, x21, #DISCV5_HDR_NONCE
    mov     x2, #12
    bl      discv5_copy
    mov     w9, #DISCV5_REQ_HANDSHAKE
    strb    w9, [x19, #DISCV5_R_STATE]
    NOW     x9
    add     x9, x9, #DISCV5_REQUEST_TIMEOUT
    str     x9, [x19, #DISCV5_R_DEADLINE]
    mov     x0, x28
    mov     x1, x19
    bl      discv5_requests_resend
9:  LEAVE   0
END_FUNCTION discv5_on_whoareyou

/*
 * discv5_requests_resend(scratch, request): the other requests waiting for
 * the same node ID and endpoint go again, now through the session the
 * request's handshake made, each with a new nonce and deadline.
 * x19 request, x20 slot, x21 slots left.
 */
LOCAL_FUNCTION discv5_requests_resend
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    STATE   x9
    MOV64   x10, DISCV5_ST_REQUESTS
    add     x20, x9, x10
    mov     x21, #DISCV5_REQUEST_SLOTS
1:  cmp     x20, x19
    b.eq    2f
    ldrb    w9, [x20, #DISCV5_R_STATE]
    cmp     w9, #DISCV5_REQ_WAITING
    b.ne    2f
    mov     x0, x20
    mov     x1, x19
    mov     x2, #32
    bl      discv5_equal
    cbz     x0, 2f
    add     x0, x20, #DISCV5_R_EP
    add     x1, x19, #DISCV5_R_EP
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_equal
    cbz     x0, 2f
    mov     x0, x28
    mov     x1, x20
    bl      discv5_request_message
    mov     x0, x28
    mov     x1, x20
    add     x2, x20, #DISCV5_R_EP
    bl      discv5_send_message
    mov     x1, x0
    add     x0, x20, #DISCV5_R_NONCE
    mov     x2, #12
    bl      discv5_copy
    NOW     x9
    add     x9, x9, #DISCV5_REQUEST_TIMEOUT
    str     x9, [x20, #DISCV5_R_DEADLINE]
2:  add     x20, x20, #DISCV5_R_SIZE
    subs    x21, x21, #1
    b.ne    1b
    LEAVE   0
END_FUNCTION discv5_requests_resend

/*
 * discv5_on_handshake(scratch): a handshake packet answering the WHOAREYOU
 * still valid for the sender's node ID and endpoint. The public key comes
 * from the record in the packet (its node ID must match), else from the
 * table. The ID proof must verify and the message must open with the
 * derived keys; then the session is stored, the challenge is used up, a
 * record from the packet goes to the table, and the message is handled.
 * x19 challenge, x20 public key, x21 state, x22 source ID, x23 1 when the
 * packet has the record.
 */
LOCAL_FUNCTION discv5_on_handshake
    ENTER   0
    mov     x28, x0
    STATE   x21
    add     x22, x28, #SC_HDR + DISCV5_HDR_SRC_ID
    mov     x1, x22
    add     x2, x28, #SC_CTX + CTX_FROM
    mov     x3, #0
    bl      discv5_challenge_find
    cbz     x0, 9f
    mov     x19, x0
    mov     x23, #0
    ldr     x9, [x28, #SC_HDR + DISCV5_HDR_RECORD + DISCV5_BL_COUNT]
    cbz     x9, 1f
    SCR     x1, SC_ENR_SCRATCH
    mov     x9, #DISCV5_ENR_SCRATCH
    str     x9, [x1]
    add     x0, x28, #SC_HDR + DISCV5_HDR_RECORD
    SCR     x2, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    cbnz    x0, 9f
    SCR     x0, SC_ENR + DISCV5_ENR_NODE_ID
    mov     x1, x22
    mov     x2, #32
    bl      discv5_equal
    cbz     x0, 9f
    SCR     x20, SC_ENR + DISCV5_ENR_PUBKEY
    mov     x23, #1
    b       2f
1:  mov     x0, x28
    mov     x1, x22
    bl      discv5_node_find
    cbz     x0, 9f
    add     x20, x0, #DISCV5_N_PUBKEY
2:  mov     x0, x20
    add     x1, x19, #DISCV5_C_DATA
    add     x2, x28, #SC_HDR
    add     x3, x21, #DISCV5_ST_NODE_ID
    SCR     x4, SC_TMP
    CALL_GLOBAL discv5_id_verify
    cbnz    x0, 9f
    SCR     x9, SC_TMP
    ldr     x9, [x9]
    cmp     x9, #1
    b.ne    9f

    /* Keys: the IDs are the sender's (initiator), then the local node's. */
    SCR     x0, SC_TMP + 8
    mov     x1, x22
    mov     x2, #32
    bl      discv5_copy
    add     x1, x21, #DISCV5_ST_NODE_ID
    mov     x2, #32
    bl      discv5_copy
    add     x0, x21, #DISCV5_ST_PRIVATE_KEY
    add     x1, x28, #SC_HDR + DISCV5_HDR_EPH_KEY
    add     x2, x19, #DISCV5_C_DATA
    SCR     x3, SC_TMP + 8
    SCR     x4, SC_KEYS
    CALL_GLOBAL discv5_derive_keys
    cbnz    x0, 9f
    add     x0, x28, #SC_HDR
    SCR     x1, SC_KEYS
    SCR     x2, SC_IN
    SCR     x3, SC_MSG
    CALL_GLOBAL discv5_message_decrypt
    cbnz    x0, 9f
    mov     x0, x28
    mov     x1, x22
    add     x2, x28, #SC_CTX + CTX_FROM
    SCR     x3, SC_KEYS + 16
    SCR     x4, SC_KEYS
    bl      discv5_session_put
    str     xzr, [x19, #DISCV5_C_SENT]
    cbz     x23, 3f
    mov     x0, x28
    SCR     x1, SC_ENR
    add     x2, x28, #SC_HDR + DISCV5_HDR_RECORD
    bl      discv5_node_add
3:  mov     x0, x28
    bl      discv5_handle_message
9:  LEAVE   0
END_FUNCTION discv5_on_handshake

/*
 * discv5_on_datagram(scratch, event): a received datagram. The sender's
 * endpoint is kept with the unused address bytes zero; a packet that does
 * not decode is dropped. x19 event, x20 packet, x21 flag.
 */
LOCAL_FUNCTION discv5_on_datagram
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    add     x0, x28, #SC_CTX + CTX_FROM
    add     x1, x19, #DISCV5_EV_DG_FROM
    mov     x2, #DISCV5_EP_SIZE
    bl      discv5_copy
    ldr     x9, [x28, #SC_CTX + CTX_FROM + DISCV5_EP_FAMILY]
    cmp     x9, #4
    b.ne    1f
    str     wzr, [x28, #SC_CTX + CTX_FROM + DISCV5_EP_ADDRESS + 4]
    str     xzr, [x28, #SC_CTX + CTX_FROM + DISCV5_EP_ADDRESS + 8]
1:  SCR     x20, SC_IN
    ldr     x9, [x19, #DISCV5_EV_DG_LEN]
    BYTELIST x20, 0, BL_PACKET_SIZE, x9
    add     x0, x20, #DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_EV_DG_DATA
    ldr     x2, [x19, #DISCV5_EV_DG_LEN]
    bl      discv5_copy
    mov     x0, x20
    STATE   x9
    add     x1, x9, #DISCV5_ST_NODE_ID
    add     x2, x28, #SC_HDR
    CALL_GLOBAL discv5_packet_decode
    cbnz    x0, 9f
    SCR     x9, SC_MSG
    BYTELIST x9, 0, BL_PACKET_SIZE, xzr
    ldr     x21, [x28, #SC_HDR + DISCV5_HDR_FLAG]
    mov     x0, x28
    cmp     x21, #DISCV5_FLAG_MESSAGE
    b.ne    2f
    bl      discv5_on_message_packet
    b       9f
2:  cmp     x21, #DISCV5_FLAG_WHOAREYOU
    b.ne    3f
    bl      discv5_on_whoareyou
    b       9f
3:  bl      discv5_on_handshake
9:  LEAVE   0
END_FUNCTION discv5_on_datagram

/* ---------------------------------------------------------------- Other events */

/* discv5_on_add_node(scratch, event): ADD_NODE: a valid record with a UDP endpoint goes to the table. x19 event, x20 length, x21 record. */
LOCAL_FUNCTION discv5_on_add_node
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    ldr     x20, [x19, #DISCV5_EV_ADD_LEN]
    cmp     x20, #DISCV5_MAX_RECORD
    b.hi    9f
    SCR     x21, SC_REC
    BYTELIST x21, 0, 328, x20
    add     x0, x21, #DISCV5_BL_FIXED
    add     x1, x19, #DISCV5_EV_ADD_DATA
    mov     x2, x20
    bl      discv5_copy
    SCR     x1, SC_ENR_SCRATCH
    mov     x9, #DISCV5_ENR_SCRATCH
    str     x9, [x1]
    mov     x0, x21
    SCR     x2, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    cbnz    x0, 9f
    mov     x0, x28
    SCR     x1, SC_ENR
    mov     x2, x21
    bl      discv5_node_add
9:  LEAVE   0
END_FUNCTION discv5_on_add_node

.set ENTRIES_BYTES, 8 + DISCV5_MAX_ENTRIES * DISCV5_LE_SIZE

/*
 * discv5_record_change(scratch, event): SET_ENDPOINT or SET_ENTRY. The
 * entries change, the sequence number goes up by 1, the record is signed
 * again, and a RECORD action carries it. When the entries are full or the
 * record would pass 300 bytes, the entries and sequence number stay as they
 * were. x19 event, x20 state, x21 saved entries.
 */
LOCAL_FUNCTION discv5_record_change
    ENTER   0
    mov     x28, x0
    mov     x19, x1
    STATE   x20
    SCR     x21, SC_TMP
    mov     x0, x21
    add     x1, x20, #DISCV5_ST_ENTRY_COUNT
    mov     x2, #ENTRIES_BYTES
    bl      discv5_copy
    ldr     x9, [x19, #DISCV5_EV_KIND]
    cmp     x9, #DISCV5_EVENT_SET_ENDPOINT
    b.ne    1f
    mov     x0, x20
    add     x1, x19, #DISCV5_EV_ENDPOINT
    bl      discv5_set_endpoint
    b       2f
1:  mov     x0, x20
    add     x1, x19, #DISCV5_EV_ENTRY_KEY
    ldr     x2, [x19, #DISCV5_EV_ENTRY_KEY_LEN]
    add     x3, x19, #DISCV5_EV_ENTRY_VALUE
    ldr     x4, [x19, #DISCV5_EV_ENTRY_VALUE_LEN]
    bl      discv5_entry_set
2:  cbnz    x0, 8f
    ldr     x9, [x20, #DISCV5_ST_SEQ]
    add     x9, x9, #1
    str     x9, [x20, #DISCV5_ST_SEQ]
    mov     x0, x20
    bl      discv5_record_build
    cbnz    x0, 7f
    mov     x0, x28
    bl      discv5_emit_record
    b       9f
7:  ldr     x9, [x20, #DISCV5_ST_SEQ]
    sub     x9, x9, #1
    str     x9, [x20, #DISCV5_ST_SEQ]
8:  add     x0, x20, #DISCV5_ST_ENTRY_COUNT
    mov     x1, x21
    mov     x2, #ENTRIES_BYTES
    bl      discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_record_change

/* discv5_owned_key(key, length) -> 1 when the key is one the core sets: "id", "secp256k1", "ip", "udp", "ip6", "udp6". x19 key, x20 length, x21 table, x22 entries left. */
LOCAL_FUNCTION discv5_owned_key
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    adr     x21, 402f
    mov     x22, #6
1:  ldrb    w9, [x21, #1]
    cmp     x9, x20
    b.ne    2f
    ldrb    w9, [x21]
    adr     x1, 400b
    add     x1, x1, x9
    mov     x0, x19
    mov     x2, x20
    bl      discv5_equal
    cbnz    x0, 9f
2:  add     x21, x21, #2
    subs    x22, x22, #1
    b.ne    1b
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION discv5_owned_key

/* The keys the core sets: offset in the key names at 400, then length. */
402:
    .byte   0, 2, 24, 9, 4, 2, 8, 3, 12, 3, 16, 4
    .p2align 3

/* ---------------------------------------------------------------- Timers */

/*
 * discv5_timers(scratch): requests past their deadline end, failed (a
 * FINDNODE that got some NODES packets counts as answered). Every
 * DISCV5_PING_INTERVAL the table member whose check is most overdue gets a
 * PING. The refresh lookup of the local node ID starts when due. Lookups
 * move on. x19 state, x20 slot, x21 slots left, x22 now, x23 best.
 */
LOCAL_FUNCTION discv5_timers
    ENTER   0
    mov     x28, x0
    STATE   x19
    NOW     x22
    MOV64   x9, DISCV5_ST_REQUESTS
    add     x20, x19, x9
    mov     x21, #DISCV5_REQUEST_SLOTS
1:  ldrb    w9, [x20, #DISCV5_R_STATE]
    cbz     w9, 2f
    ldr     x9, [x20, #DISCV5_R_DEADLINE]
    cmp     x9, x22
    b.hi    2f
    ldrb    w9, [x20, #DISCV5_R_GOT]
    cmp     w9, #0
    cset    x2, ne
    mov     x0, x28
    mov     x1, x20
    bl      discv5_request_end
2:  add     x20, x20, #DISCV5_R_SIZE
    subs    x21, x21, #1
    b.ne    1b

    /* The liveness check. */
    ldr     x9, [x19, #DISCV5_ST_NEXT_PING]
    cmp     x9, x22
    b.hi    5f
    add     x9, x22, #DISCV5_PING_INTERVAL
    str     x9, [x19, #DISCV5_ST_NEXT_PING]
    add     x20, x19, #DISCV5_ST_NODES
    mov     x21, #DISCV5_NODE_SLOTS
    mov     x23, #0
3:  ldrb    w9, [x20, #DISCV5_N_STATE]
    cmp     w9, #DISCV5_NODE_MEMBER
    b.ne    4f
    ldrb    w9, [x20, #DISCV5_N_PINGING]
    cbnz    w9, 4f
    ldr     x9, [x20, #DISCV5_N_CHECK]
    cmp     x9, x22
    b.hi    4f
    cbz     x23, 31f
    ldr     x10, [x23, #DISCV5_N_CHECK]
    cmp     x9, x10
    b.hs    4f
31: mov     x23, x20
4:  add     x20, x20, #DISCV5_N_SIZE
    subs    x21, x21, #1
    b.ne    3b
    cbz     x23, 5f
    mov     x0, x28
    mov     x1, x23
    mov     x2, #(DISCV5_MSG_PING | (DISCV5_PURPOSE_CHECK << 8))
    mov     x3, #0
    mov     x4, #0
    bl      discv5_request_start
    cbz     x0, 5f
    mov     w9, #1
    strb    w9, [x23, #DISCV5_N_PINGING]
    mov     x9, #DISCV5_RECHECK_INTERVAL
    add     x9, x22, x9
    str     x9, [x23, #DISCV5_N_CHECK]

    /* The refresh lookup. */
5:  ldr     x9, [x19, #DISCV5_ST_NEXT_REFRESH]
    cbz     x9, 6f
    cmp     x9, x22
    b.hi    6f
    MOV64   x10, DISCV5_REFRESH_INTERVAL
    add     x9, x22, x10
    str     x9, [x19, #DISCV5_ST_NEXT_REFRESH]
    mov     x0, x28
    add     x1, x19, #DISCV5_ST_NODE_ID
    bl      discv5_lookup_start

    /* Lookups waiting for a free request slot. */
6:  MOV64   x9, DISCV5_ST_LOOKUPS
    add     x20, x19, x9
    mov     x21, #DISCV5_LOOKUP_SLOTS
7:  mov     x0, x28
    mov     x1, x20
    bl      discv5_lookup_advance
    add     x20, x20, #DISCV5_L_SIZE
    subs    x21, x21, #1
    b.ne    7b
    LEAVE   0
END_FUNCTION discv5_timers

/* discv5_wakeup(scratch): a WAKEUP action for the next timer: the next check, refresh or request deadline. x19 state, x20 time. */
LOCAL_FUNCTION discv5_wakeup
    ENTER   0
    mov     x28, x0
    STATE   x19
    ldr     x20, [x19, #DISCV5_ST_NEXT_PING]
    ldr     x9, [x19, #DISCV5_ST_NEXT_REFRESH]
    cbz     x9, 1f
    cmp     x9, x20
    csel    x20, x9, x20, lo
1:  MOV64   x9, DISCV5_ST_REQUESTS
    add     x10, x19, x9
    mov     x11, #DISCV5_REQUEST_SLOTS
2:  ldrb    w9, [x10, #DISCV5_R_STATE]
    cbz     w9, 3f
    ldr     x9, [x10, #DISCV5_R_DEADLINE]
    cmp     x9, x20
    csel    x20, x9, x20, lo
3:  add     x10, x10, #DISCV5_R_SIZE
    subs    x11, x11, #1
    b.ne    2b
    mov     x0, x28
    mov     x1, #DISCV5_ACTION_WAKEUP
    mov     x2, #DISCV5_ACT_WAKEUP_SIZE
    bl      discv5_action
    cbz     x0, 9f
    str     x20, [x0, #DISCV5_ACT_WAKEUP_AT]
9:  LEAVE   0
END_FUNCTION discv5_wakeup

/* ---------------------------------------------------------------- discv5_step */

/*
 * discv5_step(state, tick, events, scratch, actions) -> status
 * Checks the scratch size, every event and the action room first; on error
 * nothing changes. Then takes the time (never below the last), reseeds the
 * DRBG, handles the events in order, runs the timers, and ends the actions
 * with WAKEUP. x19 state, x20 tick, x21 events, x22 scratch, x23 actions,
 * x24 event position, x25 events end, x26 event count, x27 event.
 */
FUNCTION discv5_step
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x0, #DISCV5_BUFFER_TOO_SMALL
    ldr     x9, [x22]
    mov     x10, #DISCV5_SCRATCH_SIZE
    cmp     x9, x10
    b.lo    99f

    /* Check the events. */
    ldr     x9, [x21, #DISCV5_BL_OFFSET]
    add     x24, x21, x9
    ldr     x9, [x21, #DISCV5_BL_COUNT]
    add     x25, x24, x9
    mov     x26, #0
1:  mov     x0, #DISCV5_INVALID_EVENT
    cmp     x24, x25
    b.hs    3f
    sub     x9, x25, x24
    cmp     x9, #16
    b.lo    99f
    ldr     x10, [x24, #DISCV5_EV_SIZE]
    cmp     x10, #16
    b.lo    99f
    tst     x10, #7
    b.ne    99f
    cmp     x10, x9
    b.hi    99f
    ldr     x11, [x24, #DISCV5_EV_KIND]
    cmp     x11, #DISCV5_EVENT_DATAGRAM
    b.ne    11f
    cmp     x10, #DISCV5_EV_DG_DATA
    b.lo    99f
    ldr     x12, [x24, #DISCV5_EV_DG_LEN]
    cmp     x12, #DISCV5_MAX_PACKET
    b.hi    99f
    sub     x13, x10, #DISCV5_EV_DG_DATA
    cmp     x12, x13
    b.hi    99f
    ldr     x12, [x24, #DISCV5_EV_DG_FROM + DISCV5_EP_FAMILY]
    cmp     x12, #4
    b.eq    2f
    cmp     x12, #6
    b.eq    2f
    b       99f
11: cmp     x11, #DISCV5_EVENT_ADD_NODE
    b.ne    12f
    cmp     x10, #DISCV5_EV_ADD_DATA
    b.lo    99f
    ldr     x12, [x24, #DISCV5_EV_ADD_LEN]
    sub     x13, x10, #DISCV5_EV_ADD_DATA
    cmp     x12, x13
    b.hi    99f
    b       2f
12: cmp     x11, #DISCV5_EVENT_LOOKUP
    b.ne    13f
    cmp     x10, #DISCV5_EV_LOOKUP_SIZE
    b.lo    99f
    b       2f
13: cmp     x11, #DISCV5_EVENT_SET_ENDPOINT
    b.ne    14f
    cmp     x10, #DISCV5_EV_ENDPOINT_SIZE
    b.lo    99f
    ldr     x12, [x24, #DISCV5_EV_ENDPOINT + DISCV5_EP_FAMILY]
    cmp     x12, #4
    b.eq    131f
    cmp     x12, #6
    b.ne    99f
131: ldr    x12, [x24, #DISCV5_EV_ENDPOINT + DISCV5_EP_PORT]
    cmp     x12, #0x10000
    b.hs    99f
    b       2f
14: cmp     x11, #DISCV5_EVENT_SET_ENTRY
    b.ne    15f
    cmp     x10, #DISCV5_EV_ENTRY_VALUE
    b.lo    99f
    ldr     x12, [x24, #DISCV5_EV_ENTRY_KEY_LEN]
    cbz     x12, 99f
    cmp     x12, #DISCV5_MAX_KEY
    b.hi    99f
    ldr     x13, [x24, #DISCV5_EV_ENTRY_VALUE_LEN]
    cmp     x13, #DISCV5_MAX_VALUE
    b.hi    99f
    sub     x14, x10, #DISCV5_EV_ENTRY_VALUE
    cmp     x13, x14
    b.hi    99f
    add     x0, x24, #DISCV5_EV_ENTRY_KEY
    mov     x1, x12
    bl      discv5_owned_key
    mov     x9, x0
    mov     x0, #DISCV5_INVALID_EVENT
    cbnz    x9, 99f
    b       2f
15: cmp     x11, #DISCV5_EVENT_OPENED          /* shell results: well formed, then ignored */
    b.ne    16f
    cmp     x10, #DISCV5_EV_OPENED_SIZE
    b.lo    99f
    b       2f
16: cmp     x11, #DISCV5_EVENT_SENT
    b.lo    99f
    cmp     x11, #DISCV5_EVENT_IDLE
    b.hi    99f
    cmp     x10, #DISCV5_EV_ERROR_SIZE
    b.lo    99f
2:  ldr     x10, [x24, #DISCV5_EV_SIZE]
    add     x24, x24, x10
    add     x26, x26, #1
    b       1b

    /* Check the action room. */
3:  mov     x0, #DISCV5_BUFFER_TOO_SMALL
    ldr     x9, [x23, #DISCV5_BL_SIZE]
    subs    x9, x9, #DISCV5_BL_FIXED
    b.lo    99f
    mov     x10, #DISCV5_ACTIONS_PER_EVENT
    mov     x11, #DISCV5_ACTIONS_BASE
    madd    x10, x26, x10, x11
    cmp     x9, x10
    b.lo    99f

    /* Commit: the time, the DRBG, the context, empty actions. */
    ldr     x9, [x20, #DISCV5_TICK_NOW]
    ldr     x10, [x19, #DISCV5_ST_NOW]
    cmp     x9, x10
    csel    x9, x9, x10, hs
    str     x9, [x19, #DISCV5_ST_NOW]
    str     x9, [x22, #SC_CTX + CTX_NOW]
    str     x19, [x22, #SC_CTX + CTX_STATE]
    str     x23, [x22, #SC_CTX + CTX_ACTIONS]
    mov     x0, x19
    add     x1, x20, #DISCV5_TICK_ENTROPY
    bl      discv5_reseed
    mov     x9, #DISCV5_BL_FIXED
    str     x9, [x23, #DISCV5_BL_OFFSET]
    str     xzr, [x23, #DISCV5_BL_COUNT]

    /* The events. */
    ldr     x9, [x21, #DISCV5_BL_OFFSET]
    add     x24, x21, x9
4:  cmp     x24, x25
    b.hs    8f
    mov     x27, x24
    ldr     x9, [x27, #DISCV5_EV_SIZE]
    add     x24, x24, x9
    ldr     x9, [x27, #DISCV5_EV_KIND]
    mov     x0, x22
    mov     x1, x27
    cmp     x9, #DISCV5_EVENT_DATAGRAM
    b.ne    41f
    bl      discv5_on_datagram
    b       4b
41: cmp     x9, #DISCV5_EVENT_ADD_NODE
    b.ne    42f
    bl      discv5_on_add_node
    b       4b
42: cmp     x9, #DISCV5_EVENT_LOOKUP
    b.ne    43f
    add     x1, x27, #DISCV5_EV_LOOKUP_TARGET
    bl      discv5_lookup_start
    b       4b
43: cmp     x9, #DISCV5_EVENT_SET_ENTRY
    b.hi    4b
    bl      discv5_record_change
    b       4b

    /* Timers, then WAKEUP. */
8:  mov     x0, x22
    bl      discv5_timers
    mov     x0, x22
    bl      discv5_wakeup
    mov     x0, #DISCV5_OK
99: LEAVE   0
END_FUNCTION discv5_step
