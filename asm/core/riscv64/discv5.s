/*
 * asm-discv5 for RISC-V (RISC-V ELF psABI, LP64D): Node Discovery Protocol
 * v5.1. Requirements: docs/reference/. Layouts: include/discv5.inc.
 *
 * Pointer arguments, status in a0. Hashes, ciphers and curve operations go
 * through asm-crypto; RLP decoding goes through asm-rlp. Baseline RV64GC
 * instructions only. The functions and their steps follow the ARM64 file
 * one for one, with its registers x0-x7 as a0-a7, x9-x15 as t0-t6 and
 * x19-x28 as s1-s10. a7 is the temporary of the offset and compare macros.
 */
.set ISA_RISCV64, 1
.include "crypto.inc"
.include "keccak.inc"
.include "hmac.inc"
.include "aes.inc"
.include "secp256k1.inc"
.include "rlp.inc"
.include "discv5.inc"
.include "platform.inc"

/* ---------------------------------------------------------------- Frames */

.set FL, 112                        /* locals start at sp + FL */

/*
 * Frame of a non-leaf function: ra and s0-s11 at sp, then bytes of locals
 * at sp + FL. bytes is a multiple of 16. A large frame moves sp with t0.
 */
.macro ENTER bytes
.if (\bytes + FL) <= 2032
    addi    sp, sp, -(\bytes + FL)
.else
    li      t0, -(\bytes + FL)
    add     sp, sp, t0
.endif
    UNWIND_ALLOC (\bytes + FL)
    sd      ra, 0(sp)
    UNWIND_SAVE ra, 0
    sd      s0, 8(sp)
    UNWIND_SAVE s0, 8
    sd      s1, 16(sp)
    UNWIND_SAVE s1, 16
    sd      s2, 24(sp)
    UNWIND_SAVE s2, 24
    sd      s3, 32(sp)
    UNWIND_SAVE s3, 32
    sd      s4, 40(sp)
    UNWIND_SAVE s4, 40
    sd      s5, 48(sp)
    UNWIND_SAVE s5, 48
    sd      s6, 56(sp)
    UNWIND_SAVE s6, 56
    sd      s7, 64(sp)
    UNWIND_SAVE s7, 64
    sd      s8, 72(sp)
    UNWIND_SAVE s8, 72
    sd      s9, 80(sp)
    UNWIND_SAVE s9, 80
    sd      s10, 88(sp)
    UNWIND_SAVE s10, 88
    sd      s11, 96(sp)
    UNWIND_SAVE s11, 96
    UNWIND_END_PROLOGUE
.endm

.macro LEAVE bytes
    UNWIND_BEGIN_EPILOGUE
    ld      ra, 0(sp)
    UNWIND_RESTORE ra
    ld      s0, 8(sp)
    UNWIND_RESTORE s0
    ld      s1, 16(sp)
    UNWIND_RESTORE s1
    ld      s2, 24(sp)
    UNWIND_RESTORE s2
    ld      s3, 32(sp)
    UNWIND_RESTORE s3
    ld      s4, 40(sp)
    UNWIND_RESTORE s4
    ld      s5, 48(sp)
    UNWIND_RESTORE s5
    ld      s6, 56(sp)
    UNWIND_RESTORE s6
    ld      s7, 64(sp)
    UNWIND_RESTORE s7
    ld      s8, 72(sp)
    UNWIND_RESTORE s8
    ld      s9, 80(sp)
    UNWIND_RESTORE s9
    ld      s10, 88(sp)
    UNWIND_RESTORE s10
    ld      s11, 96(sp)
    UNWIND_RESTORE s11
.if (\bytes + FL) <= 2047
    addi    sp, sp, (\bytes + FL)
.else
    li      t0, (\bytes + FL)
    add     sp, sp, t0
.endif
    UNWIND_FREE (\bytes + FL)
    UNWIND_END_EPILOGUE
    ret
.endm

/* rd = rs + off, for any 32-bit off. Uses a7 for a large off. */
.macro ADDO rd, rs, off
.if ((\off) >= -2048) && ((\off) <= 2047)
    addi    \rd, \rs, \off
.else
    li      a7, \off
    add     \rd, \rs, a7
.endif
.endm

/* Loads and stores at base + off, for any 32-bit off. Use a7 for a large off. */
.macro LDO rd, base, off
.if ((\off) >= -2048) && ((\off) <= 2047)
    ld      \rd, \off(\base)
.else
    li      a7, \off
    add     a7, \base, a7
    ld      \rd, 0(a7)
.endif
.endm

.macro SDO rs, base, off
.if ((\off) >= -2048) && ((\off) <= 2047)
    sd      \rs, \off(\base)
.else
    li      a7, \off
    add     a7, \base, a7
    sd      \rs, 0(a7)
.endif
.endm

/* A ByteList header at base + off: size, offset 24, count. Uses a7. */
.macro BYTELIST base, off, size, count
    sd      \count, \off+16(\base)
    li      a7, \size
    sd      a7, \off(\base)
    li      a7, DISCV5_BL_FIXED
    sd      a7, \off+8(\base)
.endm

/* Branches on a register against a constant. Use a7. */
.macro BEQI r, imm, label
    li      a7, \imm
    beq     \r, a7, \label
.endm

.macro BNEI r, imm, label
    li      a7, \imm
    bne     \r, a7, \label
.endm

/* unsigned r < imm */
.macro BLTUI r, imm, label
    li      a7, \imm
    bltu    \r, a7, \label
.endm

/* unsigned r >= imm */
.macro BGEUI r, imm, label
    li      a7, \imm
    bgeu    \r, a7, \label
.endm

/* unsigned r > imm */
.macro BGTUI r, imm, label
    li      a7, \imm
    bltu    a7, \r, \label
.endm

/* unsigned r <= imm */
.macro BLEUI r, imm, label
    li      a7, \imm
    bgeu    a7, \r, \label
.endm

/* ---------------------------------------------------------------- Byte helpers */

/* discv5_copy(dst, src, n) -> dst + n. The regions do not overlap. */
LOCAL_FUNCTION discv5_copy
    UNWIND_END_PROLOGUE
1:  beqz    a2, 2f
    lbu     t0, 0(a1)
    sb      t0, 0(a0)
    addi    a0, a0, 1
    addi    a1, a1, 1
    addi    a2, a2, -1
    j       1b
2:  ret
END_FUNCTION discv5_copy

/* discv5_zero(dst, n) -> dst + n. */
LOCAL_FUNCTION discv5_zero
    UNWIND_END_PROLOGUE
1:  beqz    a1, 2f
    sb      zero, 0(a0)
    addi    a0, a0, 1
    addi    a1, a1, -1
    j       1b
2:  ret
END_FUNCTION discv5_zero

/* discv5_equal(a, b, n) -> 1 when the n bytes at a and b are equal, else 0. */
LOCAL_FUNCTION discv5_equal
    UNWIND_END_PROLOGUE
    li      t1, 0
1:  beqz    a2, 2f
    lbu     t0, 0(a0)
    lbu     t2, 0(a1)
    xor     t0, t0, t2
    or      t1, t1, t0
    addi    a0, a0, 1
    addi    a1, a1, 1
    addi    a2, a2, -1
    j       1b
2:  seqz    a0, t1
    ret
END_FUNCTION discv5_equal

/*
 * discv5_log_distance(a, b) -> 0 when the 32-byte IDs are equal, else 256
 * minus the leading zero bits of a XOR b: 8 * (31 - i) plus the bit length
 * of the first byte i that differs.
 */
LOCAL_FUNCTION discv5_log_distance
    UNWIND_END_PROLOGUE
    li      t0, 0
1:  add     t1, a0, t0
    lbu     t1, 0(t1)
    add     t2, a1, t0
    lbu     t2, 0(t2)
    xor     t1, t1, t2
    bnez    t1, 2f
    addi    t0, t0, 1
    li      t2, 32
    bltu    t0, t2, 1b
    li      a0, 0
    ret
2:  li      t2, 31
    sub     t2, t2, t0
    slli    t2, t2, 3
3:  addi    t2, t2, 1
    srli    t1, t1, 1
    bnez    t1, 3b
    mv      a0, t2
    ret
END_FUNCTION discv5_log_distance

/* discv5_load_be(p, n) -> the n bytes at p (n at most 8) as a big-endian number. */
LOCAL_FUNCTION discv5_load_be
    UNWIND_END_PROLOGUE
    li      t0, 0
1:  beqz    a1, 2f
    lbu     t1, 0(a0)
    slli    t0, t0, 8
    or      t0, t0, t1
    addi    a0, a0, 1
    addi    a1, a1, -1
    j       1b
2:  mv      a0, t0
    ret
END_FUNCTION discv5_load_be

/* discv5_store_be(p, v, n): the low n bytes of v (n at most 8) at p, big endian. */
LOCAL_FUNCTION discv5_store_be
    UNWIND_END_PROLOGUE
    slli    t0, a2, 3
1:  beqz    t0, 2f
    addi    t0, t0, -8
    srl     t1, a1, t0
    sb      t1, 0(a0)
    addi    a0, a0, 1
    j       1b
2:  ret
END_FUNCTION discv5_store_be

/* ---------------------------------------------------------------- RLP writers */

/* n = bytes of the number v, which is not 0. Uses tmp. */
.macro BYTES_OF v, n, tmp
    mv      \tmp, \v
    li      \n, 0
97: addi    \n, \n, 1
    srli    \tmp, \tmp, 8
    bnez    \tmp, 97b
.endm

/* Write the n bytes of v big endian at a0, moving a0. Uses t1 and t2. */
.macro WRITE_BE v, n, t1, t2
    slli    \t1, \n, 3
98: addi    \t1, \t1, -8
    srl     \t2, \v, \t1
    sb      \t2, 0(a0)
    addi    a0, a0, 1
    bnez    \t1, 98b
.endm

/* discv5_rlp_header(out, length, base) -> out after the header: base 0x80 for a byte string, 0xC0 for a list. */
LOCAL_FUNCTION discv5_rlp_header
    UNWIND_END_PROLOGUE
    li      t0, 55
    bltu    t0, a1, 1f
    add     a2, a2, a1
    sb      a2, 0(a0)
    addi    a0, a0, 1
    ret
1:  BYTES_OF a1, t1, t2
    addi    a2, a2, 55
    add     a2, a2, t1
    sb      a2, 0(a0)
    addi    a0, a0, 1
    WRITE_BE a1, t1, t2, t3
    ret
END_FUNCTION discv5_rlp_header

/* discv5_rlp_bytes(out, data, len) -> out after the byte string encoding. A byte below 0x80 is itself. */
LOCAL_FUNCTION discv5_rlp_bytes
    UNWIND_END_PROLOGUE
    li      t0, 1
    bne     a2, t0, 1f
    lbu     t0, 0(a1)
    li      t1, 0x80
    bgeu    t0, t1, 1f
    sb      t0, 0(a0)
    addi    a0, a0, 1
    ret
1:  li      t0, 55
    bltu    t0, a2, 2f
    addi    t1, a2, 0x80
    sb      t1, 0(a0)
    addi    a0, a0, 1
    j       3f
2:  BYTES_OF a2, t1, t2
    addi    t3, t1, 0xB7
    sb      t3, 0(a0)
    addi    a0, a0, 1
    WRITE_BE a2, t1, t2, t3
3:  beqz    a2, 4f
    lbu     t0, 0(a1)
    sb      t0, 0(a0)
    addi    a0, a0, 1
    addi    a1, a1, 1
    addi    a2, a2, -1
    j       3b
4:  ret
END_FUNCTION discv5_rlp_bytes

/* discv5_rlp_uint(out, value) -> out after the value as a byte string, big endian with no leading zero. */
LOCAL_FUNCTION discv5_rlp_uint
    UNWIND_END_PROLOGUE
    bnez    a1, 1f
    li      t0, 0x80
    sb      t0, 0(a0)
    addi    a0, a0, 1
    ret
1:  li      t0, 0x80
    bgeu    a1, t0, 2f
    sb      a1, 0(a0)
    addi    a0, a0, 1
    ret
2:  BYTES_OF a1, t1, t2
    addi    t3, t1, 0x80
    sb      t3, 0(a0)
    addi    a0, a0, 1
    WRITE_BE a1, t1, t2, t3
    ret
END_FUNCTION discv5_rlp_uint

/* ---------------------------------------------------------------- Hashes and the DRBG */

/*
 * discv5_hash(data, len, digest, keccak): SHA-256 (keccak 0) or Keccak-256
 * (keccak 1) of len bytes, len at most 304. The bytes go into a ByteList on
 * the stack first. s1 digest, s2 keccak.
 */
LOCAL_FUNCTION discv5_hash
    ENTER   336
    mv      s1, a2
    mv      s2, a3
    li      t0, 328
    sd      t0, FL(sp)
    li      t0, DISCV5_BL_FIXED
    sd      t0, FL+8(sp)
    sd      a1, FL+16(sp)
    mv      a2, a1
    mv      a1, a0
    addi    a0, sp, FL+24
    call    discv5_copy
    addi    a0, sp, FL
    mv      a1, s1
    bnez    s2, 1f
    CALL_GLOBAL crypto_sha256
    j       2f
1:  CALL_GLOBAL crypto_keccak256
2:  LEAVE   336
END_FUNCTION discv5_hash

/*
 * discv5_random(state, out, n): n bytes from the DRBG. Each 32-byte block is
 * SHA-256(key || counter), the counter as 8 bytes little endian; the counter
 * then goes up by 1. s1 state, s2 out, s3 bytes left. The hash input at
 * sp + FL, the block at sp + FL + 64.
 */
LOCAL_FUNCTION discv5_random
    ENTER   96
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
1:  beqz    s3, 9f
    li      t0, 64
    sd      t0, FL(sp)
    li      t0, DISCV5_BL_FIXED
    sd      t0, FL+8(sp)
    li      t0, 40
    sd      t0, FL+16(sp)
    ld      t0, DISCV5_ST_DRBG_KEY(s1)
    sd      t0, FL+24(sp)
    ld      t0, DISCV5_ST_DRBG_KEY+8(s1)
    sd      t0, FL+32(sp)
    ld      t0, DISCV5_ST_DRBG_KEY+16(s1)
    sd      t0, FL+40(sp)
    ld      t0, DISCV5_ST_DRBG_KEY+24(s1)
    sd      t0, FL+48(sp)
    ld      t0, DISCV5_ST_DRBG_COUNT(s1)
    sd      t0, FL+56(sp)
    addi    t0, t0, 1
    sd      t0, DISCV5_ST_DRBG_COUNT(s1)
    addi    a0, sp, FL
    addi    a1, sp, FL+64
    CALL_GLOBAL crypto_sha256
    li      a2, 32
    bgeu    s3, a2, 2f
    mv      a2, s3
2:  sub     s3, s3, a2
    mv      a0, s2
    addi    a1, sp, FL+64
    call    discv5_copy
    mv      s2, a0
    j       1b
9:  LEAVE   96
END_FUNCTION discv5_random

/* discv5_reseed(state, entropy): the DRBG key becomes SHA-256(key || the 32 entropy bytes). s1 state. */
LOCAL_FUNCTION discv5_reseed
    ENTER   96
    mv      s1, a0
    li      t0, 88
    sd      t0, FL(sp)
    li      t0, DISCV5_BL_FIXED
    sd      t0, FL+8(sp)
    li      t0, 64
    sd      t0, FL+16(sp)
    ld      t0, DISCV5_ST_DRBG_KEY(s1)
    sd      t0, FL+24(sp)
    ld      t0, DISCV5_ST_DRBG_KEY+8(s1)
    sd      t0, FL+32(sp)
    ld      t0, DISCV5_ST_DRBG_KEY+16(s1)
    sd      t0, FL+40(sp)
    ld      t0, DISCV5_ST_DRBG_KEY+24(s1)
    sd      t0, FL+48(sp)
    addi    a0, sp, FL+56
    li      a2, 32
    call    discv5_copy
    addi    a0, sp, FL
    addi    a1, s1, DISCV5_ST_DRBG_KEY
    CALL_GLOBAL crypto_sha256
    LEAVE   96
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

/* Branch to label unless the byte string at t1 (t2 bytes) is a canonical number of at most n bytes. Uses t0. */
.macro CHECK_UINT n, label
    li      t0, \n
    bltu    t0, t2, \label
    beqz    t2, 96f
    lbu     t0, 0(t1)
    beqz    t0, \label
96:
.endm

/* t0 = the n (2 to 4) bytes at p, little endian. Uses a4. */
.macro LOAD_KEY p, n
    lbu     t0, 0(\p)
    lbu     a4, 1(\p)
    slli    a4, a4, 8
    or      t0, t0, a4
.if \n > 2
    lbu     a4, 2(\p)
    slli    a4, a4, 16
    or      t0, t0, a4
.endif
.if \n > 3
    lbu     a4, 3(\p)
    slli    a4, a4, 24
    or      t0, t0, a4
.endif
.endm

/*
 * discv5_enr_decode(record, scratch, enr) -> status
 * s1 record, s2 scratch, s3 enr, s4 record bytes, s5 items, s6 item count,
 * s7 child index, s8 previous key (pointer), s9 pairs, s10 flags: bit 0 id
 * is v4, bit 1 secp256k1 seen. Locals: sp + FL the previous key length,
 * sp + FL + 8 the signature item. In the pair loop: t5 key, t6 key length,
 * t1 value, t2 value length, a6 pair, a5 key names.
 */
FUNCTION discv5_enr_decode
    ENTER   16
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    li      a0, DISCV5_BUFFER_TOO_SMALL
    ld      t0, 0(s2)
    BLTUI   t0, DISCV5_ENR_SCRATCH, 99f
    mv      a0, s3
    li      a1, DISCV5_ENR_SIZE
    call    discv5_zero
    ld      t0, DISCV5_BL_COUNT(s1)
    beqz    t0, 98f
    BGTUI   t0, DISCV5_MAX_RECORD, 98f
    ld      s4, DISCV5_BL_OFFSET(s1)
    add     s4, s1, s4
    addi    a1, s2, ES_ITEMS
    li      t0, ES_ITEMS_SIZE
    sd      t0, 0(a1)
    mv      a0, s1
    CALL_GLOBAL rlp_decode
    bnez    a0, 98f
    addi    t1, s2, ES_ITEMS
    ld      t2, RLP_ITEMS_OFFSET(t1)
    add     s5, t1, t2
    ld      s6, RLP_ITEMS_COUNT(t1)
    ld      t0, RLP_ITEM_KIND(s5)
    BNEI    t0, RLP_KIND_LIST, 98f

    /* The signature: 64 bytes. */
    BLEUI   s6, 1, 98f
    addi    t3, s5, RLP_ITEM_STRIDE
    ld      t0, RLP_ITEM_KIND(t3)
    BNEI    t0, RLP_KIND_BYTES, 98f
    ld      t0, RLP_ITEM_LENGTH(t3)
    BNEI    t0, 64, 98f
    sd      t3, FL+8(sp)

    /* The sequence number. */
    BLEUI   s6, 2, 98f
    addi    t3, s5, 2*RLP_ITEM_STRIDE
    ld      t0, RLP_ITEM_KIND(t3)
    BNEI    t0, RLP_KIND_BYTES, 98f
    ld      t1, RLP_ITEM_OFFSET(t3)
    add     t1, s4, t1
    ld      t2, RLP_ITEM_LENGTH(t3)
    CHECK_UINT 8, 98f
    mv      a0, t1
    mv      a1, t2
    call    discv5_load_be
    sd      a0, DISCV5_ENR_SEQ(s3)

    /* Key/value pairs, keys sorted and unique. */
    li      s7, 3
    li      s8, 0
    li      s9, 0
    li      s10, 0
1:  bgeu    s7, s6, 5f
    slli    t3, s7, RLP_ITEM_SHIFT
    add     t3, s5, t3
    ld      t0, RLP_ITEM_KIND(t3)
    BNEI    t0, RLP_KIND_BYTES, 98f
    ld      t5, RLP_ITEM_OFFSET(t3)
    add     t5, s4, t5                      # key
    ld      t6, RLP_ITEM_LENGTH(t3)         # key length
    beqz    s8, 3f
    ld      a5, FL(sp)                      # previous key length
    li      t0, 0
2:  bltu    t0, a5, 21f
    bltu    a5, t6, 3f                      # the previous key is a prefix: increasing when the new key is longer
    j       98f
21: bgeu    t0, t6, 98f                     # the new key is a prefix of the previous one
    add     t1, s8, t0
    lbu     t1, 0(t1)
    add     t2, t5, t0
    lbu     t2, 0(t2)
    bltu    t1, t2, 3f
    bltu    t2, t1, 98f
    addi    t0, t0, 1
    j       2b
3:  mv      s8, t5
    sd      t6, FL(sp)
    BGEUI   s9, DISCV5_ENR_MAX_PAIRS, 98f
    addi    t4, s7, 1                       # the value
    bgeu    t4, s6, 98f
    slli    t3, t4, RLP_ITEM_SHIFT
    add     t3, s5, t3
    li      t0, DISCV5_PAIR_SIZE
    mul     t0, s9, t0
    addi    a6, s3, DISCV5_ENR_PAIRS
    add     a6, a6, t0
    sub     t0, t5, s4
    sw      t0, DISCV5_PAIR_KEY_OFFSET(a6)
    sw      t6, DISCV5_PAIR_KEY_LEN(a6)
    ld      t0, RLP_ITEM_KIND(t3)
    sw      t0, DISCV5_PAIR_VALUE_KIND(a6)
    ld      t1, RLP_ITEM_OFFSET(t3)
    ld      t2, RLP_ITEM_LENGTH(t3)
    BEQI    t0, RLP_KIND_BYTES, 4f
    li      t0, 1                           # a list: the whole encoding, header included
    BLEUI   t2, 55, 31f
    mv      a4, t2
30: addi    t0, t0, 1
    srli    a4, a4, 8
    bnez    a4, 30b
31: sub     t1, t1, t0
    add     t2, t2, t0
    sw      t1, DISCV5_PAIR_VALUE_OFFSET(a6)
    sw      t2, DISCV5_PAIR_VALUE_LEN(a6)
    j       45f
4:  sw      t1, DISCV5_PAIR_VALUE_OFFSET(a6)
    sw      t2, DISCV5_PAIR_VALUE_LEN(a6)
    add     t1, s4, t1                      # value bytes
    lla     a5, 400f
    BNEI    t6, 2, 41f                      /* "id" and "ip" */
    LOAD_KEY t5, 2
    lhu     a4, 0(a5)
    bne     t0, a4, 40f
    BNEI    t2, 2, 98f                      /* "id" = "v4" */
    lbu     a3, 0(t1)
    lbu     a4, 1(t1)
    slli    a4, a4, 8
    or      a3, a3, a4
    lhu     a4, 2(a5)
    bne     a3, a4, 98f
    ori     s10, s10, 1
    j       45f
40: lhu     a4, 4(a5)                       # "ip": 4 bytes
    bne     t0, a4, 45f
    BNEI    t2, 4, 45f
    addi    a0, s3, DISCV5_ENR_IP4
    mv      a1, t1
    li      a2, 4
    call    discv5_copy
    ld      a3, DISCV5_ENR_HAS(s3)
    ori     a3, a3, DISCV5_HAS_IP4
    sd      a3, DISCV5_ENR_HAS(s3)
    j       45f
41: BNEI    t6, 3, 43f                      /* "udp" and "ip6" */
    LOAD_KEY t5, 3
    lwu     a4, 8(a5)                       # "udp"
    bne     t0, a4, 42f
    CHECK_UINT 2, 45f
    mv      a0, t1
    mv      a1, t2
    call    discv5_load_be
    sd      a0, DISCV5_ENR_UDP4(s3)
    ld      a3, DISCV5_ENR_HAS(s3)
    ori     a3, a3, DISCV5_HAS_UDP4
    sd      a3, DISCV5_ENR_HAS(s3)
    j       45f
42: lwu     a4, 12(a5)                      # "ip6": 16 bytes
    bne     t0, a4, 45f
    BNEI    t2, 16, 45f
    addi    a0, s3, DISCV5_ENR_IP6
    mv      a1, t1
    li      a2, 16
    call    discv5_copy
    ld      a3, DISCV5_ENR_HAS(s3)
    ori     a3, a3, DISCV5_HAS_IP6
    sd      a3, DISCV5_ENR_HAS(s3)
    j       45f
43: BNEI    t6, 4, 44f                      /* "udp6" */
    LOAD_KEY t5, 4
    lwu     a4, 16(a5)
    bne     t0, a4, 45f
    CHECK_UINT 2, 45f
    mv      a0, t1
    mv      a1, t2
    call    discv5_load_be
    sd      a0, DISCV5_ENR_UDP6(s3)
    ld      a3, DISCV5_ENR_HAS(s3)
    ori     a3, a3, DISCV5_HAS_UDP6
    sd      a3, DISCV5_ENR_HAS(s3)
    j       45f
44: BNEI    t6, 9, 45f                      /* "secp256k1": 33 bytes */
    li      t0, 0
441:add     a3, t5, t0
    lbu     a3, 0(a3)
    add     a4, a5, t0
    lbu     a4, 24(a4)
    bne     a3, a4, 45f
    addi    t0, t0, 1
    BLTUI   t0, 9, 441b
    BNEI    t2, 33, 98f
    addi    a0, s3, DISCV5_ENR_PUBKEY
    mv      a1, t1
    li      a2, 33
    call    discv5_copy
    ori     s10, s10, 2
45: addi    s9, s9, 1
    addi    t4, s7, 1
    slli    t3, t4, RLP_ITEM_SHIFT
    add     t3, s5, t3
    ld      t0, RLP_ITEM_ITEMS(t3)
    add     s7, t4, t0
    j       1b

    /* The v4 scheme: the id, the key, the node ID and the signature. */
5:  BNEI    s10, 3, 98f
    sd      s9, DISCV5_ENR_COUNT(s3)
    addi    a0, s3, DISCV5_ENR_PUBKEY
    addi    a1, s2, ES_POINT
    CALL_GLOBAL crypto_secp256k1_decompress
    bnez    a0, 98f
    addi    a0, s2, ES_POINT
    li      a1, 64
    addi    a2, s3, DISCV5_ENR_NODE_ID
    li      a3, 1
    call    discv5_hash

    /* The content [seq, k, v, ...]: a new list header, then the record bytes after the signature. */
    ld      t3, FL+8(sp)
    ld      t0, RLP_ITEM_OFFSET(t3)
    add     a1, s4, t0
    addi    a0, s2, ES_SIG
    li      a2, 64
    call    discv5_copy
    ld      t3, FL+8(sp)
    ld      s7, RLP_ITEM_OFFSET(t3)
    addi    s7, s7, 64                      # the content payload starts after the signature
    ld      t0, RLP_ITEM_OFFSET(s5)
    ld      t1, RLP_ITEM_LENGTH(s5)
    add     s8, t0, t1                      # and ends with the record
    sub     s8, s8, s7
    addi    a0, s2, ES_CONTENT
    mv      a1, s8
    li      a2, 0xC0
    call    discv5_rlp_header
    add     a1, s4, s7
    mv      a2, s8
    call    discv5_copy
    addi    a1, s2, ES_CONTENT
    sub     a1, a0, a1
    addi    a0, s2, ES_CONTENT
    addi    a2, s2, ES_HASH
    li      a3, 1
    call    discv5_hash
    addi    a0, s3, DISCV5_ENR_PUBKEY
    addi    a1, s2, ES_HASH
    addi    a2, s2, ES_SIG
    addi    a3, s2, ES_VALID
    CALL_GLOBAL crypto_secp256k1_verify
    bnez    a0, 98f
    ld      t0, ES_VALID(s2)
    beqz    t0, 98f
    li      a0, DISCV5_OK
    j       99f
98: li      a0, DISCV5_INVALID_RECORD
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
    .zero   7                       # tables keep a length of a multiple of 8 for the code alignment after them
    .p2align 3

/*
 * discv5_enr_text_decode(text, record) -> status: "enr:" then URL-safe base64
 * with no padding. s1 text bytes, s2 record, s3 characters left, s4
 * output, s5 bits, s6 bits held.
 */
FUNCTION discv5_enr_text_decode
    ENTER   0
    mv      s2, a1
    mv      t0, a0
    li      a0, DISCV5_INVALID_TEXT
    ld      s3, DISCV5_BL_COUNT(t0)
    BLTUI   s3, 4, 99f
    ld      s1, DISCV5_BL_OFFSET(t0)
    add     s1, t0, s1
    lbu     t1, 0(s1)
    BNEI    t1, 'e', 99f
    lbu     t1, 1(s1)
    BNEI    t1, 'n', 99f
    lbu     t1, 2(s1)
    BNEI    t1, 'r', 99f
    lbu     t1, 3(s1)
    BNEI    t1, ':', 99f
    addi    s1, s1, 4
    addi    s3, s3, -4
    andi    t0, s3, 3
    BEQI    t0, 1, 99f
    li      t1, 0                           # every character must be in the alphabet
11: bgeu    t1, s3, 12f
    add     t2, s1, t1
    lbu     t2, 0(t2)
    addi    t1, t1, 1
    li      t4, 26
    addi    t3, t2, -'A'
    bltu    t3, t4, 11b
    addi    t3, t2, -'a'
    bltu    t3, t4, 11b
    li      t4, 10
    addi    t3, t2, -'0'
    bltu    t3, t4, 11b
    BEQI    t2, '-', 11b
    BEQI    t2, '_', 11b
    j       99f
12: li      t0, 3
    mul     t0, s3, t0
    srli    t0, t0, 2                       # output bytes
    li      a0, DISCV5_BUFFER_TOO_SMALL
    ld      t1, DISCV5_BL_SIZE(s2)
    BLTUI   t1, DISCV5_BL_FIXED, 99f
    addi    t1, t1, -DISCV5_BL_FIXED
    bltu    t1, t0, 99f
    li      a0, DISCV5_INVALID_TEXT
    addi    s4, s2, DISCV5_BL_FIXED
    li      s5, 0
    li      s6, 0
1:  beqz    s3, 8f
    lbu     t1, 0(s1)
    addi    s1, s1, 1
    addi    s3, s3, -1
    li      t3, 26
    addi    t2, t1, -'A'
    bltu    t2, t3, 2f
    addi    t2, t1, -'a'
    bltu    t2, t3, 21f
    li      t3, 10
    addi    t2, t1, -'0'
    bltu    t2, t3, 22f
    li      t2, 62
    BEQI    t1, '-', 2f
    li      t2, 63
    j       2f
21: addi    t2, t2, 26
    j       2f
22: addi    t2, t2, 52
2:  slli    s5, s5, 6
    or      s5, s5, t2
    addi    s6, s6, 6
    BLTUI   s6, 8, 1b
    addi    s6, s6, -8
    srl     t1, s5, s6
    sb      t1, 0(s4)
    addi    s4, s4, 1
    j       1b
8:  li      t0, DISCV5_BL_FIXED
    sd      t0, DISCV5_BL_OFFSET(s2)
    addi    t0, s2, DISCV5_BL_FIXED
    sub     t0, s4, t0
    sd      t0, DISCV5_BL_COUNT(s2)
    li      a0, DISCV5_OK
99: LEAVE   0
END_FUNCTION discv5_enr_text_decode

/* discv5_local_record(state, record) -> status: a copy of the local record. s1 state, s2 record, s3 length. */
FUNCTION discv5_local_record
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    li      a0, DISCV5_BUFFER_TOO_SMALL
    ld      s3, DISCV5_ST_RECORD_LEN(s1)
    ld      t0, DISCV5_BL_SIZE(s2)
    BLTUI   t0, DISCV5_BL_FIXED, 9f
    addi    t0, t0, -DISCV5_BL_FIXED
    bltu    t0, s3, 9f
    li      t1, DISCV5_BL_FIXED
    sd      t1, DISCV5_BL_OFFSET(s2)
    sd      s3, DISCV5_BL_COUNT(s2)
    addi    a0, s2, DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_ST_RECORD
    mv      a2, s3
    call    discv5_copy
    li      a0, DISCV5_OK
9:  LEAVE   0
END_FUNCTION discv5_local_record

/* ---------------------------------------------------------------- Packets (discv5-wire.md) */

/* discv5_packet_decode stack: the masked bytes and the unmasked bytes, as ByteLists. */
.set PD_IN, 0
.set PD_OUT, 520
.set PD_UNMASK, 496                 /* most bytes unmasked: the static header and 473 bytes of authdata */
.set PD_AUTH_MAX, PD_UNMASK - DISCV5_STATIC_HEADER
.set HS_FIXED, 34 + 64 + 33         /* handshake authdata before the record */

/*
 * discv5_packet_decode(packet, local_id, header) -> status
 * s1 packet, s2 local_id, s3 header, s4 packet bytes, s5 length,
 * s6 unmasked bytes, s7 flag, s8 authdata size.
 */
FUNCTION discv5_packet_decode
    ENTER   1040
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    ld      s5, DISCV5_BL_COUNT(s1)
    BLTUI   s5, DISCV5_MIN_PACKET, 98f
    BGTUI   s5, DISCV5_MAX_PACKET, 98f
    ld      s4, DISCV5_BL_OFFSET(s1)
    add     s4, s1, s4
    addi    a0, s3, DISCV5_HDR_IV
    mv      a1, s4
    li      a2, 16
    call    discv5_copy
    addi    t0, s5, -DISCV5_MASKED_START
    li      t1, PD_UNMASK
    bgeu    t1, t0, 1f
    mv      t0, t1
1:  addi    t2, sp, FL+PD_IN
    BYTELIST t2, 0, 520, t0
    addi    t2, sp, FL+PD_OUT
    BYTELIST t2, 0, 520, zero
    addi    a0, sp, FL+PD_IN+DISCV5_BL_FIXED
    addi    a1, s4, DISCV5_MASKED_START
    mv      a2, t0
    call    discv5_copy
    mv      a0, s2
    addi    a1, s3, DISCV5_HDR_IV
    addi    a2, sp, FL+PD_IN
    addi    a3, sp, FL+PD_OUT
    CALL_GLOBAL crypto_aes128_ctr
    addi    s6, sp, FL+PD_OUT+DISCV5_BL_FIXED

    /* The static header: "discv5", version at least 1, flag, nonce, authdata size. */
    lla     t2, 410f
    li      t0, 0
11: add     t3, s6, t0
    lbu     t3, 0(t3)
    add     t4, t2, t0
    lbu     t4, 0(t4)
    bne     t3, t4, 98f
    addi    t0, t0, 1
    BLTUI   t0, 6, 11b
    lbu     t0, 6(s6)
    lbu     t1, 7(s6)
    slli    t0, t0, 8
    or      t0, t0, t1
    beqz    t0, 98f
    lbu     s7, 8(s6)
    sd      s7, DISCV5_HDR_FLAG(s3)
    addi    a0, s3, DISCV5_HDR_NONCE
    addi    a1, s6, 9
    li      a2, 12
    call    discv5_copy
    lbu     t0, 21(s6)
    lbu     t1, 22(s6)
    slli    t0, t0, 8
    or      s8, t0, t1
    addi    t0, s5, -DISCV5_HEADER_START    # bytes after the static header
    BEQI    s7, DISCV5_FLAG_WHOAREYOU, 12f
    BLTUI   t0, 48, 98f
12: bltu    t0, s8, 98f
    BGTUI   s8, PD_AUTH_MAX, 98f

    /* The unmasked header, kept for the message's associated data. */
    addi    t0, s8, DISCV5_HEADER_START
    addi    t1, s3, DISCV5_HDR_HEADER
    BYTELIST t1, 0, DISCV5_HDR_HEADER_SIZE, t0
    addi    a0, s3, DISCV5_HDR_HEADER+DISCV5_BL_FIXED
    addi    a1, s3, DISCV5_HDR_IV
    li      a2, 16
    call    discv5_copy
    mv      a1, s6
    addi    a2, s8, DISCV5_STATIC_HEADER
    call    discv5_copy
    addi    t1, s3, DISCV5_HDR_RECORD
    BYTELIST t1, 0, DISCV5_HDR_RECORD_SIZE, zero
    addi    s6, s6, DISCV5_STATIC_HEADER    # authdata
    bnez    s7, 2f
    BNEI    s8, 32, 98f
    addi    a0, s3, DISCV5_HDR_SRC_ID
    mv      a1, s6
    li      a2, 32
    call    discv5_copy
    j       8f
2:  BNEI    s7, DISCV5_FLAG_WHOAREYOU, 3f
    BNEI    s8, 24, 98f
    addi    a0, s3, DISCV5_HDR_ID_NONCE
    mv      a1, s6
    li      a2, 16
    call    discv5_copy
    addi    a0, s6, 16
    li      a1, 8
    call    discv5_load_be
    sd      a0, DISCV5_HDR_ENR_SEQ(s3)
    j       8f
3:  BNEI    s7, DISCV5_FLAG_HANDSHAKE, 98f
    BLTUI   s8, HS_FIXED, 98f
    lbu     t0, 32(s6)
    BNEI    t0, 64, 98f
    lbu     t0, 33(s6)
    BNEI    t0, 33, 98f
    addi    t0, s8, -HS_FIXED
    BGTUI   t0, DISCV5_MAX_RECORD, 98f
    sd      t0, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(s3)
    addi    a0, s3, DISCV5_HDR_SRC_ID
    mv      a1, s6
    li      a2, 32
    call    discv5_copy
    addi    a0, s3, DISCV5_HDR_SIGNATURE
    addi    a1, s6, 34
    li      a2, 64
    call    discv5_copy
    addi    a0, s3, DISCV5_HDR_EPH_KEY
    addi    a1, s6, 98
    li      a2, 33
    call    discv5_copy
    addi    a0, s3, DISCV5_HDR_RECORD+DISCV5_BL_FIXED
    addi    a1, s6, 131
    ld      a2, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(s3)
    call    discv5_copy
8:  li      a0, DISCV5_OK
    j       99f
98: li      a0, DISCV5_INVALID_PACKET
99: LEAVE   1040
END_FUNCTION discv5_packet_decode

.set GCM_MIN, CRYPTO_GCM_TAG_SIZE + 1   /* the shortest sealed message: a tag and a byte */

/*
 * discv5_message_decrypt(header, key, packet, message) -> status: AES-GCM
 * open of the bytes after the header, with the header nonce and the
 * unmasked header as associated data. The sealed bytes at sp + FL.
 * s1 header, s2 key, s3 packet, s4 message, s5 header length, s6 sealed length.
 */
FUNCTION discv5_message_decrypt
    ENTER   1312
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    ld      s5, DISCV5_HDR_HEADER+DISCV5_BL_COUNT(s1)
    ld      s6, DISCV5_BL_COUNT(s3)
    bltu    s6, s5, 98f
    sub     s6, s6, s5
    BLTUI   s6, GCM_MIN, 98f
    BGTUI   s6, 1304, 98f
    addi    t0, sp, FL
    BYTELIST t0, 0, 1304, s6
    ld      a1, DISCV5_BL_OFFSET(s3)
    add     a1, s3, a1
    add     a1, a1, s5
    addi    a0, sp, FL+DISCV5_BL_FIXED
    mv      a2, s6
    call    discv5_copy
    mv      a0, s2
    addi    a1, s1, DISCV5_HDR_NONCE
    addi    a2, sp, FL
    addi    a3, s1, DISCV5_HDR_HEADER
    mv      a4, s4
    CALL_GLOBAL crypto_aes128_gcm_ad
    BNEI    a0, CRYPTO_GCM_FAIL, 99f
98: li      a0, DISCV5_DECRYPT_FAIL
99: LEAVE   1312
END_FUNCTION discv5_message_decrypt

/* discv5_packet_encode stack: the header to mask, the masked header, the sealed message. */
.set PE_IN, 0
.set PE_OUT, 520
.set PE_SEALED, 1040

/*
 * discv5_packet_encode(header, dest_id, key, message, packet) -> status
 * s1 header, s2 dest_id, s3 key, s4 message, s5 packet, s6 flag,
 * s7 header length, s8 total length, s9 write position.
 */
FUNCTION discv5_packet_encode
    ENTER   2352
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    ld      s6, DISCV5_HDR_FLAG(s1)

    /* The unmasked header: IV, "discv5", version 1, flag, nonce, authdata size, authdata. */
    addi    a0, s1, DISCV5_HDR_HEADER+DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_HDR_IV
    li      a2, 16
    call    discv5_copy
    lla     a1, 410f
    li      a2, 6
    call    discv5_copy
    sb      zero, 0(a0)
    li      t0, 1
    sb      t0, 1(a0)
    sb      s6, 2(a0)
    addi    a0, a0, 3
    addi    a1, s1, DISCV5_HDR_NONCE
    li      a2, 12
    call    discv5_copy
    mv      s9, a0
    bnez    s6, 1f
    li      t0, 32
    j       4f
1:  BNEI    s6, DISCV5_FLAG_WHOAREYOU, 2f
    li      t0, 24
    j       4f
2:  BNEI    s6, DISCV5_FLAG_HANDSHAKE, 98f
    ld      t0, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(s1)
    BGTUI   t0, DISCV5_MAX_RECORD, 98f
    addi    t0, t0, HS_FIXED
4:  srli    t1, t0, 8
    sb      t1, 0(s9)
    sb      t0, 1(s9)
    addi    s9, s9, 2
    addi    s7, t0, DISCV5_HEADER_START
    mv      a0, s9
    BEQI    s6, DISCV5_FLAG_WHOAREYOU, 5f
    addi    a1, s1, DISCV5_HDR_SRC_ID
    li      a2, 32
    call    discv5_copy
    BNEI    s6, DISCV5_FLAG_HANDSHAKE, 6f
    li      t0, 64
    sb      t0, 0(a0)
    li      t0, 33
    sb      t0, 1(a0)
    addi    a0, a0, 2
    addi    a1, s1, DISCV5_HDR_SIGNATURE
    li      a2, 64
    call    discv5_copy
    addi    a1, s1, DISCV5_HDR_EPH_KEY
    li      a2, 33
    call    discv5_copy
    addi    a1, s1, DISCV5_HDR_RECORD+DISCV5_BL_FIXED
    ld      a2, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(s1)
    call    discv5_copy
    j       6f
5:  addi    a1, s1, DISCV5_HDR_ID_NONCE
    li      a2, 16
    call    discv5_copy
    ld      a1, DISCV5_HDR_ENR_SEQ(s1)
    li      a2, 8
    call    discv5_store_be
6:  sd      s7, DISCV5_HDR_HEADER+DISCV5_BL_COUNT(s1)
    li      t0, DISCV5_HDR_HEADER_SIZE
    sd      t0, DISCV5_HDR_HEADER+DISCV5_BL_SIZE(s1)
    li      t0, DISCV5_BL_FIXED
    sd      t0, DISCV5_HDR_HEADER+DISCV5_BL_OFFSET(s1)

    /* Sizes: the header, then the sealed message unless this is WHOAREYOU. */
    mv      s8, s7
    BEQI    s6, DISCV5_FLAG_WHOAREYOU, 7f
    ld      t0, DISCV5_BL_COUNT(s4)
    addi    t0, t0, CRYPTO_GCM_TAG_SIZE
    add     s8, s8, t0
7:  BGTUI   s8, DISCV5_MAX_PACKET, 98f
    li      a0, DISCV5_BUFFER_TOO_SMALL
    ld      t0, DISCV5_BL_SIZE(s5)
    BLTUI   t0, DISCV5_BL_FIXED, 99f
    addi    t0, t0, -DISCV5_BL_FIXED
    bltu    t0, s8, 99f

    /* Mask: AES-CTR with the first 16 bytes of the destination ID, the IV as counter. */
    addi    t0, s7, -DISCV5_MASKED_START
    addi    t1, sp, FL+PE_IN
    BYTELIST t1, 0, 520, t0
    addi    t1, sp, FL+PE_OUT
    BYTELIST t1, 0, 520, zero
    addi    a0, sp, FL+PE_IN+DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_HDR_HEADER+DISCV5_BL_FIXED+DISCV5_MASKED_START
    mv      a2, t0
    call    discv5_copy
    mv      a0, s2
    addi    a1, s1, DISCV5_HDR_IV
    addi    a2, sp, FL+PE_IN
    addi    a3, sp, FL+PE_OUT
    CALL_GLOBAL crypto_aes128_ctr
    li      t0, DISCV5_BL_FIXED
    sd      t0, DISCV5_BL_OFFSET(s5)
    sd      s8, DISCV5_BL_COUNT(s5)
    addi    a0, s5, DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_HDR_IV
    li      a2, 16
    call    discv5_copy
    addi    a1, sp, FL+PE_OUT+DISCV5_BL_FIXED
    addi    a2, s7, -DISCV5_MASKED_START
    call    discv5_copy
    mv      s9, a0
    BEQI    s6, DISCV5_FLAG_WHOAREYOU, 8f

    /* The message: AES-GCM with the nonce, the unmasked header as associated data. */
    ADDO    t1, sp, FL+PE_SEALED
    BYTELIST t1, 0, 1304, zero
    mv      a0, s3
    addi    a1, s1, DISCV5_HDR_NONCE
    mv      a2, s4
    addi    a3, s1, DISCV5_HDR_HEADER
    ADDO    a4, sp, FL+PE_SEALED
    CALL_GLOBAL crypto_aes128_gcm_ae
    mv      a0, s9
    ADDO    a1, sp, FL+PE_SEALED+DISCV5_BL_FIXED
    ADDO    t0, sp, FL+PE_SEALED
    ld      a2, DISCV5_BL_COUNT(t0)
    call    discv5_copy
8:  li      a0, DISCV5_OK
    j       99f
98: li      a0, DISCV5_INVALID_PACKET
99: LEAVE   2352
END_FUNCTION discv5_packet_encode

/* Protocol strings. */
    .p2align 3
410:
    .ascii  "discv5"
    .zero   2
411:
    .ascii  "discovery v5 key agreement"
    .zero   6
412:
    .ascii  "discovery v5 identity proof"
    .zero   5
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
 * s1 private_key, s2 public_key, s3 challenge, s4 ids, s5 keys.
 */
FUNCTION discv5_derive_keys
    ENTER   DK_FRAME
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    addi    t1, sp, FL+DK_IKM
    li      t0, 33
    BYTELIST t1, 0, 64, t0
    mv      a0, s2
    mv      a1, s1
    addi    a2, sp, FL+DK_IKM+DISCV5_BL_FIXED
    CALL_GLOBAL crypto_secp256k1_ecdh
    bnez    a0, 98f
    addi    t1, sp, FL+DK_SALT
    li      t0, DISCV5_CHALLENGE_SIZE
    BYTELIST t1, 0, 88, t0
    addi    a0, sp, FL+DK_SALT+DISCV5_BL_FIXED
    mv      a1, s3
    li      a2, DISCV5_CHALLENGE_SIZE
    call    discv5_copy
    li      t0, 136
    sd      t0, FL+DK_SCRATCH1(sp)
    addi    t1, sp, FL+DK_PRK
    li      t0, 32
    BYTELIST t1, 0, 56, t0
    addi    a0, sp, FL+DK_SALT
    addi    a1, sp, FL+DK_IKM
    addi    a2, sp, FL+DK_SCRATCH1
    addi    a3, sp, FL+DK_PRK+DISCV5_BL_FIXED
    CALL_GLOBAL crypto_hkdf_extract
    addi    t1, sp, FL+DK_INFO
    li      t0, 90
    BYTELIST t1, 0, 120, t0
    addi    a0, sp, FL+DK_INFO+DISCV5_BL_FIXED
    lla     a1, 411b
    li      a2, 26
    call    discv5_copy
    mv      a1, s4
    li      a2, 64
    call    discv5_copy
    li      t0, 32
    sd      t0, FL+DK_LENGTH(sp)
    li      t0, 224
    sd      t0, FL+DK_SCRATCH2(sp)
    addi    t1, sp, FL+DK_OKM
    BYTELIST t1, 0, 56, zero
    addi    a0, sp, FL+DK_PRK
    addi    a1, sp, FL+DK_INFO
    addi    a2, sp, FL+DK_LENGTH
    addi    a3, sp, FL+DK_SCRATCH2
    addi    a4, sp, FL+DK_OKM
    CALL_GLOBAL crypto_hkdf_expand
    ld      t0, FL+DK_OKM+DISCV5_BL_FIXED(sp)
    sd      t0, 0(s5)
    ld      t0, FL+DK_OKM+DISCV5_BL_FIXED+8(sp)
    sd      t0, 8(s5)
    ld      t0, FL+DK_OKM+DISCV5_BL_FIXED+16(sp)
    sd      t0, 16(s5)
    ld      t0, FL+DK_OKM+DISCV5_BL_FIXED+24(sp)
    sd      t0, 24(s5)
    li      a0, DISCV5_OK
    j       99f
98: li      a0, DISCV5_INVALID_KEY
99: LEAVE   DK_FRAME
END_FUNCTION discv5_derive_keys

/*
 * The ID signature hash at sp + FL + 160: SHA-256("discovery v5 identity
 * proof" || challenge || ephemeral key || destination ID). Input: s3
 * challenge, s4 ephemeral key, s5 destination ID. The 155 input bytes at sp + FL.
 */
.macro ID_HASH unused=0
.if \unused
.endif
    addi    a0, sp, FL
    lla     a1, 412b
    li      a2, 27
    call    discv5_copy
    mv      a1, s3
    li      a2, DISCV5_CHALLENGE_SIZE
    call    discv5_copy
    mv      a1, s4
    li      a2, 33
    call    discv5_copy
    mv      a1, s5
    li      a2, 32
    call    discv5_copy
    addi    a0, sp, FL
    li      a1, 155
    addi    a2, sp, FL+160
    li      a3, 0
    call    discv5_hash
.endm

/* discv5_id_sign(private_key, challenge, ephemeral_key, dest_id, signature) -> status. s1 private key, s6 signature. */
FUNCTION discv5_id_sign
    ENTER   192
    mv      s1, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    mv      s6, a4
    ID_HASH
    mv      a0, s1
    addi    a1, sp, FL+160
    mv      a2, s6
    CALL_GLOBAL crypto_secp256k1_sign
    beqz    a0, 9f
    li      a0, DISCV5_INVALID_KEY
9:  LEAVE   192
END_FUNCTION discv5_id_sign

/*
 * discv5_id_verify(public_key, challenge, header, dest_id, valid) -> status:
 * checks the signature and ephemeral key held in header. s1 public key,
 * s2 header, s6 valid.
 */
FUNCTION discv5_id_verify
    ENTER   192
    mv      s1, a0
    mv      s3, a1
    mv      s2, a2
    addi    s4, a2, DISCV5_HDR_EPH_KEY
    mv      s5, a3
    mv      s6, a4
    ID_HASH
    mv      a0, s1
    addi    a1, sp, FL+160
    addi    a2, s2, DISCV5_HDR_SIGNATURE
    mv      a3, s6
    CALL_GLOBAL crypto_secp256k1_verify
    beqz    a0, 9f
    li      a0, DISCV5_INVALID_KEY
9:  LEAVE   192
END_FUNCTION discv5_id_verify

/* ---------------------------------------------------------------- The local record */

/*
 * discv5_entry_set(state, key, key_len, value, value_len) -> 0, or 1 when the
 * 16 entries are full: sets one entry of the local record, keeping the keys
 * sorted. key_len 1 to 16, value_len 0 to 64.
 * s1 state, s2 key, s3 key length, s4 value, s5 value length,
 * s6 entry index, s7 entry count, s8 a moving index, then the entry.
 */
LOCAL_FUNCTION discv5_entry_set
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    ld      s7, DISCV5_ST_ENTRY_COUNT(s1)
    li      s6, 0
1:  bgeu    s6, s7, 4f                      # after every key: append
    li      t0, DISCV5_LE_SIZE
    mul     t0, s6, t0
    addi    t1, s1, DISCV5_ST_ENTRIES
    add     t1, t1, t0                      # the entry
    lbu     t2, DISCV5_LE_KEY_LEN(t1)
    addi    t3, t1, DISCV5_LE_KEY
    li      t4, 0
2:  bgeu    t4, t2, 21f                     # compare the entry key with the key
    bgeu    t4, s3, 5f                      # the key is a prefix of the entry key: insert before
    add     t5, t3, t4
    lbu     t5, 0(t5)
    add     t6, s2, t4
    lbu     t6, 0(t6)
    bltu    t5, t6, 3f                      # the entry key is smaller: go on
    bltu    t6, t5, 5f                      # larger: insert before
    addi    t4, t4, 1
    j       2b
21: beq     t2, s3, 6f                      # the same key: replace the value
3:  addi    s6, s6, 1
    j       1b
4:  BGEUI   s7, DISCV5_MAX_ENTRIES, 8f
    j       7f
5:  BGEUI   s7, DISCV5_MAX_ENTRIES, 8f      # insert at s6: move entries s6.. up by one
    mv      s8, s7
51: bgeu    s6, s8, 7f
    li      t0, DISCV5_LE_SIZE
    mul     t0, s8, t0
    addi    a0, s1, DISCV5_ST_ENTRIES
    add     a0, a0, t0
    addi    a1, a0, -DISCV5_LE_SIZE
    li      a2, DISCV5_LE_SIZE
    call    discv5_copy
    addi    s8, s8, -1
    j       51b
7:  addi    s7, s7, 1
    sd      s7, DISCV5_ST_ENTRY_COUNT(s1)
6:  li      t0, DISCV5_LE_SIZE
    mul     t0, s6, t0
    addi    s8, s1, DISCV5_ST_ENTRIES
    add     s8, s8, t0
    sb      s3, DISCV5_LE_KEY_LEN(s8)
    sb      s5, DISCV5_LE_VALUE_LEN(s8)
    addi    a0, s8, DISCV5_LE_KEY
    mv      a1, s2
    mv      a2, s3
    call    discv5_copy
    addi    a0, s8, DISCV5_LE_VALUE
    mv      a1, s4
    mv      a2, s5
    call    discv5_copy
    li      a0, 0
    j       9f
8:  li      a0, 1
9:  LEAVE   0
END_FUNCTION discv5_entry_set

/* discv5_record_build stack: the payload, the content, the signature, the hash, the record. */
.set RB_PAYLOAD, 0                  /* up to 1400 bytes */
.set RB_CONTENT, 1408               /* up to 304 bytes */
.set RB_SIG, 1712                   /* 64 bytes */
.set RB_HASH, 1776                  /* 32 bytes */
.set RB_RECORD, 1808                /* up to 304 bytes */
.set RB_FRAME, 2112
.set RB_MAX_PAYLOAD, DISCV5_MAX_RECORD - 67     /* the signature takes 66 bytes, the header 1 or more */

/*
 * discv5_record_build(state) -> 0, or 1 when the record would pass 300 bytes:
 * signs [seq, k, v, ...] of the entries and writes the record to the state.
 * s1 state, s2 payload length, s3 entry index, s4 entry.
 */
LOCAL_FUNCTION discv5_record_build
    ENTER   RB_FRAME
    mv      s1, a0
    addi    a0, sp, FL+RB_PAYLOAD
    ld      a1, DISCV5_ST_SEQ(s1)
    call    discv5_rlp_uint
    li      s3, 0
1:  ld      t0, DISCV5_ST_ENTRY_COUNT(s1)
    bgeu    s3, t0, 2f
    li      t0, DISCV5_LE_SIZE
    mul     t0, s3, t0
    addi    t1, s1, DISCV5_ST_ENTRIES
    add     s4, t1, t0
    addi    a1, s4, DISCV5_LE_KEY
    lbu     a2, DISCV5_LE_KEY_LEN(s4)
    call    discv5_rlp_bytes
    addi    a1, s4, DISCV5_LE_VALUE
    lbu     a2, DISCV5_LE_VALUE_LEN(s4)
    call    discv5_rlp_bytes
    addi    s3, s3, 1
    j       1b
2:  addi    t0, sp, FL+RB_PAYLOAD
    sub     s2, a0, t0                      # payload length
    li      a0, 1
    BGTUI   s2, RB_MAX_PAYLOAD, 9f
    addi    a0, sp, FL+RB_CONTENT
    mv      a1, s2
    li      a2, 0xC0
    call    discv5_rlp_header
    addi    a1, sp, FL+RB_PAYLOAD
    mv      a2, s2
    call    discv5_copy
    addi    t0, sp, FL+RB_CONTENT
    sub     a1, a0, t0
    addi    a0, sp, FL+RB_CONTENT
    addi    a2, sp, FL+RB_HASH
    li      a3, 1
    call    discv5_hash
    addi    a0, s1, DISCV5_ST_PRIVATE_KEY
    addi    a1, sp, FL+RB_HASH
    addi    a2, sp, FL+RB_SIG
    CALL_GLOBAL crypto_secp256k1_sign
    addi    a0, sp, FL+RB_RECORD
    addi    a1, s2, 66
    li      a2, 0xC0
    call    discv5_rlp_header
    addi    a1, sp, FL+RB_SIG
    li      a2, 64
    call    discv5_rlp_bytes
    addi    a1, sp, FL+RB_PAYLOAD
    mv      a2, s2
    call    discv5_copy
    addi    t0, sp, FL+RB_RECORD
    sub     a2, a0, t0
    li      a0, 1
    BGTUI   a2, DISCV5_MAX_RECORD, 9f
    sd      a2, DISCV5_ST_RECORD_LEN(s1)
    addi    a0, s1, DISCV5_ST_RECORD
    addi    a1, sp, FL+RB_RECORD
    call    discv5_copy
    li      a0, 0
9:  LEAVE   RB_FRAME
END_FUNCTION discv5_record_build

/*
 * discv5_set_endpoint(state, endpoint): the "ip" and "udp" entries, or "ip6"
 * and "udp6", from the endpoint. A port of 0 sets no port entry. Returns 0,
 * or 1 when the entries are full. s1 state, s2 endpoint, s3 port key, s4 its
 * length, s5 port bytes, s6 result. The port bytes at sp + FL.
 */
LOCAL_FUNCTION discv5_set_endpoint
    ENTER   16
    mv      s1, a0
    mv      s2, a1
    li      s6, 0
    ld      t0, DISCV5_EP_FAMILY(s2)
    BNEI    t0, 4, 1f
    mv      a0, s1
    lla     a1, 400b+4                      # "ip"
    li      a2, 2
    addi    a3, s2, DISCV5_EP_ADDRESS
    li      a4, 4
    call    discv5_entry_set
    or      s6, s6, a0
    lla     s3, 400b+8                      # "udp"
    li      s4, 3
    j       2f
1:  BNEI    t0, 6, 9f
    mv      a0, s1
    lla     a1, 400b+12                     # "ip6"
    li      a2, 3
    addi    a3, s2, DISCV5_EP_ADDRESS
    li      a4, 16
    call    discv5_entry_set
    or      s6, s6, a0
    lla     s3, 400b+16                     # "udp6"
    li      s4, 4
2:  ld      t0, DISCV5_EP_PORT(s2)
    beqz    t0, 9f
    li      s5, 2                           # the port without leading zero bytes
    BGEUI   t0, 0x100, 3f
    li      s5, 1
3:  addi    a0, sp, FL
    mv      a1, t0
    mv      a2, s5
    call    discv5_store_be
    mv      a0, s1
    mv      a1, s3
    mv      a2, s4
    addi    a3, sp, FL
    mv      a4, s5
    call    discv5_entry_set
    or      s6, s6, a0
9:  mv      a0, s6
    LEAVE   16
END_FUNCTION discv5_set_endpoint

/*
 * discv5_init(config, state) -> status
 * s1 config, s2 state. The public key at sp + FL, the point at sp + FL + 48.
 */
FUNCTION discv5_init
    ENTER   112
    mv      s1, a0
    mv      s2, a1
    mv      a0, s1
    addi    a1, sp, FL
    CALL_GLOBAL crypto_secp256k1_public_key
    mv      t0, a0
    li      a0, DISCV5_INVALID_KEY
    bnez    t0, 9f
    mv      a0, s2
    li      a1, DISCV5_STATE_SIZE
    call    discv5_zero
    addi    a0, s2, DISCV5_ST_PRIVATE_KEY
    mv      a1, s1
    li      a2, 32
    call    discv5_copy
    addi    a0, s2, DISCV5_ST_PUBLIC_KEY
    addi    a1, sp, FL
    li      a2, 33
    call    discv5_copy
    addi    a0, sp, FL
    addi    a1, sp, FL+48
    CALL_GLOBAL crypto_secp256k1_decompress
    addi    a0, sp, FL+48
    li      a1, 64
    addi    a2, s2, DISCV5_ST_NODE_ID
    li      a3, 1
    call    discv5_hash
    ld      t0, DISCV5_CFG_SEQ(s1)
    sd      t0, DISCV5_ST_SEQ(s2)
    ld      t0, DISCV5_CFG_BUCKET_IP_LIMIT(s1)
    SDO     t0, s2, DISCV5_ST_BUCKET_IP_LIMIT
    ld      t0, DISCV5_CFG_TABLE_IP_LIMIT(s1)
    SDO     t0, s2, DISCV5_ST_TABLE_IP_LIMIT
    ld      t0, DISCV5_CFG_SUBNET4(s1)
    li      t1, 32
    bleu    t0, t1, 71f
    mv      t0, t1
71: SDO     t0, s2, DISCV5_ST_SUBNET4
    ld      t0, DISCV5_CFG_SUBNET6(s1)
    li      t1, 128
    bleu    t0, t1, 72f
    mv      t0, t1
72: SDO     t0, s2, DISCV5_ST_SUBNET6
    ld      t0, DISCV5_CFG_LIMIT_LAN(s1)
    snez    t0, t0
    SDO     t0, s2, DISCV5_ST_LIMIT_LAN
    mv      a0, s2
    addi    a1, s1, DISCV5_CFG_ENTROPY
    call    discv5_reseed
    ld      t0, DISCV5_CFG_NOW(s1)
    sd      t0, DISCV5_ST_NOW(s2)
    addi    t0, t0, DISCV5_PING_INTERVAL
    sd      t0, DISCV5_ST_NEXT_PING(s2)
    mv      a0, s2
    lla     a1, 400b                        # "id" = "v4"
    li      a2, 2
    lla     a3, 400b+2
    li      a4, 2
    call    discv5_entry_set
    mv      a0, s2
    lla     a1, 400b+24                     # "secp256k1"
    li      a2, 9
    addi    a3, s2, DISCV5_ST_PUBLIC_KEY
    li      a4, 33
    call    discv5_entry_set
    mv      a0, s2
    addi    a1, s1, DISCV5_CFG_PORT
    call    discv5_set_endpoint
    mv      a0, s2
    call    discv5_record_build
    li      a0, DISCV5_OK
9:  LEAVE   112
END_FUNCTION discv5_init

/* ---------------------------------------------------------------- The state machine: layout */

/*
 * discv5_step scratch, from its start. Every step helper takes the scratch
 * start as its first argument and keeps it in s10; the context block holds
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

/* reg = s10 + off: an address in the scratch. Uses a7. */
.macro SCR reg, off
    ADDO    \reg, s10, \off
.endm

/* reg = the state. */
.macro STATE reg
    ld      \reg, SC_CTX+CTX_STATE(s10)
.endm

/* reg = the time. */
.macro NOW reg
    ld      \reg, SC_CTX+CTX_NOW(s10)
.endm

/* ---------------------------------------------------------------- Actions */

/*
 * discv5_action(scratch, kind, size) -> the new action, zeroed, with size
 * and kind set; 0 when the actions have no room. size is a multiple of 8.
 * s1 kind, s2 size, s3 actions, s4 the action.
 */
LOCAL_FUNCTION discv5_action
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    ld      s3, SC_CTX+CTX_ACTIONS(s10)
    ld      t0, DISCV5_BL_COUNT(s3)
    ld      t1, DISCV5_BL_SIZE(s3)
    addi    t1, t1, -DISCV5_BL_FIXED
    sub     t1, t1, t0
    li      a0, 0
    bltu    t1, s2, 9f
    addi    s4, s3, DISCV5_BL_FIXED
    add     s4, s4, t0
    add     t0, t0, s2
    sd      t0, DISCV5_BL_COUNT(s3)
    mv      a0, s4
    mv      a1, s2
    call    discv5_zero
    sd      s2, DISCV5_ACT_SIZE(s4)
    sd      s1, DISCV5_ACT_KIND(s4)
    mv      a0, s4
9:  LEAVE   0
END_FUNCTION discv5_action

/* discv5_send_packet(scratch, endpoint): a SEND action with the packet in the scratch. s1 endpoint, s2 packet, s3 length, s4 action. */
LOCAL_FUNCTION discv5_send_packet
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    SCR     s2, SC_PKT
    ld      s3, DISCV5_BL_COUNT(s2)
    addi    a2, s3, DISCV5_ACT_SEND_DATA+7
    andi    a2, a2, -8
    li      a1, DISCV5_ACTION_SEND
    call    discv5_action
    beqz    a0, 9f
    mv      s4, a0
    addi    a0, s4, DISCV5_ACT_SEND_TO
    mv      a1, s1
    li      a2, DISCV5_EP_SIZE
    call    discv5_copy
    sd      s3, DISCV5_ACT_SEND_LEN(s4)
    addi    a0, s4, DISCV5_ACT_SEND_DATA
    addi    a1, s2, DISCV5_BL_FIXED
    mv      a2, s3
    call    discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_send_packet

/*
 * discv5_enr_endpoint(enr, endpoint) -> 1 when the record has a UDP endpoint:
 * "ip" and "udp", else "ip6" and "udp6", with a port above 0.
 */
LOCAL_FUNCTION discv5_enr_endpoint
    UNWIND_END_PROLOGUE
    sd      zero, 0(a1)
    sd      zero, 8(a1)
    sd      zero, 16(a1)
    sd      zero, 24(a1)
    ld      t0, DISCV5_ENR_HAS(a0)
    andi    t1, t0, (DISCV5_HAS_IP4 | DISCV5_HAS_UDP4)
    li      t2, (DISCV5_HAS_IP4 | DISCV5_HAS_UDP4)
    bne     t1, t2, 1f
    ld      t1, DISCV5_ENR_UDP4(a0)
    beqz    t1, 1f
    sd      t1, DISCV5_EP_PORT(a1)
    li      t1, 4
    sd      t1, DISCV5_EP_FAMILY(a1)
    lwu     t1, DISCV5_ENR_IP4(a0)
    sw      t1, DISCV5_EP_ADDRESS(a1)
    li      a0, 1
    ret
1:  andi    t1, t0, (DISCV5_HAS_IP6 | DISCV5_HAS_UDP6)
    li      t2, (DISCV5_HAS_IP6 | DISCV5_HAS_UDP6)
    bne     t1, t2, 2f
    ld      t1, DISCV5_ENR_UDP6(a0)
    beqz    t1, 2f
    sd      t1, DISCV5_EP_PORT(a1)
    li      t1, 6
    sd      t1, DISCV5_EP_FAMILY(a1)
    ld      t1, DISCV5_ENR_IP6(a0)
    sd      t1, DISCV5_EP_ADDRESS(a1)
    ld      t1, DISCV5_ENR_IP6+8(a0)
    sd      t1, DISCV5_EP_ADDRESS+8(a1)
    li      a0, 1
    ret
2:  li      a0, 0
    ret
END_FUNCTION discv5_enr_endpoint

/* ---------------------------------------------------------------- Sessions and challenges */

/*
 * discv5_session_find(scratch, id, endpoint) -> the session for the node ID
 * and endpoint, or 0. s1 id, s2 endpoint, s3 slot, s4 slots left.
 */
LOCAL_FUNCTION discv5_session_find
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    STATE   t0
    ADDO    s3, t0, DISCV5_ST_SESSIONS
    li      s4, DISCV5_SESSION_SLOTS
1:  ld      t0, DISCV5_S_USED(s3)
    beqz    t0, 2f
    mv      a0, s3
    mv      a1, s1
    li      a2, 32
    call    discv5_equal
    beqz    a0, 2f
    addi    a0, s3, DISCV5_S_EP
    mv      a1, s2
    li      a2, DISCV5_EP_SIZE
    call    discv5_equal
    beqz    a0, 2f
    mv      a0, s3
    j       9f
2:  addi    s3, s3, DISCV5_S_SIZE
    addi    s4, s4, -1
    bnez    s4, 1b
    li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_session_find

/*
 * discv5_session_put(scratch, id, endpoint, write_key, read_key) -> the
 * session: the slot of the same node and endpoint, else a free slot, else
 * the one used longest ago. s1 id, s2 endpoint, s3 write key, s4 read key,
 * s5 slot, s6 slots left, s7 the oldest.
 */
LOCAL_FUNCTION discv5_session_put
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    mv      s4, a4
    call    discv5_session_find
    mv      s5, a0
    bnez    s5, 5f
    STATE   t0
    ADDO    s5, t0, DISCV5_ST_SESSIONS
    mv      s7, s5
    li      s6, DISCV5_SESSION_SLOTS
1:  ld      t0, DISCV5_S_USED(s5)
    beqz    t0, 5f
    ld      t1, DISCV5_S_USED(s7)
    bgeu    t0, t1, 11f
    mv      s7, s5
11: addi    s5, s5, DISCV5_S_SIZE
    addi    s6, s6, -1
    bnez    s6, 1b
    mv      s5, s7
5:  mv      a0, s5
    mv      a1, s1
    li      a2, 32
    call    discv5_copy
    addi    a0, s5, DISCV5_S_EP
    mv      a1, s2
    li      a2, DISCV5_EP_SIZE
    call    discv5_copy
    ld      t0, 0(s3)
    sd      t0, DISCV5_S_WRITE_KEY(s5)
    ld      t0, 8(s3)
    sd      t0, DISCV5_S_WRITE_KEY+8(s5)
    ld      t0, 0(s4)
    sd      t0, DISCV5_S_READ_KEY(s5)
    ld      t0, 8(s4)
    sd      t0, DISCV5_S_READ_KEY+8(s5)
    sd      zero, DISCV5_S_COUNTER(s5)
    NOW     t0
    addi    t0, t0, 1
    sd      t0, DISCV5_S_USED(s5)
    mv      a0, s5
    LEAVE   0
END_FUNCTION discv5_session_put

/*
 * discv5_challenge_find(scratch, id, endpoint, any) -> the WHOAREYOU sent to
 * the node ID and endpoint and still valid, or 0. With any 1 and no match: a
 * free slot, else the oldest slot. Expired slots become free. C_SENT holds
 * the time plus 1. s1 id, s2 endpoint, s3 any, s4 slot, s5 slots left,
 * s6 spare, s7 the time plus 1.
 */
LOCAL_FUNCTION discv5_challenge_find
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    NOW     s7
    addi    s7, s7, 1
    STATE   t0
    ADDO    s4, t0, DISCV5_ST_CHALLENGES
    li      s6, 0
    li      s5, DISCV5_CHALLENGE_SLOTS
1:  ld      t0, DISCV5_C_SENT(s4)
    beqz    t0, 3f
    addi    t1, t0, DISCV5_CHALLENGE_TIMEOUT
    bltu    s7, t1, 2f
    sd      zero, DISCV5_C_SENT(s4)         # expired
    j       3f
2:  mv      a0, s4
    mv      a1, s1
    li      a2, 32
    call    discv5_equal
    beqz    a0, 4f
    addi    a0, s4, DISCV5_C_EP
    mv      a1, s2
    li      a2, DISCV5_EP_SIZE
    call    discv5_equal
    beqz    a0, 4f
    mv      a0, s4
    j       9f
4:  beqz    s6, 41f                         # a valid slot: the spare when it is the oldest
    ld      t1, DISCV5_C_SENT(s6)
    beqz    t1, 5f
    ld      t0, DISCV5_C_SENT(s4)
    bgeu    t0, t1, 5f
41: mv      s6, s4
    j       5f
3:  beqz    s6, 31f                         # a free slot: the spare unless one is free already
    ld      t1, DISCV5_C_SENT(s6)
    beqz    t1, 5f
31: mv      s6, s4
5:  addi    s4, s4, DISCV5_C_SIZE
    addi    s5, s5, -1
    bnez    s5, 1b
    li      a0, 0
    beqz    s3, 9f
    mv      a0, s6
9:  LEAVE   0
END_FUNCTION discv5_challenge_find

/* ---------------------------------------------------------------- Requests */

/*
 * discv5_request_find(scratch, nonce) -> the waiting request whose last
 * packet had this nonce, or 0. s1 nonce, s2 slot, s3 slots left.
 */
LOCAL_FUNCTION discv5_request_find
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    STATE   t0
    ADDO    s2, t0, DISCV5_ST_REQUESTS
    li      s3, DISCV5_REQUEST_SLOTS
1:  lbu     t0, DISCV5_R_STATE(s2)
    beqz    t0, 2f
    addi    a0, s2, DISCV5_R_NONCE
    mv      a1, s1
    li      a2, 12
    call    discv5_equal
    beqz    a0, 2f
    mv      a0, s2
    j       9f
2:  addi    s2, s2, DISCV5_R_SIZE
    addi    s3, s3, -1
    bnez    s3, 1b
    li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_request_find

/*
 * discv5_request_match(scratch, id, request_id, type) -> the waiting request
 * of this type to the node ID, from the sender's endpoint, with this request
 * ID, or 0. request_id: the 8 bytes sent. s1 id, s2 request ID, s3 type,
 * s4 slot, s5 slots left.
 */
LOCAL_FUNCTION discv5_request_match
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    STATE   t0
    ADDO    s4, t0, DISCV5_ST_REQUESTS
    li      s5, DISCV5_REQUEST_SLOTS
1:  lbu     t0, DISCV5_R_STATE(s4)
    beqz    t0, 2f
    lbu     t0, DISCV5_R_TYPE(s4)
    bne     t0, s3, 2f
    ld      t0, DISCV5_R_REQ_ID(s4)
    bne     t0, s2, 2f
    mv      a0, s4
    mv      a1, s1
    li      a2, 32
    call    discv5_equal
    beqz    a0, 2f
    addi    a0, s4, DISCV5_R_EP
    addi    a1, s10, SC_CTX+CTX_FROM
    li      a2, DISCV5_EP_SIZE
    call    discv5_equal
    beqz    a0, 2f
    mv      a0, s4
    j       9f
2:  addi    s4, s4, DISCV5_R_SIZE
    addi    s5, s5, -1
    bnez    s5, 1b
    li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_request_match

/* ---------------------------------------------------------------- The node table */

/* discv5_bucket(state, id) -> the bucket: 0 for log distances up to 240, else the distance minus 240. */
LOCAL_FUNCTION discv5_bucket
    ENTER   0
    addi    a0, a0, DISCV5_ST_NODE_ID
    call    discv5_log_distance
    li      t0, 240
    bgeu    t0, a0, 1f
    addi    a0, a0, -240
    j       9f
1:  li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_bucket

/* discv5_node_find(scratch, id) -> the table slot of the node ID, member or replacement, or 0. s1 id, s2 slot, s3 slots left. */
LOCAL_FUNCTION discv5_node_find
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    STATE   t0
    ADDO    s2, t0, DISCV5_ST_NODES
    li      s3, DISCV5_NODE_SLOTS
1:  lbu     t0, DISCV5_N_STATE(s2)
    beqz    t0, 2f
    mv      a0, s2
    mv      a1, s1
    li      a2, 32
    call    discv5_equal
    beqz    a0, 2f
    mv      a0, s2
    j       9f
2:  addi    s2, s2, DISCV5_N_SIZE
    addi    s3, s3, -1
    bnez    s3, 1b
    li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_node_find

/*
 * discv5_node_count(scratch, bucket, kind) -> the slots of this kind (1
 * member, 2 replacement) in the bucket; in a1 the free slot found first (0
 * when none), in a2 the oldest slot of the kind in the bucket.
 * t1 slot, t2 slots left, t3 free, t4 oldest.
 */
LOCAL_FUNCTION discv5_node_count
    UNWIND_END_PROLOGUE
    ld      t0, SC_CTX+CTX_STATE(a0)
    ADDO    t1, t0, DISCV5_ST_NODES
    li      t2, DISCV5_NODE_SLOTS
    li      a0, 0
    li      t3, 0
    li      t4, 0
1:  lbu     t0, DISCV5_N_STATE(t1)
    bnez    t0, 2f
    bnez    t3, 3f
    mv      t3, t1
    j       3f
2:  bne     t0, a2, 3f
    lbu     t0, DISCV5_N_BUCKET(t1)
    bne     t0, a1, 3f
    addi    a0, a0, 1
    beqz    t4, 21f
    ld      t0, DISCV5_N_ADDED(t1)
    ld      t5, DISCV5_N_ADDED(t4)
    bgeu    t0, t5, 3f
21: mv      t4, t1
3:  addi    t1, t1, DISCV5_N_SIZE
    addi    t2, t2, -1
    bnez    t2, 1b
    mv      a1, t3
    mv      a2, t4
    ret
END_FUNCTION discv5_node_count

/*
 * discv5_ip_lan(endpoint) -> 1 when the address is loopback, private or link
 * local as Go's net/netip reports them (geth's AddrIsLAN), else 0. An
 * IPv4-mapped IPv6 address counts as its IPv4 address. A leaf: a1 family,
 * a2 the address, a3-a6 and t0 values.
 */
LOCAL_FUNCTION discv5_ip_lan
    UNWIND_END_PROLOGUE
    ld      a1, DISCV5_EP_FAMILY(a0)
    addi    a2, a0, DISCV5_EP_ADDRESS
    li      t0, 4
    beq     a1, t0, 4f
    ld      a3, 0(a2)                       # bytes 0-7
    ld      a4, 8(a2)                       # bytes 8-15
    bnez    a3, 6f
    li      a5, 1
    slli    a5, a5, 56
    beq     a4, a5, 1f                      # ::1
    slli    a5, a4, 32
    srli    a5, a5, 32
    li      a6, 0xFFFF0000
    bne     a5, a6, 0f
    addi    a2, a2, 12                      # ::ffff:a.b.c.d
    j       4f
6:  lbu     a5, 0(a2)
    andi    a6, a5, 0xFE
    li      t0, 0xFC
    beq     a6, t0, 1f                      # fc00::/7
    li      t0, 0xFE
    bne     a5, t0, 0f
    lbu     a6, 1(a2)
    andi    a6, a6, 0xC0
    li      t0, 0x80
    beq     a6, t0, 1f                      # fe80::/10
    j       0f
4:  lbu     a5, 0(a2)
    lbu     a6, 1(a2)
    li      t0, 127
    beq     a5, t0, 1f                      # 127/8
    li      t0, 10
    beq     a5, t0, 1f                      # 10/8
    li      t0, 172
    bne     a5, t0, 41f
    andi    t0, a6, 0xF0
    li      a3, 16
    beq     t0, a3, 1f                      # 172.16/12
    j       0f
41: li      t0, 192
    bne     a5, t0, 42f
    li      t0, 168
    beq     a6, t0, 1f                      # 192.168/16
    j       0f
42: li      t0, 169
    bne     a5, t0, 0f
    li      t0, 254
    beq     a6, t0, 1f                      # 169.254/16
0:  li      a0, 0
    ret
1:  li      a0, 1
    ret
END_FUNCTION discv5_ip_lan

/* discv5_prefix_equal(a, b, bits) -> 1 when the first bits bits at a and b are equal, else 0. A leaf. */
LOCAL_FUNCTION discv5_prefix_equal
    UNWIND_END_PROLOGUE
    li      t0, 8
1:  bltu    a2, t0, 2f
    lbu     a3, 0(a0)
    lbu     a4, 0(a1)
    bne     a3, a4, 0f
    addi    a0, a0, 1
    addi    a1, a1, 1
    addi    a2, a2, -8
    j       1b
2:  beqz    a2, 3f
    lbu     a3, 0(a0)
    lbu     a4, 0(a1)
    xor     a3, a3, a4
    sub     a5, t0, a2
    srl     a3, a3, a5
    bnez    a3, 0f
3:  li      a0, 1
    ret
0:  li      a0, 0
    ret
END_FUNCTION discv5_prefix_equal

/*
 * discv5_ip_fits(scratch, endpoint, bucket, exclude) -> 1 when a node at the
 * endpoint keeps its subnet within the IP limits of the table and of the
 * bucket, else 0. Every used slot but exclude counts. When the local
 * network is left out of the limits, a local address always fits and never
 * counts. s1 endpoint, s2 bucket, s3 exclude, s4 slot, s5 slots left,
 * s6 table count, s7 bucket count, s8 prefix bits, s9 state.
 */
LOCAL_FUNCTION discv5_ip_fits
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    STATE   s9
    LDO     t0, s9, DISCV5_ST_BUCKET_IP_LIMIT
    LDO     t1, s9, DISCV5_ST_TABLE_IP_LIMIT
    or      t0, t0, t1
    beqz    t0, 8f                          # no limits
    LDO     t0, s9, DISCV5_ST_LIMIT_LAN
    bnez    t0, 1f
    mv      a0, s1
    call    discv5_ip_lan
    bnez    a0, 8f                          # a local address
1:  ld      t0, DISCV5_EP_FAMILY(s1)
    LDO     s8, s9, DISCV5_ST_SUBNET4
    li      t1, 4
    beq     t0, t1, 2f
    LDO     s8, s9, DISCV5_ST_SUBNET6
2:  ADDO    s4, s9, DISCV5_ST_NODES
    li      s5, DISCV5_NODE_SLOTS
    li      s6, 0
    li      s7, 0
3:  lbu     t0, DISCV5_N_STATE(s4)
    beqz    t0, 7f
    beq     s4, s3, 7f
    ld      t0, DISCV5_N_EP+DISCV5_EP_FAMILY(s4)
    ld      t1, DISCV5_EP_FAMILY(s1)
    bne     t0, t1, 7f
    addi    a0, s4, DISCV5_N_EP+DISCV5_EP_ADDRESS
    addi    a1, s1, DISCV5_EP_ADDRESS
    mv      a2, s8
    call    discv5_prefix_equal
    beqz    a0, 7f
    LDO     t0, s9, DISCV5_ST_LIMIT_LAN
    bnez    t0, 5f
    addi    a0, s4, DISCV5_N_EP
    call    discv5_ip_lan
    bnez    a0, 7f                          # a local address never counts
5:  addi    s6, s6, 1
    lbu     t0, DISCV5_N_BUCKET(s4)
    bne     t0, s2, 7f
    addi    s7, s7, 1
7:  addi    s4, s4, DISCV5_N_SIZE
    addi    s5, s5, -1
    bnez    s5, 3b
    li      a0, 0
    LDO     t0, s9, DISCV5_ST_TABLE_IP_LIMIT
    beqz    t0, 71f
    bgeu    s6, t0, 9f
71: LDO     t0, s9, DISCV5_ST_BUCKET_IP_LIMIT
    beqz    t0, 8f
    bgeu    s7, t0, 9f
8:  li      a0, 1
9:  LEAVE   0
END_FUNCTION discv5_ip_fits

/*
 * discv5_node_add(scratch, enr, record) -> the slot, or 0: adds a checked
 * record with a UDP endpoint to the table, or updates its slot when the
 * record is newer. A full bucket takes it as a replacement; a full
 * replacement list drops its oldest. A node that would pass an IP limit is
 * left out; a newer record whose address would pass one is not taken, and
 * the slot keeps the old record. s1 enr, s2 record, s3 slot,
 * s4 bucket, s5 kind. The endpoint at sp + FL.
 */
LOCAL_FUNCTION discv5_node_add
    ENTER   32
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      a0, s1
    addi    a1, sp, FL
    call    discv5_enr_endpoint
    beqz    a0, 9f
    STATE   t0
    addi    a0, t0, DISCV5_ST_NODE_ID
    mv      a1, s1
    li      a2, 32
    call    discv5_equal
    mv      t0, a0
    li      a0, 0
    bnez    t0, 9f                          # ourselves
    mv      a0, s10
    mv      a1, s1
    call    discv5_node_find
    mv      s3, a0
    beqz    s3, 1f
    ld      t0, DISCV5_N_SEQ(s3)            # known: keep the newer record
    ld      t1, DISCV5_ENR_SEQ(s1)
    bgeu    t0, t1, 9f
    mv      a0, s10
    addi    a1, sp, FL
    lbu     a2, DISCV5_N_BUCKET(s3)
    mv      a3, s3
    call    discv5_ip_fits
    mv      t0, a0
    mv      a0, s3
    beqz    t0, 9f                          # the new address passes a limit
    j       6f
1:  STATE   a0
    mv      a1, s1
    call    discv5_bucket
    mv      s4, a0
    mv      a0, s10
    addi    a1, sp, FL
    mv      a2, s4
    li      a3, 0
    call    discv5_ip_fits
    beqz    a0, 9f                          # the subnet is full
    mv      a0, s10
    mv      a1, s4
    li      a2, DISCV5_NODE_MEMBER
    call    discv5_node_count
    mv      s3, a1
    BGEUI   a0, DISCV5_K, 2f
    li      s5, DISCV5_NODE_MEMBER
    j       5f
2:  mv      a0, s10
    mv      a1, s4
    li      a2, DISCV5_NODE_REPLACEMENT
    call    discv5_node_count
    mv      s3, a1
    BLTUI   a0, DISCV5_REPLACEMENTS, 3f
    mv      s3, a2                          # replace the oldest replacement
3:  li      s5, DISCV5_NODE_REPLACEMENT
5:  li      a0, 0
    beqz    s3, 9f
    mv      a0, s3
    li      a1, DISCV5_N_SIZE
    call    discv5_zero
    sb      s5, DISCV5_N_STATE(s3)
    sb      s4, DISCV5_N_BUCKET(s3)
    NOW     t0
    sd      t0, DISCV5_N_ADDED(s3)
    sd      t0, DISCV5_N_CHECK(s3)
    STATE   t1
    ld      t2, DISCV5_ST_NEXT_REFRESH(t1)
    bnez    t2, 6f
    addi    t0, t0, DISCV5_PING_INTERVAL    # the first node: look up our own ID soon
    sd      t0, DISCV5_ST_NEXT_REFRESH(t1)
6:  mv      a0, s3
    mv      a1, s1
    li      a2, 32
    call    discv5_copy
    addi    a0, s3, DISCV5_N_PUBKEY
    addi    a1, s1, DISCV5_ENR_PUBKEY
    li      a2, 33
    call    discv5_copy
    addi    a0, s3, DISCV5_N_EP
    addi    a1, sp, FL
    li      a2, DISCV5_EP_SIZE
    call    discv5_copy
    ld      t0, DISCV5_ENR_SEQ(s1)
    sd      t0, DISCV5_N_SEQ(s3)
    ld      a2, DISCV5_BL_COUNT(s2)
    sd      a2, DISCV5_N_RECORD_LEN(s3)
    ld      t0, DISCV5_BL_OFFSET(s2)
    add     a1, s2, t0
    addi    a0, s3, DISCV5_N_RECORD
    call    discv5_copy
    mv      a0, s3
9:  LEAVE   32
END_FUNCTION discv5_node_add

/*
 * discv5_node_remove(scratch, slot): frees the slot. A member's place goes
 * to the newest replacement of its bucket. t2 slot, t3 slots left, t4 the
 * newest replacement.
 */
LOCAL_FUNCTION discv5_node_remove
    UNWIND_END_PROLOGUE
    lbu     t0, DISCV5_N_STATE(a1)
    lbu     t1, DISCV5_N_BUCKET(a1)
    sb      zero, DISCV5_N_STATE(a1)
    BNEI    t0, DISCV5_NODE_MEMBER, 9f
    ld      t2, SC_CTX+CTX_STATE(a0)
    ADDO    t2, t2, DISCV5_ST_NODES
    li      t3, DISCV5_NODE_SLOTS
    li      t4, 0
1:  lbu     t5, DISCV5_N_STATE(t2)
    BNEI    t5, DISCV5_NODE_REPLACEMENT, 2f
    lbu     t5, DISCV5_N_BUCKET(t2)
    bne     t5, t1, 2f
    beqz    t4, 11f
    ld      t5, DISCV5_N_ADDED(t2)
    ld      t6, DISCV5_N_ADDED(t4)
    bltu    t5, t6, 2f
11: mv      t4, t2
2:  addi    t2, t2, DISCV5_N_SIZE
    addi    t3, t3, -1
    bnez    t3, 1b
    beqz    t4, 9f
    li      t5, DISCV5_NODE_MEMBER
    sb      t5, DISCV5_N_STATE(t4)
    sb      zero, DISCV5_N_LIVE(t4)
    sb      zero, DISCV5_N_FAILS(t4)
    ld      t5, SC_CTX+CTX_NOW(a0)
    sd      t5, DISCV5_N_CHECK(t4)
9:  ret
END_FUNCTION discv5_node_remove

/* ---------------------------------------------------------------- Messages out */

.set RANDOM_PLAIN, DISCV5_RANDOM_MESSAGE - CRYPTO_GCM_TAG_SIZE      /* plaintext bytes of a random message */
.set WHOAREYOU_MASKED, DISCV5_CHALLENGE_SIZE - DISCV5_MASKED_START  /* masked bytes of a WHOAREYOU */

/* reg = the payload of RLP item item, a pointer to its Item record in the message. Uses a7. */
.macro ITEM_DATA reg, item
    ld      \reg, RLP_ITEM_OFFSET(\item)
    li      a7, SC_RLP+DISCV5_BL_FIXED
    add     \reg, \reg, a7
    add     \reg, \reg, s10
.endm

/*
 * discv5_msg_finish(scratch, type, end): the message in the scratch becomes
 * the type byte, then an RLP list of the payload from SC_TMP up to end.
 * s1 type, s2 payload length, s3 message.
 */
LOCAL_FUNCTION discv5_msg_finish
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    SCR     t0, SC_TMP
    sub     s2, a2, t0
    SCR     s3, SC_MSG
    BYTELIST s3, 0, BL_PACKET_SIZE, zero
    addi    a0, s3, DISCV5_BL_FIXED
    sb      s1, 0(a0)
    addi    a0, a0, 1
    mv      a1, s2
    li      a2, 0xC0
    call    discv5_rlp_header
    SCR     a1, SC_TMP
    mv      a2, s2
    call    discv5_copy
    addi    t0, s3, DISCV5_BL_FIXED
    sub     t0, a0, t0
    sd      t0, DISCV5_BL_COUNT(s3)
    LEAVE   0
END_FUNCTION discv5_msg_finish

/*
 * discv5_send_message(scratch, id, endpoint) -> the nonce used, 12 bytes in
 * the scratch. Sends the message in the scratch to the node. With a session
 * for the node ID and endpoint it goes as an ordinary message; else the
 * packet carries 20 random message bytes, so that the node answers with
 * WHOAREYOU. s1 id, s2 endpoint, s3 session, s4 header, s5 state, s6 the
 * random message, s7 key, s8 message.
 */
LOCAL_FUNCTION discv5_send_message
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    STATE   s5
    SCR     s4, SC_HDR2
    sd      zero, DISCV5_HDR_FLAG(s4)
    mv      a0, s5
    addi    a1, s4, DISCV5_HDR_IV
    li      a2, 16
    call    discv5_random
    addi    a0, s4, DISCV5_HDR_SRC_ID
    addi    a1, s5, DISCV5_ST_NODE_ID
    li      a2, 32
    call    discv5_copy
    mv      a0, s10
    mv      a1, s1
    mv      a2, s2
    call    discv5_session_find
    mv      s3, a0
    beqz    s3, 1f

    /* The nonce: the message count, 4 bytes big endian, then 8 random bytes. */
    ld      t0, DISCV5_S_COUNTER(s3)
    addi    t0, t0, 1
    sd      t0, DISCV5_S_COUNTER(s3)
    NOW     t1
    addi    t1, t1, 1
    sd      t1, DISCV5_S_USED(s3)
    addi    a0, s4, DISCV5_HDR_NONCE
    mv      a1, t0
    li      a2, 4
    call    discv5_store_be
    mv      a0, s5
    addi    a1, s4, DISCV5_HDR_NONCE+4
    li      a2, 8
    call    discv5_random
    addi    s7, s3, DISCV5_S_WRITE_KEY
    SCR     s8, SC_MSG
    j       2f

    /* No session: a random nonce, and 4 random bytes sealed under a random key. */
1:  mv      a0, s5
    addi    a1, s4, DISCV5_HDR_NONCE
    li      a2, 12
    call    discv5_random
    mv      a0, s5
    SCR     a1, SC_KEYS
    li      a2, 16
    call    discv5_random
    SCR     s6, SC_EPH
    li      t0, RANDOM_PLAIN
    BYTELIST s6, 0, 48, t0
    mv      a0, s5
    addi    a1, s6, DISCV5_BL_FIXED
    li      a2, RANDOM_PLAIN
    call    discv5_random
    SCR     s7, SC_KEYS
    mv      s8, s6
2:  SCR     a4, SC_PKT
    BYTELIST a4, 0, BL_PACKET_SIZE, zero
    mv      a0, s4
    mv      a1, s1
    mv      a2, s7
    mv      a3, s8
    CALL_GLOBAL discv5_packet_encode
    bnez    a0, 9f
    mv      a0, s10
    mv      a1, s2
    call    discv5_send_packet
9:  addi    a0, s4, DISCV5_HDR_NONCE
    LEAVE   0
END_FUNCTION discv5_send_message

/*
 * discv5_challenge_new(scratch, challenge): a new WHOAREYOU for the sender
 * of the packet received, answering its nonce, in the challenge slot. The
 * enr-seq is the sequence number of the sender's record in the table, else
 * 0. s1 challenge, s2 id-nonce position, s3 state, s4 header received.
 */
LOCAL_FUNCTION discv5_challenge_new
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    STATE   s3
    addi    s4, s10, SC_HDR
    mv      a0, s1
    addi    a1, s4, DISCV5_HDR_SRC_ID
    li      a2, 32
    call    discv5_copy
    addi    a0, s1, DISCV5_C_EP
    addi    a1, s10, SC_CTX+CTX_FROM
    li      a2, DISCV5_EP_SIZE
    call    discv5_copy
    NOW     t0
    addi    t0, t0, 1
    sd      t0, DISCV5_C_SENT(s1)
    mv      a0, s3
    addi    a1, s1, DISCV5_C_DATA
    li      a2, 16
    call    discv5_random
    addi    a0, s1, DISCV5_C_DATA+DISCV5_MASKED_START
    lla     a1, 410b
    li      a2, 6
    call    discv5_copy
    sb      zero, 0(a0)
    li      t0, 1
    sb      t0, 1(a0)
    li      t0, DISCV5_FLAG_WHOAREYOU
    sb      t0, 2(a0)
    addi    a0, a0, 3
    addi    a1, s4, DISCV5_HDR_NONCE
    li      a2, 12
    call    discv5_copy
    sb      zero, 0(a0)
    li      t0, 24
    sb      t0, 1(a0)
    addi    s2, a0, 2
    mv      a0, s3
    mv      a1, s2
    li      a2, 16
    call    discv5_random                   # id-nonce
    mv      a0, s10
    addi    a1, s4, DISCV5_HDR_SRC_ID
    call    discv5_node_find
    beqz    a0, 1f
    ld      a0, DISCV5_N_SEQ(a0)
1:  mv      a1, a0
    addi    a0, s2, 16
    li      a2, 8
    call    discv5_store_be
    LEAVE   0
END_FUNCTION discv5_challenge_new

/*
 * discv5_send_whoareyou(scratch, challenge): sends the stored WHOAREYOU: its
 * IV, then the rest masked with AES-CTR under the first 16 bytes of the
 * challenged node ID, the IV as counter. s1 challenge, s2 masking input,
 * s3 masking output, s4 packet.
 */
LOCAL_FUNCTION discv5_send_whoareyou
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    SCR     s2, SC_TMP
    addi    s3, s2, 80
    li      t0, WHOAREYOU_MASKED
    BYTELIST s2, 0, 72, t0
    BYTELIST s3, 0, 72, zero
    addi    a0, s2, DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_C_DATA+DISCV5_MASKED_START
    li      a2, WHOAREYOU_MASKED
    call    discv5_copy
    mv      a0, s1
    addi    a1, s1, DISCV5_C_DATA
    mv      a2, s2
    mv      a3, s3
    CALL_GLOBAL crypto_aes128_ctr
    SCR     s4, SC_PKT
    li      t0, DISCV5_CHALLENGE_SIZE
    BYTELIST s4, 0, BL_PACKET_SIZE, t0
    addi    a0, s4, DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_C_DATA
    li      a2, DISCV5_MASKED_START
    call    discv5_copy
    addi    a1, s3, DISCV5_BL_FIXED
    li      a2, WHOAREYOU_MASKED
    call    discv5_copy
    mv      a0, s10
    addi    a1, s1, DISCV5_C_EP
    call    discv5_send_packet
    LEAVE   0
END_FUNCTION discv5_send_whoareyou

/* ---------------------------------------------------------------- Actions with records */

/* discv5_emit_record(scratch): a RECORD action with the local record. s1 state, s2 length. */
LOCAL_FUNCTION discv5_emit_record
    ENTER   0
    mv      s10, a0
    STATE   s1
    ld      s2, DISCV5_ST_RECORD_LEN(s1)
    addi    a2, s2, DISCV5_ACT_RECORD_DATA+7
    andi    a2, a2, -8
    li      a1, DISCV5_ACTION_RECORD
    call    discv5_action
    beqz    a0, 9f
    sd      s2, DISCV5_ACT_RECORD_LEN(a0)
    addi    a0, a0, DISCV5_ACT_RECORD_DATA
    addi    a1, s1, DISCV5_ST_RECORD
    mv      a2, s2
    call    discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_emit_record

/* discv5_emit_found(scratch): a NODE_FOUND action with the checked record in the scratch. s1 record, s2 length, s3 action. */
LOCAL_FUNCTION discv5_emit_found
    ENTER   0
    mv      s10, a0
    SCR     s1, SC_REC
    ld      s2, DISCV5_BL_COUNT(s1)
    addi    a2, s2, DISCV5_ACT_FOUND_DATA+7
    andi    a2, a2, -8
    li      a1, DISCV5_ACTION_NODE_FOUND
    call    discv5_action
    beqz    a0, 9f
    mv      s3, a0
    sd      s2, DISCV5_ACT_FOUND_LEN(s3)
    addi    a0, s3, DISCV5_ACT_FOUND_ID
    SCR     a1, SC_ENR+DISCV5_ENR_NODE_ID
    li      a2, 32
    call    discv5_copy
    addi    a0, s3, DISCV5_ACT_FOUND_DATA
    ld      t0, DISCV5_BL_OFFSET(s1)
    add     a1, s1, t0
    mv      a2, s2
    call    discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_emit_found

/* discv5_emit_done(scratch, target, found): a LOOKUP_DONE action. s1 target, s2 found. */
LOCAL_FUNCTION discv5_emit_done
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    li      a1, DISCV5_ACTION_LOOKUP_DONE
    li      a2, DISCV5_ACT_DONE_SIZE
    call    discv5_action
    beqz    a0, 9f
    sd      s2, DISCV5_ACT_DONE_FOUND(a0)
    addi    a0, a0, DISCV5_ACT_DONE_TARGET
    mv      a1, s1
    li      a2, 32
    call    discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_emit_done

/* ---------------------------------------------------------------- Requests out */

/*
 * discv5_request_message(scratch, request): the request's message in the
 * scratch: PING [request-id, enr-seq] or FINDNODE [request-id, [distance,
 * ...]]. The request ID is 8 bytes, big endian. s1 request, s2 write
 * position, s3 distance list header, s4 distance index.
 */
LOCAL_FUNCTION discv5_request_message
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    SCR     s2, SC_TMP
    li      t0, 0x88
    sb      t0, 0(s2)
    addi    a0, s2, 1
    ld      a1, DISCV5_R_REQ_ID(s1)
    li      a2, 8
    call    discv5_store_be
    addi    s2, s2, 9
    lbu     t0, DISCV5_R_TYPE(s1)
    BNEI    t0, DISCV5_MSG_PING, 1f
    mv      a0, s2
    STATE   t0
    ld      a1, DISCV5_ST_SEQ(t0)
    call    discv5_rlp_uint
    mv      a2, a0
    li      a1, DISCV5_MSG_PING
    j       8f
1:  mv      s3, s2
    addi    s2, s2, 1
    li      s4, 0
2:  lbu     t0, DISCV5_R_DIST_COUNT(s1)
    bgeu    s4, t0, 3f
    slli    t0, s4, 1
    add     t0, s1, t0
    lhu     a1, DISCV5_R_DISTANCES(t0)
    mv      a0, s2
    call    discv5_rlp_uint
    mv      s2, a0
    addi    s4, s4, 1
    j       2b
3:  sub     t0, s2, s3                      # at most 3 distances: a one-byte list header
    addi    t0, t0, 0xC0-1
    sb      t0, 0(s3)
    mv      a2, s2
    li      a1, DISCV5_MSG_FINDNODE
8:  mv      a0, s10
    call    discv5_msg_finish
    LEAVE   0
END_FUNCTION discv5_request_message

/*
 * discv5_request_start(scratch, node, kind, count, distances) -> the request,
 * or 0 when every request slot is busy. node: ID, public key and endpoint,
 * the first 104 bytes of a table slot or lookup candidate. kind: the message
 * type, the purpose << 8, the lookup slot << 16. distances: count u16
 * values, the first in the low bits. s1 node, s2 kind, s3 count,
 * s4 distances, s5 slot, s6 slots left.
 */
LOCAL_FUNCTION discv5_request_start
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    mv      s4, a4
    STATE   t0
    ADDO    s5, t0, DISCV5_ST_REQUESTS
    li      s6, DISCV5_REQUEST_SLOTS
1:  lbu     t0, DISCV5_R_STATE(s5)
    beqz    t0, 2f
    addi    s5, s5, DISCV5_R_SIZE
    addi    s6, s6, -1
    bnez    s6, 1b
    li      a0, 0
    j       9f
2:  mv      a0, s5
    li      a1, DISCV5_R_SIZE
    call    discv5_zero
    mv      a0, s5
    mv      a1, s1
    li      a2, 104
    call    discv5_copy
    STATE   t0
    ld      t1, DISCV5_ST_REQ_ID(t0)
    addi    t1, t1, 1
    sd      t1, DISCV5_ST_REQ_ID(t0)
    sd      t1, DISCV5_R_REQ_ID(s5)
    li      t0, DISCV5_REQ_WAITING
    sb      t0, DISCV5_R_STATE(s5)
    sb      s2, DISCV5_R_TYPE(s5)
    srli    t0, s2, 8
    sb      t0, DISCV5_R_PURPOSE(s5)
    srli    t0, s2, 16
    sb      t0, DISCV5_R_LOOKUP(s5)
    NOW     t0
    addi    t0, t0, DISCV5_REQUEST_TIMEOUT
    sd      t0, DISCV5_R_DEADLINE(s5)
    sb      s3, DISCV5_R_DIST_COUNT(s5)
    sw      s4, DISCV5_R_DISTANCES(s5)
    srli    t0, s4, 32
    sh      t0, DISCV5_R_DISTANCES+4(s5)
    mv      a0, s10
    mv      a1, s5
    call    discv5_request_message
    mv      a0, s10
    mv      a1, s5
    addi    a2, s5, DISCV5_R_EP
    call    discv5_send_message
    mv      a1, a0
    addi    a0, s5, DISCV5_R_NONCE
    li      a2, 12
    call    discv5_copy
    mv      a0, s5
9:  LEAVE   0
END_FUNCTION discv5_request_start

/*
 * discv5_request_end(scratch, request, ok): frees the request and uses the
 * result. A check marks the node live, or counts a failure: a node that is
 * not live, or failed DISCV5_MAX_FAILS times in a row, leaves the table. A
 * lookup request marks its candidate answered or failed and moves the
 * lookup on. s1 request, s2 ok, s3 purpose, s4 node or lookup.
 */
LOCAL_FUNCTION discv5_request_end
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    sb      zero, DISCV5_R_STATE(s1)
    lbu     s3, DISCV5_R_PURPOSE(s1)
    BNEI    s3, DISCV5_PURPOSE_CHECK, 3f
    mv      a0, s10
    mv      a1, s1
    call    discv5_node_find
    beqz    a0, 9f
    mv      s4, a0
    sb      zero, DISCV5_N_PINGING(s4)
    beqz    s2, 1f
    li      t0, 1
    sb      t0, DISCV5_N_LIVE(s4)
    sb      zero, DISCV5_N_FAILS(s4)
    j       9f
1:  lbu     t0, DISCV5_N_FAILS(s4)
    addi    t0, t0, 1
    sb      t0, DISCV5_N_FAILS(s4)
    NOW     t1
    sd      t1, DISCV5_N_CHECK(s4)          # check again soon
    lbu     t1, DISCV5_N_LIVE(s4)
    beqz    t1, 2f
    BLTUI   t0, DISCV5_MAX_FAILS, 9f
2:  mv      a0, s10
    mv      a1, s4
    call    discv5_node_remove
    j       9f
3:  BNEI    s3, DISCV5_PURPOSE_LOOKUP, 9f
    lbu     t0, DISCV5_R_LOOKUP(s1)
    li      t1, DISCV5_L_SIZE
    mul     t0, t0, t1
    STATE   t1
    ADDO    t1, t1, DISCV5_ST_LOOKUPS
    add     s4, t1, t0
    ld      t0, DISCV5_L_ACTIVE(s4)
    beqz    t0, 9f
    mv      a0, s4
    mv      a1, s1
    call    discv5_candidate_find
    beqz    a0, 5f
    li      t0, DISCV5_LC_FAILED
    beqz    s2, 4f
    li      t0, DISCV5_LC_ANSWERED
4:  sd      t0, DISCV5_LC_STATE(a0)
5:  mv      a0, s10
    mv      a1, s4
    call    discv5_lookup_advance
9:  LEAVE   0
END_FUNCTION discv5_request_end

/* ---------------------------------------------------------------- Lookups */

/* reg = candidate index of the lookup in s1. Uses a7. */
.macro CANDIDATE reg, index
    li      a7, DISCV5_LC_SIZE
    mul     \reg, \index, a7
    add     \reg, \reg, s1
    addi    \reg, \reg, DISCV5_L_CANDIDATES
.endm

/* discv5_candidate_find(lookup, id) -> the lookup's candidate with the node ID, or 0. s1 lookup, s2 id, s3 index, s4 candidate. */
LOCAL_FUNCTION discv5_candidate_find
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    li      s3, 0
1:  ld      t0, DISCV5_L_COUNT(s1)
    bgeu    s3, t0, 8f
    CANDIDATE s4, s3
    mv      a0, s4
    mv      a1, s2
    li      a2, 32
    call    discv5_equal
    bnez    a0, 2f
    addi    s3, s3, 1
    j       1b
2:  mv      a0, s4
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_candidate_find

/* discv5_closer(a, b, target) -> 1 when ID a is closer to the target than ID b: a XOR target is below b XOR target. */
LOCAL_FUNCTION discv5_closer
    UNWIND_END_PROLOGUE
    li      t0, 0
1:  add     t1, a0, t0
    lbu     t1, 0(t1)
    add     t2, a1, t0
    lbu     t2, 0(t2)
    add     t3, a2, t0
    lbu     t3, 0(t3)
    xor     t1, t1, t3
    xor     t2, t2, t3
    bne     t1, t2, 2f
    addi    t0, t0, 1
    li      t3, 32
    bltu    t0, t3, 1b
    li      a0, 0
    ret
2:  sltu    a0, t1, t2
    ret
END_FUNCTION discv5_closer

/*
 * discv5_candidate_insert(scratch, lookup, node) -> 1 when the node joins the
 * candidates. They stay sorted by distance to the target, closest first, and
 * keep the DISCV5_K closest; the local node and known candidates are left
 * out. node: ID, public key and endpoint, 104 bytes. s1 lookup, s2 node,
 * s3 position, s4 count, s5 candidate.
 */
LOCAL_FUNCTION discv5_candidate_insert
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    STATE   t0
    addi    a0, t0, DISCV5_ST_NODE_ID
    mv      a1, s2
    li      a2, 32
    call    discv5_equal
    bnez    a0, 8f
    mv      a0, s1
    mv      a1, s2
    call    discv5_candidate_find
    bnez    a0, 8f
    ld      s4, DISCV5_L_COUNT(s1)
    li      s3, 0
1:  bgeu    s3, s4, 2f
    CANDIDATE a1, s3
    mv      a0, s2
    mv      a2, s1                          # the target
    call    discv5_closer
    bnez    a0, 2f
    addi    s3, s3, 1
    j       1b
2:  BGEUI   s3, DISCV5_K, 8f
    BLTUI   s4, DISCV5_K, 3f                # full: the last one drops out
    li      s4, DISCV5_K-1
3:  bgeu    s3, s4, 4f                      # move position to count - 1 down by one, from the end
    addi    s4, s4, -1
    CANDIDATE a1, s4
    addi    a0, a1, DISCV5_LC_SIZE
    li      a2, DISCV5_LC_SIZE
    call    discv5_copy
    j       3b
4:  CANDIDATE s5, s3
    mv      a0, s5
    mv      a1, s2
    li      a2, 104
    call    discv5_copy
    sd      zero, DISCV5_LC_STATE(s5)
    ld      t0, DISCV5_L_COUNT(s1)
    addi    t0, t0, 1
    BLEUI   t0, DISCV5_K, 5f
    li      t0, DISCV5_K
5:  sd      t0, DISCV5_L_COUNT(s1)
    li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_candidate_insert

/*
 * discv5_lookup_distances(target, id) -> in a0 the distances to ask the node
 * for, in a1 their count: d, then d + 1 and d - 1, d + 2 and d - 2, ... up
 * to 3, keeping 1 to 256, with d the log distance of the target and the
 * node. Packed as u16 values, the first in the low bits.
 * s1 d, s2 packed, s3 count, s4 step.
 */
LOCAL_FUNCTION discv5_lookup_distances
    ENTER   0
    call    discv5_log_distance
    mv      s1, a0
    mv      s2, a0
    li      s3, 1
    li      s4, 1
1:  BGEUI   s3, 3, 9f
    add     t0, s1, s4
    BGTUI   t0, 256, 2f
    slli    t1, s3, 4
    sll     t0, t0, t1
    or      s2, s2, t0
    addi    s3, s3, 1
2:  BGEUI   s3, 3, 9f
    sub     t0, s1, s4
    blez    t0, 3f
    slli    t1, s3, 4
    sll     t0, t0, t1
    or      s2, s2, t0
    addi    s3, s3, 1
3:  addi    s4, s4, 1
    j       1b
9:  mv      a0, s2
    mv      a1, s3
    LEAVE   0
END_FUNCTION discv5_lookup_distances

/*
 * discv5_lookup_advance(scratch, lookup): asks new candidates, closest
 * first, while fewer than DISCV5_ALPHA requests are pending. With nothing
 * pending and nothing new, the lookup ends with a LOOKUP_DONE action.
 * s1 lookup, s2 pending, s3 index, s4 candidate, s5 new candidates not
 * asked, s6 lookup slot number.
 */
LOCAL_FUNCTION discv5_lookup_advance
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    ld      t0, DISCV5_L_ACTIVE(s1)
    beqz    t0, 9f
    STATE   t0
    ADDO    t0, t0, DISCV5_ST_LOOKUPS
    sub     t0, s1, t0
    li      t1, DISCV5_L_SIZE
    divu    s6, t0, t1
    li      s2, 0
    li      s3, 0
1:  ld      t0, DISCV5_L_COUNT(s1)
    bgeu    s3, t0, 2f
    CANDIDATE s4, s3
    ld      t1, DISCV5_LC_STATE(s4)
    BNEI    t1, DISCV5_LC_ASKED, 11f
    addi    s2, s2, 1
11: addi    s3, s3, 1
    j       1b
2:  li      s3, 0
    li      s5, 0
3:  ld      t0, DISCV5_L_COUNT(s1)
    bgeu    s3, t0, 5f
    CANDIDATE s4, s3
    ld      t1, DISCV5_LC_STATE(s4)
    bnez    t1, 4f
    BGEUI   s2, DISCV5_ALPHA, 41f
    mv      a0, s1
    mv      a1, s4
    call    discv5_lookup_distances
    mv      a3, a1
    mv      a4, a0
    slli    a2, s6, 16
    ori     a2, a2, DISCV5_MSG_FINDNODE | (DISCV5_PURPOSE_LOOKUP << 8)
    mv      a0, s10
    mv      a1, s4
    call    discv5_request_start
    beqz    a0, 41f
    li      t0, DISCV5_LC_ASKED
    sd      t0, DISCV5_LC_STATE(s4)
    addi    s2, s2, 1
    j       4f
41: addi    s5, s5, 1
4:  addi    s3, s3, 1
    j       3b
5:  or      t0, s2, s5
    bnez    t0, 9f
    sd      zero, DISCV5_L_ACTIVE(s1)
    mv      a0, s10
    mv      a1, s1
    ld      a2, DISCV5_L_FOUND(s1)
    call    discv5_emit_done
9:  LEAVE   0
END_FUNCTION discv5_lookup_advance

/*
 * discv5_lookup_start(scratch, target): starts a lookup of the target from
 * the table members. With every lookup slot busy it ends at once with
 * LOOKUP_DONE and 0 found. s1 target, s2 lookup, s3 slots left,
 * s4 node slot, s5 nodes left.
 */
LOCAL_FUNCTION discv5_lookup_start
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    STATE   t0
    ADDO    s2, t0, DISCV5_ST_LOOKUPS
    li      s3, DISCV5_LOOKUP_SLOTS
1:  ld      t0, DISCV5_L_ACTIVE(s2)
    beqz    t0, 2f
    addi    s2, s2, DISCV5_L_SIZE
    addi    s3, s3, -1
    bnez    s3, 1b
    mv      a0, s10
    mv      a1, s1
    li      a2, 0
    call    discv5_emit_done
    j       9f
2:  mv      a0, s2
    li      a1, DISCV5_L_SIZE
    call    discv5_zero
    mv      a0, s2
    mv      a1, s1
    li      a2, 32
    call    discv5_copy
    li      t0, 1
    sd      t0, DISCV5_L_ACTIVE(s2)
    STATE   t0
    ADDO    s4, t0, DISCV5_ST_NODES
    li      s5, DISCV5_NODE_SLOTS
3:  lbu     t0, DISCV5_N_STATE(s4)
    BNEI    t0, DISCV5_NODE_MEMBER, 4f
    mv      a0, s10
    mv      a1, s2
    mv      a2, s4
    call    discv5_candidate_insert
4:  addi    s4, s4, DISCV5_N_SIZE
    addi    s5, s5, -1
    bnez    s5, 3b
    mv      a0, s10
    mv      a1, s2
    call    discv5_lookup_advance
9:  LEAVE   0
END_FUNCTION discv5_lookup_start

/* ---------------------------------------------------------------- Messages in */

/*
 * discv5_msg_field(scratch, k) -> the Item record of field k of the message
 * list (field 0 is the request ID), or 0 when the list is shorter.
 * t0 items, t1 index, t2 list end.
 */
LOCAL_FUNCTION discv5_msg_field
    UNWIND_END_PROLOGUE
    ADDO    t0, a0, SC_ITEMS
    ld      t1, RLP_ITEMS_OFFSET(t0)
    add     t0, t0, t1
    ld      t2, RLP_ITEM_ITEMS(t0)
    li      t1, 1
1:  bgeu    t1, t2, 8f
    slli    t3, t1, RLP_ITEM_SHIFT
    add     t3, t0, t3
    beqz    a1, 9f
    addi    a1, a1, -1
    ld      t4, RLP_ITEM_ITEMS(t3)
    add     t1, t1, t4
    j       1b
8:  li      a0, 0
    ret
9:  mv      a0, t3
    ret
END_FUNCTION discv5_msg_field

/*
 * discv5_item_uint(scratch, item) -> in a0 the number, in a1 1 when the
 * message item is a canonical number of at most 8 bytes, else 0. item may
 * be 0 (a missing field).
 */
LOCAL_FUNCTION discv5_item_uint
    UNWIND_END_PROLOGUE
    mv      a2, a1
    li      a1, 0
    beqz    a2, 9f
    ld      t0, RLP_ITEM_KIND(a2)
    BNEI    t0, RLP_KIND_BYTES, 9f
    ld      t1, RLP_ITEM_LENGTH(a2)
    BGTUI   t1, 8, 9f
    ld      t2, RLP_ITEM_OFFSET(a2)
    li      a7, SC_RLP+DISCV5_BL_FIXED
    add     t3, a0, a7
    add     t3, t3, t2
    li      a0, 0
    beqz    t1, 2f
    lbu     t4, 0(t3)
    beqz    t4, 9f                          # a leading zero
1:  lbu     t4, 0(t3)
    slli    a0, a0, 8
    or      a0, a0, t4
    addi    t3, t3, 1
    addi    t1, t1, -1
    bnez    t1, 1b
2:  li      a1, 1
9:  ret
END_FUNCTION discv5_item_uint

/*
 * discv5_handle_message(scratch): the decrypted message in the scratch, from
 * the sender of the packet: a type byte, then an RLP list whose first field
 * is a request ID of at most 8 bytes. Anything else is dropped.
 * s1 message bytes, s2 length, s3 RLP ByteList, s4 type, s5 item.
 */
LOCAL_FUNCTION discv5_handle_message
    ENTER   0
    mv      s10, a0
    SCR     s1, SC_MSG
    ld      s2, DISCV5_BL_COUNT(s1)
    BLTUI   s2, 2, 9f
    ld      t0, DISCV5_BL_OFFSET(s1)
    add     s1, s1, t0
    lbu     s4, 0(s1)
    SCR     s3, SC_RLP
    addi    t0, s2, -1
    BYTELIST s3, 0, BL_PACKET_SIZE, t0
    addi    a0, s3, DISCV5_BL_FIXED
    addi    a1, s1, 1
    addi    a2, s2, -1
    call    discv5_copy
    SCR     a1, SC_ITEMS
    li      t0, SC_ITEMS_SIZE
    sd      t0, RLP_ITEMS_SIZE(a1)
    mv      a0, s3
    CALL_GLOBAL rlp_decode
    bnez    a0, 9f
    SCR     t0, SC_ITEMS
    ld      t1, RLP_ITEMS_OFFSET(t0)
    add     t0, t0, t1
    ld      t1, RLP_ITEM_KIND(t0)
    BNEI    t1, RLP_KIND_LIST, 9f
    mv      a0, s10
    li      a1, 0
    call    discv5_msg_field
    beqz    a0, 9f
    mv      s5, a0
    ld      t0, RLP_ITEM_KIND(s5)
    BNEI    t0, RLP_KIND_BYTES, 9f
    ld      s2, RLP_ITEM_LENGTH(s5)
    BGTUI   s2, 8, 9f
    sd      s2, SC_CTX+CTX_REQID_LEN(s10)
    sd      zero, SC_CTX+CTX_REQID(s10)
    addi    a0, s10, SC_CTX+CTX_REQID
    ITEM_DATA a1, s5
    mv      a2, s2
    call    discv5_copy
    mv      a0, s10
    BNEI    s4, DISCV5_MSG_PING, 1f
    call    discv5_on_ping
    j       9f
1:  BNEI    s4, DISCV5_MSG_PONG, 2f
    call    discv5_on_pong
    j       9f
2:  BNEI    s4, DISCV5_MSG_FINDNODE, 3f
    call    discv5_on_findnode
    j       9f
3:  BNEI    s4, DISCV5_MSG_NODES, 4f
    call    discv5_on_nodes
    j       9f
4:  BNEI    s4, DISCV5_MSG_TALKREQ, 9f
    call    discv5_on_talkreq
9:  LEAVE   0
END_FUNCTION discv5_handle_message

/* discv5_reply(scratch, type, end): finishes the message and sends it to the sender of the packet received. */
LOCAL_FUNCTION discv5_reply
    ENTER   0
    mv      s10, a0
    call    discv5_msg_finish
    mv      a0, s10
    addi    a1, s10, SC_HDR+DISCV5_HDR_SRC_ID
    addi    a2, s10, SC_CTX+CTX_FROM
    call    discv5_send_message
    LEAVE   0
END_FUNCTION discv5_reply

/* discv5_reqid_out(scratch) -> the write position after the request ID received, written at SC_TMP. */
LOCAL_FUNCTION discv5_reqid_out
    ENTER   0
    mv      s10, a0
    SCR     a0, SC_TMP
    addi    a1, s10, SC_CTX+CTX_REQID
    ld      a2, SC_CTX+CTX_REQID_LEN(s10)
    call    discv5_rlp_bytes
    LEAVE   0
END_FUNCTION discv5_reqid_out

/*
 * discv5_on_ping(scratch): PING [request-id, enr-seq] -> PONG [request-id,
 * enr-seq, ip, port], with the local sequence number and the endpoint the
 * PING came from. s2 the sender's endpoint.
 */
LOCAL_FUNCTION discv5_on_ping
    ENTER   0
    mv      s10, a0
    li      a1, 1
    call    discv5_msg_field
    mv      a1, a0
    mv      a0, s10
    call    discv5_item_uint
    beqz    a1, 9f
    addi    s2, s10, SC_CTX+CTX_FROM
    mv      a0, s10
    call    discv5_reqid_out
    STATE   t0
    ld      a1, DISCV5_ST_SEQ(t0)
    call    discv5_rlp_uint
    addi    a1, s2, DISCV5_EP_ADDRESS
    ld      t0, DISCV5_EP_FAMILY(s2)
    li      a2, 4
    BEQI    t0, 4, 1f
    li      a2, 16
1:  call    discv5_rlp_bytes
    ld      a1, DISCV5_EP_PORT(s2)
    call    discv5_rlp_uint
    mv      a2, a0
    mv      a0, s10
    li      a1, DISCV5_MSG_PONG
    call    discv5_reply
9:  LEAVE   0
END_FUNCTION discv5_on_ping

/* discv5_on_talkreq(scratch): TALKREQ [request-id, protocol, request] -> TALKRESP [request-id, ""]: no protocol is served. */
LOCAL_FUNCTION discv5_on_talkreq
    ENTER   0
    mv      s10, a0
    call    discv5_reqid_out
    li      t0, 0x80
    sb      t0, 0(a0)
    addi    a2, a0, 1
    mv      a0, s10
    li      a1, DISCV5_MSG_TALKRESP
    call    discv5_reply
    LEAVE   0
END_FUNCTION discv5_on_talkreq

/*
 * discv5_on_pong(scratch): PONG [request-id, enr-seq, ip, port] answering a
 * PING sent ends the check. An ENDPOINT action reports the endpoint the node
 * saw; a newer record is fetched with FINDNODE [0].
 * s1 request, s2 enr-seq, s3 node, s4 action, s5 ip item, s6 ip length,
 * s7 port.
 */
LOCAL_FUNCTION discv5_on_pong
    ENTER   0
    mv      s10, a0
    ld      t0, SC_CTX+CTX_REQID_LEN(s10)
    BNEI    t0, 8, 9f
    li      a1, 1
    call    discv5_msg_field
    mv      a1, a0
    mv      a0, s10
    call    discv5_item_uint
    beqz    a1, 9f
    mv      s2, a0
    addi    a0, s10, SC_CTX+CTX_REQID
    li      a1, 8
    call    discv5_load_be
    mv      a2, a0
    mv      a0, s10
    addi    a1, s10, SC_HDR+DISCV5_HDR_SRC_ID
    li      a3, DISCV5_MSG_PING
    call    discv5_request_match
    beqz    a0, 9f
    mv      s1, a0

    /* ENDPOINT: ip of 4 or 16 bytes and a port. */
    mv      a0, s10
    li      a1, 2
    call    discv5_msg_field
    beqz    a0, 5f
    mv      s5, a0
    ld      t0, RLP_ITEM_KIND(s5)
    BNEI    t0, RLP_KIND_BYTES, 5f
    ld      s6, RLP_ITEM_LENGTH(s5)
    BEQI    s6, 4, 1f
    BNEI    s6, 16, 5f
1:  mv      a0, s10
    li      a1, 3
    call    discv5_msg_field
    mv      a1, a0
    mv      a0, s10
    call    discv5_item_uint
    beqz    a1, 5f
    mv      s7, a0
    BGEUI   s7, 0x10000, 5f
    mv      a0, s10
    li      a1, DISCV5_ACTION_ENDPOINT
    li      a2, DISCV5_ACT_EP_SIZE
    call    discv5_action
    beqz    a0, 5f
    mv      s4, a0
    sd      s7, DISCV5_ACT_EP_SEEN+DISCV5_EP_PORT(s4)
    li      t0, 4
    BEQI    s6, 4, 2f
    li      t0, 6
2:  sd      t0, DISCV5_ACT_EP_SEEN+DISCV5_EP_FAMILY(s4)
    addi    a0, s4, DISCV5_ACT_EP_SEEN+DISCV5_EP_ADDRESS
    ITEM_DATA a1, s5
    mv      a2, s6
    call    discv5_copy
    addi    a0, s4, DISCV5_ACT_EP_FROM
    addi    a1, s10, SC_HDR+DISCV5_HDR_SRC_ID
    li      a2, 32
    call    discv5_copy

    /* The check succeeded; fetch a newer record. */
5:  mv      a0, s10
    mv      a1, s1
    li      a2, 1
    call    discv5_request_end
    mv      a0, s10
    mv      a1, s1
    call    discv5_node_find
    beqz    a0, 9f
    mv      s3, a0
    ld      t0, DISCV5_N_SEQ(s3)
    bgeu    t0, s2, 9f
    mv      a0, s10
    mv      a1, s3
    li      a2, DISCV5_MSG_FINDNODE | (DISCV5_PURPOSE_REFRESH << 8)
    li      a3, 1
    li      a4, 0
    call    discv5_request_start
9:  LEAVE   0
END_FUNCTION discv5_on_pong

/* discv5_result_record(scratch, result) -> in a0 the bytes, in a1 the length of a FINDNODE result: a table slot, or 0 for the local record. */
LOCAL_FUNCTION discv5_result_record
    UNWIND_END_PROLOGUE
    bnez    a1, 1f
    ld      t0, SC_CTX+CTX_STATE(a0)
    ld      a1, DISCV5_ST_RECORD_LEN(t0)
    addi    a0, t0, DISCV5_ST_RECORD
    ret
1:  addi    a0, a1, DISCV5_N_RECORD
    ld      a1, DISCV5_N_RECORD_LEN(a1)
    ret
END_FUNCTION discv5_result_record

/*
 * discv5_nodes_send(scratch, start, end, total, bytes): NODES [request-id,
 * total, [record, ...]] with the results from start to end (bytes record
 * bytes in all), to the sender of the FINDNODE. s1 index, s2 end,
 * s3 total, s4 bytes, s5 write position.
 */
LOCAL_FUNCTION discv5_nodes_send
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    mv      s4, a4
    call    discv5_reqid_out
    mv      a1, s3
    call    discv5_rlp_uint
    mv      a1, s4
    li      a2, 0xC0
    call    discv5_rlp_header
    mv      s5, a0
1:  bgeu    s1, s2, 2f
    slli    t0, s1, 3
    add     t0, s10, t0
    LDO     a1, t0, SC_RESULT
    mv      a0, s10
    call    discv5_result_record
    mv      a2, a1
    mv      a1, a0
    mv      a0, s5
    call    discv5_copy
    mv      s5, a0
    addi    s1, s1, 1
    j       1b
2:  mv      a0, s10
    li      a1, DISCV5_MSG_NODES
    mv      a2, s5
    call    discv5_reply
    LEAVE   0
END_FUNCTION discv5_nodes_send

/*
 * discv5_nodes_pack(scratch, count, send, total) -> the NODES packets needed
 * for the count results: each holds records while their bytes stay within
 * DISCV5_NODES_BYTES, and no results take one empty packet. With send 1 the
 * packets go out, each announcing total. s1 count, s2 send, s3 total,
 * s4 index, s5 packets, s6 packet start, s7 record bytes.
 */
LOCAL_FUNCTION discv5_nodes_pack
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    li      s4, 0
    li      s5, 0
1:  mv      s6, s4
    li      s7, 0
2:  bgeu    s4, s1, 3f
    slli    t0, s4, 3
    add     t0, s10, t0
    LDO     a1, t0, SC_RESULT
    mv      a0, s10
    call    discv5_result_record
    add     t0, s7, a1
    BGTUI   t0, DISCV5_NODES_BYTES, 3f
    mv      s7, t0
    addi    s4, s4, 1
    j       2b
3:  addi    s5, s5, 1
    beqz    s2, 4f
    mv      a0, s10
    mv      a1, s6
    mv      a2, s4
    mv      a3, s3
    mv      a4, s7
    call    discv5_nodes_send
4:  bltu    s4, s1, 1b
    mv      a0, s5
    LEAVE   0
END_FUNCTION discv5_nodes_pack

/*
 * discv5_on_findnode(scratch): FINDNODE [request-id, [distance, ...]] ->
 * NODES packets with up to DISCV5_RESULT_LIMIT records: the local record for
 * distance 0, else live table members at exactly that log distance from the
 * local node. Distances past 256 and repeats are skipped; the first
 * DISCV5_MAX_DISTANCES distinct distances count. s1 list item, s2 item
 * index, s3 list end, s4 distances, s5 results, s6 distance, s7 node slot,
 * s8 slots left, s9 items, then the distance index.
 */
LOCAL_FUNCTION discv5_on_findnode
    ENTER   0
    mv      s10, a0
    li      a1, 1
    call    discv5_msg_field
    beqz    a0, 9f
    mv      s1, a0
    ld      t0, RLP_ITEM_KIND(s1)
    BNEI    t0, RLP_KIND_LIST, 9f
    SCR     s9, SC_ITEMS
    ld      t0, RLP_ITEMS_OFFSET(s9)
    add     s9, s9, t0
    sub     s2, s1, s9
    srli    s2, s2, RLP_ITEM_SHIFT
    ld      s3, RLP_ITEM_ITEMS(s1)
    add     s3, s2, s3
    addi    s2, s2, 1
    li      s4, 0

    /* The distances. */
1:  bgeu    s2, s3, 3f
    slli    a1, s2, RLP_ITEM_SHIFT
    add     a1, s9, a1
    ld      t0, RLP_ITEM_ITEMS(a1)
    add     s2, s2, t0
    mv      a0, s10
    call    discv5_item_uint
    beqz    a1, 9f
    mv      s6, a0
    BGTUI   s6, 256, 1b
    BGEUI   s4, DISCV5_MAX_DISTANCES, 1b
    SCR     t1, SC_DIST
    li      t2, 0
2:  bgeu    t2, s4, 21f
    slli    t3, t2, 3
    add     t3, t1, t3
    ld      t3, 0(t3)
    beq     t3, s6, 1b
    addi    t2, t2, 1
    j       2b
21: slli    t3, s4, 3
    add     t3, t1, t3
    sd      s6, 0(t3)
    addi    s4, s4, 1
    j       1b

    /* The results. */
3:  li      s5, 0
    li      s9, 0
4:  bgeu    s9, s4, 7f
    BGEUI   s5, DISCV5_RESULT_LIMIT, 7f
    SCR     t0, SC_DIST
    slli    t1, s9, 3
    add     t0, t0, t1
    ld      s6, 0(t0)
    addi    s9, s9, 1
    bnez    s6, 5f
    SCR     t0, SC_RESULT
    slli    t1, s5, 3
    add     t0, t0, t1
    sd      zero, 0(t0)
    addi    s5, s5, 1
    j       4b
5:  STATE   t0
    ADDO    s7, t0, DISCV5_ST_NODES
    li      s8, DISCV5_NODE_SLOTS
6:  BGEUI   s5, DISCV5_RESULT_LIMIT, 4b
    lbu     t0, DISCV5_N_STATE(s7)
    BNEI    t0, DISCV5_NODE_MEMBER, 61f
    lbu     t0, DISCV5_N_LIVE(s7)
    beqz    t0, 61f
    STATE   t0
    addi    a0, t0, DISCV5_ST_NODE_ID
    mv      a1, s7
    call    discv5_log_distance
    bne     a0, s6, 61f
    SCR     t0, SC_RESULT
    slli    t1, s5, 3
    add     t0, t0, t1
    sd      s7, 0(t0)
    addi    s5, s5, 1
61: addi    s7, s7, DISCV5_N_SIZE
    addi    s8, s8, -1
    bnez    s8, 6b
    j       4b

    /* Count the packets, then send them. */
7:  mv      a0, s10
    mv      a1, s5
    li      a2, 0
    li      a3, 0
    call    discv5_nodes_pack
    mv      a3, a0
    mv      a0, s10
    mv      a1, s5
    li      a2, 1
    call    discv5_nodes_pack
9:  LEAVE   0
END_FUNCTION discv5_on_findnode

/*
 * discv5_nodes_record(scratch, item, request, lookup): one record of a NODES
 * answer to the request. It must be a valid record with a UDP port above
 * 1024, at one of the distances asked from the answering node. For a lookup
 * (lookup not 0) a record new to it gives NODE_FOUND and becomes a
 * candidate; every good record goes to the table. s1 item, s2 request,
 * s3 lookup, s4 record, then the node view, s5 header length, s6 length.
 */
LOCAL_FUNCTION discv5_nodes_record
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    mv      s2, a2
    mv      s3, a3
    ld      t0, RLP_ITEM_KIND(s1)
    BNEI    t0, RLP_KIND_LIST, 9f
    ld      t2, RLP_ITEM_LENGTH(s1)
    li      s5, 1
    BLEUI   t2, 55, 1f
    mv      t0, t2
10: addi    s5, s5, 1
    srli    t0, t0, 8
    bnez    t0, 10b
1:  add     s6, t2, s5
    BGTUI   s6, DISCV5_MAX_RECORD, 9f
    SCR     s4, SC_REC
    BYTELIST s4, 0, 328, s6
    ITEM_DATA a1, s1
    sub     a1, a1, s5
    addi    a0, s4, DISCV5_BL_FIXED
    mv      a2, s6
    call    discv5_copy
    SCR     a1, SC_ENR_SCRATCH
    li      t0, DISCV5_ENR_SCRATCH
    sd      t0, 0(a1)
    mv      a0, s4
    SCR     a2, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    bnez    a0, 9f
    SCR     a0, SC_ENR
    SCR     a1, SC_VIEW+DISCV5_N_EP
    call    discv5_enr_endpoint
    beqz    a0, 9f
    SCR     t0, SC_VIEW+DISCV5_N_EP
    ld      t0, DISCV5_EP_PORT(t0)
    BLEUI   t0, 1024, 9f
    mv      a0, s2
    SCR     a1, SC_ENR+DISCV5_ENR_NODE_ID
    call    discv5_log_distance
    lbu     t1, DISCV5_R_DIST_COUNT(s2)
    addi    t2, s2, DISCV5_R_DISTANCES
2:  beqz    t1, 9f
    lhu     t3, 0(t2)
    addi    t2, t2, 2
    beq     t3, a0, 3f
    addi    t1, t1, -1
    j       2b
3:  STATE   t0
    addi    a0, t0, DISCV5_ST_NODE_ID
    SCR     a1, SC_ENR+DISCV5_ENR_NODE_ID
    li      a2, 32
    call    discv5_equal
    bnez    a0, 9f
    SCR     s4, SC_VIEW
    mv      a0, s4
    SCR     a1, SC_ENR+DISCV5_ENR_NODE_ID
    li      a2, 32
    call    discv5_copy
    addi    a0, s4, DISCV5_N_PUBKEY
    SCR     a1, SC_ENR+DISCV5_ENR_PUBKEY
    li      a2, 33
    call    discv5_copy
    beqz    s3, 4f
    mv      a0, s3
    mv      a1, s4
    call    discv5_candidate_find
    bnez    a0, 4f
    mv      a0, s10
    call    discv5_emit_found
    ld      t0, DISCV5_L_FOUND(s3)
    addi    t0, t0, 1
    sd      t0, DISCV5_L_FOUND(s3)
    mv      a0, s10
    mv      a1, s3
    mv      a2, s4
    call    discv5_candidate_insert
4:  mv      a0, s10
    SCR     a1, SC_ENR
    SCR     a2, SC_REC
    call    discv5_node_add
9:  LEAVE   0
END_FUNCTION discv5_nodes_record

/*
 * discv5_on_nodes(scratch): NODES [request-id, total, [record, ...]]
 * answering a FINDNODE sent. The request ends after min(total,
 * DISCV5_NODES_LIMIT) packets, at least 1; each packet moves its deadline
 * on. s1 request, s2 child index, s3 list end, s4 items, s5 lookup,
 * s6 item, s7 total.
 */
LOCAL_FUNCTION discv5_on_nodes
    ENTER   0
    mv      s10, a0
    ld      t0, SC_CTX+CTX_REQID_LEN(s10)
    BNEI    t0, 8, 9f
    li      a1, 1
    call    discv5_msg_field
    mv      a1, a0
    mv      a0, s10
    call    discv5_item_uint
    beqz    a1, 9f
    mv      s7, a0
    mv      a0, s10
    li      a1, 2
    call    discv5_msg_field
    beqz    a0, 9f
    mv      s6, a0
    ld      t0, RLP_ITEM_KIND(s6)
    BNEI    t0, RLP_KIND_LIST, 9f
    addi    a0, s10, SC_CTX+CTX_REQID
    li      a1, 8
    call    discv5_load_be
    mv      a2, a0
    mv      a0, s10
    addi    a1, s10, SC_HDR+DISCV5_HDR_SRC_ID
    li      a3, DISCV5_MSG_FINDNODE
    call    discv5_request_match
    beqz    a0, 9f
    mv      s1, a0
    li      s5, 0
    lbu     t0, DISCV5_R_PURPOSE(s1)
    BNEI    t0, DISCV5_PURPOSE_LOOKUP, 1f
    lbu     t0, DISCV5_R_LOOKUP(s1)
    li      t1, DISCV5_L_SIZE
    mul     t0, t0, t1
    STATE   t1
    ADDO    t1, t1, DISCV5_ST_LOOKUPS
    add     t0, t1, t0
    ld      t1, DISCV5_L_ACTIVE(t0)
    beqz    t1, 1f
    mv      s5, t0
1:  SCR     s4, SC_ITEMS
    ld      t0, RLP_ITEMS_OFFSET(s4)
    add     s4, s4, t0
    sub     s2, s6, s4
    srli    s2, s2, RLP_ITEM_SHIFT
    ld      s3, RLP_ITEM_ITEMS(s6)
    add     s3, s2, s3
    addi    s2, s2, 1
2:  bgeu    s2, s3, 5f
    slli    s6, s2, RLP_ITEM_SHIFT
    add     s6, s4, s6
    ld      t0, RLP_ITEM_ITEMS(s6)
    add     s2, s2, t0
    mv      a0, s10
    mv      a1, s6
    mv      a2, s1
    mv      a3, s5
    call    discv5_nodes_record
    j       2b
5:  lbu     t0, DISCV5_R_TOTAL(s1)
    bnez    t0, 6f
    li      t0, DISCV5_NODES_LIMIT
    bgeu    s7, t0, 51f
    mv      t0, s7
51: bnez    t0, 52f
    li      t0, 1
52: sb      t0, DISCV5_R_TOTAL(s1)
6:  lbu     t1, DISCV5_R_GOT(s1)
    addi    t1, t1, 1
    sb      t1, DISCV5_R_GOT(s1)
    bltu    t1, t0, 7f
    mv      a0, s10
    mv      a1, s1
    li      a2, 1
    call    discv5_request_end
    j       9f
7:  NOW     t0
    addi    t0, t0, DISCV5_REQUEST_TIMEOUT
    sd      t0, DISCV5_R_DEADLINE(s1)
9:  LEAVE   0
END_FUNCTION discv5_on_nodes

/* ---------------------------------------------------------------- Packets in */

/*
 * discv5_on_message_packet(scratch): an ordinary message packet. With a
 * session for the sender's node ID and endpoint whose key opens it, the
 * message is handled. Else the sender gets WHOAREYOU: the one still valid
 * for that node and endpoint, sent again unchanged, or a new one.
 * s1 source ID, s2 endpoint, s3 session or challenge.
 */
LOCAL_FUNCTION discv5_on_message_packet
    ENTER   0
    mv      s10, a0
    addi    s1, s10, SC_HDR+DISCV5_HDR_SRC_ID
    addi    s2, s10, SC_CTX+CTX_FROM
    mv      a1, s1
    mv      a2, s2
    call    discv5_session_find
    beqz    a0, 2f
    mv      s3, a0
    addi    a0, s10, SC_HDR
    addi    a1, s3, DISCV5_S_READ_KEY
    SCR     a2, SC_IN
    SCR     a3, SC_MSG
    CALL_GLOBAL discv5_message_decrypt
    bnez    a0, 2f
    NOW     t0
    addi    t0, t0, 1
    sd      t0, DISCV5_S_USED(s3)
    mv      a0, s10
    call    discv5_handle_message
    j       9f
2:  mv      a0, s10
    mv      a1, s1
    mv      a2, s2
    li      a3, 0
    call    discv5_challenge_find
    mv      s3, a0
    bnez    s3, 3f
    mv      a0, s10
    mv      a1, s1
    mv      a2, s2
    li      a3, 1
    call    discv5_challenge_find
    mv      s3, a0
    mv      a0, s10
    mv      a1, s3
    call    discv5_challenge_new
3:  mv      a0, s10
    mv      a1, s3
    call    discv5_send_whoareyou
9:  LEAVE   0
END_FUNCTION discv5_on_message_packet

/*
 * discv5_on_whoareyou(scratch): a WHOAREYOU answering a request that waits
 * (matched by the nonce sent). A new ephemeral key gives the session keys;
 * the ID proof signs the challenge; the request goes again in a handshake
 * packet, with the local record when the challenge's enr-seq is older.
 * s1 request, s2 state, s3 header out, s4 session, s5 challenge data.
 */
LOCAL_FUNCTION discv5_on_whoareyou
    ENTER   0
    mv      s10, a0
    addi    a1, s10, SC_HDR+DISCV5_HDR_NONCE
    call    discv5_request_find
    beqz    a0, 9f
    mv      s1, a0
    lbu     t0, DISCV5_R_STATE(s1)
    BNEI    t0, DISCV5_REQ_WAITING, 9f
    STATE   s2
    addi    s5, s10, SC_HDR+DISCV5_HDR_HEADER+DISCV5_BL_FIXED
1:  mv      a0, s2
    SCR     a1, SC_EPH
    li      a2, 32
    call    discv5_random
    SCR     a0, SC_EPH
    SCR     a1, SC_EPH+32
    CALL_GLOBAL crypto_secp256k1_public_key
    bnez    a0, 1b

    /* Keys: the IDs are the local node's (initiator), then the remote's. */
    SCR     a0, SC_TMP
    addi    a1, s2, DISCV5_ST_NODE_ID
    li      a2, 32
    call    discv5_copy
    mv      a1, s1
    li      a2, 32
    call    discv5_copy
    SCR     a0, SC_EPH
    addi    a1, s1, DISCV5_R_PUBKEY
    mv      a2, s5
    SCR     a3, SC_TMP
    SCR     a4, SC_KEYS
    CALL_GLOBAL discv5_derive_keys
    bnez    a0, 9f
    SCR     s3, SC_HDR2
    addi    a0, s2, DISCV5_ST_PRIVATE_KEY
    mv      a1, s5
    SCR     a2, SC_EPH+32
    mv      a3, s1
    addi    a4, s3, DISCV5_HDR_SIGNATURE
    CALL_GLOBAL discv5_id_sign
    bnez    a0, 9f
    addi    a0, s3, DISCV5_HDR_EPH_KEY
    SCR     a1, SC_EPH+32
    li      a2, 33
    call    discv5_copy
    mv      a0, s10
    mv      a1, s1
    addi    a2, s1, DISCV5_R_EP
    SCR     a3, SC_KEYS
    SCR     a4, SC_KEYS+16
    call    discv5_session_put
    mv      s4, a0
    li      t0, 1
    sd      t0, DISCV5_S_COUNTER(s4)

    /* The header: flag 2, the first nonce of the session. */
    li      t0, DISCV5_FLAG_HANDSHAKE
    sd      t0, DISCV5_HDR_FLAG(s3)
    mv      a0, s2
    addi    a1, s3, DISCV5_HDR_IV
    li      a2, 16
    call    discv5_random
    addi    a0, s3, DISCV5_HDR_SRC_ID
    addi    a1, s2, DISCV5_ST_NODE_ID
    li      a2, 32
    call    discv5_copy
    addi    a0, s3, DISCV5_HDR_NONCE
    li      a1, 1
    li      a2, 4
    call    discv5_store_be
    mv      a0, s2
    addi    a1, s3, DISCV5_HDR_NONCE+4
    li      a2, 8
    call    discv5_random
    addi    t1, s3, DISCV5_HDR_RECORD
    BYTELIST t1, 0, DISCV5_HDR_RECORD_SIZE, zero
    ld      t0, SC_HDR+DISCV5_HDR_ENR_SEQ(s10)
    ld      t1, DISCV5_ST_SEQ(s2)
    bgeu    t0, t1, 2f
    ld      a2, DISCV5_ST_RECORD_LEN(s2)
    sd      a2, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(s3)
    addi    a0, s3, DISCV5_HDR_RECORD+DISCV5_BL_FIXED
    addi    a1, s2, DISCV5_ST_RECORD
    call    discv5_copy

    /* The request again. */
2:  mv      a0, s10
    mv      a1, s1
    call    discv5_request_message
    SCR     t1, SC_PKT
    BYTELIST t1, 0, BL_PACKET_SIZE, zero
    mv      a0, s3
    mv      a1, s1
    addi    a2, s4, DISCV5_S_WRITE_KEY
    SCR     a3, SC_MSG
    SCR     a4, SC_PKT
    CALL_GLOBAL discv5_packet_encode
    bnez    a0, 9f
    mv      a0, s10
    addi    a1, s1, DISCV5_R_EP
    call    discv5_send_packet
    addi    a0, s1, DISCV5_R_NONCE
    addi    a1, s3, DISCV5_HDR_NONCE
    li      a2, 12
    call    discv5_copy
    li      t0, DISCV5_REQ_HANDSHAKE
    sb      t0, DISCV5_R_STATE(s1)
    NOW     t0
    addi    t0, t0, DISCV5_REQUEST_TIMEOUT
    sd      t0, DISCV5_R_DEADLINE(s1)
    mv      a0, s10
    mv      a1, s1
    call    discv5_requests_resend
9:  LEAVE   0
END_FUNCTION discv5_on_whoareyou

/*
 * discv5_requests_resend(scratch, request): the other requests waiting for
 * the same node ID and endpoint go again, now through the session the
 * request's handshake made, each with a new nonce and deadline.
 * s1 request, s2 slot, s3 slots left.
 */
LOCAL_FUNCTION discv5_requests_resend
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    STATE   t0
    ADDO    s2, t0, DISCV5_ST_REQUESTS
    li      s3, DISCV5_REQUEST_SLOTS
1:  beq     s2, s1, 2f
    lbu     t0, DISCV5_R_STATE(s2)
    BNEI    t0, DISCV5_REQ_WAITING, 2f
    mv      a0, s2
    mv      a1, s1
    li      a2, 32
    call    discv5_equal
    beqz    a0, 2f
    addi    a0, s2, DISCV5_R_EP
    addi    a1, s1, DISCV5_R_EP
    li      a2, DISCV5_EP_SIZE
    call    discv5_equal
    beqz    a0, 2f
    mv      a0, s10
    mv      a1, s2
    call    discv5_request_message
    mv      a0, s10
    mv      a1, s2
    addi    a2, s2, DISCV5_R_EP
    call    discv5_send_message
    mv      a1, a0
    addi    a0, s2, DISCV5_R_NONCE
    li      a2, 12
    call    discv5_copy
    NOW     t0
    addi    t0, t0, DISCV5_REQUEST_TIMEOUT
    sd      t0, DISCV5_R_DEADLINE(s2)
2:  addi    s2, s2, DISCV5_R_SIZE
    addi    s3, s3, -1
    bnez    s3, 1b
    LEAVE   0
END_FUNCTION discv5_requests_resend

/*
 * discv5_on_handshake(scratch): a handshake packet answering the WHOAREYOU
 * still valid for the sender's node ID and endpoint. The public key comes
 * from the record in the packet (its node ID must match), else from the
 * table. The ID proof must verify and the message must open with the
 * derived keys; then the session is stored, the challenge is used up, a
 * record from the packet goes to the table, and the message is handled.
 * s1 challenge, s2 public key, s3 state, s4 source ID, s5 1 when the
 * packet has the record.
 */
LOCAL_FUNCTION discv5_on_handshake
    ENTER   0
    mv      s10, a0
    STATE   s3
    addi    s4, s10, SC_HDR+DISCV5_HDR_SRC_ID
    mv      a1, s4
    addi    a2, s10, SC_CTX+CTX_FROM
    li      a3, 0
    call    discv5_challenge_find
    beqz    a0, 9f
    mv      s1, a0
    li      s5, 0
    ld      t0, SC_HDR+DISCV5_HDR_RECORD+DISCV5_BL_COUNT(s10)
    beqz    t0, 1f
    SCR     a1, SC_ENR_SCRATCH
    li      t0, DISCV5_ENR_SCRATCH
    sd      t0, 0(a1)
    addi    a0, s10, SC_HDR+DISCV5_HDR_RECORD
    SCR     a2, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    bnez    a0, 9f
    SCR     a0, SC_ENR+DISCV5_ENR_NODE_ID
    mv      a1, s4
    li      a2, 32
    call    discv5_equal
    beqz    a0, 9f
    SCR     s2, SC_ENR+DISCV5_ENR_PUBKEY
    li      s5, 1
    j       2f
1:  mv      a0, s10
    mv      a1, s4
    call    discv5_node_find
    beqz    a0, 9f
    addi    s2, a0, DISCV5_N_PUBKEY
2:  mv      a0, s2
    addi    a1, s1, DISCV5_C_DATA
    addi    a2, s10, SC_HDR
    addi    a3, s3, DISCV5_ST_NODE_ID
    SCR     a4, SC_TMP
    CALL_GLOBAL discv5_id_verify
    bnez    a0, 9f
    SCR     t0, SC_TMP
    ld      t0, 0(t0)
    BNEI    t0, 1, 9f

    /* Keys: the IDs are the sender's (initiator), then the local node's. */
    SCR     a0, SC_TMP+8
    mv      a1, s4
    li      a2, 32
    call    discv5_copy
    addi    a1, s3, DISCV5_ST_NODE_ID
    li      a2, 32
    call    discv5_copy
    addi    a0, s3, DISCV5_ST_PRIVATE_KEY
    addi    a1, s10, SC_HDR+DISCV5_HDR_EPH_KEY
    addi    a2, s1, DISCV5_C_DATA
    SCR     a3, SC_TMP+8
    SCR     a4, SC_KEYS
    CALL_GLOBAL discv5_derive_keys
    bnez    a0, 9f
    addi    a0, s10, SC_HDR
    SCR     a1, SC_KEYS
    SCR     a2, SC_IN
    SCR     a3, SC_MSG
    CALL_GLOBAL discv5_message_decrypt
    bnez    a0, 9f
    mv      a0, s10
    mv      a1, s4
    addi    a2, s10, SC_CTX+CTX_FROM
    SCR     a3, SC_KEYS+16
    SCR     a4, SC_KEYS
    call    discv5_session_put
    sd      zero, DISCV5_C_SENT(s1)
    beqz    s5, 3f
    mv      a0, s10
    SCR     a1, SC_ENR
    addi    a2, s10, SC_HDR+DISCV5_HDR_RECORD
    call    discv5_node_add
3:  mv      a0, s10
    call    discv5_handle_message
9:  LEAVE   0
END_FUNCTION discv5_on_handshake

/*
 * discv5_on_datagram(scratch, event): a received datagram. The sender's
 * endpoint is kept with the unused address bytes zero; a packet that does
 * not decode is dropped. s1 event, s2 packet, s3 flag.
 */
LOCAL_FUNCTION discv5_on_datagram
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    addi    a0, s10, SC_CTX+CTX_FROM
    addi    a1, s1, DISCV5_EV_DG_FROM
    li      a2, DISCV5_EP_SIZE
    call    discv5_copy
    ld      t0, SC_CTX+CTX_FROM+DISCV5_EP_FAMILY(s10)
    BNEI    t0, 4, 1f
    sw      zero, SC_CTX+CTX_FROM+DISCV5_EP_ADDRESS+4(s10)
    sd      zero, SC_CTX+CTX_FROM+DISCV5_EP_ADDRESS+8(s10)
1:  SCR     s2, SC_IN
    ld      t0, DISCV5_EV_DG_LEN(s1)
    BYTELIST s2, 0, BL_PACKET_SIZE, t0
    addi    a0, s2, DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_EV_DG_DATA
    ld      a2, DISCV5_EV_DG_LEN(s1)
    call    discv5_copy
    mv      a0, s2
    STATE   t0
    addi    a1, t0, DISCV5_ST_NODE_ID
    addi    a2, s10, SC_HDR
    CALL_GLOBAL discv5_packet_decode
    bnez    a0, 9f
    SCR     t1, SC_MSG
    BYTELIST t1, 0, BL_PACKET_SIZE, zero
    ld      s3, SC_HDR+DISCV5_HDR_FLAG(s10)
    mv      a0, s10
    bnez    s3, 2f
    call    discv5_on_message_packet
    j       9f
2:  BNEI    s3, DISCV5_FLAG_WHOAREYOU, 3f
    call    discv5_on_whoareyou
    j       9f
3:  call    discv5_on_handshake
9:  LEAVE   0
END_FUNCTION discv5_on_datagram

/* ---------------------------------------------------------------- Other events */

/* discv5_on_add_node(scratch, event): ADD_NODE: a valid record with a UDP endpoint goes to the table. s1 event, s2 length, s3 record. */
LOCAL_FUNCTION discv5_on_add_node
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    ld      s2, DISCV5_EV_ADD_LEN(s1)
    BGTUI   s2, DISCV5_MAX_RECORD, 9f
    SCR     s3, SC_REC
    BYTELIST s3, 0, 328, s2
    addi    a0, s3, DISCV5_BL_FIXED
    addi    a1, s1, DISCV5_EV_ADD_DATA
    mv      a2, s2
    call    discv5_copy
    SCR     a1, SC_ENR_SCRATCH
    li      t0, DISCV5_ENR_SCRATCH
    sd      t0, 0(a1)
    mv      a0, s3
    SCR     a2, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    bnez    a0, 9f
    mv      a0, s10
    SCR     a1, SC_ENR
    mv      a2, s3
    call    discv5_node_add
9:  LEAVE   0
END_FUNCTION discv5_on_add_node

.set ENTRIES_BYTES, 8 + DISCV5_MAX_ENTRIES * DISCV5_LE_SIZE

/*
 * discv5_record_change(scratch, event): SET_ENDPOINT or SET_ENTRY. The
 * entries change, the sequence number goes up by 1, the record is signed
 * again, and a RECORD action carries it. When the entries are full or the
 * record would pass 300 bytes, the entries and sequence number stay as they
 * were. s1 event, s2 state, s3 saved entries.
 */
LOCAL_FUNCTION discv5_record_change
    ENTER   0
    mv      s10, a0
    mv      s1, a1
    STATE   s2
    SCR     s3, SC_TMP
    mv      a0, s3
    addi    a1, s2, DISCV5_ST_ENTRY_COUNT
    li      a2, ENTRIES_BYTES
    call    discv5_copy
    ld      t0, DISCV5_EV_KIND(s1)
    BNEI    t0, DISCV5_EVENT_SET_ENDPOINT, 1f
    mv      a0, s2
    addi    a1, s1, DISCV5_EV_ENDPOINT
    call    discv5_set_endpoint
    j       2f
1:  mv      a0, s2
    addi    a1, s1, DISCV5_EV_ENTRY_KEY
    ld      a2, DISCV5_EV_ENTRY_KEY_LEN(s1)
    addi    a3, s1, DISCV5_EV_ENTRY_VALUE
    ld      a4, DISCV5_EV_ENTRY_VALUE_LEN(s1)
    call    discv5_entry_set
2:  bnez    a0, 8f
    ld      t0, DISCV5_ST_SEQ(s2)
    addi    t0, t0, 1
    sd      t0, DISCV5_ST_SEQ(s2)
    mv      a0, s2
    call    discv5_record_build
    bnez    a0, 7f
    mv      a0, s10
    call    discv5_emit_record
    j       9f
7:  ld      t0, DISCV5_ST_SEQ(s2)
    addi    t0, t0, -1
    sd      t0, DISCV5_ST_SEQ(s2)
8:  addi    a0, s2, DISCV5_ST_ENTRY_COUNT
    mv      a1, s3
    li      a2, ENTRIES_BYTES
    call    discv5_copy
9:  LEAVE   0
END_FUNCTION discv5_record_change

/* discv5_owned_key(key, length) -> 1 when the key is one the core sets: "id", "secp256k1", "ip", "udp", "ip6", "udp6". s1 key, s2 length, s3 table, s4 entries left. */
LOCAL_FUNCTION discv5_owned_key
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    lla     s3, 402f
    li      s4, 6
1:  lbu     t0, 1(s3)
    bne     t0, s2, 2f
    lbu     t0, 0(s3)
    lla     a1, 400b
    add     a1, a1, t0
    mv      a0, s1
    mv      a2, s2
    call    discv5_equal
    bnez    a0, 9f
2:  addi    s3, s3, 2
    addi    s4, s4, -1
    bnez    s4, 1b
    li      a0, 0
9:  LEAVE   0
END_FUNCTION discv5_owned_key

/* The keys the core sets: offset in the key names at 400, then length. */
402:
    .byte   0, 2, 24, 9, 4, 2, 8, 3, 12, 3, 16, 4
    .zero   4
    .p2align 3

/* ---------------------------------------------------------------- Timers */

/*
 * discv5_timers(scratch): requests past their deadline end, failed (a
 * FINDNODE that got some NODES packets counts as answered). Every
 * DISCV5_PING_INTERVAL the table member whose check is most overdue gets a
 * PING. The refresh lookup of the local node ID starts when due. Lookups
 * move on. s1 state, s2 slot, s3 slots left, s4 now, s5 best.
 */
LOCAL_FUNCTION discv5_timers
    ENTER   0
    mv      s10, a0
    STATE   s1
    NOW     s4
    ADDO    s2, s1, DISCV5_ST_REQUESTS
    li      s3, DISCV5_REQUEST_SLOTS
1:  lbu     t0, DISCV5_R_STATE(s2)
    beqz    t0, 2f
    ld      t0, DISCV5_R_DEADLINE(s2)
    bltu    s4, t0, 2f
    lbu     t0, DISCV5_R_GOT(s2)
    snez    a2, t0
    mv      a0, s10
    mv      a1, s2
    call    discv5_request_end
2:  addi    s2, s2, DISCV5_R_SIZE
    addi    s3, s3, -1
    bnez    s3, 1b

    /* The liveness check. */
    ld      t0, DISCV5_ST_NEXT_PING(s1)
    bltu    s4, t0, 5f
    addi    t0, s4, DISCV5_PING_INTERVAL
    sd      t0, DISCV5_ST_NEXT_PING(s1)
    ADDO    s2, s1, DISCV5_ST_NODES
    li      s3, DISCV5_NODE_SLOTS
    li      s5, 0
3:  lbu     t0, DISCV5_N_STATE(s2)
    BNEI    t0, DISCV5_NODE_MEMBER, 4f
    lbu     t0, DISCV5_N_PINGING(s2)
    bnez    t0, 4f
    ld      t0, DISCV5_N_CHECK(s2)
    bltu    s4, t0, 4f
    beqz    s5, 31f
    ld      t1, DISCV5_N_CHECK(s5)
    bgeu    t0, t1, 4f
31: mv      s5, s2
4:  addi    s2, s2, DISCV5_N_SIZE
    addi    s3, s3, -1
    bnez    s3, 3b
    beqz    s5, 5f
    mv      a0, s10
    mv      a1, s5
    li      a2, DISCV5_MSG_PING | (DISCV5_PURPOSE_CHECK << 8)
    li      a3, 0
    li      a4, 0
    call    discv5_request_start
    beqz    a0, 5f
    li      t0, 1
    sb      t0, DISCV5_N_PINGING(s5)
    li      t0, DISCV5_RECHECK_INTERVAL
    add     t0, s4, t0
    sd      t0, DISCV5_N_CHECK(s5)

    /* The refresh lookup. */
5:  ld      t0, DISCV5_ST_NEXT_REFRESH(s1)
    beqz    t0, 6f
    bltu    s4, t0, 6f
    li      t0, DISCV5_REFRESH_INTERVAL
    add     t0, s4, t0
    sd      t0, DISCV5_ST_NEXT_REFRESH(s1)
    mv      a0, s10
    addi    a1, s1, DISCV5_ST_NODE_ID
    call    discv5_lookup_start

    /* Lookups waiting for a free request slot. */
6:  ADDO    s2, s1, DISCV5_ST_LOOKUPS
    li      s3, DISCV5_LOOKUP_SLOTS
7:  mv      a0, s10
    mv      a1, s2
    call    discv5_lookup_advance
    addi    s2, s2, DISCV5_L_SIZE
    addi    s3, s3, -1
    bnez    s3, 7b
    LEAVE   0
END_FUNCTION discv5_timers

/* discv5_wakeup(scratch): a WAKEUP action for the next timer: the next check, refresh or request deadline. s1 state, s2 time. */
LOCAL_FUNCTION discv5_wakeup
    ENTER   0
    mv      s10, a0
    STATE   s1
    ld      s2, DISCV5_ST_NEXT_PING(s1)
    ld      t0, DISCV5_ST_NEXT_REFRESH(s1)
    beqz    t0, 1f
    bgeu    t0, s2, 1f
    mv      s2, t0
1:  ADDO    t1, s1, DISCV5_ST_REQUESTS
    li      t2, DISCV5_REQUEST_SLOTS
2:  lbu     t0, DISCV5_R_STATE(t1)
    beqz    t0, 3f
    ld      t0, DISCV5_R_DEADLINE(t1)
    bgeu    t0, s2, 3f
    mv      s2, t0
3:  addi    t1, t1, DISCV5_R_SIZE
    addi    t2, t2, -1
    bnez    t2, 2b
    mv      a0, s10
    li      a1, DISCV5_ACTION_WAKEUP
    li      a2, DISCV5_ACT_WAKEUP_SIZE
    call    discv5_action
    beqz    a0, 9f
    sd      s2, DISCV5_ACT_WAKEUP_AT(a0)
9:  LEAVE   0
END_FUNCTION discv5_wakeup

/* ---------------------------------------------------------------- discv5_step */

/*
 * discv5_step(state, tick, events, scratch, actions) -> status
 * Checks the scratch size, every event and the action room first; on error
 * nothing changes. Then takes the time (never below the last), reseeds the
 * DRBG, handles the events in order, runs the timers, and ends the actions
 * with WAKEUP. s1 state, s2 tick, s3 events, s4 scratch, s5 actions,
 * s6 event position, s7 events end, s8 event count, s9 event.
 */
FUNCTION discv5_step
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    li      a0, DISCV5_BUFFER_TOO_SMALL
    ld      t0, 0(s4)
    BLTUI   t0, DISCV5_SCRATCH_SIZE, 99f

    /* Check the events. */
    ld      t0, DISCV5_BL_OFFSET(s3)
    add     s6, s3, t0
    ld      t0, DISCV5_BL_COUNT(s3)
    add     s7, s6, t0
    li      s8, 0
1:  li      a0, DISCV5_INVALID_EVENT
    bgeu    s6, s7, 3f
    sub     t0, s7, s6
    BLTUI   t0, 16, 99f
    ld      t1, DISCV5_EV_SIZE(s6)
    BLTUI   t1, 16, 99f
    andi    t2, t1, 7
    bnez    t2, 99f
    bltu    t0, t1, 99f
    ld      t2, DISCV5_EV_KIND(s6)
    BNEI    t2, DISCV5_EVENT_DATAGRAM, 11f
    BLTUI   t1, DISCV5_EV_DG_DATA, 99f
    ld      t3, DISCV5_EV_DG_LEN(s6)
    BGTUI   t3, DISCV5_MAX_PACKET, 99f
    addi    t4, t1, -DISCV5_EV_DG_DATA
    bltu    t4, t3, 99f
    ld      t3, DISCV5_EV_DG_FROM+DISCV5_EP_FAMILY(s6)
    BEQI    t3, 4, 2f
    BEQI    t3, 6, 2f
    j       99f
11: BNEI    t2, DISCV5_EVENT_ADD_NODE, 12f
    BLTUI   t1, DISCV5_EV_ADD_DATA, 99f
    ld      t3, DISCV5_EV_ADD_LEN(s6)
    addi    t4, t1, -DISCV5_EV_ADD_DATA
    bltu    t4, t3, 99f
    j       2f
12: BNEI    t2, DISCV5_EVENT_LOOKUP, 13f
    BLTUI   t1, DISCV5_EV_LOOKUP_SIZE, 99f
    j       2f
13: BNEI    t2, DISCV5_EVENT_SET_ENDPOINT, 14f
    BLTUI   t1, DISCV5_EV_ENDPOINT_SIZE, 99f
    ld      t3, DISCV5_EV_ENDPOINT+DISCV5_EP_FAMILY(s6)
    BEQI    t3, 4, 131f
    BNEI    t3, 6, 99f
131:ld      t3, DISCV5_EV_ENDPOINT+DISCV5_EP_PORT(s6)
    BGEUI   t3, 0x10000, 99f
    j       2f
14: BNEI    t2, DISCV5_EVENT_SET_ENTRY, 15f
    BLTUI   t1, DISCV5_EV_ENTRY_VALUE, 99f
    ld      t3, DISCV5_EV_ENTRY_KEY_LEN(s6)
    beqz    t3, 99f
    BGTUI   t3, DISCV5_MAX_KEY, 99f
    ld      t4, DISCV5_EV_ENTRY_VALUE_LEN(s6)
    BGTUI   t4, DISCV5_MAX_VALUE, 99f
    addi    t5, t1, -DISCV5_EV_ENTRY_VALUE
    bltu    t5, t4, 99f
    addi    a0, s6, DISCV5_EV_ENTRY_KEY
    mv      a1, t3
    call    discv5_owned_key
    mv      t0, a0
    li      a0, DISCV5_INVALID_EVENT
    bnez    t0, 99f
    j       2f
15: BNEI    t2, DISCV5_EVENT_OPENED, 16f    # shell results: well formed, then ignored
    BLTUI   t1, DISCV5_EV_OPENED_SIZE, 99f
    j       2f
16: BLTUI   t2, DISCV5_EVENT_SENT, 99f
    BGTUI   t2, DISCV5_EVENT_IDLE, 99f
    BLTUI   t1, DISCV5_EV_ERROR_SIZE, 99f
2:  ld      t1, DISCV5_EV_SIZE(s6)
    add     s6, s6, t1
    addi    s8, s8, 1
    j       1b

    /* Check the action room. */
3:  li      a0, DISCV5_BUFFER_TOO_SMALL
    ld      t0, DISCV5_BL_SIZE(s5)
    BLTUI   t0, DISCV5_BL_FIXED, 99f
    addi    t0, t0, -DISCV5_BL_FIXED
    li      t1, DISCV5_ACTIONS_PER_EVENT
    mul     t1, s8, t1
    li      t2, DISCV5_ACTIONS_BASE
    add     t1, t1, t2
    bltu    t0, t1, 99f

    /* Commit: the time, the DRBG, the context, empty actions. */
    ld      t0, DISCV5_TICK_NOW(s2)
    ld      t1, DISCV5_ST_NOW(s1)
    bgeu    t0, t1, 31f
    mv      t0, t1
31: sd      t0, DISCV5_ST_NOW(s1)
    sd      t0, SC_CTX+CTX_NOW(s4)
    sd      s1, SC_CTX+CTX_STATE(s4)
    sd      s5, SC_CTX+CTX_ACTIONS(s4)
    mv      a0, s1
    addi    a1, s2, DISCV5_TICK_ENTROPY
    call    discv5_reseed
    li      t0, DISCV5_BL_FIXED
    sd      t0, DISCV5_BL_OFFSET(s5)
    sd      zero, DISCV5_BL_COUNT(s5)

    /* The events. */
    ld      t0, DISCV5_BL_OFFSET(s3)
    add     s6, s3, t0
4:  bgeu    s6, s7, 8f
    mv      s9, s6
    ld      t0, DISCV5_EV_SIZE(s9)
    add     s6, s6, t0
    ld      t0, DISCV5_EV_KIND(s9)
    mv      a0, s4
    mv      a1, s9
    BNEI    t0, DISCV5_EVENT_DATAGRAM, 41f
    call    discv5_on_datagram
    j       4b
41: BNEI    t0, DISCV5_EVENT_ADD_NODE, 42f
    call    discv5_on_add_node
    j       4b
42: BNEI    t0, DISCV5_EVENT_LOOKUP, 43f
    addi    a1, s9, DISCV5_EV_LOOKUP_TARGET
    call    discv5_lookup_start
    j       4b
43: BGTUI   t0, DISCV5_EVENT_SET_ENTRY, 4b
    call    discv5_record_change
    j       4b

    /* Timers, then WAKEUP. */
8:  mv      a0, s4
    call    discv5_timers
    mv      a0, s4
    call    discv5_wakeup
    li      a0, DISCV5_OK
99: LEAVE   0
END_FUNCTION discv5_step
