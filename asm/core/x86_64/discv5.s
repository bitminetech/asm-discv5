/*
 * asm-discv5 for x86-64 (System V AMD64 psABI): Node Discovery Protocol v5.1.
 * AT&T syntax. Requirements: docs/reference/. Layouts: include/discv5.inc.
 *
 * Pointer arguments, status in rax. Hashes, ciphers and curve operations go
 * through asm-crypto; RLP decoding goes through asm-rlp. Baseline x86-64
 * instructions only. The functions and their steps follow the ARM64 file
 * one for one; where ARM64 keeps a value in a register that x86-64 lacks,
 * it sits on the stack.
 *
 * Every macro has a named parameter. In a macro without one, the Mach-O
 * assembler reads $0 to $9 as positional arguments.
 */
.set ISA_X86_64, 1
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
 * Frame: rbx, rbp, r12-r15, then bytes of locals at rsp. bytes is 8 more
 * than a multiple of 16, so rsp is 16-byte aligned at each call.
 */
.macro ENTER bytes
    push    %rbx
    UNWIND_PUSH %rbx
    push    %rbp
    UNWIND_PUSH %rbp
    push    %r12
    UNWIND_PUSH %r12
    push    %r13
    UNWIND_PUSH %r13
    push    %r14
    UNWIND_PUSH %r14
    push    %r15
    UNWIND_PUSH %r15
    sub     $\bytes, %rsp
    UNWIND_ALLOC \bytes
    UNWIND_END_PROLOGUE
.endm

.macro LEAVE bytes
    UNWIND_BEGIN_EPILOGUE
    add     $\bytes, %rsp
    UNWIND_FREE \bytes
    pop     %r15
    UNWIND_POP %r15
    pop     %r14
    UNWIND_POP %r14
    pop     %r13
    UNWIND_POP %r13
    pop     %r12
    UNWIND_POP %r12
    pop     %rbp
    UNWIND_POP %rbp
    pop     %rbx
    UNWIND_POP %rbx
    UNWIND_END_EPILOGUE
    ret
.endm

/* A ByteList header at off(base): size, offset 24, count. */
.macro BYTELIST base, off, size, count
    movq    \count, \off+16(\base)
    movq    $\size, \off(\base)
    movq    $DISCV5_BL_FIXED, \off+8(\base)
.endm

/* ---------------------------------------------------------------- Byte helpers */

/* discv5_copy(dst, src, n) -> dst + n. The regions do not overlap. */
LOCAL_FUNCTION discv5_copy
    UNWIND_END_PROLOGUE
    mov     %rdx, %rcx
    rep movsb
    mov     %rdi, %rax
    ret
END_FUNCTION discv5_copy

/* discv5_zero(dst, n) -> dst + n. */
LOCAL_FUNCTION discv5_zero
    UNWIND_END_PROLOGUE
    mov     %rsi, %rcx
    xor     %eax, %eax
    rep stosb
    mov     %rdi, %rax
    ret
END_FUNCTION discv5_zero

/* discv5_equal(a, b, n) -> 1 when the n bytes at a and b are equal, else 0. */
LOCAL_FUNCTION discv5_equal
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
    xor     %r8d, %r8d
1:  test    %rdx, %rdx
    jz      2f
    movzbl  (%rdi), %ecx
    xorb    (%rsi), %cl
    or      %rcx, %r8
    inc     %rdi
    inc     %rsi
    dec     %rdx
    jmp     1b
2:  test    %r8, %r8
    sete    %al
    ret
END_FUNCTION discv5_equal

/* discv5_log_distance(a, b) -> 0 when the 32-byte IDs are equal, else 256 minus the leading zero bits of a XOR b. */
LOCAL_FUNCTION discv5_log_distance
    UNWIND_END_PROLOGUE
    mov     $256, %eax
    xor     %ecx, %ecx
1:  mov     (%rdi,%rcx), %rdx
    xor     (%rsi,%rcx), %rdx
    bswap   %rdx
    test    %rdx, %rdx
    jnz     2f
    sub     $64, %rax
    add     $8, %rcx
    cmp     $32, %rcx
    jb      1b
    xor     %eax, %eax
    ret
2:  bsr     %rdx, %rdx                      /* 63 minus the leading zero bits */
    sub     $63, %rax
    add     %rdx, %rax
    ret
END_FUNCTION discv5_log_distance

/* discv5_load_be(p, n) -> the n bytes at p (n at most 8) as a big-endian number. */
LOCAL_FUNCTION discv5_load_be
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
1:  test    %rsi, %rsi
    jz      2f
    shl     $8, %rax
    movzbl  (%rdi), %ecx
    or      %rcx, %rax
    inc     %rdi
    dec     %rsi
    jmp     1b
2:  ret
END_FUNCTION discv5_load_be

/* discv5_store_be(p, v, n): the low n bytes of v (n at most 8) at p, big endian. */
LOCAL_FUNCTION discv5_store_be
    UNWIND_END_PROLOGUE
    lea     0(,%rdx,8), %rcx
1:  test    %rcx, %rcx
    jz      2f
    sub     $8, %rcx
    mov     %rsi, %rax
    shr     %cl, %rax
    mov     %al, (%rdi)
    inc     %rdi
    jmp     1b
2:  ret
END_FUNCTION discv5_store_be

/* ---------------------------------------------------------------- RLP writers */

/* nbytes = bytes of the number v, which is not 0. Uses rcx. */
.macro BYTES_OF v, nbytes
    bsr     \v, %rcx
    lea     8(%rcx), \nbytes
    shr     $3, \nbytes
.endm

/* Write the n bytes of v big endian at rdi, moving rdi. Uses rax and rcx. */
.macro WRITE_BE v, n
    lea     0(,\n,8), %rcx
97: sub     $8, %rcx
    mov     \v, %rax
    shr     %cl, %rax
    mov     %al, (%rdi)
    inc     %rdi
    test    %rcx, %rcx
    jnz     97b
.endm

/* discv5_rlp_header(out, length, base) -> out after the header: base 0x80 for a byte string, 0xC0 for a list. */
LOCAL_FUNCTION discv5_rlp_header
    UNWIND_END_PROLOGUE
    cmp     $55, %rsi
    ja      1f
    add     %rsi, %rdx
    mov     %dl, (%rdi)
    lea     1(%rdi), %rax
    ret
1:  BYTES_OF %rsi, %r8
    lea     55(%rdx,%r8), %rdx
    mov     %dl, (%rdi)
    inc     %rdi
    WRITE_BE %rsi, %r8
    mov     %rdi, %rax
    ret
END_FUNCTION discv5_rlp_header

/* discv5_rlp_bytes(out, data, len) -> out after the byte string encoding. A byte below 0x80 is itself. */
LOCAL_FUNCTION discv5_rlp_bytes
    UNWIND_END_PROLOGUE
    cmp     $1, %rdx
    jne     1f
    movzbl  (%rsi), %eax
    cmp     $0x80, %eax
    jae     1f
    mov     %al, (%rdi)
    lea     1(%rdi), %rax
    ret
1:  mov     %rsi, %r9
    cmp     $55, %rdx
    ja      2f
    lea     0x80(%rdx), %eax
    mov     %al, (%rdi)
    inc     %rdi
    jmp     3f
2:  BYTES_OF %rdx, %r8
    lea     0xB7(%r8), %eax
    mov     %al, (%rdi)
    inc     %rdi
    WRITE_BE %rdx, %r8
3:  mov     %r9, %rsi
    mov     %rdx, %rcx
    rep movsb
    mov     %rdi, %rax
    ret
END_FUNCTION discv5_rlp_bytes

/* discv5_rlp_uint(out, value) -> out after the value as a byte string, big endian with no leading zero. */
LOCAL_FUNCTION discv5_rlp_uint
    UNWIND_END_PROLOGUE
    test    %rsi, %rsi
    jnz     1f
    movb    $0x80, (%rdi)
    lea     1(%rdi), %rax
    ret
1:  cmp     $0x80, %rsi
    jae     2f
    mov     %sil, (%rdi)
    lea     1(%rdi), %rax
    ret
2:  BYTES_OF %rsi, %r8
    lea     0x80(%r8), %eax
    mov     %al, (%rdi)
    inc     %rdi
    WRITE_BE %rsi, %r8
    mov     %rdi, %rax
    ret
END_FUNCTION discv5_rlp_uint

/* ---------------------------------------------------------------- Hashes and the DRBG */

/*
 * discv5_hash(data, len, digest, keccak): SHA-256 (keccak 0) or Keccak-256
 * (keccak 1) of len bytes, len at most 304. The bytes go into a ByteList on
 * the stack first. rbx digest, rbp keccak.
 */
LOCAL_FUNCTION discv5_hash
    ENTER   344
    mov     %rdx, %rbx
    mov     %rcx, %rbp
    movq    $328, (%rsp)
    movq    $DISCV5_BL_FIXED, 8(%rsp)
    mov     %rsi, 16(%rsp)
    mov     %rsi, %rcx
    mov     %rdi, %rsi
    lea     24(%rsp), %rdi
    rep movsb
    mov     %rsp, %rdi
    mov     %rbx, %rsi
    test    %rbp, %rbp
    jnz     1f
    CALL_GLOBAL crypto_sha256
    jmp     2f
1:  CALL_GLOBAL crypto_keccak256
2:  LEAVE   344
END_FUNCTION discv5_hash

/*
 * discv5_random(state, out, n): n bytes from the DRBG. Each 32-byte block is
 * SHA-256(key || counter), the counter as 8 bytes little endian; the counter
 * then goes up by 1. rbx state, rbp out, r12 bytes left. The hash input
 * at rsp, the block at rsp + 64.
 */
LOCAL_FUNCTION discv5_random
    ENTER   104
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
1:  test    %r12, %r12
    jz      9f
    movq    $64, (%rsp)
    movq    $DISCV5_BL_FIXED, 8(%rsp)
    movq    $40, 16(%rsp)
    mov     DISCV5_ST_DRBG_KEY(%rbx), %rax
    mov     %rax, 24(%rsp)
    mov     DISCV5_ST_DRBG_KEY+8(%rbx), %rax
    mov     %rax, 32(%rsp)
    mov     DISCV5_ST_DRBG_KEY+16(%rbx), %rax
    mov     %rax, 40(%rsp)
    mov     DISCV5_ST_DRBG_KEY+24(%rbx), %rax
    mov     %rax, 48(%rsp)
    mov     DISCV5_ST_DRBG_COUNT(%rbx), %rax
    mov     %rax, 56(%rsp)
    inc     %rax
    mov     %rax, DISCV5_ST_DRBG_COUNT(%rbx)
    mov     %rsp, %rdi
    lea     64(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    mov     $32, %ecx
    cmp     %rcx, %r12
    cmovb   %r12, %rcx
    sub     %rcx, %r12
    mov     %rbp, %rdi
    lea     64(%rsp), %rsi
    rep movsb
    mov     %rdi, %rbp
    jmp     1b
9:  LEAVE   104
END_FUNCTION discv5_random

/* discv5_reseed(state, entropy): the DRBG key becomes SHA-256(key || the 32 entropy bytes). rbx state. */
LOCAL_FUNCTION discv5_reseed
    ENTER   104
    mov     %rdi, %rbx
    movq    $88, (%rsp)
    movq    $DISCV5_BL_FIXED, 8(%rsp)
    movq    $64, 16(%rsp)
    mov     DISCV5_ST_DRBG_KEY(%rbx), %rax
    mov     %rax, 24(%rsp)
    mov     DISCV5_ST_DRBG_KEY+8(%rbx), %rax
    mov     %rax, 32(%rsp)
    mov     DISCV5_ST_DRBG_KEY+16(%rbx), %rax
    mov     %rax, 40(%rsp)
    mov     DISCV5_ST_DRBG_KEY+24(%rbx), %rax
    mov     %rax, 48(%rsp)
    mov     (%rsi), %rax
    mov     %rax, 56(%rsp)
    mov     8(%rsi), %rax
    mov     %rax, 64(%rsp)
    mov     16(%rsi), %rax
    mov     %rax, 72(%rsp)
    mov     24(%rsi), %rax
    mov     %rax, 80(%rsp)
    mov     %rsp, %rdi
    lea     DISCV5_ST_DRBG_KEY(%rbx), %rsi
    CALL_GLOBAL crypto_sha256
    LEAVE   104
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

/* Branch to label unless the n-byte string at ptr (len bytes) is a canonical number of at most n bytes. */
.macro CHECK_UINT ptr, len, n, label
    cmp     $\n, \len
    ja      \label
    test    \len, \len
    jz      96f
    cmpb    $0, (\ptr)
    je      \label
96:
.endm

/* discv5_enr_decode locals. */
.set ED_COUNT, 0                    /* item count */
.set ED_PREV, 8                     /* the previous key, 0 before the first; then the content length */
.set ED_PAIRS, 16                   /* pairs */
.set ED_FLAGS, 24                   /* bit 0 id is v4, bit 1 secp256k1 seen */
.set ED_PREV_LEN, 32                /* the previous key's length */
.set ED_SIG, 40                     /* the signature item */

/*
 * discv5_enr_decode(record, scratch, enr) -> status
 * rbx record, rbp scratch, r12 enr, r13 record bytes, r14 items, r15 child
 * index. Locals ED_*.
 */
FUNCTION discv5_enr_decode
    ENTER   56
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     $DISCV5_BUFFER_TOO_SMALL, %eax
    cmpq    $DISCV5_ENR_SCRATCH, (%rbp)
    jb      99f
    mov     %r12, %rdi
    mov     $DISCV5_ENR_SIZE, %esi
    call    discv5_zero
    mov     DISCV5_BL_COUNT(%rbx), %rax
    test    %rax, %rax
    jz      98f
    cmp     $DISCV5_MAX_RECORD, %rax
    ja      98f
    mov     DISCV5_BL_OFFSET(%rbx), %r13
    add     %rbx, %r13
    lea     ES_ITEMS(%rbp), %rsi
    movq    $ES_ITEMS_SIZE, (%rsi)
    mov     %rbx, %rdi
    CALL_GLOBAL rlp_decode
    test    %rax, %rax
    jnz     98f
    lea     ES_ITEMS(%rbp), %rcx
    mov     RLP_ITEMS_OFFSET(%rcx), %r14
    add     %rcx, %r14
    mov     RLP_ITEMS_COUNT(%rcx), %rax
    mov     %rax, ED_COUNT(%rsp)
    cmpq    $RLP_KIND_LIST, RLP_ITEM_KIND(%r14)
    jne     98f

    /* The signature: 64 bytes. */
    cmpq    $1, ED_COUNT(%rsp)
    jbe     98f
    lea     RLP_ITEM_STRIDE(%r14), %rcx
    cmpq    $RLP_KIND_BYTES, RLP_ITEM_KIND(%rcx)
    jne     98f
    cmpq    $64, RLP_ITEM_LENGTH(%rcx)
    jne     98f
    mov     %rcx, ED_SIG(%rsp)

    /* The sequence number. */
    cmpq    $2, ED_COUNT(%rsp)
    jbe     98f
    lea     2*RLP_ITEM_STRIDE(%r14), %rcx
    cmpq    $RLP_KIND_BYTES, RLP_ITEM_KIND(%rcx)
    jne     98f
    mov     RLP_ITEM_OFFSET(%rcx), %rdi
    add     %r13, %rdi
    mov     RLP_ITEM_LENGTH(%rcx), %rsi
    CHECK_UINT %rdi, %rsi, 8, 98f
    call    discv5_load_be
    mov     %rax, DISCV5_ENR_SEQ(%r12)

    /* Key/value pairs, keys sorted and unique. rsi key, rdx key length, r8 value, r9 value length, r10 pair. */
    mov     $3, %r15
    movq    $0, ED_PREV(%rsp)
    movq    $0, ED_PAIRS(%rsp)
    movq    $0, ED_FLAGS(%rsp)
1:  cmp     ED_COUNT(%rsp), %r15
    jae     5f
    mov     %r15, %rcx
    shl     $RLP_ITEM_SHIFT, %rcx
    add     %r14, %rcx
    cmpq    $RLP_KIND_BYTES, RLP_ITEM_KIND(%rcx)
    jne     98f
    mov     RLP_ITEM_OFFSET(%rcx), %rsi
    add     %r13, %rsi
    mov     RLP_ITEM_LENGTH(%rcx), %rdx
    mov     ED_PREV(%rsp), %rdi
    test    %rdi, %rdi
    jz      3f
    mov     ED_PREV_LEN(%rsp), %r8
    xor     %ecx, %ecx
2:  cmp     %r8, %rcx
    jb      21f
    cmp     %r8, %rdx                       /* the previous key is a prefix: increasing when the new key is longer */
    ja      3f
    jmp     98f
21: cmp     %rdx, %rcx
    jae     98f                             /* the new key is a prefix of the previous one */
    movzbl  (%rdi,%rcx), %eax
    movzbl  (%rsi,%rcx), %r9d
    cmp     %r9d, %eax
    jb      3f
    ja      98f
    inc     %rcx
    jmp     2b
3:  mov     %rsi, ED_PREV(%rsp)
    mov     %rdx, ED_PREV_LEN(%rsp)
    mov     ED_PAIRS(%rsp), %r10
    cmp     $DISCV5_ENR_MAX_PAIRS, %r10
    jae     98f
    lea     1(%r15), %rcx                   /* the value */
    cmp     ED_COUNT(%rsp), %rcx
    jae     98f
    shl     $RLP_ITEM_SHIFT, %rcx
    add     %r14, %rcx
    imul    $DISCV5_PAIR_SIZE, %r10, %r10
    lea     DISCV5_ENR_PAIRS(%r12,%r10), %r10
    mov     %rsi, %rax
    sub     %r13, %rax
    mov     %eax, DISCV5_PAIR_KEY_OFFSET(%r10)
    mov     %edx, DISCV5_PAIR_KEY_LEN(%r10)
    mov     RLP_ITEM_KIND(%rcx), %rax
    mov     %eax, DISCV5_PAIR_VALUE_KIND(%r10)
    mov     RLP_ITEM_OFFSET(%rcx), %r8
    mov     RLP_ITEM_LENGTH(%rcx), %r9
    cmp     $RLP_KIND_BYTES, %rax
    je      4f
    mov     $1, %eax                        /* a list: the whole encoding, header included */
    cmp     $55, %r9
    jbe     31f
    bsr     %r9, %rax
    add     $8, %rax
    shr     $3, %rax
    inc     %rax
31: sub     %rax, %r8
    add     %rax, %r9
    mov     %r8d, DISCV5_PAIR_VALUE_OFFSET(%r10)
    mov     %r9d, DISCV5_PAIR_VALUE_LEN(%r10)
    jmp     45f
4:  mov     %r8d, DISCV5_PAIR_VALUE_OFFSET(%r10)
    mov     %r9d, DISCV5_PAIR_VALUE_LEN(%r10)
    add     %r13, %r8                       /* value bytes */
    lea     400f(%rip), %r11
    cmp     $2, %rdx                        /* "id" and "ip" */
    jne     41f
    movzwl  (%rsi), %eax
    cmpw    (%r11), %ax
    jne     40f
    cmp     $2, %r9                         /* "id" = "v4" */
    jne     98f
    movzwl  (%r8), %ecx
    cmpw    2(%r11), %cx
    jne     98f
    orq     $1, ED_FLAGS(%rsp)
    jmp     45f
40: cmpw    4(%r11), %ax                    /* "ip": 4 bytes */
    jne     45f
    cmp     $4, %r9
    jne     45f
    mov     (%r8), %ecx
    mov     %ecx, DISCV5_ENR_IP4(%r12)
    orq     $DISCV5_HAS_IP4, DISCV5_ENR_HAS(%r12)
    jmp     45f
41: cmp     $3, %rdx                        /* "udp" and "ip6" */
    jne     43f
    movzwl  (%rsi), %eax
    movzbl  2(%rsi), %ecx
    shl     $16, %ecx
    or      %ecx, %eax
    cmp     8(%r11), %eax                   /* "udp" */
    jne     42f
    CHECK_UINT %r8, %r9, 2, 45f
    mov     %r8, %rdi
    mov     %r9, %rsi
    call    discv5_load_be
    mov     %rax, DISCV5_ENR_UDP4(%r12)
    orq     $DISCV5_HAS_UDP4, DISCV5_ENR_HAS(%r12)
    jmp     45f
42: cmp     12(%r11), %eax                  /* "ip6": 16 bytes */
    jne     45f
    cmp     $16, %r9
    jne     45f
    mov     (%r8), %rcx
    mov     %rcx, DISCV5_ENR_IP6(%r12)
    mov     8(%r8), %rcx
    mov     %rcx, DISCV5_ENR_IP6+8(%r12)
    orq     $DISCV5_HAS_IP6, DISCV5_ENR_HAS(%r12)
    jmp     45f
43: cmp     $4, %rdx                        /* "udp6" */
    jne     44f
    mov     (%rsi), %eax
    cmp     16(%r11), %eax
    jne     45f
    CHECK_UINT %r8, %r9, 2, 45f
    mov     %r8, %rdi
    mov     %r9, %rsi
    call    discv5_load_be
    mov     %rax, DISCV5_ENR_UDP6(%r12)
    orq     $DISCV5_HAS_UDP6, DISCV5_ENR_HAS(%r12)
    jmp     45f
44: cmp     $9, %rdx                        /* "secp256k1": 33 bytes */
    jne     45f
    mov     (%rsi), %rax
    cmp     24(%r11), %rax
    jne     45f
    movzbl  8(%rsi), %eax
    cmpb    32(%r11), %al
    jne     45f
    cmp     $33, %r9
    jne     98f
    lea     DISCV5_ENR_PUBKEY(%r12), %rdi
    mov     %r8, %rsi
    mov     $33, %edx
    call    discv5_copy
    orq     $2, ED_FLAGS(%rsp)
45: incq    ED_PAIRS(%rsp)
    lea     1(%r15), %rcx
    mov     %rcx, %rax
    shl     $RLP_ITEM_SHIFT, %rax
    add     %r14, %rax
    add     RLP_ITEM_ITEMS(%rax), %rcx
    mov     %rcx, %r15
    jmp     1b

    /* The v4 scheme: the id, the key, the node ID and the signature. */
5:  cmpq    $3, ED_FLAGS(%rsp)
    jne     98f
    mov     ED_PAIRS(%rsp), %rax
    mov     %rax, DISCV5_ENR_COUNT(%r12)
    lea     DISCV5_ENR_PUBKEY(%r12), %rdi
    lea     ES_POINT(%rbp), %rsi
    CALL_GLOBAL crypto_secp256k1_decompress
    test    %rax, %rax
    jnz     98f
    lea     ES_POINT(%rbp), %rdi
    mov     $64, %esi
    lea     DISCV5_ENR_NODE_ID(%r12), %rdx
    mov     $1, %ecx
    call    discv5_hash

    /* The content [seq, k, v, ...]: a new list header, then the record bytes after the signature. */
    mov     ED_SIG(%rsp), %rcx
    mov     RLP_ITEM_OFFSET(%rcx), %rsi
    add     %r13, %rsi
    lea     ES_SIG(%rbp), %rdi
    mov     $64, %edx
    call    discv5_copy
    mov     ED_SIG(%rsp), %rcx
    mov     RLP_ITEM_OFFSET(%rcx), %r15
    add     $64, %r15                       /* the content payload starts after the signature */
    mov     RLP_ITEM_OFFSET(%r14), %rax
    add     RLP_ITEM_LENGTH(%r14), %rax     /* and ends with the record */
    sub     %r15, %rax
    mov     %rax, ED_PREV(%rsp)
    lea     ES_CONTENT(%rbp), %rdi
    mov     %rax, %rsi
    mov     $0xC0, %edx
    call    discv5_rlp_header
    mov     %rax, %rdi
    lea     (%r13,%r15), %rsi
    mov     ED_PREV(%rsp), %rdx
    call    discv5_copy
    lea     ES_CONTENT(%rbp), %rdi
    mov     %rax, %rsi
    sub     %rdi, %rsi
    lea     ES_HASH(%rbp), %rdx
    mov     $1, %ecx
    call    discv5_hash
    lea     DISCV5_ENR_PUBKEY(%r12), %rdi
    lea     ES_HASH(%rbp), %rsi
    lea     ES_SIG(%rbp), %rdx
    lea     ES_VALID(%rbp), %rcx
    CALL_GLOBAL crypto_secp256k1_verify
    test    %rax, %rax
    jnz     98f
    cmpq    $0, ES_VALID(%rbp)
    je      98f
    xor     %eax, %eax
    jmp     99f
98: mov     $DISCV5_INVALID_RECORD, %eax
99: LEAVE   56
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
 * with no padding. rbx text bytes, rbp record, r12 characters left, r13
 * output, r14 bits, r15 bits held.
 */
FUNCTION discv5_enr_text_decode
    ENTER   8
    mov     %rsi, %rbp
    mov     $DISCV5_INVALID_TEXT, %eax
    mov     DISCV5_BL_COUNT(%rdi), %r12
    cmp     $4, %r12
    jb      99f
    mov     DISCV5_BL_OFFSET(%rdi), %rbx
    add     %rdi, %rbx
    cmpl    $0x3a726e65, (%rbx)             /* "enr:" */
    jne     99f
    add     $4, %rbx
    sub     $4, %r12
    mov     %r12, %rcx
    and     $3, %rcx
    cmp     $1, %rcx
    je      99f
    xor     %ecx, %ecx                      /* every character must be in the alphabet */
11: cmp     %r12, %rcx
    jae     12f
    movzbl  (%rbx,%rcx), %edx
    inc     %rcx
    lea     -'A'(%rdx), %r8d
    cmp     $26, %r8d
    jb      11b
    lea     -'a'(%rdx), %r8d
    cmp     $26, %r8d
    jb      11b
    lea     -'0'(%rdx), %r8d
    cmp     $10, %r8d
    jb      11b
    cmp     $'-', %edx
    je      11b
    cmp     $'_', %edx
    je      11b
    jmp     99f
12: lea     (%r12,%r12,2), %rcx
    shr     $2, %rcx                        /* output bytes */
    mov     $DISCV5_BUFFER_TOO_SMALL, %eax
    mov     DISCV5_BL_SIZE(%rbp), %rdx
    sub     $DISCV5_BL_FIXED, %rdx
    jb      99f
    cmp     %rcx, %rdx
    jb      99f
    lea     DISCV5_BL_FIXED(%rbp), %r13
    xor     %r14d, %r14d
    xor     %r15d, %r15d
1:  test    %r12, %r12
    jz      8f
    movzbl  (%rbx), %edx
    inc     %rbx
    dec     %r12
    lea     -'A'(%rdx), %r8d
    cmp     $26, %r8d
    jb      2f
    lea     -'a'(%rdx), %r8d
    cmp     $26, %r8d
    lea     26(%r8), %r8d
    jb      2f
    lea     -'0'(%rdx), %r8d
    cmp     $10, %r8d
    lea     52(%r8), %r8d
    jb      2f
    mov     $62, %r8d
    cmp     $'-', %edx
    je      2f
    mov     $63, %r8d
2:  shl     $6, %r14
    or      %r8, %r14
    add     $6, %r15
    cmp     $8, %r15
    jb      1b
    sub     $8, %r15
    mov     %r14, %rax
    mov     %r15, %rcx
    shr     %cl, %rax
    mov     %al, (%r13)
    inc     %r13
    jmp     1b
8:  movq    $DISCV5_BL_FIXED, DISCV5_BL_OFFSET(%rbp)
    lea     DISCV5_BL_FIXED(%rbp), %rax
    sub     %rax, %r13
    mov     %r13, DISCV5_BL_COUNT(%rbp)
    xor     %eax, %eax
99: LEAVE   8
END_FUNCTION discv5_enr_text_decode

/* discv5_local_record(state, record) -> status: a copy of the local record. rbx state, rbp record, r12 length. */
FUNCTION discv5_local_record
    ENTER   8
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     $DISCV5_BUFFER_TOO_SMALL, %eax
    mov     DISCV5_ST_RECORD_LEN(%rbx), %r12
    mov     DISCV5_BL_SIZE(%rbp), %rcx
    sub     $DISCV5_BL_FIXED, %rcx
    jb      9f
    cmp     %r12, %rcx
    jb      9f
    movq    $DISCV5_BL_FIXED, DISCV5_BL_OFFSET(%rbp)
    mov     %r12, DISCV5_BL_COUNT(%rbp)
    lea     DISCV5_BL_FIXED(%rbp), %rdi
    lea     DISCV5_ST_RECORD(%rbx), %rsi
    mov     %r12, %rdx
    call    discv5_copy
    xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_local_record

/* ---------------------------------------------------------------- Packets (discv5-wire.md) */

/* discv5_packet_decode stack: the masked bytes and the unmasked bytes, as ByteLists, then the flag and the authdata size. */
.set PD_IN, 0
.set PD_OUT, 520
.set PD_FLAG, 1040
.set PD_AUTH, 1048
.set PD_UNMASK, 496                 /* most bytes unmasked: the static header and 473 bytes of authdata */

/*
 * discv5_packet_decode(packet, local_id, header) -> status
 * rbx packet, rbp local_id, r12 header, r13 packet bytes, r14 length,
 * r15 unmasked bytes.
 */
FUNCTION discv5_packet_decode
    ENTER   1064
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     DISCV5_BL_COUNT(%rbx), %r14
    cmp     $DISCV5_MIN_PACKET, %r14
    jb      98f
    cmp     $DISCV5_MAX_PACKET, %r14
    ja      98f
    mov     DISCV5_BL_OFFSET(%rbx), %r13
    add     %rbx, %r13
    mov     (%r13), %rax
    mov     %rax, DISCV5_HDR_IV(%r12)
    mov     8(%r13), %rax
    mov     %rax, DISCV5_HDR_IV+8(%r12)
    lea     -DISCV5_MASKED_START(%r14), %rcx
    mov     $PD_UNMASK, %eax
    cmp     %rax, %rcx
    cmova   %rax, %rcx
    BYTELIST %rsp, PD_IN, 520, %rcx
    BYTELIST %rsp, PD_OUT, 520, $0
    lea     PD_IN+DISCV5_BL_FIXED(%rsp), %rdi
    lea     DISCV5_MASKED_START(%r13), %rsi
    mov     %rcx, %rdx
    call    discv5_copy
    mov     %rbp, %rdi
    lea     DISCV5_HDR_IV(%r12), %rsi
    lea     PD_IN(%rsp), %rdx
    lea     PD_OUT(%rsp), %rcx
    CALL_GLOBAL crypto_aes128_ctr
    lea     PD_OUT+DISCV5_BL_FIXED(%rsp), %r15

    /* The static header: "discv5", version at least 1, flag, nonce, authdata size. */
    lea     410f(%rip), %rax
    mov     (%r15), %ecx
    cmp     (%rax), %ecx
    jne     98f
    movzwl  4(%r15), %ecx
    cmpw    4(%rax), %cx
    jne     98f
    movzbl  6(%r15), %ecx
    movzbl  7(%r15), %edx
    shl     $8, %ecx
    or      %edx, %ecx
    jz      98f
    movzbl  8(%r15), %eax
    mov     %rax, PD_FLAG(%rsp)
    mov     %rax, DISCV5_HDR_FLAG(%r12)
    lea     DISCV5_HDR_NONCE(%r12), %rdi
    lea     9(%r15), %rsi
    mov     $12, %edx
    call    discv5_copy
    movzbl  21(%r15), %eax
    movzbl  22(%r15), %ecx
    shl     $8, %eax
    or      %ecx, %eax
    mov     %rax, PD_AUTH(%rsp)
    lea     -DISCV5_HEADER_START(%r14), %rcx    /* bytes after the static header */
    cmpq    $DISCV5_FLAG_WHOAREYOU, PD_FLAG(%rsp)
    je      1f
    cmp     $48, %rcx
    jb      98f
1:  cmp     %rcx, %rax
    ja      98f
    cmp     $(PD_UNMASK - DISCV5_STATIC_HEADER), %rax
    ja      98f

    /* The unmasked header, kept for the message's associated data. */
    lea     DISCV5_HEADER_START(%rax), %rcx
    lea     DISCV5_HDR_HEADER(%r12), %rdx
    BYTELIST %rdx, 0, DISCV5_HDR_HEADER_SIZE, %rcx
    lea     DISCV5_HDR_HEADER+DISCV5_BL_FIXED(%r12), %rdi
    lea     DISCV5_HDR_IV(%r12), %rsi
    mov     $16, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     %r15, %rsi
    mov     PD_AUTH(%rsp), %rdx
    add     $DISCV5_STATIC_HEADER, %rdx
    call    discv5_copy
    lea     DISCV5_HDR_RECORD(%r12), %rdx
    BYTELIST %rdx, 0, DISCV5_HDR_RECORD_SIZE, $0
    add     $DISCV5_STATIC_HEADER, %r15     /* authdata */
    mov     PD_FLAG(%rsp), %rax
    mov     PD_AUTH(%rsp), %rcx
    cmp     $DISCV5_FLAG_MESSAGE, %rax
    jne     2f
    cmp     $32, %rcx
    jne     98f
    lea     DISCV5_HDR_SRC_ID(%r12), %rdi
    mov     %r15, %rsi
    mov     $32, %edx
    call    discv5_copy
    jmp     8f
2:  cmp     $DISCV5_FLAG_WHOAREYOU, %rax
    jne     3f
    cmp     $24, %rcx
    jne     98f
    lea     DISCV5_HDR_ID_NONCE(%r12), %rdi
    mov     %r15, %rsi
    mov     $16, %edx
    call    discv5_copy
    lea     16(%r15), %rdi
    mov     $8, %esi
    call    discv5_load_be
    mov     %rax, DISCV5_HDR_ENR_SEQ(%r12)
    jmp     8f
3:  cmp     $DISCV5_FLAG_HANDSHAKE, %rax
    jne     98f
    cmp     $(34 + 64 + 33), %rcx
    jb      98f
    cmpb    $64, 32(%r15)
    jne     98f
    cmpb    $33, 33(%r15)
    jne     98f
    sub     $(34 + 64 + 33), %rcx
    cmp     $DISCV5_MAX_RECORD, %rcx
    ja      98f
    mov     %rcx, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(%r12)
    lea     DISCV5_HDR_SRC_ID(%r12), %rdi
    mov     %r15, %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_HDR_SIGNATURE(%r12), %rdi
    lea     34(%r15), %rsi
    mov     $64, %edx
    call    discv5_copy
    lea     DISCV5_HDR_EPH_KEY(%r12), %rdi
    lea     98(%r15), %rsi
    mov     $33, %edx
    call    discv5_copy
    lea     DISCV5_HDR_RECORD+DISCV5_BL_FIXED(%r12), %rdi
    lea     131(%r15), %rsi
    mov     DISCV5_HDR_RECORD+DISCV5_BL_COUNT(%r12), %rdx
    call    discv5_copy
8:  xor     %eax, %eax
    jmp     99f
98: mov     $DISCV5_INVALID_PACKET, %eax
99: LEAVE   1064
END_FUNCTION discv5_packet_decode

/*
 * discv5_message_decrypt(header, key, packet, message) -> status: AES-GCM
 * open of the bytes after the header, with the header nonce and the
 * unmasked header as associated data. The sealed bytes at rsp.
 * rbx header, rbp key, r12 packet, r13 message, r14 header length, r15 sealed length.
 */
FUNCTION discv5_message_decrypt
    ENTER   1320
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     DISCV5_HDR_HEADER+DISCV5_BL_COUNT(%rbx), %r14
    mov     DISCV5_BL_COUNT(%r12), %r15
    sub     %r14, %r15
    jb      98f
    cmp     $(CRYPTO_GCM_TAG_SIZE + 1), %r15
    jb      98f
    cmp     $1304, %r15
    ja      98f
    BYTELIST %rsp, 0, 1304, %r15
    mov     DISCV5_BL_OFFSET(%r12), %rsi
    add     %r12, %rsi
    add     %r14, %rsi
    lea     DISCV5_BL_FIXED(%rsp), %rdi
    mov     %r15, %rdx
    call    discv5_copy
    mov     %rbp, %rdi
    lea     DISCV5_HDR_NONCE(%rbx), %rsi
    mov     %rsp, %rdx
    lea     DISCV5_HDR_HEADER(%rbx), %rcx
    mov     %r13, %r8
    CALL_GLOBAL crypto_aes128_gcm_ad
    cmp     $CRYPTO_GCM_FAIL, %rax
    jne     99f
98: mov     $DISCV5_DECRYPT_FAIL, %eax
99: LEAVE   1320
END_FUNCTION discv5_message_decrypt

/* discv5_packet_encode stack: the header to mask, the masked header, the sealed message, then three numbers. */
.set PE_IN, 0
.set PE_OUT, 520
.set PE_SEALED, 1040
.set PE_HLEN, 2344                  /* header length */
.set PE_TOTAL, 2352                 /* packet length */
.set PE_POS, 2360                   /* write position */

/*
 * discv5_packet_encode(header, dest_id, key, message, packet) -> status
 * rbx header, rbp dest_id, r12 key, r13 message, r14 packet, r15 flag.
 */
FUNCTION discv5_packet_encode
    ENTER   2376
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, %r14
    mov     DISCV5_HDR_FLAG(%rbx), %r15

    /* The unmasked header: IV, "discv5", version 1, flag, nonce, authdata size, authdata. */
    lea     DISCV5_HDR_HEADER+DISCV5_BL_FIXED(%rbx), %rdi
    lea     DISCV5_HDR_IV(%rbx), %rsi
    mov     $16, %edx
    call    discv5_copy
    mov     %rax, %rdi
    lea     410f(%rip), %rsi
    mov     $6, %edx
    call    discv5_copy
    movb    $0, (%rax)
    movb    $1, 1(%rax)
    mov     %r15b, 2(%rax)
    lea     3(%rax), %rdi
    lea     DISCV5_HDR_NONCE(%rbx), %rsi
    mov     $12, %edx
    call    discv5_copy
    mov     %rax, PE_POS(%rsp)
    cmp     $DISCV5_FLAG_MESSAGE, %r15
    jne     1f
    mov     $32, %ecx
    jmp     4f
1:  cmp     $DISCV5_FLAG_WHOAREYOU, %r15
    jne     2f
    mov     $24, %ecx
    jmp     4f
2:  cmp     $DISCV5_FLAG_HANDSHAKE, %r15
    jne     98f
    mov     DISCV5_HDR_RECORD+DISCV5_BL_COUNT(%rbx), %rcx
    cmp     $DISCV5_MAX_RECORD, %rcx
    ja      98f
    add     $(34 + 64 + 33), %rcx
4:  mov     PE_POS(%rsp), %rdi
    mov     %ecx, %eax
    shr     $8, %eax
    mov     %al, (%rdi)
    mov     %cl, 1(%rdi)
    add     $2, %rdi
    lea     DISCV5_HEADER_START(%rcx), %rax
    mov     %rax, PE_HLEN(%rsp)
    cmp     $DISCV5_FLAG_WHOAREYOU, %r15
    je      5f
    lea     DISCV5_HDR_SRC_ID(%rbx), %rsi
    mov     $32, %edx
    call    discv5_copy
    cmp     $DISCV5_FLAG_HANDSHAKE, %r15
    jne     6f
    movb    $64, (%rax)
    movb    $33, 1(%rax)
    lea     2(%rax), %rdi
    lea     DISCV5_HDR_SIGNATURE(%rbx), %rsi
    mov     $64, %edx
    call    discv5_copy
    mov     %rax, %rdi
    lea     DISCV5_HDR_EPH_KEY(%rbx), %rsi
    mov     $33, %edx
    call    discv5_copy
    mov     %rax, %rdi
    lea     DISCV5_HDR_RECORD+DISCV5_BL_FIXED(%rbx), %rsi
    mov     DISCV5_HDR_RECORD+DISCV5_BL_COUNT(%rbx), %rdx
    call    discv5_copy
    jmp     6f
5:  lea     DISCV5_HDR_ID_NONCE(%rbx), %rsi
    mov     $16, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     DISCV5_HDR_ENR_SEQ(%rbx), %rsi
    mov     $8, %edx
    call    discv5_store_be
6:  mov     PE_HLEN(%rsp), %rax
    mov     %rax, DISCV5_HDR_HEADER+DISCV5_BL_COUNT(%rbx)
    movq    $DISCV5_HDR_HEADER_SIZE, DISCV5_HDR_HEADER+DISCV5_BL_SIZE(%rbx)
    movq    $DISCV5_BL_FIXED, DISCV5_HDR_HEADER+DISCV5_BL_OFFSET(%rbx)

    /* Sizes: the header, then the sealed message unless this is WHOAREYOU. */
    mov     %rax, %rcx
    cmp     $DISCV5_FLAG_WHOAREYOU, %r15
    je      7f
    mov     DISCV5_BL_COUNT(%r13), %rdx
    add     $CRYPTO_GCM_TAG_SIZE, %rdx
    add     %rdx, %rcx
7:  mov     %rcx, PE_TOTAL(%rsp)
    cmp     $DISCV5_MAX_PACKET, %rcx
    ja      98f
    mov     $DISCV5_BUFFER_TOO_SMALL, %eax
    mov     DISCV5_BL_SIZE(%r14), %rdx
    sub     $DISCV5_BL_FIXED, %rdx
    jb      99f
    cmp     %rcx, %rdx
    jb      99f

    /* Mask: AES-CTR with the first 16 bytes of the destination ID, the IV as counter. */
    mov     PE_HLEN(%rsp), %rcx
    sub     $DISCV5_MASKED_START, %rcx
    BYTELIST %rsp, PE_IN, 520, %rcx
    BYTELIST %rsp, PE_OUT, 520, $0
    lea     PE_IN+DISCV5_BL_FIXED(%rsp), %rdi
    lea     DISCV5_HDR_HEADER+DISCV5_BL_FIXED+DISCV5_MASKED_START(%rbx), %rsi
    mov     %rcx, %rdx
    call    discv5_copy
    mov     %rbp, %rdi
    lea     DISCV5_HDR_IV(%rbx), %rsi
    lea     PE_IN(%rsp), %rdx
    lea     PE_OUT(%rsp), %rcx
    CALL_GLOBAL crypto_aes128_ctr
    movq    $DISCV5_BL_FIXED, DISCV5_BL_OFFSET(%r14)
    mov     PE_TOTAL(%rsp), %rax
    mov     %rax, DISCV5_BL_COUNT(%r14)
    lea     DISCV5_BL_FIXED(%r14), %rdi
    lea     DISCV5_HDR_IV(%rbx), %rsi
    mov     $16, %edx
    call    discv5_copy
    mov     %rax, %rdi
    lea     PE_OUT+DISCV5_BL_FIXED(%rsp), %rsi
    mov     PE_HLEN(%rsp), %rdx
    sub     $DISCV5_MASKED_START, %rdx
    call    discv5_copy
    mov     %rax, PE_POS(%rsp)
    cmp     $DISCV5_FLAG_WHOAREYOU, %r15
    je      8f

    /* The message: AES-GCM with the nonce, the unmasked header as associated data. */
    lea     PE_SEALED(%rsp), %rax
    BYTELIST %rax, 0, 1304, $0
    mov     %r12, %rdi
    lea     DISCV5_HDR_NONCE(%rbx), %rsi
    mov     %r13, %rdx
    lea     DISCV5_HDR_HEADER(%rbx), %rcx
    lea     PE_SEALED(%rsp), %r8
    CALL_GLOBAL crypto_aes128_gcm_ae
    mov     PE_POS(%rsp), %rdi
    lea     PE_SEALED+DISCV5_BL_FIXED(%rsp), %rsi
    mov     PE_SEALED+DISCV5_BL_COUNT(%rsp), %rdx
    call    discv5_copy
8:  xor     %eax, %eax
    jmp     99f
98: mov     $DISCV5_INVALID_PACKET, %eax
99: LEAVE   2376
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
.set DK_FRAME, 760

/*
 * discv5_derive_keys(private_key, public_key, challenge, ids, keys) -> status
 * secret = ecdh(public_key, private_key); prk = HKDF-Extract(challenge,
 * secret); keys = HKDF-Expand(prk, "discovery v5 key agreement" || ids, 32):
 * the initiator key, then the recipient key. ids: node ID A, then node ID B.
 * rbx private_key, rbp public_key, r12 challenge, r13 ids, r14 keys.
 */
FUNCTION discv5_derive_keys
    ENTER   DK_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, %r14
    BYTELIST %rsp, DK_IKM, 64, $33
    mov     %rbp, %rdi
    mov     %rbx, %rsi
    lea     DK_IKM+DISCV5_BL_FIXED(%rsp), %rdx
    CALL_GLOBAL crypto_secp256k1_ecdh
    test    %rax, %rax
    jnz     98f
    BYTELIST %rsp, DK_SALT, 88, $DISCV5_CHALLENGE_SIZE
    lea     DK_SALT+DISCV5_BL_FIXED(%rsp), %rdi
    mov     %r12, %rsi
    mov     $DISCV5_CHALLENGE_SIZE, %edx
    call    discv5_copy
    movq    $136, DK_SCRATCH1(%rsp)
    BYTELIST %rsp, DK_PRK, 56, $32
    lea     DK_SALT(%rsp), %rdi
    lea     DK_IKM(%rsp), %rsi
    lea     DK_SCRATCH1(%rsp), %rdx
    lea     DK_PRK+DISCV5_BL_FIXED(%rsp), %rcx
    CALL_GLOBAL crypto_hkdf_extract
    BYTELIST %rsp, DK_INFO, 120, $90
    lea     DK_INFO+DISCV5_BL_FIXED(%rsp), %rdi
    lea     411b(%rip), %rsi
    mov     $26, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     %r13, %rsi
    mov     $64, %edx
    call    discv5_copy
    movq    $32, DK_LENGTH(%rsp)
    movq    $224, DK_SCRATCH2(%rsp)
    lea     DK_OKM(%rsp), %rax
    BYTELIST %rax, 0, 56, $0
    lea     DK_PRK(%rsp), %rdi
    lea     DK_INFO(%rsp), %rsi
    lea     DK_LENGTH(%rsp), %rdx
    lea     DK_SCRATCH2(%rsp), %rcx
    lea     DK_OKM(%rsp), %r8
    CALL_GLOBAL crypto_hkdf_expand
    mov     DK_OKM+DISCV5_BL_FIXED(%rsp), %rax
    mov     %rax, (%r14)
    mov     DK_OKM+DISCV5_BL_FIXED+8(%rsp), %rax
    mov     %rax, 8(%r14)
    mov     DK_OKM+DISCV5_BL_FIXED+16(%rsp), %rax
    mov     %rax, 16(%r14)
    mov     DK_OKM+DISCV5_BL_FIXED+24(%rsp), %rax
    mov     %rax, 24(%r14)
    xor     %eax, %eax
    jmp     99f
98: mov     $DISCV5_INVALID_KEY, %eax
99: LEAVE   DK_FRAME
END_FUNCTION discv5_derive_keys

/*
 * The ID signature hash at rsp + 160: SHA-256("discovery v5 identity proof"
 * || challenge || ephemeral key || destination ID). Input: r12 challenge,
 * r13 ephemeral key, r14 destination ID. The 155 input bytes at rsp.
 */
.macro ID_HASH unused=0
.if \unused
.endif
    mov     %rsp, %rdi
    lea     412b(%rip), %rsi
    mov     $27, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     %r12, %rsi
    mov     $DISCV5_CHALLENGE_SIZE, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     %r13, %rsi
    mov     $33, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     %r14, %rsi
    mov     $32, %edx
    call    discv5_copy
    mov     %rsp, %rdi
    mov     $155, %esi
    lea     160(%rsp), %rdx
    xor     %ecx, %ecx
    call    discv5_hash
.endm

/* discv5_id_sign(private_key, challenge, ephemeral_key, dest_id, signature) -> status. rbx private key, r15 signature. */
FUNCTION discv5_id_sign
    ENTER   200
    mov     %rdi, %rbx
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, %r14
    mov     %r8, %r15
    ID_HASH
    mov     %rbx, %rdi
    lea     160(%rsp), %rsi
    mov     %r15, %rdx
    CALL_GLOBAL crypto_secp256k1_sign
    test    %rax, %rax
    jz      9f
    mov     $DISCV5_INVALID_KEY, %eax
9:  LEAVE   200
END_FUNCTION discv5_id_sign

/*
 * discv5_id_verify(public_key, challenge, header, dest_id, valid) -> status:
 * checks the signature and ephemeral key held in header. rbx public key,
 * rbp header, r15 valid.
 */
FUNCTION discv5_id_verify
    ENTER   200
    mov     %rdi, %rbx
    mov     %rsi, %r12
    mov     %rdx, %rbp
    lea     DISCV5_HDR_EPH_KEY(%rdx), %r13
    mov     %rcx, %r14
    mov     %r8, %r15
    ID_HASH
    mov     %rbx, %rdi
    lea     160(%rsp), %rsi
    lea     DISCV5_HDR_SIGNATURE(%rbp), %rdx
    mov     %r15, %rcx
    CALL_GLOBAL crypto_secp256k1_verify
    test    %rax, %rax
    jz      9f
    mov     $DISCV5_INVALID_KEY, %eax
9:  LEAVE   200
END_FUNCTION discv5_id_verify

/* ---------------------------------------------------------------- The local record */

/*
 * discv5_entry_set(state, key, key_len, value, value_len) -> 0, or 1 when the
 * 16 entries are full: sets one entry of the local record, keeping the keys
 * sorted. key_len 1 to 16, value_len 0 to 64.
 * rbx state, rbp key, r12 key length, r13 value, r14 value length,
 * r15 entry index. Locals: rsp the entry count, rsp + 8 a moving index, then the entry.
 */
LOCAL_FUNCTION discv5_entry_set
    ENTER   24
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, %r14
    mov     DISCV5_ST_ENTRY_COUNT(%rbx), %rax
    mov     %rax, (%rsp)
    xor     %r15d, %r15d
1:  cmp     (%rsp), %r15
    jae     4f                              /* after every key: append */
    imul    $DISCV5_LE_SIZE, %r15, %rax
    lea     DISCV5_ST_ENTRIES(%rbx,%rax), %r8   /* the entry */
    movzbl  DISCV5_LE_KEY_LEN(%r8), %r9d
    lea     DISCV5_LE_KEY(%r8), %r10
    xor     %ecx, %ecx
2:  cmp     %r9, %rcx                       /* compare the entry key with the key */
    jae     21f
    cmp     %r12, %rcx
    jae     5f                              /* the key is a prefix of the entry key: insert before */
    movzbl  (%r10,%rcx), %eax
    movzbl  (%rbp,%rcx), %edx
    cmp     %edx, %eax
    jb      3f                              /* the entry key is smaller: go on */
    ja      5f                              /* larger: insert before */
    inc     %rcx
    jmp     2b
21: cmp     %r12, %r9
    je      6f                              /* the same key: replace the value */
3:  inc     %r15
    jmp     1b
4:  cmpq    $DISCV5_MAX_ENTRIES, (%rsp)
    jae     8f
    jmp     7f
5:  cmpq    $DISCV5_MAX_ENTRIES, (%rsp)     /* insert at r15: move entries r15.. up by one */
    jae     8f
    mov     (%rsp), %rax
    mov     %rax, 8(%rsp)
51: cmp     %r15, 8(%rsp)
    jbe     7f
    imul    $DISCV5_LE_SIZE, 8(%rsp), %rax
    lea     DISCV5_ST_ENTRIES(%rbx,%rax), %rdi
    lea     -DISCV5_LE_SIZE(%rdi), %rsi
    mov     $DISCV5_LE_SIZE, %edx
    call    discv5_copy
    decq    8(%rsp)
    jmp     51b
7:  incq    (%rsp)
    mov     (%rsp), %rax
    mov     %rax, DISCV5_ST_ENTRY_COUNT(%rbx)
6:  imul    $DISCV5_LE_SIZE, %r15, %rax
    lea     DISCV5_ST_ENTRIES(%rbx,%rax), %rax
    mov     %rax, 16(%rsp)
    mov     %r12b, DISCV5_LE_KEY_LEN(%rax)
    mov     %r14b, DISCV5_LE_VALUE_LEN(%rax)
    lea     DISCV5_LE_KEY(%rax), %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    discv5_copy
    mov     16(%rsp), %rax
    lea     DISCV5_LE_VALUE(%rax), %rdi
    mov     %r13, %rsi
    mov     %r14, %rdx
    call    discv5_copy
    xor     %eax, %eax
    jmp     9f
8:  mov     $1, %eax
9:  LEAVE   24
END_FUNCTION discv5_entry_set

/* discv5_record_build stack: the payload, the content, the signature, the hash, the record. */
.set RB_PAYLOAD, 0                  /* up to 1400 bytes */
.set RB_CONTENT, 1408               /* up to 304 bytes */
.set RB_SIG, 1712                   /* 64 bytes */
.set RB_HASH, 1776                  /* 32 bytes */
.set RB_RECORD, 1808                /* up to 304 bytes */
.set RB_FRAME, 2120

/*
 * discv5_record_build(state) -> 0, or 1 when the record would pass 300 bytes:
 * signs [seq, k, v, ...] of the entries and writes the record to the state.
 * rbx state, rbp payload length, r12 entry index, r13 entry, then the record length.
 */
LOCAL_FUNCTION discv5_record_build
    ENTER   RB_FRAME
    mov     %rdi, %rbx
    lea     RB_PAYLOAD(%rsp), %rdi
    mov     DISCV5_ST_SEQ(%rbx), %rsi
    call    discv5_rlp_uint
    xor     %r12d, %r12d
1:  cmp     DISCV5_ST_ENTRY_COUNT(%rbx), %r12
    jae     2f
    imul    $DISCV5_LE_SIZE, %r12, %rcx
    lea     DISCV5_ST_ENTRIES(%rbx,%rcx), %r13
    mov     %rax, %rdi
    lea     DISCV5_LE_KEY(%r13), %rsi
    movzbl  DISCV5_LE_KEY_LEN(%r13), %edx
    call    discv5_rlp_bytes
    mov     %rax, %rdi
    lea     DISCV5_LE_VALUE(%r13), %rsi
    movzbl  DISCV5_LE_VALUE_LEN(%r13), %edx
    call    discv5_rlp_bytes
    inc     %r12
    jmp     1b
2:  mov     %rax, %rbp
    sub     %rsp, %rbp                      /* payload length */
    mov     $1, %eax
    cmp     $(DISCV5_MAX_RECORD - 67), %rbp /* the signature takes 66 bytes, the header 1 or more */
    ja      9f
    lea     RB_CONTENT(%rsp), %rdi
    mov     %rbp, %rsi
    mov     $0xC0, %edx
    call    discv5_rlp_header
    mov     %rax, %rdi
    lea     RB_PAYLOAD(%rsp), %rsi
    mov     %rbp, %rdx
    call    discv5_copy
    lea     RB_CONTENT(%rsp), %rdi
    mov     %rax, %rsi
    sub     %rdi, %rsi
    lea     RB_HASH(%rsp), %rdx
    mov     $1, %ecx
    call    discv5_hash
    lea     DISCV5_ST_PRIVATE_KEY(%rbx), %rdi
    lea     RB_HASH(%rsp), %rsi
    lea     RB_SIG(%rsp), %rdx
    CALL_GLOBAL crypto_secp256k1_sign
    lea     RB_RECORD(%rsp), %rdi
    lea     66(%rbp), %rsi
    mov     $0xC0, %edx
    call    discv5_rlp_header
    mov     %rax, %rdi
    lea     RB_SIG(%rsp), %rsi
    mov     $64, %edx
    call    discv5_rlp_bytes
    mov     %rax, %rdi
    lea     RB_PAYLOAD(%rsp), %rsi
    mov     %rbp, %rdx
    call    discv5_copy
    lea     RB_RECORD(%rsp), %rcx
    sub     %rcx, %rax
    mov     %rax, %r13
    mov     $1, %eax
    cmp     $DISCV5_MAX_RECORD, %r13
    ja      9f
    mov     %r13, DISCV5_ST_RECORD_LEN(%rbx)
    lea     DISCV5_ST_RECORD(%rbx), %rdi
    lea     RB_RECORD(%rsp), %rsi
    mov     %r13, %rdx
    call    discv5_copy
    xor     %eax, %eax
9:  LEAVE   RB_FRAME
END_FUNCTION discv5_record_build

/*
 * discv5_set_endpoint(state, endpoint): the "ip" and "udp" entries, or "ip6"
 * and "udp6", from the endpoint. A port of 0 sets no port entry. Returns 0,
 * or 1 when the entries are full. rbx state, rbp endpoint, r12 port key,
 * r13 its length, r14 port bytes, r15 result. The port bytes at rsp.
 */
LOCAL_FUNCTION discv5_set_endpoint
    ENTER   24
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    xor     %r15d, %r15d
    mov     DISCV5_EP_FAMILY(%rbp), %rax
    cmp     $4, %rax
    jne     1f
    mov     %rbx, %rdi
    lea     400b+4(%rip), %rsi              /* "ip" */
    mov     $2, %edx
    lea     DISCV5_EP_ADDRESS(%rbp), %rcx
    mov     $4, %r8d
    call    discv5_entry_set
    or      %rax, %r15
    lea     400b+8(%rip), %r12              /* "udp" */
    mov     $3, %r13d
    jmp     2f
1:  cmp     $6, %rax
    jne     9f
    mov     %rbx, %rdi
    lea     400b+12(%rip), %rsi             /* "ip6" */
    mov     $3, %edx
    lea     DISCV5_EP_ADDRESS(%rbp), %rcx
    mov     $16, %r8d
    call    discv5_entry_set
    or      %rax, %r15
    lea     400b+16(%rip), %r12             /* "udp6" */
    mov     $4, %r13d
2:  mov     DISCV5_EP_PORT(%rbp), %rsi
    test    %rsi, %rsi
    jz      9f
    mov     $2, %r14d                       /* the port without leading zero bytes */
    mov     $1, %eax
    cmp     $0x100, %rsi
    cmovb   %rax, %r14
    mov     %rsp, %rdi
    mov     %r14, %rdx
    call    discv5_store_be
    mov     %rbx, %rdi
    mov     %r12, %rsi
    mov     %r13, %rdx
    mov     %rsp, %rcx
    mov     %r14, %r8
    call    discv5_entry_set
    or      %rax, %r15
9:  mov     %r15, %rax
    LEAVE   24
END_FUNCTION discv5_set_endpoint

/*
 * discv5_init(config, state) -> status
 * rbx config, rbp state. The public key at rsp, the point at rsp + 48.
 */
FUNCTION discv5_init
    ENTER   120
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rbx, %rdi
    mov     %rsp, %rsi
    CALL_GLOBAL crypto_secp256k1_public_key
    mov     %rax, %rcx
    mov     $DISCV5_INVALID_KEY, %eax
    test    %rcx, %rcx
    jnz     9f
    mov     %rbp, %rdi
    mov     $DISCV5_STATE_SIZE, %esi
    call    discv5_zero
    lea     DISCV5_ST_PRIVATE_KEY(%rbp), %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_ST_PUBLIC_KEY(%rbp), %rdi
    mov     %rsp, %rsi
    mov     $33, %edx
    call    discv5_copy
    mov     %rsp, %rdi
    lea     48(%rsp), %rsi
    CALL_GLOBAL crypto_secp256k1_decompress
    lea     48(%rsp), %rdi
    mov     $64, %esi
    lea     DISCV5_ST_NODE_ID(%rbp), %rdx
    mov     $1, %ecx
    call    discv5_hash
    mov     DISCV5_CFG_SEQ(%rbx), %rax
    mov     %rax, DISCV5_ST_SEQ(%rbp)
    mov     DISCV5_CFG_BUCKET_IP_LIMIT(%rbx), %rax
    mov     %rax, DISCV5_ST_BUCKET_IP_LIMIT(%rbp)
    mov     DISCV5_CFG_TABLE_IP_LIMIT(%rbx), %rax
    mov     %rax, DISCV5_ST_TABLE_IP_LIMIT(%rbp)
    mov     DISCV5_CFG_SUBNET4(%rbx), %rax
    mov     $32, %ecx
    cmp     %rcx, %rax
    cmova   %rcx, %rax
    mov     %rax, DISCV5_ST_SUBNET4(%rbp)
    mov     DISCV5_CFG_SUBNET6(%rbx), %rax
    mov     $128, %ecx
    cmp     %rcx, %rax
    cmova   %rcx, %rax
    mov     %rax, DISCV5_ST_SUBNET6(%rbp)
    xor     %eax, %eax
    cmpq    $0, DISCV5_CFG_LIMIT_LAN(%rbx)
    setne   %al
    mov     %rax, DISCV5_ST_LIMIT_LAN(%rbp)
    mov     %rbp, %rdi
    lea     DISCV5_CFG_ENTROPY(%rbx), %rsi
    call    discv5_reseed
    mov     DISCV5_CFG_NOW(%rbx), %rax
    mov     %rax, DISCV5_ST_NOW(%rbp)
    add     $DISCV5_PING_INTERVAL, %rax
    mov     %rax, DISCV5_ST_NEXT_PING(%rbp)
    mov     %rbp, %rdi
    lea     400b(%rip), %rsi                /* "id" = "v4" */
    mov     $2, %edx
    lea     400b+2(%rip), %rcx
    mov     $2, %r8d
    call    discv5_entry_set
    mov     %rbp, %rdi
    lea     400b+24(%rip), %rsi             /* "secp256k1" */
    mov     $9, %edx
    lea     DISCV5_ST_PUBLIC_KEY(%rbp), %rcx
    mov     $33, %r8d
    call    discv5_entry_set
    mov     %rbp, %rdi
    lea     DISCV5_CFG_PORT(%rbx), %rsi
    call    discv5_set_endpoint
    mov     %rbp, %rdi
    call    discv5_record_build
    xor     %eax, %eax
9:  LEAVE   120
END_FUNCTION discv5_init

/* ---------------------------------------------------------------- The state machine: layout */

/*
 * discv5_step scratch, from its start. Every step helper takes the scratch
 * start as its first argument and keeps it in r15; the context block holds
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

/* reg = r15 + off: an address in the scratch. */
.macro SCR reg, off
    lea     \off(%r15), \reg
.endm

/* reg = the state. */
.macro STATE reg
    mov     SC_CTX+CTX_STATE(%r15), \reg
.endm

/* reg = the time. */
.macro NOW reg
    mov     SC_CTX+CTX_NOW(%r15), \reg
.endm

/* ---------------------------------------------------------------- Actions */

/*
 * discv5_action(scratch, kind, size) -> the new action, zeroed, with size
 * and kind set; 0 when the actions have no room. size is a multiple of 8.
 * rbx kind, rbp size, r12 actions, r13 the action.
 */
LOCAL_FUNCTION discv5_action
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     SC_CTX+CTX_ACTIONS(%r15), %r12
    mov     DISCV5_BL_COUNT(%r12), %rcx
    mov     DISCV5_BL_SIZE(%r12), %rdx
    sub     $DISCV5_BL_FIXED, %rdx
    sub     %rcx, %rdx
    xor     %eax, %eax
    cmp     %rbp, %rdx
    jb      9f
    lea     DISCV5_BL_FIXED(%r12,%rcx), %r13
    add     %rbp, %rcx
    mov     %rcx, DISCV5_BL_COUNT(%r12)
    mov     %r13, %rdi
    mov     %rbp, %rsi
    call    discv5_zero
    mov     %rbp, DISCV5_ACT_SIZE(%r13)
    mov     %rbx, DISCV5_ACT_KIND(%r13)
    mov     %r13, %rax
9:  LEAVE   8
END_FUNCTION discv5_action

/* discv5_send_packet(scratch, endpoint): a SEND action with the packet in the scratch. rbx endpoint, rbp packet, r12 length, r13 action. */
LOCAL_FUNCTION discv5_send_packet
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    SCR     %rbp, SC_PKT
    mov     DISCV5_BL_COUNT(%rbp), %r12
    lea     DISCV5_ACT_SEND_DATA+7(%r12), %rdx
    and     $~7, %rdx
    mov     $DISCV5_ACTION_SEND, %esi
    call    discv5_action
    test    %rax, %rax
    jz      9f
    mov     %rax, %r13
    lea     DISCV5_ACT_SEND_TO(%r13), %rdi
    mov     %rbx, %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_copy
    mov     %r12, DISCV5_ACT_SEND_LEN(%r13)
    lea     DISCV5_ACT_SEND_DATA(%r13), %rdi
    lea     DISCV5_BL_FIXED(%rbp), %rsi
    mov     %r12, %rdx
    call    discv5_copy
9:  LEAVE   8
END_FUNCTION discv5_send_packet

/*
 * discv5_enr_endpoint(enr, endpoint) -> 1 when the record has a UDP endpoint:
 * "ip" and "udp", else "ip6" and "udp6", with a port above 0.
 */
LOCAL_FUNCTION discv5_enr_endpoint
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
    mov     %rax, (%rsi)
    mov     %rax, 8(%rsi)
    mov     %rax, 16(%rsi)
    mov     %rax, 24(%rsi)
    mov     DISCV5_ENR_HAS(%rdi), %rcx
    mov     %rcx, %rdx
    and     $(DISCV5_HAS_IP4 | DISCV5_HAS_UDP4), %rdx
    cmp     $(DISCV5_HAS_IP4 | DISCV5_HAS_UDP4), %rdx
    jne     1f
    mov     DISCV5_ENR_UDP4(%rdi), %rdx
    test    %rdx, %rdx
    jz      1f
    mov     %rdx, DISCV5_EP_PORT(%rsi)
    movq    $4, DISCV5_EP_FAMILY(%rsi)
    mov     DISCV5_ENR_IP4(%rdi), %edx
    mov     %edx, DISCV5_EP_ADDRESS(%rsi)
    mov     $1, %eax
    ret
1:  mov     %rcx, %rdx
    and     $(DISCV5_HAS_IP6 | DISCV5_HAS_UDP6), %rdx
    cmp     $(DISCV5_HAS_IP6 | DISCV5_HAS_UDP6), %rdx
    jne     2f
    mov     DISCV5_ENR_UDP6(%rdi), %rdx
    test    %rdx, %rdx
    jz      2f
    mov     %rdx, DISCV5_EP_PORT(%rsi)
    movq    $6, DISCV5_EP_FAMILY(%rsi)
    mov     DISCV5_ENR_IP6(%rdi), %rdx
    mov     %rdx, DISCV5_EP_ADDRESS(%rsi)
    mov     DISCV5_ENR_IP6+8(%rdi), %rdx
    mov     %rdx, DISCV5_EP_ADDRESS+8(%rsi)
    mov     $1, %eax
    ret
2:  xor     %eax, %eax
    ret
END_FUNCTION discv5_enr_endpoint

/* ---------------------------------------------------------------- Sessions and challenges */

/*
 * discv5_session_find(scratch, id, endpoint) -> the session for the node ID
 * and endpoint, or 0. rbx id, rbp endpoint, r12 slot, r13 slots left.
 */
LOCAL_FUNCTION discv5_session_find
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    STATE   %r12
    add     $DISCV5_ST_SESSIONS, %r12
    mov     $DISCV5_SESSION_SLOTS, %r13d
1:  cmpq    $0, DISCV5_S_USED(%r12)
    je      2f
    mov     %r12, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    lea     DISCV5_S_EP(%r12), %rdi
    mov     %rbp, %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    mov     %r12, %rax
    jmp     9f
2:  add     $DISCV5_S_SIZE, %r12
    dec     %r13
    jnz     1b
    xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_session_find

/*
 * discv5_session_put(scratch, id, endpoint, write_key, read_key) -> the
 * session: the slot of the same node and endpoint, else a free slot, else
 * the one used longest ago. rbx id, rbp endpoint, r12 write key, r13 read
 * key, r14 slot.
 */
LOCAL_FUNCTION discv5_session_put
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    mov     %r8, %r13
    call    discv5_session_find
    mov     %rax, %r14
    test    %r14, %r14
    jnz     5f
    STATE   %r14
    add     $DISCV5_ST_SESSIONS, %r14
    mov     %r14, %rcx                      /* the oldest */
    mov     $DISCV5_SESSION_SLOTS, %edx
1:  mov     DISCV5_S_USED(%r14), %rax
    test    %rax, %rax
    jz      5f
    cmp     DISCV5_S_USED(%rcx), %rax
    cmovb   %r14, %rcx
    add     $DISCV5_S_SIZE, %r14
    dec     %rdx
    jnz     1b
    mov     %rcx, %r14
5:  mov     %r14, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_S_EP(%r14), %rdi
    mov     %rbp, %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_copy
    mov     (%r12), %rax
    mov     %rax, DISCV5_S_WRITE_KEY(%r14)
    mov     8(%r12), %rax
    mov     %rax, DISCV5_S_WRITE_KEY+8(%r14)
    mov     (%r13), %rax
    mov     %rax, DISCV5_S_READ_KEY(%r14)
    mov     8(%r13), %rax
    mov     %rax, DISCV5_S_READ_KEY+8(%r14)
    movq    $0, DISCV5_S_COUNTER(%r14)
    NOW     %rax
    inc     %rax
    mov     %rax, DISCV5_S_USED(%r14)
    mov     %r14, %rax
    LEAVE   8
END_FUNCTION discv5_session_put

/*
 * discv5_challenge_find(scratch, id, endpoint, any) -> the WHOAREYOU sent to
 * the node ID and endpoint and still valid, or 0. With any 1 and no match: a
 * free slot, else the oldest slot. Expired slots become free. C_SENT holds
 * the time plus 1. rbx id, rbp endpoint, r12 slot, r13 slots left,
 * r14 spare. Locals: rsp any, rsp + 8 the time plus 1.
 */
LOCAL_FUNCTION discv5_challenge_find
    ENTER   24
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, (%rsp)
    NOW     %rax
    inc     %rax
    mov     %rax, 8(%rsp)
    STATE   %r12
    add     $DISCV5_ST_CHALLENGES, %r12
    xor     %r14d, %r14d
    mov     $DISCV5_CHALLENGE_SLOTS, %r13d
1:  mov     DISCV5_C_SENT(%r12), %rax
    test    %rax, %rax
    jz      3f
    add     $DISCV5_CHALLENGE_TIMEOUT, %rax
    cmp     8(%rsp), %rax
    ja      2f
    movq    $0, DISCV5_C_SENT(%r12)         /* expired */
    jmp     3f
2:  mov     %r12, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      4f
    lea     DISCV5_C_EP(%r12), %rdi
    mov     %rbp, %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      4f
    mov     %r12, %rax
    jmp     9f
4:  test    %r14, %r14                      /* a valid slot: the spare when it is the oldest */
    jz      41f
    mov     DISCV5_C_SENT(%r14), %rcx
    test    %rcx, %rcx
    jz      5f
    cmp     %rcx, DISCV5_C_SENT(%r12)
    jae     5f
41: mov     %r12, %r14
    jmp     5f
3:  test    %r14, %r14                      /* a free slot: the spare unless one is free already */
    jz      31f
    cmpq    $0, DISCV5_C_SENT(%r14)
    je      5f
31: mov     %r12, %r14
5:  add     $DISCV5_C_SIZE, %r12
    dec     %r13
    jnz     1b
    xor     %eax, %eax
    cmpq    $0, (%rsp)
    je      9f
    mov     %r14, %rax
9:  LEAVE   24
END_FUNCTION discv5_challenge_find

/* ---------------------------------------------------------------- Requests */

/*
 * discv5_request_find(scratch, nonce) -> the waiting request whose last
 * packet had this nonce, or 0. rbx nonce, r12 slot, r13 slots left.
 */
LOCAL_FUNCTION discv5_request_find
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    STATE   %r12
    add     $DISCV5_ST_REQUESTS, %r12
    mov     $DISCV5_REQUEST_SLOTS, %r13d
1:  cmpb    $0, DISCV5_R_STATE(%r12)
    je      2f
    lea     DISCV5_R_NONCE(%r12), %rdi
    mov     %rbx, %rsi
    mov     $12, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    mov     %r12, %rax
    jmp     9f
2:  add     $DISCV5_R_SIZE, %r12
    dec     %r13
    jnz     1b
    xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_request_find

/*
 * discv5_request_match(scratch, id, request_id, type) -> the waiting request
 * of this type to the node ID, from the sender's endpoint, with this request
 * ID, or 0. request_id: the 8 bytes sent. rbx id, rbp request ID, r12 type,
 * r13 slot, r14 slots left.
 */
LOCAL_FUNCTION discv5_request_match
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    STATE   %r13
    add     $DISCV5_ST_REQUESTS, %r13
    mov     $DISCV5_REQUEST_SLOTS, %r14d
1:  cmpb    $0, DISCV5_R_STATE(%r13)
    je      2f
    movzbl  DISCV5_R_TYPE(%r13), %eax
    cmp     %r12, %rax
    jne     2f
    cmp     DISCV5_R_REQ_ID(%r13), %rbp
    jne     2f
    mov     %r13, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    lea     DISCV5_R_EP(%r13), %rdi
    SCR     %rsi, SC_CTX+CTX_FROM
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    mov     %r13, %rax
    jmp     9f
2:  add     $DISCV5_R_SIZE, %r13
    dec     %r14
    jnz     1b
    xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_request_match

/* ---------------------------------------------------------------- The node table */

/* discv5_bucket(state, id) -> the bucket: 0 for log distances up to 240, else the distance minus 240. */
LOCAL_FUNCTION discv5_bucket
    ENTER   8
    add     $DISCV5_ST_NODE_ID, %rdi
    call    discv5_log_distance
    xor     %ecx, %ecx
    sub     $240, %rax
    cmovbe  %rcx, %rax
    LEAVE   8
END_FUNCTION discv5_bucket

/* discv5_node_find(scratch, id) -> the table slot of the node ID, member or replacement, or 0. rbx id, r12 slot, r13 slots left. */
LOCAL_FUNCTION discv5_node_find
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    STATE   %r12
    add     $DISCV5_ST_NODES, %r12
    mov     $DISCV5_NODE_SLOTS, %r13d
1:  cmpb    $0, DISCV5_N_STATE(%r12)
    je      2f
    mov     %r12, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    mov     %r12, %rax
    jmp     9f
2:  add     $DISCV5_N_SIZE, %r12
    dec     %r13
    jnz     1b
    xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_node_find

/*
 * discv5_node_count(scratch, bucket, kind) -> the slots of this kind (1
 * member, 2 replacement) in the bucket; in rdx the free slot found first (0
 * when none), in rcx the oldest slot of the kind in the bucket.
 * r8 slot, r9 slots left, r10 free, r11 oldest.
 */
LOCAL_FUNCTION discv5_node_count
    UNWIND_END_PROLOGUE
    mov     SC_CTX+CTX_STATE(%rdi), %r8
    add     $DISCV5_ST_NODES, %r8
    mov     $DISCV5_NODE_SLOTS, %r9d
    xor     %eax, %eax
    xor     %r10d, %r10d
    xor     %r11d, %r11d
1:  movzbl  DISCV5_N_STATE(%r8), %ecx
    test    %ecx, %ecx
    jnz     2f
    test    %r10, %r10
    jnz     3f
    mov     %r8, %r10
    jmp     3f
2:  cmp     %rdx, %rcx
    jne     3f
    movzbl  DISCV5_N_BUCKET(%r8), %ecx
    cmp     %rsi, %rcx
    jne     3f
    inc     %rax
    test    %r11, %r11
    jz      21f
    mov     DISCV5_N_ADDED(%r8), %rcx
    cmp     DISCV5_N_ADDED(%r11), %rcx
    jae     3f
21: mov     %r8, %r11
3:  add     $DISCV5_N_SIZE, %r8
    dec     %r9
    jnz     1b
    mov     %r10, %rdx
    mov     %r11, %rcx
    ret
END_FUNCTION discv5_node_count

/*
 * discv5_ip_lan(endpoint) -> 1 when the address is loopback, private or link
 * local as Go's net/netip reports them (geth's AddrIsLAN), else 0. An
 * IPv4-mapped IPv6 address counts as its IPv4 address. A leaf: rsi the
 * address, rax, rcx and rdx values.
 */
LOCAL_FUNCTION discv5_ip_lan
    UNWIND_END_PROLOGUE
    lea     DISCV5_EP_ADDRESS(%rdi), %rsi
    cmpq    $4, DISCV5_EP_FAMILY(%rdi)
    je      4f
    mov     (%rsi), %rcx                    /* bytes 0-7 */
    mov     8(%rsi), %rdx                   /* bytes 8-15 */
    test    %rcx, %rcx
    jnz     6f
    mov     $1, %eax
    shl     $56, %rax
    cmp     %rax, %rdx
    je      1f                              /* ::1 */
    mov     %edx, %eax
    cmp     $0xFFFF0000, %eax
    jne     0f
    add     $12, %rsi                       /* ::ffff:a.b.c.d */
    jmp     4f
6:  movzbl  (%rsi), %eax
    mov     %eax, %ecx
    and     $0xFE, %ecx
    cmp     $0xFC, %ecx
    je      1f                              /* fc00::/7 */
    cmp     $0xFE, %eax
    jne     0f
    movzbl  1(%rsi), %ecx
    and     $0xC0, %ecx
    cmp     $0x80, %ecx
    je      1f                              /* fe80::/10 */
    jmp     0f
4:  movzbl  (%rsi), %eax
    movzbl  1(%rsi), %ecx
    cmp     $127, %eax
    je      1f                              /* 127/8 */
    cmp     $10, %eax
    je      1f                              /* 10/8 */
    cmp     $172, %eax
    jne     41f
    and     $0xF0, %ecx
    cmp     $16, %ecx
    je      1f                              /* 172.16/12 */
    jmp     0f
41: cmp     $192, %eax
    jne     42f
    cmp     $168, %ecx
    je      1f                              /* 192.168/16 */
    jmp     0f
42: cmp     $169, %eax
    jne     0f
    cmp     $254, %ecx
    je      1f                              /* 169.254/16 */
0:  xor     %eax, %eax
    ret
1:  mov     $1, %eax
    ret
END_FUNCTION discv5_ip_lan

/* discv5_prefix_equal(a, b, bits) -> 1 when the first bits bits at a and b are equal, else 0. A leaf. */
LOCAL_FUNCTION discv5_prefix_equal
    UNWIND_END_PROLOGUE
1:  cmp     $8, %rdx
    jb      2f
    movzbl  (%rdi), %eax
    cmpb    (%rsi), %al
    jne     0f
    inc     %rdi
    inc     %rsi
    sub     $8, %rdx
    jmp     1b
2:  test    %rdx, %rdx
    jz      3f
    movzbl  (%rdi), %eax
    movzbl  (%rsi), %r8d
    xor     %r8d, %eax
    mov     $8, %ecx
    sub     %edx, %ecx
    shr     %cl, %eax
    test    %eax, %eax
    jnz     0f
3:  mov     $1, %eax
    ret
0:  xor     %eax, %eax
    ret
END_FUNCTION discv5_prefix_equal

/*
 * discv5_ip_fits(scratch, endpoint, bucket, exclude) -> 1 when a node at the
 * endpoint keeps its subnet within the IP limits of the table and of the
 * bucket, else 0. Every used slot but exclude counts. When the local
 * network is left out of the limits, a local address always fits and never
 * counts. rbx endpoint, rbp bucket, r12 exclude, r13 slot, r14 slots left;
 * at rsp the table count, then the bucket count, the prefix bits and the
 * state.
 */
LOCAL_FUNCTION discv5_ip_fits
    ENTER   40
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    STATE   %rax
    mov     %rax, 24(%rsp)
    mov     DISCV5_ST_BUCKET_IP_LIMIT(%rax), %rcx
    or      DISCV5_ST_TABLE_IP_LIMIT(%rax), %rcx
    jz      8f                              /* no limits */
    cmpq    $0, DISCV5_ST_LIMIT_LAN(%rax)
    jne     1f
    mov     %rbx, %rdi
    call    discv5_ip_lan
    test    %rax, %rax
    jnz     8f                              /* a local address */
1:  mov     24(%rsp), %rax
    mov     DISCV5_ST_SUBNET4(%rax), %rcx
    cmpq    $4, DISCV5_EP_FAMILY(%rbx)
    je      2f
    mov     DISCV5_ST_SUBNET6(%rax), %rcx
2:  mov     %rcx, 16(%rsp)
    lea     DISCV5_ST_NODES(%rax), %r13
    mov     $DISCV5_NODE_SLOTS, %r14d
    movq    $0, (%rsp)
    movq    $0, 8(%rsp)
3:  cmpb    $0, DISCV5_N_STATE(%r13)
    je      7f
    cmp     %r12, %r13
    je      7f
    mov     DISCV5_N_EP+DISCV5_EP_FAMILY(%r13), %rax
    cmp     DISCV5_EP_FAMILY(%rbx), %rax
    jne     7f
    lea     DISCV5_N_EP+DISCV5_EP_ADDRESS(%r13), %rdi
    lea     DISCV5_EP_ADDRESS(%rbx), %rsi
    mov     16(%rsp), %rdx
    call    discv5_prefix_equal
    test    %rax, %rax
    jz      7f
    mov     24(%rsp), %rax
    cmpq    $0, DISCV5_ST_LIMIT_LAN(%rax)
    jne     5f
    lea     DISCV5_N_EP(%r13), %rdi
    call    discv5_ip_lan
    test    %rax, %rax
    jnz     7f                              /* a local address never counts */
5:  incq    (%rsp)
    movzbl  DISCV5_N_BUCKET(%r13), %eax
    cmp     %rbp, %rax
    jne     7f
    incq    8(%rsp)
7:  add     $DISCV5_N_SIZE, %r13
    dec     %r14
    jnz     3b
    xor     %eax, %eax
    mov     24(%rsp), %rcx
    mov     DISCV5_ST_TABLE_IP_LIMIT(%rcx), %rdx
    test    %rdx, %rdx
    jz      71f
    cmp     %rdx, (%rsp)
    jae     9f
71: mov     DISCV5_ST_BUCKET_IP_LIMIT(%rcx), %rdx
    test    %rdx, %rdx
    jz      8f
    cmp     %rdx, 8(%rsp)
    jae     9f
8:  mov     $1, %eax
9:  LEAVE   40
END_FUNCTION discv5_ip_fits

/*
 * discv5_node_add(scratch, enr, record) -> the slot, or 0: adds a checked
 * record with a UDP endpoint to the table, or updates its slot when the
 * record is newer. A full bucket takes it as a replacement; a full
 * replacement list drops its oldest. A node that would pass an IP limit is
 * left out; a newer record whose address would pass one is not taken, and
 * the slot keeps the old record. rbx enr, rbp record, r12 slot,
 * r13 bucket, r14 kind. The endpoint at rsp.
 */
LOCAL_FUNCTION discv5_node_add
    ENTER   40
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rbx, %rdi
    mov     %rsp, %rsi
    call    discv5_enr_endpoint
    test    %rax, %rax
    jz      9f
    STATE   %rdi
    add     $DISCV5_ST_NODE_ID, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_equal
    mov     %rax, %rcx
    xor     %eax, %eax
    test    %rcx, %rcx
    jnz     9f                              /* ourselves */
    mov     %r15, %rdi
    mov     %rbx, %rsi
    call    discv5_node_find
    mov     %rax, %r12
    test    %r12, %r12
    jz      1f
    mov     DISCV5_ENR_SEQ(%rbx), %rcx      /* known: keep the newer record */
    cmp     DISCV5_N_SEQ(%r12), %rcx
    jbe     9f
    mov     %r15, %rdi
    mov     %rsp, %rsi
    movzbl  DISCV5_N_BUCKET(%r12), %edx
    mov     %r12, %rcx
    call    discv5_ip_fits
    mov     %rax, %rcx
    mov     %r12, %rax
    test    %rcx, %rcx
    jz      9f                              /* the new address passes a limit */
    jmp     6f
1:  STATE   %rdi
    mov     %rbx, %rsi
    call    discv5_bucket
    mov     %rax, %r13
    mov     %r15, %rdi
    mov     %rsp, %rsi
    mov     %r13, %rdx
    xor     %ecx, %ecx
    call    discv5_ip_fits
    test    %rax, %rax
    jz      9f                              /* the subnet is full */
    mov     %r15, %rdi
    mov     %r13, %rsi
    mov     $DISCV5_NODE_MEMBER, %edx
    call    discv5_node_count
    mov     %rdx, %r12
    cmp     $DISCV5_K, %rax
    jae     2f
    mov     $DISCV5_NODE_MEMBER, %r14d
    jmp     5f
2:  mov     %r15, %rdi
    mov     %r13, %rsi
    mov     $DISCV5_NODE_REPLACEMENT, %edx
    call    discv5_node_count
    mov     %rdx, %r12
    cmp     $DISCV5_REPLACEMENTS, %rax
    jb      3f
    mov     %rcx, %r12                      /* replace the oldest replacement */
3:  mov     $DISCV5_NODE_REPLACEMENT, %r14d
5:  xor     %eax, %eax
    test    %r12, %r12
    jz      9f
    mov     %r12, %rdi
    mov     $DISCV5_N_SIZE, %esi
    call    discv5_zero
    mov     %r14b, DISCV5_N_STATE(%r12)
    mov     %r13b, DISCV5_N_BUCKET(%r12)
    NOW     %rax
    mov     %rax, DISCV5_N_ADDED(%r12)
    mov     %rax, DISCV5_N_CHECK(%r12)
    STATE   %rcx
    cmpq    $0, DISCV5_ST_NEXT_REFRESH(%rcx)
    jne     6f
    add     $DISCV5_PING_INTERVAL, %rax     /* the first node: look up our own ID soon */
    mov     %rax, DISCV5_ST_NEXT_REFRESH(%rcx)
6:  mov     %r12, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_N_PUBKEY(%r12), %rdi
    lea     DISCV5_ENR_PUBKEY(%rbx), %rsi
    mov     $33, %edx
    call    discv5_copy
    lea     DISCV5_N_EP(%r12), %rdi
    mov     %rsp, %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_copy
    mov     DISCV5_ENR_SEQ(%rbx), %rax
    mov     %rax, DISCV5_N_SEQ(%r12)
    mov     DISCV5_BL_COUNT(%rbp), %rdx
    mov     %rdx, DISCV5_N_RECORD_LEN(%r12)
    mov     DISCV5_BL_OFFSET(%rbp), %rsi
    add     %rbp, %rsi
    lea     DISCV5_N_RECORD(%r12), %rdi
    call    discv5_copy
    mov     %r12, %rax
9:  LEAVE   40
END_FUNCTION discv5_node_add

/*
 * discv5_node_remove(scratch, slot): frees the slot. A member's place goes
 * to the newest replacement of its bucket. r8 slot, r9 slots left,
 * r10 the newest replacement.
 */
LOCAL_FUNCTION discv5_node_remove
    UNWIND_END_PROLOGUE
    movzbl  DISCV5_N_STATE(%rsi), %eax
    movzbl  DISCV5_N_BUCKET(%rsi), %edx
    movb    $0, DISCV5_N_STATE(%rsi)
    cmp     $DISCV5_NODE_MEMBER, %eax
    jne     9f
    mov     SC_CTX+CTX_STATE(%rdi), %r8
    add     $DISCV5_ST_NODES, %r8
    mov     $DISCV5_NODE_SLOTS, %r9d
    xor     %r10d, %r10d
1:  cmpb    $DISCV5_NODE_REPLACEMENT, DISCV5_N_STATE(%r8)
    jne     2f
    movzbl  DISCV5_N_BUCKET(%r8), %ecx
    cmp     %edx, %ecx
    jne     2f
    test    %r10, %r10
    jz      11f
    mov     DISCV5_N_ADDED(%r8), %rcx
    cmp     DISCV5_N_ADDED(%r10), %rcx
    jb      2f
11: mov     %r8, %r10
2:  add     $DISCV5_N_SIZE, %r8
    dec     %r9
    jnz     1b
    test    %r10, %r10
    jz      9f
    movb    $DISCV5_NODE_MEMBER, DISCV5_N_STATE(%r10)
    movb    $0, DISCV5_N_LIVE(%r10)
    movb    $0, DISCV5_N_FAILS(%r10)
    mov     SC_CTX+CTX_NOW(%rdi), %rax
    mov     %rax, DISCV5_N_CHECK(%r10)
9:  ret
END_FUNCTION discv5_node_remove

/* ---------------------------------------------------------------- Messages out */

.set RANDOM_PLAIN, DISCV5_RANDOM_MESSAGE - CRYPTO_GCM_TAG_SIZE      /* plaintext bytes of a random message */
.set WHOAREYOU_MASKED, DISCV5_CHALLENGE_SIZE - DISCV5_MASKED_START  /* masked bytes of a WHOAREYOU */

/* reg = the payload of RLP item item, a pointer to its Item record in the message. */
.macro ITEM_DATA reg, item
    mov     RLP_ITEM_OFFSET(\item), \reg
    lea     SC_RLP+DISCV5_BL_FIXED(%r15,\reg), \reg
.endm

/*
 * discv5_msg_finish(scratch, type, end): the message in the scratch becomes
 * the type byte, then an RLP list of the payload from SC_TMP up to end.
 * rbx type, rbp payload length, r12 message.
 */
LOCAL_FUNCTION discv5_msg_finish
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    SCR     %rax, SC_TMP
    mov     %rdx, %rbp
    sub     %rax, %rbp
    SCR     %r12, SC_MSG
    BYTELIST %r12, 0, BL_PACKET_SIZE, $0
    mov     %bl, DISCV5_BL_FIXED(%r12)
    lea     DISCV5_BL_FIXED+1(%r12), %rdi
    mov     %rbp, %rsi
    mov     $0xC0, %edx
    call    discv5_rlp_header
    mov     %rax, %rdi
    SCR     %rsi, SC_TMP
    mov     %rbp, %rdx
    call    discv5_copy
    lea     DISCV5_BL_FIXED(%r12), %rcx
    sub     %rcx, %rax
    mov     %rax, DISCV5_BL_COUNT(%r12)
    LEAVE   8
END_FUNCTION discv5_msg_finish

/*
 * discv5_send_message(scratch, id, endpoint) -> the nonce used, 12 bytes in
 * the scratch. Sends the message in the scratch to the node. With a session
 * for the node ID and endpoint it goes as an ordinary message; else the
 * packet carries 20 random message bytes, so that the node answers with
 * WHOAREYOU. rbx id, rbp endpoint, r12 session, then the random message,
 * r13 header, r14 state. Locals: rsp the key, rsp + 8 the message.
 */
LOCAL_FUNCTION discv5_send_message
    ENTER   24
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    STATE   %r14
    SCR     %r13, SC_HDR2
    movq    $DISCV5_FLAG_MESSAGE, DISCV5_HDR_FLAG(%r13)
    mov     %r14, %rdi
    lea     DISCV5_HDR_IV(%r13), %rsi
    mov     $16, %edx
    call    discv5_random
    lea     DISCV5_HDR_SRC_ID(%r13), %rdi
    lea     DISCV5_ST_NODE_ID(%r14), %rsi
    mov     $32, %edx
    call    discv5_copy
    mov     %r15, %rdi
    mov     %rbx, %rsi
    mov     %rbp, %rdx
    call    discv5_session_find
    mov     %rax, %r12
    test    %r12, %r12
    jz      1f

    /* The nonce: the message count, 4 bytes big endian, then 8 random bytes. */
    mov     DISCV5_S_COUNTER(%r12), %rsi
    inc     %rsi
    mov     %rsi, DISCV5_S_COUNTER(%r12)
    NOW     %rax
    inc     %rax
    mov     %rax, DISCV5_S_USED(%r12)
    lea     DISCV5_HDR_NONCE(%r13), %rdi
    mov     $4, %edx
    call    discv5_store_be
    mov     %r14, %rdi
    lea     DISCV5_HDR_NONCE+4(%r13), %rsi
    mov     $8, %edx
    call    discv5_random
    lea     DISCV5_S_WRITE_KEY(%r12), %rax
    mov     %rax, (%rsp)
    SCR     %rax, SC_MSG
    mov     %rax, 8(%rsp)
    jmp     2f

    /* No session: a random nonce, and 4 random bytes sealed under a random key. */
1:  mov     %r14, %rdi
    lea     DISCV5_HDR_NONCE(%r13), %rsi
    mov     $12, %edx
    call    discv5_random
    mov     %r14, %rdi
    SCR     %rsi, SC_KEYS
    mov     $16, %edx
    call    discv5_random
    SCR     %r12, SC_EPH
    BYTELIST %r12, 0, 48, $RANDOM_PLAIN
    mov     %r14, %rdi
    lea     DISCV5_BL_FIXED(%r12), %rsi
    mov     $RANDOM_PLAIN, %edx
    call    discv5_random
    SCR     %rax, SC_KEYS
    mov     %rax, (%rsp)
    mov     %r12, 8(%rsp)
2:  SCR     %r8, SC_PKT
    BYTELIST %r8, 0, BL_PACKET_SIZE, $0
    mov     %r13, %rdi
    mov     %rbx, %rsi
    mov     (%rsp), %rdx
    mov     8(%rsp), %rcx
    CALL_GLOBAL discv5_packet_encode
    test    %rax, %rax
    jnz     9f
    mov     %r15, %rdi
    mov     %rbp, %rsi
    call    discv5_send_packet
9:  lea     DISCV5_HDR_NONCE(%r13), %rax
    LEAVE   24
END_FUNCTION discv5_send_message

/*
 * discv5_challenge_new(scratch, challenge): a new WHOAREYOU for the sender
 * of the packet received, answering its nonce, in the challenge slot. The
 * enr-seq is the sequence number of the sender's record in the table, else
 * 0. rbx challenge, rbp id-nonce position, r12 state, r13 header received.
 */
LOCAL_FUNCTION discv5_challenge_new
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    STATE   %r12
    SCR     %r13, SC_HDR
    mov     %rbx, %rdi
    lea     DISCV5_HDR_SRC_ID(%r13), %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_C_EP(%rbx), %rdi
    SCR     %rsi, SC_CTX+CTX_FROM
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_copy
    NOW     %rax
    inc     %rax
    mov     %rax, DISCV5_C_SENT(%rbx)
    mov     %r12, %rdi
    lea     DISCV5_C_DATA(%rbx), %rsi
    mov     $16, %edx
    call    discv5_random
    lea     DISCV5_C_DATA+DISCV5_MASKED_START(%rbx), %rdi
    lea     410b(%rip), %rsi
    mov     $6, %edx
    call    discv5_copy
    movb    $0, (%rax)
    movb    $1, 1(%rax)
    movb    $DISCV5_FLAG_WHOAREYOU, 2(%rax)
    lea     3(%rax), %rdi
    lea     DISCV5_HDR_NONCE(%r13), %rsi
    mov     $12, %edx
    call    discv5_copy
    movb    $0, (%rax)
    movb    $24, 1(%rax)
    lea     2(%rax), %rbp
    mov     %r12, %rdi
    mov     %rbp, %rsi
    mov     $16, %edx
    call    discv5_random                   /* id-nonce */
    mov     %r15, %rdi
    lea     DISCV5_HDR_SRC_ID(%r13), %rsi
    call    discv5_node_find
    test    %rax, %rax
    jz      1f
    mov     DISCV5_N_SEQ(%rax), %rax
1:  mov     %rax, %rsi
    lea     16(%rbp), %rdi
    mov     $8, %edx
    call    discv5_store_be
    LEAVE   8
END_FUNCTION discv5_challenge_new

/*
 * discv5_send_whoareyou(scratch, challenge): sends the stored WHOAREYOU: its
 * IV, then the rest masked with AES-CTR under the first 16 bytes of the
 * challenged node ID, the IV as counter. rbx challenge, rbp masking input,
 * r12 masking output, r13 packet.
 */
LOCAL_FUNCTION discv5_send_whoareyou
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    SCR     %rbp, SC_TMP
    lea     80(%rbp), %r12
    BYTELIST %rbp, 0, 72, $WHOAREYOU_MASKED
    BYTELIST %r12, 0, 72, $0
    lea     DISCV5_BL_FIXED(%rbp), %rdi
    lea     DISCV5_C_DATA+DISCV5_MASKED_START(%rbx), %rsi
    mov     $WHOAREYOU_MASKED, %edx
    call    discv5_copy
    mov     %rbx, %rdi
    lea     DISCV5_C_DATA(%rbx), %rsi
    mov     %rbp, %rdx
    mov     %r12, %rcx
    CALL_GLOBAL crypto_aes128_ctr
    SCR     %r13, SC_PKT
    BYTELIST %r13, 0, BL_PACKET_SIZE, $DISCV5_CHALLENGE_SIZE
    lea     DISCV5_BL_FIXED(%r13), %rdi
    lea     DISCV5_C_DATA(%rbx), %rsi
    mov     $DISCV5_MASKED_START, %edx
    call    discv5_copy
    mov     %rax, %rdi
    lea     DISCV5_BL_FIXED(%r12), %rsi
    mov     $WHOAREYOU_MASKED, %edx
    call    discv5_copy
    mov     %r15, %rdi
    lea     DISCV5_C_EP(%rbx), %rsi
    call    discv5_send_packet
    LEAVE   8
END_FUNCTION discv5_send_whoareyou

/* ---------------------------------------------------------------- Actions with records */

/* discv5_emit_record(scratch): a RECORD action with the local record. rbx state, rbp length. */
LOCAL_FUNCTION discv5_emit_record
    ENTER   8
    mov     %rdi, %r15
    STATE   %rbx
    mov     DISCV5_ST_RECORD_LEN(%rbx), %rbp
    lea     DISCV5_ACT_RECORD_DATA+7(%rbp), %rdx
    and     $~7, %rdx
    mov     $DISCV5_ACTION_RECORD, %esi
    call    discv5_action
    test    %rax, %rax
    jz      9f
    mov     %rbp, DISCV5_ACT_RECORD_LEN(%rax)
    lea     DISCV5_ACT_RECORD_DATA(%rax), %rdi
    lea     DISCV5_ST_RECORD(%rbx), %rsi
    mov     %rbp, %rdx
    call    discv5_copy
9:  LEAVE   8
END_FUNCTION discv5_emit_record

/* discv5_emit_found(scratch): a NODE_FOUND action with the checked record in the scratch. rbx record, rbp length, r12 action. */
LOCAL_FUNCTION discv5_emit_found
    ENTER   8
    mov     %rdi, %r15
    SCR     %rbx, SC_REC
    mov     DISCV5_BL_COUNT(%rbx), %rbp
    lea     DISCV5_ACT_FOUND_DATA+7(%rbp), %rdx
    and     $~7, %rdx
    mov     $DISCV5_ACTION_NODE_FOUND, %esi
    call    discv5_action
    test    %rax, %rax
    jz      9f
    mov     %rax, %r12
    mov     %rbp, DISCV5_ACT_FOUND_LEN(%r12)
    lea     DISCV5_ACT_FOUND_ID(%r12), %rdi
    SCR     %rsi, SC_ENR+DISCV5_ENR_NODE_ID
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_ACT_FOUND_DATA(%r12), %rdi
    mov     DISCV5_BL_OFFSET(%rbx), %rsi
    add     %rbx, %rsi
    mov     %rbp, %rdx
    call    discv5_copy
9:  LEAVE   8
END_FUNCTION discv5_emit_found

/* discv5_emit_done(scratch, target, found): a LOOKUP_DONE action. rbx target, rbp found. */
LOCAL_FUNCTION discv5_emit_done
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     $DISCV5_ACTION_LOOKUP_DONE, %esi
    mov     $DISCV5_ACT_DONE_SIZE, %edx
    call    discv5_action
    test    %rax, %rax
    jz      9f
    mov     %rbp, DISCV5_ACT_DONE_FOUND(%rax)
    lea     DISCV5_ACT_DONE_TARGET(%rax), %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_copy
9:  LEAVE   8
END_FUNCTION discv5_emit_done

/* ---------------------------------------------------------------- Requests out */

/*
 * discv5_request_message(scratch, request): the request's message in the
 * scratch: PING [request-id, enr-seq] or FINDNODE [request-id, [distance,
 * ...]]. The request ID is 8 bytes, big endian. rbx request, rbp write
 * position, r12 distance list header, r13 distance index.
 */
LOCAL_FUNCTION discv5_request_message
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    SCR     %rbp, SC_TMP
    movb    $0x88, (%rbp)
    lea     1(%rbp), %rdi
    mov     DISCV5_R_REQ_ID(%rbx), %rsi
    mov     $8, %edx
    call    discv5_store_be
    add     $9, %rbp
    cmpb    $DISCV5_MSG_PING, DISCV5_R_TYPE(%rbx)
    jne     1f
    mov     %rbp, %rdi
    STATE   %rax
    mov     DISCV5_ST_SEQ(%rax), %rsi
    call    discv5_rlp_uint
    mov     %rax, %rdx
    mov     $DISCV5_MSG_PING, %esi
    jmp     8f
1:  mov     %rbp, %r12
    inc     %rbp
    xor     %r13d, %r13d
2:  movzbl  DISCV5_R_DIST_COUNT(%rbx), %eax
    cmp     %rax, %r13
    jae     3f
    movzwl  DISCV5_R_DISTANCES(%rbx,%r13,2), %esi
    mov     %rbp, %rdi
    call    discv5_rlp_uint
    mov     %rax, %rbp
    inc     %r13
    jmp     2b
3:  mov     %rbp, %rax                      /* at most 3 distances: a one-byte list header */
    sub     %r12, %rax
    add     $(0xC0 - 1), %eax
    mov     %al, (%r12)
    mov     %rbp, %rdx
    mov     $DISCV5_MSG_FINDNODE, %esi
8:  mov     %r15, %rdi
    call    discv5_msg_finish
    LEAVE   8
END_FUNCTION discv5_request_message

/*
 * discv5_request_start(scratch, node, kind, count, distances) -> the request,
 * or 0 when every request slot is busy. node: ID, public key and endpoint,
 * the first 104 bytes of a table slot or lookup candidate. kind: the message
 * type, the purpose << 8, the lookup slot << 16. distances: count u16
 * values, the first in the low bits. rbx node, rbp kind, r12 count,
 * r13 distances, r14 slot.
 */
LOCAL_FUNCTION discv5_request_start
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    mov     %r8, %r13
    STATE   %r14
    add     $DISCV5_ST_REQUESTS, %r14
    mov     $DISCV5_REQUEST_SLOTS, %ecx
1:  cmpb    $0, DISCV5_R_STATE(%r14)
    je      2f
    add     $DISCV5_R_SIZE, %r14
    dec     %rcx
    jnz     1b
    xor     %eax, %eax
    jmp     9f
2:  mov     %r14, %rdi
    mov     $DISCV5_R_SIZE, %esi
    call    discv5_zero
    mov     %r14, %rdi
    mov     %rbx, %rsi
    mov     $104, %edx
    call    discv5_copy
    STATE   %rcx
    mov     DISCV5_ST_REQ_ID(%rcx), %rax
    inc     %rax
    mov     %rax, DISCV5_ST_REQ_ID(%rcx)
    mov     %rax, DISCV5_R_REQ_ID(%r14)
    movb    $DISCV5_REQ_WAITING, DISCV5_R_STATE(%r14)
    mov     %bpl, DISCV5_R_TYPE(%r14)
    mov     %rbp, %rax
    shr     $8, %rax
    mov     %al, DISCV5_R_PURPOSE(%r14)
    shr     $8, %rax
    mov     %al, DISCV5_R_LOOKUP(%r14)
    NOW     %rax
    add     $DISCV5_REQUEST_TIMEOUT, %rax
    mov     %rax, DISCV5_R_DEADLINE(%r14)
    mov     %r12b, DISCV5_R_DIST_COUNT(%r14)
    mov     %r13d, DISCV5_R_DISTANCES(%r14)
    mov     %r13, %rax
    shr     $32, %rax
    mov     %ax, DISCV5_R_DISTANCES+4(%r14)
    mov     %r15, %rdi
    mov     %r14, %rsi
    call    discv5_request_message
    mov     %r15, %rdi
    mov     %r14, %rsi
    lea     DISCV5_R_EP(%r14), %rdx
    call    discv5_send_message
    lea     DISCV5_R_NONCE(%r14), %rdi
    mov     %rax, %rsi
    mov     $12, %edx
    call    discv5_copy
    mov     %r14, %rax
9:  LEAVE   8
END_FUNCTION discv5_request_start

/*
 * discv5_request_end(scratch, request, ok): frees the request and uses the
 * result. A check marks the node live, or counts a failure: a node that is
 * not live, or failed DISCV5_MAX_FAILS times in a row, leaves the table. A
 * lookup request marks its candidate answered or failed and moves the
 * lookup on. rbx request, rbp ok, r12 purpose, r13 node or lookup.
 */
LOCAL_FUNCTION discv5_request_end
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    movb    $0, DISCV5_R_STATE(%rbx)
    movzbl  DISCV5_R_PURPOSE(%rbx), %r12d
    cmp     $DISCV5_PURPOSE_CHECK, %r12d
    jne     3f
    mov     %r15, %rdi
    mov     %rbx, %rsi
    call    discv5_node_find
    test    %rax, %rax
    jz      9f
    mov     %rax, %r13
    movb    $0, DISCV5_N_PINGING(%r13)
    test    %rbp, %rbp
    jz      1f
    movb    $1, DISCV5_N_LIVE(%r13)
    movb    $0, DISCV5_N_FAILS(%r13)
    jmp     9f
1:  movzbl  DISCV5_N_FAILS(%r13), %eax
    inc     %eax
    mov     %al, DISCV5_N_FAILS(%r13)
    NOW     %rcx
    mov     %rcx, DISCV5_N_CHECK(%r13)      /* check again soon */
    cmpb    $0, DISCV5_N_LIVE(%r13)
    je      2f
    cmp     $DISCV5_MAX_FAILS, %eax
    jb      9f
2:  mov     %r15, %rdi
    mov     %r13, %rsi
    call    discv5_node_remove
    jmp     9f
3:  cmp     $DISCV5_PURPOSE_LOOKUP, %r12d
    jne     9f
    movzbl  DISCV5_R_LOOKUP(%rbx), %eax
    imul    $DISCV5_L_SIZE, %rax, %rax
    STATE   %r13
    lea     DISCV5_ST_LOOKUPS(%r13,%rax), %r13
    cmpq    $0, DISCV5_L_ACTIVE(%r13)
    je      9f
    mov     %r13, %rdi
    mov     %rbx, %rsi
    call    discv5_candidate_find
    test    %rax, %rax
    jz      5f
    mov     $DISCV5_LC_FAILED, %ecx
    mov     $DISCV5_LC_ANSWERED, %edx
    test    %rbp, %rbp
    cmovnz  %rdx, %rcx
    mov     %rcx, DISCV5_LC_STATE(%rax)
5:  mov     %r15, %rdi
    mov     %r13, %rsi
    call    discv5_lookup_advance
9:  LEAVE   8
END_FUNCTION discv5_request_end

/* ---------------------------------------------------------------- Lookups */

/* reg = candidate index of the lookup in rbx. */
.macro CANDIDATE reg, index
    imul    $DISCV5_LC_SIZE, \index, \reg
    lea     DISCV5_L_CANDIDATES(%rbx,\reg), \reg
.endm

/* discv5_candidate_find(lookup, id) -> the lookup's candidate with the node ID, or 0. rbx lookup, rbp id, r12 index, r13 candidate. */
LOCAL_FUNCTION discv5_candidate_find
    ENTER   8
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    xor     %r12d, %r12d
1:  cmp     DISCV5_L_COUNT(%rbx), %r12
    jae     8f
    CANDIDATE %r13, %r12
    mov     %r13, %rdi
    mov     %rbp, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jnz     2f
    inc     %r12
    jmp     1b
2:  mov     %r13, %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_candidate_find

/* discv5_closer(a, b, target) -> 1 when ID a is closer to the target than ID b: a XOR target is below b XOR target. */
LOCAL_FUNCTION discv5_closer
    UNWIND_END_PROLOGUE
    xor     %ecx, %ecx
1:  mov     (%rdi,%rcx), %rax
    mov     (%rsi,%rcx), %r8
    mov     (%rdx,%rcx), %r9
    xor     %r9, %rax
    xor     %r9, %r8
    bswap   %rax
    bswap   %r8
    cmp     %r8, %rax
    jne     2f
    add     $8, %rcx
    cmp     $32, %rcx
    jb      1b
    xor     %eax, %eax
    ret
2:  setb    %al
    movzbl  %al, %eax
    ret
END_FUNCTION discv5_closer

/*
 * discv5_candidate_insert(scratch, lookup, node) -> 1 when the node joins the
 * candidates. They stay sorted by distance to the target, closest first, and
 * keep the DISCV5_K closest; the local node and known candidates are left
 * out. node: ID, public key and endpoint, 104 bytes. rbx lookup, rbp node,
 * r12 position, r13 count, r14 candidate.
 */
LOCAL_FUNCTION discv5_candidate_insert
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    STATE   %rdi
    add     $DISCV5_ST_NODE_ID, %rdi
    mov     %rbp, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jnz     8f
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    discv5_candidate_find
    test    %rax, %rax
    jnz     8f
    mov     DISCV5_L_COUNT(%rbx), %r13
    xor     %r12d, %r12d
1:  cmp     %r13, %r12
    jae     2f
    CANDIDATE %rsi, %r12
    mov     %rbp, %rdi
    mov     %rbx, %rdx                      /* the target */
    call    discv5_closer
    test    %rax, %rax
    jnz     2f
    inc     %r12
    jmp     1b
2:  cmp     $DISCV5_K, %r12
    jae     8f
    cmp     $DISCV5_K, %r13                 /* full: the last one drops out */
    jb      3f
    mov     $(DISCV5_K - 1), %r13d
3:  cmp     %r12, %r13                      /* move position to count - 1 down by one, from the end */
    jbe     4f
    dec     %r13
    CANDIDATE %rsi, %r13
    lea     DISCV5_LC_SIZE(%rsi), %rdi
    mov     $DISCV5_LC_SIZE, %edx
    call    discv5_copy
    jmp     3b
4:  CANDIDATE %r14, %r12
    mov     %r14, %rdi
    mov     %rbp, %rsi
    mov     $104, %edx
    call    discv5_copy
    movq    $DISCV5_LC_NEW, DISCV5_LC_STATE(%r14)
    mov     DISCV5_L_COUNT(%rbx), %rax
    inc     %rax
    mov     $DISCV5_K, %ecx
    cmp     %rcx, %rax
    cmova   %rcx, %rax
    mov     %rax, DISCV5_L_COUNT(%rbx)
    mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   8
END_FUNCTION discv5_candidate_insert

/*
 * discv5_lookup_distances(target, id) -> in rax the distances to ask the node
 * for, in rdx their count: d, then d + 1 and d - 1, d + 2 and d - 2, ... up
 * to 3, keeping 1 to 256, with d the log distance of the target and the
 * node. Packed as u16 values, the first in the low bits.
 * rbx d, rbp packed, r12 count, r13 step.
 */
LOCAL_FUNCTION discv5_lookup_distances
    ENTER   8
    call    discv5_log_distance
    mov     %rax, %rbx
    mov     %rax, %rbp
    mov     $1, %r12d
    mov     $1, %r13d
1:  cmp     $3, %r12
    jae     9f
    lea     (%rbx,%r13), %rax
    cmp     $256, %rax
    ja      2f
    mov     %r12, %rcx
    shl     $4, %rcx
    shl     %cl, %rax
    or      %rax, %rbp
    inc     %r12
2:  cmp     $3, %r12
    jae     9f
    mov     %rbx, %rax
    sub     %r13, %rax
    jle     3f
    mov     %r12, %rcx
    shl     $4, %rcx
    shl     %cl, %rax
    or      %rax, %rbp
    inc     %r12
3:  inc     %r13
    jmp     1b
9:  mov     %rbp, %rax
    mov     %r12, %rdx
    LEAVE   8
END_FUNCTION discv5_lookup_distances

/*
 * discv5_lookup_advance(scratch, lookup): asks new candidates, closest
 * first, while fewer than DISCV5_ALPHA requests are pending. With nothing
 * pending and nothing new, the lookup ends with a LOOKUP_DONE action.
 * rbx lookup, rbp pending, r12 index, r13 candidate, r14 new candidates not
 * asked. The lookup slot number at rsp.
 */
LOCAL_FUNCTION discv5_lookup_advance
    ENTER   24
    mov     %rdi, %r15
    mov     %rsi, %rbx
    cmpq    $0, DISCV5_L_ACTIVE(%rbx)
    je      9f
    STATE   %rcx
    add     $DISCV5_ST_LOOKUPS, %rcx
    mov     %rbx, %rax
    sub     %rcx, %rax
    xor     %edx, %edx
    mov     $DISCV5_L_SIZE, %ecx
    div     %rcx
    mov     %rax, (%rsp)
    xor     %ebp, %ebp
    xor     %r12d, %r12d
1:  cmp     DISCV5_L_COUNT(%rbx), %r12
    jae     2f
    CANDIDATE %r13, %r12
    cmpq    $DISCV5_LC_ASKED, DISCV5_LC_STATE(%r13)
    jne     11f
    inc     %rbp
11: inc     %r12
    jmp     1b
2:  xor     %r12d, %r12d
    xor     %r14d, %r14d
3:  cmp     DISCV5_L_COUNT(%rbx), %r12
    jae     5f
    CANDIDATE %r13, %r12
    cmpq    $DISCV5_LC_NEW, DISCV5_LC_STATE(%r13)
    jne     4f
    cmp     $DISCV5_ALPHA, %rbp
    jae     41f
    mov     %rbx, %rdi
    mov     %r13, %rsi
    call    discv5_lookup_distances
    mov     %rdx, %rcx
    mov     %rax, %r8
    mov     (%rsp), %rdx
    shl     $16, %rdx
    or      $(DISCV5_MSG_FINDNODE | (DISCV5_PURPOSE_LOOKUP << 8)), %rdx
    mov     %r15, %rdi
    mov     %r13, %rsi
    call    discv5_request_start
    test    %rax, %rax
    jz      41f
    movq    $DISCV5_LC_ASKED, DISCV5_LC_STATE(%r13)
    inc     %rbp
    jmp     4f
41: inc     %r14
4:  inc     %r12
    jmp     3b
5:  mov     %rbp, %rax
    or      %r14, %rax
    jnz     9f
    movq    $0, DISCV5_L_ACTIVE(%rbx)
    mov     %r15, %rdi
    mov     %rbx, %rsi
    mov     DISCV5_L_FOUND(%rbx), %rdx
    call    discv5_emit_done
9:  LEAVE   24
END_FUNCTION discv5_lookup_advance

/*
 * discv5_lookup_start(scratch, target): starts a lookup of the target from
 * the table members. With every lookup slot busy it ends at once with
 * LOOKUP_DONE and 0 found. rbx target, rbp lookup, r12 slots left,
 * r13 node slot, r14 nodes left.
 */
LOCAL_FUNCTION discv5_lookup_start
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    STATE   %rbp
    add     $DISCV5_ST_LOOKUPS, %rbp
    mov     $DISCV5_LOOKUP_SLOTS, %r12d
1:  cmpq    $0, DISCV5_L_ACTIVE(%rbp)
    je      2f
    add     $DISCV5_L_SIZE, %rbp
    dec     %r12
    jnz     1b
    mov     %r15, %rdi
    mov     %rbx, %rsi
    xor     %edx, %edx
    call    discv5_emit_done
    jmp     9f
2:  mov     %rbp, %rdi
    mov     $DISCV5_L_SIZE, %esi
    call    discv5_zero
    mov     %rbp, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_copy
    movq    $1, DISCV5_L_ACTIVE(%rbp)
    STATE   %r13
    add     $DISCV5_ST_NODES, %r13
    mov     $DISCV5_NODE_SLOTS, %r14d
3:  cmpb    $DISCV5_NODE_MEMBER, DISCV5_N_STATE(%r13)
    jne     4f
    mov     %r15, %rdi
    mov     %rbp, %rsi
    mov     %r13, %rdx
    call    discv5_candidate_insert
4:  add     $DISCV5_N_SIZE, %r13
    dec     %r14
    jnz     3b
    mov     %r15, %rdi
    mov     %rbp, %rsi
    call    discv5_lookup_advance
9:  LEAVE   8
END_FUNCTION discv5_lookup_start

/* ---------------------------------------------------------------- Messages in */

/*
 * discv5_msg_field(scratch, k) -> the Item record of field k of the message
 * list (field 0 is the request ID), or 0 when the list is shorter.
 * r8 items, rcx index, r9 list end.
 */
LOCAL_FUNCTION discv5_msg_field
    UNWIND_END_PROLOGUE
    lea     SC_ITEMS(%rdi), %r8
    add     RLP_ITEMS_OFFSET(%r8), %r8
    mov     RLP_ITEM_ITEMS(%r8), %r9
    mov     $1, %ecx
1:  cmp     %r9, %rcx
    jae     8f
    mov     %rcx, %rax
    shl     $RLP_ITEM_SHIFT, %rax
    add     %r8, %rax
    test    %rsi, %rsi
    jz      9f
    dec     %rsi
    add     RLP_ITEM_ITEMS(%rax), %rcx
    jmp     1b
8:  xor     %eax, %eax
9:  ret
END_FUNCTION discv5_msg_field

/*
 * discv5_item_uint(scratch, item) -> in rax the number, in rdx 1 when the
 * message item is a canonical number of at most 8 bytes, else 0. item may
 * be 0 (a missing field).
 */
LOCAL_FUNCTION discv5_item_uint
    UNWIND_END_PROLOGUE
    xor     %edx, %edx
    xor     %eax, %eax
    test    %rsi, %rsi
    jz      9f
    cmpq    $RLP_KIND_BYTES, RLP_ITEM_KIND(%rsi)
    jne     9f
    mov     RLP_ITEM_LENGTH(%rsi), %rcx
    cmp     $8, %rcx
    ja      9f
    mov     RLP_ITEM_OFFSET(%rsi), %r8
    lea     SC_RLP+DISCV5_BL_FIXED(%rdi,%r8), %r8
    test    %rcx, %rcx
    jz      2f
    cmpb    $0, (%r8)
    je      9f                              /* a leading zero */
1:  shl     $8, %rax
    movzbl  (%r8), %r9d
    or      %r9, %rax
    inc     %r8
    dec     %rcx
    jnz     1b
2:  mov     $1, %edx
9:  ret
END_FUNCTION discv5_item_uint

/*
 * discv5_handle_message(scratch): the decrypted message in the scratch, from
 * the sender of the packet: a type byte, then an RLP list whose first field
 * is a request ID of at most 8 bytes. Anything else is dropped.
 * rbx message bytes, rbp length, r12 RLP ByteList, r13 type, r14 item.
 */
LOCAL_FUNCTION discv5_handle_message
    ENTER   8
    mov     %rdi, %r15
    SCR     %rbx, SC_MSG
    mov     DISCV5_BL_COUNT(%rbx), %rbp
    cmp     $2, %rbp
    jb      9f
    add     DISCV5_BL_OFFSET(%rbx), %rbx
    movzbl  (%rbx), %r13d
    SCR     %r12, SC_RLP
    lea     -1(%rbp), %rax
    BYTELIST %r12, 0, BL_PACKET_SIZE, %rax
    lea     DISCV5_BL_FIXED(%r12), %rdi
    lea     1(%rbx), %rsi
    lea     -1(%rbp), %rdx
    call    discv5_copy
    SCR     %rsi, SC_ITEMS
    movq    $SC_ITEMS_SIZE, RLP_ITEMS_SIZE(%rsi)
    mov     %r12, %rdi
    CALL_GLOBAL rlp_decode
    test    %rax, %rax
    jnz     9f
    SCR     %rax, SC_ITEMS
    add     RLP_ITEMS_OFFSET(%rax), %rax
    cmpq    $RLP_KIND_LIST, RLP_ITEM_KIND(%rax)
    jne     9f
    mov     %r15, %rdi
    xor     %esi, %esi
    call    discv5_msg_field
    test    %rax, %rax
    jz      9f
    mov     %rax, %r14
    cmpq    $RLP_KIND_BYTES, RLP_ITEM_KIND(%r14)
    jne     9f
    mov     RLP_ITEM_LENGTH(%r14), %rbp
    cmp     $8, %rbp
    ja      9f
    mov     %rbp, SC_CTX+CTX_REQID_LEN(%r15)
    movq    $0, SC_CTX+CTX_REQID(%r15)
    lea     SC_CTX+CTX_REQID(%r15), %rdi
    ITEM_DATA %rsi, %r14
    mov     %rbp, %rdx
    call    discv5_copy
    mov     %r15, %rdi
    cmp     $DISCV5_MSG_PING, %r13d
    jne     1f
    call    discv5_on_ping
    jmp     9f
1:  cmp     $DISCV5_MSG_PONG, %r13d
    jne     2f
    call    discv5_on_pong
    jmp     9f
2:  cmp     $DISCV5_MSG_FINDNODE, %r13d
    jne     3f
    call    discv5_on_findnode
    jmp     9f
3:  cmp     $DISCV5_MSG_NODES, %r13d
    jne     4f
    call    discv5_on_nodes
    jmp     9f
4:  cmp     $DISCV5_MSG_TALKREQ, %r13d
    jne     9f
    call    discv5_on_talkreq
9:  LEAVE   8
END_FUNCTION discv5_handle_message

/* discv5_reply(scratch, type, end): finishes the message and sends it to the sender of the packet received. */
LOCAL_FUNCTION discv5_reply
    ENTER   8
    mov     %rdi, %r15
    call    discv5_msg_finish
    mov     %r15, %rdi
    lea     SC_HDR+DISCV5_HDR_SRC_ID(%r15), %rsi
    lea     SC_CTX+CTX_FROM(%r15), %rdx
    call    discv5_send_message
    LEAVE   8
END_FUNCTION discv5_reply

/* discv5_reqid_out(scratch) -> the write position after the request ID received, written at SC_TMP. */
LOCAL_FUNCTION discv5_reqid_out
    ENTER   8
    mov     %rdi, %r15
    lea     SC_TMP(%r15), %rdi
    lea     SC_CTX+CTX_REQID(%r15), %rsi
    mov     SC_CTX+CTX_REQID_LEN(%r15), %rdx
    call    discv5_rlp_bytes
    LEAVE   8
END_FUNCTION discv5_reqid_out

/*
 * discv5_on_ping(scratch): PING [request-id, enr-seq] -> PONG [request-id,
 * enr-seq, ip, port], with the local sequence number and the endpoint the
 * PING came from. rbx the sender's endpoint.
 */
LOCAL_FUNCTION discv5_on_ping
    ENTER   8
    mov     %rdi, %r15
    mov     $1, %esi
    call    discv5_msg_field
    mov     %r15, %rdi
    mov     %rax, %rsi
    call    discv5_item_uint
    test    %rdx, %rdx
    jz      9f
    lea     SC_CTX+CTX_FROM(%r15), %rbx
    mov     %r15, %rdi
    call    discv5_reqid_out
    mov     %rax, %rdi
    STATE   %rax
    mov     DISCV5_ST_SEQ(%rax), %rsi
    call    discv5_rlp_uint
    mov     %rax, %rdi
    lea     DISCV5_EP_ADDRESS(%rbx), %rsi
    mov     $4, %edx
    mov     $16, %ecx
    cmpq    $4, DISCV5_EP_FAMILY(%rbx)
    cmovne  %rcx, %rdx
    call    discv5_rlp_bytes
    mov     %rax, %rdi
    mov     DISCV5_EP_PORT(%rbx), %rsi
    call    discv5_rlp_uint
    mov     %rax, %rdx
    mov     %r15, %rdi
    mov     $DISCV5_MSG_PONG, %esi
    call    discv5_reply
9:  LEAVE   8
END_FUNCTION discv5_on_ping

/* discv5_on_talkreq(scratch): TALKREQ [request-id, protocol, request] -> TALKRESP [request-id, ""]: no protocol is served. */
LOCAL_FUNCTION discv5_on_talkreq
    ENTER   8
    mov     %rdi, %r15
    call    discv5_reqid_out
    movb    $0x80, (%rax)
    lea     1(%rax), %rdx
    mov     %r15, %rdi
    mov     $DISCV5_MSG_TALKRESP, %esi
    call    discv5_reply
    LEAVE   8
END_FUNCTION discv5_on_talkreq

/*
 * discv5_on_pong(scratch): PONG [request-id, enr-seq, ip, port] answering a
 * PING sent ends the check. An ENDPOINT action reports the endpoint the node
 * saw; a newer record is fetched with FINDNODE [0].
 * rbx request, rbp enr-seq, r12 action, then the node, r13 ip item,
 * r14 ip length. The port at rsp.
 */
LOCAL_FUNCTION discv5_on_pong
    ENTER   24
    mov     %rdi, %r15
    cmpq    $8, SC_CTX+CTX_REQID_LEN(%r15)
    jne     9f
    mov     $1, %esi
    call    discv5_msg_field
    mov     %r15, %rdi
    mov     %rax, %rsi
    call    discv5_item_uint
    test    %rdx, %rdx
    jz      9f
    mov     %rax, %rbp
    lea     SC_CTX+CTX_REQID(%r15), %rdi
    mov     $8, %esi
    call    discv5_load_be
    mov     %rax, %rdx
    mov     %r15, %rdi
    lea     SC_HDR+DISCV5_HDR_SRC_ID(%r15), %rsi
    mov     $DISCV5_MSG_PING, %ecx
    call    discv5_request_match
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx

    /* ENDPOINT: ip of 4 or 16 bytes and a port. */
    mov     %r15, %rdi
    mov     $2, %esi
    call    discv5_msg_field
    test    %rax, %rax
    jz      5f
    mov     %rax, %r13
    cmpq    $RLP_KIND_BYTES, RLP_ITEM_KIND(%r13)
    jne     5f
    mov     RLP_ITEM_LENGTH(%r13), %r14
    cmp     $4, %r14
    je      1f
    cmp     $16, %r14
    jne     5f
1:  mov     %r15, %rdi
    mov     $3, %esi
    call    discv5_msg_field
    mov     %r15, %rdi
    mov     %rax, %rsi
    call    discv5_item_uint
    test    %rdx, %rdx
    jz      5f
    cmp     $0x10000, %rax
    jae     5f
    mov     %rax, (%rsp)
    mov     %r15, %rdi
    mov     $DISCV5_ACTION_ENDPOINT, %esi
    mov     $DISCV5_ACT_EP_SIZE, %edx
    call    discv5_action
    test    %rax, %rax
    jz      5f
    mov     %rax, %r12
    mov     (%rsp), %rax
    mov     %rax, DISCV5_ACT_EP_SEEN+DISCV5_EP_PORT(%r12)
    mov     $4, %eax
    mov     $6, %ecx
    cmp     $4, %r14
    cmovne  %rcx, %rax
    mov     %rax, DISCV5_ACT_EP_SEEN+DISCV5_EP_FAMILY(%r12)
    lea     DISCV5_ACT_EP_SEEN+DISCV5_EP_ADDRESS(%r12), %rdi
    ITEM_DATA %rsi, %r13
    mov     %r14, %rdx
    call    discv5_copy
    lea     DISCV5_ACT_EP_FROM(%r12), %rdi
    lea     SC_HDR+DISCV5_HDR_SRC_ID(%r15), %rsi
    mov     $32, %edx
    call    discv5_copy

    /* The check succeeded; fetch a newer record. */
5:  mov     %r15, %rdi
    mov     %rbx, %rsi
    mov     $1, %edx
    call    discv5_request_end
    mov     %r15, %rdi
    mov     %rbx, %rsi
    call    discv5_node_find
    test    %rax, %rax
    jz      9f
    mov     %rax, %r12
    cmp     DISCV5_N_SEQ(%r12), %rbp
    jbe     9f
    mov     %r15, %rdi
    mov     %r12, %rsi
    mov     $(DISCV5_MSG_FINDNODE | (DISCV5_PURPOSE_REFRESH << 8)), %edx
    mov     $1, %ecx
    xor     %r8d, %r8d
    call    discv5_request_start
9:  LEAVE   24
END_FUNCTION discv5_on_pong

/* discv5_result_record(scratch, result) -> in rax the bytes, in rdx the length of a FINDNODE result: a table slot, or 0 for the local record. */
LOCAL_FUNCTION discv5_result_record
    UNWIND_END_PROLOGUE
    test    %rsi, %rsi
    jnz     1f
    mov     SC_CTX+CTX_STATE(%rdi), %rcx
    mov     DISCV5_ST_RECORD_LEN(%rcx), %rdx
    lea     DISCV5_ST_RECORD(%rcx), %rax
    ret
1:  lea     DISCV5_N_RECORD(%rsi), %rax
    mov     DISCV5_N_RECORD_LEN(%rsi), %rdx
    ret
END_FUNCTION discv5_result_record

/*
 * discv5_nodes_send(scratch, start, end, total, bytes): NODES [request-id,
 * total, [record, ...]] with the results from start to end (bytes record
 * bytes in all), to the sender of the FINDNODE. rbx index, rbp end,
 * r12 total, r13 bytes, r14 write position.
 */
LOCAL_FUNCTION discv5_nodes_send
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    mov     %r8, %r13
    call    discv5_reqid_out
    mov     %rax, %rdi
    mov     %r12, %rsi
    call    discv5_rlp_uint
    mov     %rax, %rdi
    mov     %r13, %rsi
    mov     $0xC0, %edx
    call    discv5_rlp_header
    mov     %rax, %r14
1:  cmp     %rbp, %rbx
    jae     2f
    mov     SC_RESULT(%r15,%rbx,8), %rsi
    mov     %r15, %rdi
    call    discv5_result_record
    mov     %r14, %rdi
    mov     %rax, %rsi
    call    discv5_copy
    mov     %rax, %r14
    inc     %rbx
    jmp     1b
2:  mov     %r15, %rdi
    mov     $DISCV5_MSG_NODES, %esi
    mov     %r14, %rdx
    call    discv5_reply
    LEAVE   8
END_FUNCTION discv5_nodes_send

/*
 * discv5_nodes_pack(scratch, count, send, total) -> the NODES packets needed
 * for the count results: each holds records while their bytes stay within
 * DISCV5_NODES_BYTES, and no results take one empty packet. With send 1 the
 * packets go out, each announcing total. rbx count, rbp send, r12 total,
 * r13 index, r14 packets. Locals: rsp the packet start, rsp + 8 its record bytes.
 */
LOCAL_FUNCTION discv5_nodes_pack
    ENTER   24
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    xor     %r13d, %r13d
    xor     %r14d, %r14d
1:  mov     %r13, (%rsp)
    movq    $0, 8(%rsp)
2:  cmp     %rbx, %r13
    jae     3f
    mov     SC_RESULT(%r15,%r13,8), %rsi
    mov     %r15, %rdi
    call    discv5_result_record
    add     8(%rsp), %rdx
    cmp     $DISCV5_NODES_BYTES, %rdx
    ja      3f
    mov     %rdx, 8(%rsp)
    inc     %r13
    jmp     2b
3:  inc     %r14
    test    %rbp, %rbp
    jz      4f
    mov     %r15, %rdi
    mov     (%rsp), %rsi
    mov     %r13, %rdx
    mov     %r12, %rcx
    mov     8(%rsp), %r8
    call    discv5_nodes_send
4:  cmp     %rbx, %r13
    jb      1b
    mov     %r14, %rax
    LEAVE   24
END_FUNCTION discv5_nodes_pack

/*
 * discv5_on_findnode(scratch): FINDNODE [request-id, [distance, ...]] ->
 * NODES packets with up to DISCV5_RESULT_LIMIT records: the local record for
 * distance 0, else live table members at exactly that log distance from the
 * local node. Distances past 256 and repeats are skipped; the first
 * DISCV5_MAX_DISTANCES distinct distances count. rbx item index, then the
 * node slot, rbp list end, then slots left, r12 distances, r13 results,
 * r14 items, then the distance index. The distance at rsp.
 */
LOCAL_FUNCTION discv5_on_findnode
    ENTER   24
    mov     %rdi, %r15
    mov     $1, %esi
    call    discv5_msg_field
    test    %rax, %rax
    jz      9f
    cmpq    $RLP_KIND_LIST, RLP_ITEM_KIND(%rax)
    jne     9f
    SCR     %r14, SC_ITEMS
    add     RLP_ITEMS_OFFSET(%r14), %r14
    mov     %rax, %rbx
    sub     %r14, %rbx
    shr     $RLP_ITEM_SHIFT, %rbx
    mov     RLP_ITEM_ITEMS(%rax), %rbp
    add     %rbx, %rbp
    inc     %rbx
    xor     %r12d, %r12d

    /* The distances. */
1:  cmp     %rbp, %rbx
    jae     3f
    mov     %rbx, %rsi
    shl     $RLP_ITEM_SHIFT, %rsi
    add     %r14, %rsi
    add     RLP_ITEM_ITEMS(%rsi), %rbx
    mov     %r15, %rdi
    call    discv5_item_uint
    test    %rdx, %rdx
    jz      9f
    cmp     $256, %rax
    ja      1b
    cmp     $DISCV5_MAX_DISTANCES, %r12
    jae     1b
    xor     %ecx, %ecx
2:  cmp     %r12, %rcx
    jae     21f
    cmp     SC_DIST(%r15,%rcx,8), %rax
    je      1b
    inc     %rcx
    jmp     2b
21: mov     %rax, SC_DIST(%r15,%r12,8)
    inc     %r12
    jmp     1b

    /* The results. */
3:  xor     %r13d, %r13d
    xor     %r14d, %r14d
4:  cmp     %r12, %r14
    jae     7f
    cmp     $DISCV5_RESULT_LIMIT, %r13
    jae     7f
    mov     SC_DIST(%r15,%r14,8), %rax
    mov     %rax, (%rsp)
    inc     %r14
    test    %rax, %rax
    jnz     5f
    movq    $0, SC_RESULT(%r15,%r13,8)
    inc     %r13
    jmp     4b
5:  STATE   %rbx
    add     $DISCV5_ST_NODES, %rbx
    mov     $DISCV5_NODE_SLOTS, %ebp
6:  cmp     $DISCV5_RESULT_LIMIT, %r13
    jae     4b
    cmpb    $DISCV5_NODE_MEMBER, DISCV5_N_STATE(%rbx)
    jne     61f
    cmpb    $0, DISCV5_N_LIVE(%rbx)
    je      61f
    STATE   %rdi
    add     $DISCV5_ST_NODE_ID, %rdi
    mov     %rbx, %rsi
    call    discv5_log_distance
    cmp     (%rsp), %rax
    jne     61f
    mov     %rbx, SC_RESULT(%r15,%r13,8)
    inc     %r13
61: add     $DISCV5_N_SIZE, %rbx
    dec     %rbp
    jnz     6b
    jmp     4b

    /* Count the packets, then send them. */
7:  mov     %r15, %rdi
    mov     %r13, %rsi
    xor     %edx, %edx
    xor     %ecx, %ecx
    call    discv5_nodes_pack
    mov     %rax, %rcx
    mov     %r15, %rdi
    mov     %r13, %rsi
    mov     $1, %edx
    call    discv5_nodes_pack
9:  LEAVE   24
END_FUNCTION discv5_on_findnode

/*
 * discv5_nodes_record(scratch, item, request, lookup): one record of a NODES
 * answer to the request. It must be a valid record with a UDP port above
 * 1024, at one of the distances asked from the answering node. For a lookup
 * (lookup not 0) a record new to it gives NODE_FOUND and becomes a
 * candidate; every good record goes to the table. rbx item, rbp request,
 * r12 lookup, r13 record, then the node view, r14 header length. The
 * record length at rsp.
 */
LOCAL_FUNCTION discv5_nodes_record
    ENTER   24
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r12
    cmpq    $RLP_KIND_LIST, RLP_ITEM_KIND(%rbx)
    jne     9f
    mov     RLP_ITEM_LENGTH(%rbx), %rcx
    mov     $1, %r14d
    cmp     $55, %rcx
    jbe     1f
    bsr     %rcx, %r14
    add     $8, %r14
    shr     $3, %r14
    inc     %r14
1:  lea     (%rcx,%r14), %rax
    cmp     $DISCV5_MAX_RECORD, %rax
    ja      9f
    mov     %rax, (%rsp)
    SCR     %r13, SC_REC
    BYTELIST %r13, 0, 328, %rax
    ITEM_DATA %rsi, %rbx
    sub     %r14, %rsi
    lea     DISCV5_BL_FIXED(%r13), %rdi
    mov     (%rsp), %rdx
    call    discv5_copy
    SCR     %rsi, SC_ENR_SCRATCH
    movq    $DISCV5_ENR_SCRATCH, (%rsi)
    mov     %r13, %rdi
    SCR     %rdx, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    test    %rax, %rax
    jnz     9f
    SCR     %rdi, SC_ENR
    SCR     %rsi, SC_VIEW+DISCV5_N_EP
    call    discv5_enr_endpoint
    test    %rax, %rax
    jz      9f
    cmpq    $1024, SC_VIEW+DISCV5_N_EP+DISCV5_EP_PORT(%r15)
    jbe     9f
    mov     %rbp, %rdi
    SCR     %rsi, SC_ENR+DISCV5_ENR_NODE_ID
    call    discv5_log_distance
    movzbl  DISCV5_R_DIST_COUNT(%rbp), %ecx
    lea     DISCV5_R_DISTANCES(%rbp), %rdx
2:  test    %rcx, %rcx
    jz      9f
    movzwl  (%rdx), %r8d
    add     $2, %rdx
    cmp     %rax, %r8
    je      3f
    dec     %rcx
    jmp     2b
3:  STATE   %rdi
    add     $DISCV5_ST_NODE_ID, %rdi
    SCR     %rsi, SC_ENR+DISCV5_ENR_NODE_ID
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jnz     9f
    SCR     %r13, SC_VIEW
    mov     %r13, %rdi
    SCR     %rsi, SC_ENR+DISCV5_ENR_NODE_ID
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_N_PUBKEY(%r13), %rdi
    SCR     %rsi, SC_ENR+DISCV5_ENR_PUBKEY
    mov     $33, %edx
    call    discv5_copy
    test    %r12, %r12
    jz      4f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    discv5_candidate_find
    test    %rax, %rax
    jnz     4f
    mov     %r15, %rdi
    call    discv5_emit_found
    incq    DISCV5_L_FOUND(%r12)
    mov     %r15, %rdi
    mov     %r12, %rsi
    mov     %r13, %rdx
    call    discv5_candidate_insert
4:  mov     %r15, %rdi
    SCR     %rsi, SC_ENR
    SCR     %rdx, SC_REC
    call    discv5_node_add
9:  LEAVE   24
END_FUNCTION discv5_nodes_record

/*
 * discv5_on_nodes(scratch): NODES [request-id, total, [record, ...]]
 * answering a FINDNODE sent. The request ends after min(total,
 * DISCV5_NODES_LIMIT) packets, at least 1; each packet moves its deadline
 * on. rbx request, rbp child index, r12 list end, r13 items, r14 lookup.
 * Locals: rsp total, rsp + 8 the record list item.
 */
LOCAL_FUNCTION discv5_on_nodes
    ENTER   24
    mov     %rdi, %r15
    cmpq    $8, SC_CTX+CTX_REQID_LEN(%r15)
    jne     9f
    mov     $1, %esi
    call    discv5_msg_field
    mov     %r15, %rdi
    mov     %rax, %rsi
    call    discv5_item_uint
    test    %rdx, %rdx
    jz      9f
    mov     %rax, (%rsp)
    mov     %r15, %rdi
    mov     $2, %esi
    call    discv5_msg_field
    test    %rax, %rax
    jz      9f
    cmpq    $RLP_KIND_LIST, RLP_ITEM_KIND(%rax)
    jne     9f
    mov     %rax, 8(%rsp)
    lea     SC_CTX+CTX_REQID(%r15), %rdi
    mov     $8, %esi
    call    discv5_load_be
    mov     %rax, %rdx
    mov     %r15, %rdi
    lea     SC_HDR+DISCV5_HDR_SRC_ID(%r15), %rsi
    mov     $DISCV5_MSG_FINDNODE, %ecx
    call    discv5_request_match
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    xor     %r14d, %r14d
    cmpb    $DISCV5_PURPOSE_LOOKUP, DISCV5_R_PURPOSE(%rbx)
    jne     1f
    movzbl  DISCV5_R_LOOKUP(%rbx), %eax
    imul    $DISCV5_L_SIZE, %rax, %rax
    STATE   %rcx
    lea     DISCV5_ST_LOOKUPS(%rcx,%rax), %rax
    cmpq    $0, DISCV5_L_ACTIVE(%rax)
    cmovne  %rax, %r14
1:  SCR     %r13, SC_ITEMS
    add     RLP_ITEMS_OFFSET(%r13), %r13
    mov     8(%rsp), %rax
    mov     %rax, %rbp
    sub     %r13, %rbp
    shr     $RLP_ITEM_SHIFT, %rbp
    mov     RLP_ITEM_ITEMS(%rax), %r12
    add     %rbp, %r12
    inc     %rbp
2:  cmp     %r12, %rbp
    jae     5f
    mov     %rbp, %rsi
    shl     $RLP_ITEM_SHIFT, %rsi
    add     %r13, %rsi
    add     RLP_ITEM_ITEMS(%rsi), %rbp
    mov     %r15, %rdi
    mov     %rbx, %rdx
    mov     %r14, %rcx
    call    discv5_nodes_record
    jmp     2b
5:  movzbl  DISCV5_R_TOTAL(%rbx), %eax
    test    %eax, %eax
    jnz     6f
    mov     (%rsp), %rax
    mov     $DISCV5_NODES_LIMIT, %ecx
    cmp     %rcx, %rax
    cmovae  %rcx, %rax
    mov     $1, %ecx
    test    %rax, %rax
    cmovz   %rcx, %rax
    mov     %al, DISCV5_R_TOTAL(%rbx)
6:  movzbl  DISCV5_R_GOT(%rbx), %ecx
    inc     %ecx
    mov     %cl, DISCV5_R_GOT(%rbx)
    cmp     %eax, %ecx
    jb      7f
    mov     %r15, %rdi
    mov     %rbx, %rsi
    mov     $1, %edx
    call    discv5_request_end
    jmp     9f
7:  NOW     %rax
    add     $DISCV5_REQUEST_TIMEOUT, %rax
    mov     %rax, DISCV5_R_DEADLINE(%rbx)
9:  LEAVE   24
END_FUNCTION discv5_on_nodes

/* ---------------------------------------------------------------- Packets in */

/*
 * discv5_on_message_packet(scratch): an ordinary message packet. With a
 * session for the sender's node ID and endpoint whose key opens it, the
 * message is handled. Else the sender gets WHOAREYOU: the one still valid
 * for that node and endpoint, sent again unchanged, or a new one.
 * rbx source ID, rbp endpoint, r12 session or challenge.
 */
LOCAL_FUNCTION discv5_on_message_packet
    ENTER   8
    mov     %rdi, %r15
    lea     SC_HDR+DISCV5_HDR_SRC_ID(%r15), %rbx
    lea     SC_CTX+CTX_FROM(%r15), %rbp
    mov     %rbx, %rsi
    mov     %rbp, %rdx
    call    discv5_session_find
    test    %rax, %rax
    jz      2f
    mov     %rax, %r12
    lea     SC_HDR(%r15), %rdi
    lea     DISCV5_S_READ_KEY(%r12), %rsi
    SCR     %rdx, SC_IN
    SCR     %rcx, SC_MSG
    CALL_GLOBAL discv5_message_decrypt
    test    %rax, %rax
    jnz     2f
    NOW     %rax
    inc     %rax
    mov     %rax, DISCV5_S_USED(%r12)
    mov     %r15, %rdi
    call    discv5_handle_message
    jmp     9f
2:  mov     %r15, %rdi
    mov     %rbx, %rsi
    mov     %rbp, %rdx
    xor     %ecx, %ecx
    call    discv5_challenge_find
    mov     %rax, %r12
    test    %r12, %r12
    jnz     3f
    mov     %r15, %rdi
    mov     %rbx, %rsi
    mov     %rbp, %rdx
    mov     $1, %ecx
    call    discv5_challenge_find
    mov     %rax, %r12
    mov     %r15, %rdi
    mov     %r12, %rsi
    call    discv5_challenge_new
3:  mov     %r15, %rdi
    mov     %r12, %rsi
    call    discv5_send_whoareyou
9:  LEAVE   8
END_FUNCTION discv5_on_message_packet

/*
 * discv5_on_whoareyou(scratch): a WHOAREYOU answering a request that waits
 * (matched by the nonce sent). A new ephemeral key gives the session keys;
 * the ID proof signs the challenge; the request goes again in a handshake
 * packet, with the local record when the challenge's enr-seq is older.
 * rbx request, rbp state, r12 header out, r13 session, r14 challenge data.
 */
LOCAL_FUNCTION discv5_on_whoareyou
    ENTER   8
    mov     %rdi, %r15
    lea     SC_HDR+DISCV5_HDR_NONCE(%r15), %rsi
    call    discv5_request_find
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    cmpb    $DISCV5_REQ_WAITING, DISCV5_R_STATE(%rbx)
    jne     9f
    STATE   %rbp
    lea     SC_HDR+DISCV5_HDR_HEADER+DISCV5_BL_FIXED(%r15), %r14
1:  mov     %rbp, %rdi
    SCR     %rsi, SC_EPH
    mov     $32, %edx
    call    discv5_random
    SCR     %rdi, SC_EPH
    SCR     %rsi, SC_EPH+32
    CALL_GLOBAL crypto_secp256k1_public_key
    test    %rax, %rax
    jnz     1b

    /* Keys: the IDs are the local node's (initiator), then the remote's. */
    SCR     %rdi, SC_TMP
    lea     DISCV5_ST_NODE_ID(%rbp), %rsi
    mov     $32, %edx
    call    discv5_copy
    mov     %rax, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_copy
    SCR     %rdi, SC_EPH
    lea     DISCV5_R_PUBKEY(%rbx), %rsi
    mov     %r14, %rdx
    SCR     %rcx, SC_TMP
    SCR     %r8, SC_KEYS
    CALL_GLOBAL discv5_derive_keys
    test    %rax, %rax
    jnz     9f
    SCR     %r12, SC_HDR2
    lea     DISCV5_ST_PRIVATE_KEY(%rbp), %rdi
    mov     %r14, %rsi
    SCR     %rdx, SC_EPH+32
    mov     %rbx, %rcx
    lea     DISCV5_HDR_SIGNATURE(%r12), %r8
    CALL_GLOBAL discv5_id_sign
    test    %rax, %rax
    jnz     9f
    lea     DISCV5_HDR_EPH_KEY(%r12), %rdi
    SCR     %rsi, SC_EPH+32
    mov     $33, %edx
    call    discv5_copy
    mov     %r15, %rdi
    mov     %rbx, %rsi
    lea     DISCV5_R_EP(%rbx), %rdx
    SCR     %rcx, SC_KEYS
    SCR     %r8, SC_KEYS+16
    call    discv5_session_put
    mov     %rax, %r13
    movq    $1, DISCV5_S_COUNTER(%r13)

    /* The header: flag 2, the first nonce of the session. */
    movq    $DISCV5_FLAG_HANDSHAKE, DISCV5_HDR_FLAG(%r12)
    mov     %rbp, %rdi
    lea     DISCV5_HDR_IV(%r12), %rsi
    mov     $16, %edx
    call    discv5_random
    lea     DISCV5_HDR_SRC_ID(%r12), %rdi
    lea     DISCV5_ST_NODE_ID(%rbp), %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_HDR_NONCE(%r12), %rdi
    mov     $1, %esi
    mov     $4, %edx
    call    discv5_store_be
    mov     %rbp, %rdi
    lea     DISCV5_HDR_NONCE+4(%r12), %rsi
    mov     $8, %edx
    call    discv5_random
    lea     DISCV5_HDR_RECORD(%r12), %rax
    BYTELIST %rax, 0, DISCV5_HDR_RECORD_SIZE, $0
    mov     SC_HDR+DISCV5_HDR_ENR_SEQ(%r15), %rax
    cmp     DISCV5_ST_SEQ(%rbp), %rax
    jae     2f
    mov     DISCV5_ST_RECORD_LEN(%rbp), %rdx
    mov     %rdx, DISCV5_HDR_RECORD+DISCV5_BL_COUNT(%r12)
    lea     DISCV5_HDR_RECORD+DISCV5_BL_FIXED(%r12), %rdi
    lea     DISCV5_ST_RECORD(%rbp), %rsi
    call    discv5_copy

    /* The request again. */
2:  mov     %r15, %rdi
    mov     %rbx, %rsi
    call    discv5_request_message
    SCR     %rax, SC_PKT
    BYTELIST %rax, 0, BL_PACKET_SIZE, $0
    mov     %r12, %rdi
    mov     %rbx, %rsi
    lea     DISCV5_S_WRITE_KEY(%r13), %rdx
    SCR     %rcx, SC_MSG
    SCR     %r8, SC_PKT
    CALL_GLOBAL discv5_packet_encode
    test    %rax, %rax
    jnz     9f
    mov     %r15, %rdi
    lea     DISCV5_R_EP(%rbx), %rsi
    call    discv5_send_packet
    lea     DISCV5_R_NONCE(%rbx), %rdi
    lea     DISCV5_HDR_NONCE(%r12), %rsi
    mov     $12, %edx
    call    discv5_copy
    movb    $DISCV5_REQ_HANDSHAKE, DISCV5_R_STATE(%rbx)
    NOW     %rax
    add     $DISCV5_REQUEST_TIMEOUT, %rax
    mov     %rax, DISCV5_R_DEADLINE(%rbx)
    mov     %r15, %rdi
    mov     %rbx, %rsi
    call    discv5_requests_resend
9:  LEAVE   8
END_FUNCTION discv5_on_whoareyou

/*
 * discv5_requests_resend(scratch, request): the other requests waiting for
 * the same node ID and endpoint go again, now through the session the
 * request's handshake made, each with a new nonce and deadline.
 * rbx request, rbp slot, r12 slots left.
 */
LOCAL_FUNCTION discv5_requests_resend
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    STATE   %rbp
    add     $DISCV5_ST_REQUESTS, %rbp
    mov     $DISCV5_REQUEST_SLOTS, %r12d
1:  cmp     %rbx, %rbp
    je      2f
    cmpb    $DISCV5_REQ_WAITING, DISCV5_R_STATE(%rbp)
    jne     2f
    mov     %rbp, %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    lea     DISCV5_R_EP(%rbp), %rdi
    lea     DISCV5_R_EP(%rbx), %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      2f
    mov     %r15, %rdi
    mov     %rbp, %rsi
    call    discv5_request_message
    mov     %r15, %rdi
    mov     %rbp, %rsi
    lea     DISCV5_R_EP(%rbp), %rdx
    call    discv5_send_message
    lea     DISCV5_R_NONCE(%rbp), %rdi
    mov     %rax, %rsi
    mov     $12, %edx
    call    discv5_copy
    NOW     %rax
    add     $DISCV5_REQUEST_TIMEOUT, %rax
    mov     %rax, DISCV5_R_DEADLINE(%rbp)
2:  add     $DISCV5_R_SIZE, %rbp
    dec     %r12
    jnz     1b
    LEAVE   8
END_FUNCTION discv5_requests_resend

/*
 * discv5_on_handshake(scratch): a handshake packet answering the WHOAREYOU
 * still valid for the sender's node ID and endpoint. The public key comes
 * from the record in the packet (its node ID must match), else from the
 * table. The ID proof must verify and the message must open with the
 * derived keys; then the session is stored, the challenge is used up, a
 * record from the packet goes to the table, and the message is handled.
 * rbx challenge, rbp public key, r12 state, r13 source ID, r14 1 when the
 * packet has the record.
 */
LOCAL_FUNCTION discv5_on_handshake
    ENTER   8
    mov     %rdi, %r15
    STATE   %r12
    lea     SC_HDR+DISCV5_HDR_SRC_ID(%r15), %r13
    mov     %r13, %rsi
    lea     SC_CTX+CTX_FROM(%r15), %rdx
    xor     %ecx, %ecx
    call    discv5_challenge_find
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    xor     %r14d, %r14d
    cmpq    $0, SC_HDR+DISCV5_HDR_RECORD+DISCV5_BL_COUNT(%r15)
    je      1f
    SCR     %rsi, SC_ENR_SCRATCH
    movq    $DISCV5_ENR_SCRATCH, (%rsi)
    lea     SC_HDR+DISCV5_HDR_RECORD(%r15), %rdi
    SCR     %rdx, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    test    %rax, %rax
    jnz     9f
    SCR     %rdi, SC_ENR+DISCV5_ENR_NODE_ID
    mov     %r13, %rsi
    mov     $32, %edx
    call    discv5_equal
    test    %rax, %rax
    jz      9f
    SCR     %rbp, SC_ENR+DISCV5_ENR_PUBKEY
    mov     $1, %r14d
    jmp     2f
1:  mov     %r15, %rdi
    mov     %r13, %rsi
    call    discv5_node_find
    test    %rax, %rax
    jz      9f
    lea     DISCV5_N_PUBKEY(%rax), %rbp
2:  mov     %rbp, %rdi
    lea     DISCV5_C_DATA(%rbx), %rsi
    lea     SC_HDR(%r15), %rdx
    lea     DISCV5_ST_NODE_ID(%r12), %rcx
    SCR     %r8, SC_TMP
    CALL_GLOBAL discv5_id_verify
    test    %rax, %rax
    jnz     9f
    cmpq    $1, SC_TMP(%r15)
    jne     9f

    /* Keys: the IDs are the sender's (initiator), then the local node's. */
    SCR     %rdi, SC_TMP+8
    mov     %r13, %rsi
    mov     $32, %edx
    call    discv5_copy
    mov     %rax, %rdi
    lea     DISCV5_ST_NODE_ID(%r12), %rsi
    mov     $32, %edx
    call    discv5_copy
    lea     DISCV5_ST_PRIVATE_KEY(%r12), %rdi
    lea     SC_HDR+DISCV5_HDR_EPH_KEY(%r15), %rsi
    lea     DISCV5_C_DATA(%rbx), %rdx
    SCR     %rcx, SC_TMP+8
    SCR     %r8, SC_KEYS
    CALL_GLOBAL discv5_derive_keys
    test    %rax, %rax
    jnz     9f
    lea     SC_HDR(%r15), %rdi
    SCR     %rsi, SC_KEYS
    SCR     %rdx, SC_IN
    SCR     %rcx, SC_MSG
    CALL_GLOBAL discv5_message_decrypt
    test    %rax, %rax
    jnz     9f
    mov     %r15, %rdi
    mov     %r13, %rsi
    lea     SC_CTX+CTX_FROM(%r15), %rdx
    SCR     %rcx, SC_KEYS+16
    SCR     %r8, SC_KEYS
    call    discv5_session_put
    movq    $0, DISCV5_C_SENT(%rbx)
    test    %r14, %r14
    jz      3f
    mov     %r15, %rdi
    SCR     %rsi, SC_ENR
    lea     SC_HDR+DISCV5_HDR_RECORD(%r15), %rdx
    call    discv5_node_add
3:  mov     %r15, %rdi
    call    discv5_handle_message
9:  LEAVE   8
END_FUNCTION discv5_on_handshake

/*
 * discv5_on_datagram(scratch, event): a received datagram. The sender's
 * endpoint is kept with the unused address bytes zero; a packet that does
 * not decode is dropped. rbx event, rbp packet.
 */
LOCAL_FUNCTION discv5_on_datagram
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    lea     SC_CTX+CTX_FROM(%r15), %rdi
    lea     DISCV5_EV_DG_FROM(%rbx), %rsi
    mov     $DISCV5_EP_SIZE, %edx
    call    discv5_copy
    cmpq    $4, SC_CTX+CTX_FROM+DISCV5_EP_FAMILY(%r15)
    jne     1f
    movl    $0, SC_CTX+CTX_FROM+DISCV5_EP_ADDRESS+4(%r15)
    movq    $0, SC_CTX+CTX_FROM+DISCV5_EP_ADDRESS+8(%r15)
1:  SCR     %rbp, SC_IN
    mov     DISCV5_EV_DG_LEN(%rbx), %rax
    BYTELIST %rbp, 0, BL_PACKET_SIZE, %rax
    lea     DISCV5_BL_FIXED(%rbp), %rdi
    lea     DISCV5_EV_DG_DATA(%rbx), %rsi
    mov     DISCV5_EV_DG_LEN(%rbx), %rdx
    call    discv5_copy
    mov     %rbp, %rdi
    STATE   %rsi
    add     $DISCV5_ST_NODE_ID, %rsi
    lea     SC_HDR(%r15), %rdx
    CALL_GLOBAL discv5_packet_decode
    test    %rax, %rax
    jnz     9f
    SCR     %rax, SC_MSG
    BYTELIST %rax, 0, BL_PACKET_SIZE, $0
    mov     SC_HDR+DISCV5_HDR_FLAG(%r15), %rax
    mov     %r15, %rdi
    cmp     $DISCV5_FLAG_MESSAGE, %rax
    jne     2f
    call    discv5_on_message_packet
    jmp     9f
2:  cmp     $DISCV5_FLAG_WHOAREYOU, %rax
    jne     3f
    call    discv5_on_whoareyou
    jmp     9f
3:  call    discv5_on_handshake
9:  LEAVE   8
END_FUNCTION discv5_on_datagram

/* ---------------------------------------------------------------- Other events */

/* discv5_on_add_node(scratch, event): ADD_NODE: a valid record with a UDP endpoint goes to the table. rbx event, rbp length, r12 record. */
LOCAL_FUNCTION discv5_on_add_node
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     DISCV5_EV_ADD_LEN(%rbx), %rbp
    cmp     $DISCV5_MAX_RECORD, %rbp
    ja      9f
    SCR     %r12, SC_REC
    BYTELIST %r12, 0, 328, %rbp
    lea     DISCV5_BL_FIXED(%r12), %rdi
    lea     DISCV5_EV_ADD_DATA(%rbx), %rsi
    mov     %rbp, %rdx
    call    discv5_copy
    SCR     %rsi, SC_ENR_SCRATCH
    movq    $DISCV5_ENR_SCRATCH, (%rsi)
    mov     %r12, %rdi
    SCR     %rdx, SC_ENR
    CALL_GLOBAL discv5_enr_decode
    test    %rax, %rax
    jnz     9f
    mov     %r15, %rdi
    SCR     %rsi, SC_ENR
    mov     %r12, %rdx
    call    discv5_node_add
9:  LEAVE   8
END_FUNCTION discv5_on_add_node

.set ENTRIES_BYTES, 8 + DISCV5_MAX_ENTRIES * DISCV5_LE_SIZE

/*
 * discv5_record_change(scratch, event): SET_ENDPOINT or SET_ENTRY. The
 * entries change, the sequence number goes up by 1, the record is signed
 * again, and a RECORD action carries it. When the entries are full or the
 * record would pass 300 bytes, the entries and sequence number stay as they
 * were. rbx event, rbp state, r12 saved entries.
 */
LOCAL_FUNCTION discv5_record_change
    ENTER   8
    mov     %rdi, %r15
    mov     %rsi, %rbx
    STATE   %rbp
    SCR     %r12, SC_TMP
    mov     %r12, %rdi
    lea     DISCV5_ST_ENTRY_COUNT(%rbp), %rsi
    mov     $ENTRIES_BYTES, %edx
    call    discv5_copy
    cmpq    $DISCV5_EVENT_SET_ENDPOINT, DISCV5_EV_KIND(%rbx)
    jne     1f
    mov     %rbp, %rdi
    lea     DISCV5_EV_ENDPOINT(%rbx), %rsi
    call    discv5_set_endpoint
    jmp     2f
1:  mov     %rbp, %rdi
    lea     DISCV5_EV_ENTRY_KEY(%rbx), %rsi
    mov     DISCV5_EV_ENTRY_KEY_LEN(%rbx), %rdx
    lea     DISCV5_EV_ENTRY_VALUE(%rbx), %rcx
    mov     DISCV5_EV_ENTRY_VALUE_LEN(%rbx), %r8
    call    discv5_entry_set
2:  test    %rax, %rax
    jnz     8f
    incq    DISCV5_ST_SEQ(%rbp)
    mov     %rbp, %rdi
    call    discv5_record_build
    test    %rax, %rax
    jnz     7f
    mov     %r15, %rdi
    call    discv5_emit_record
    jmp     9f
7:  decq    DISCV5_ST_SEQ(%rbp)
8:  lea     DISCV5_ST_ENTRY_COUNT(%rbp), %rdi
    mov     %r12, %rsi
    mov     $ENTRIES_BYTES, %edx
    call    discv5_copy
9:  LEAVE   8
END_FUNCTION discv5_record_change

/* discv5_owned_key(key, length) -> 1 when the key is one the core sets: "id", "secp256k1", "ip", "udp", "ip6", "udp6". rbx key, rbp length, r12 table, r13 entries left. */
LOCAL_FUNCTION discv5_owned_key
    ENTER   8
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    lea     402f(%rip), %r12
    mov     $6, %r13d
1:  movzbl  1(%r12), %eax
    cmp     %rbp, %rax
    jne     2f
    movzbl  (%r12), %eax
    lea     400b(%rip), %rsi
    add     %rax, %rsi
    mov     %rbx, %rdi
    mov     %rbp, %rdx
    call    discv5_equal
    test    %rax, %rax
    jnz     9f
2:  add     $2, %r12
    dec     %r13
    jnz     1b
    xor     %eax, %eax
9:  LEAVE   8
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
 * move on. rbx state, rbp slot, r12 slots left, r13 now, r14 best.
 */
LOCAL_FUNCTION discv5_timers
    ENTER   8
    mov     %rdi, %r15
    STATE   %rbx
    NOW     %r13
    lea     DISCV5_ST_REQUESTS(%rbx), %rbp
    mov     $DISCV5_REQUEST_SLOTS, %r12d
1:  cmpb    $0, DISCV5_R_STATE(%rbp)
    je      2f
    cmp     DISCV5_R_DEADLINE(%rbp), %r13
    jb      2f
    xor     %edx, %edx
    cmpb    $0, DISCV5_R_GOT(%rbp)
    setne   %dl
    mov     %r15, %rdi
    mov     %rbp, %rsi
    call    discv5_request_end
2:  add     $DISCV5_R_SIZE, %rbp
    dec     %r12
    jnz     1b

    /* The liveness check. */
    cmp     DISCV5_ST_NEXT_PING(%rbx), %r13
    jb      5f
    lea     DISCV5_PING_INTERVAL(%r13), %rax
    mov     %rax, DISCV5_ST_NEXT_PING(%rbx)
    lea     DISCV5_ST_NODES(%rbx), %rbp
    mov     $DISCV5_NODE_SLOTS, %r12d
    xor     %r14d, %r14d
3:  cmpb    $DISCV5_NODE_MEMBER, DISCV5_N_STATE(%rbp)
    jne     4f
    cmpb    $0, DISCV5_N_PINGING(%rbp)
    jne     4f
    mov     DISCV5_N_CHECK(%rbp), %rax
    cmp     %r13, %rax
    ja      4f
    test    %r14, %r14
    jz      31f
    cmp     DISCV5_N_CHECK(%r14), %rax
    jae     4f
31: mov     %rbp, %r14
4:  add     $DISCV5_N_SIZE, %rbp
    dec     %r12
    jnz     3b
    test    %r14, %r14
    jz      5f
    mov     %r15, %rdi
    mov     %r14, %rsi
    mov     $(DISCV5_MSG_PING | (DISCV5_PURPOSE_CHECK << 8)), %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    call    discv5_request_start
    test    %rax, %rax
    jz      5f
    movb    $1, DISCV5_N_PINGING(%r14)
    lea     DISCV5_RECHECK_INTERVAL(%r13), %rax
    mov     %rax, DISCV5_N_CHECK(%r14)

    /* The refresh lookup. */
5:  mov     DISCV5_ST_NEXT_REFRESH(%rbx), %rax
    test    %rax, %rax
    jz      6f
    cmp     %rax, %r13
    jb      6f
    mov     $DISCV5_REFRESH_INTERVAL, %eax
    add     %r13, %rax
    mov     %rax, DISCV5_ST_NEXT_REFRESH(%rbx)
    mov     %r15, %rdi
    lea     DISCV5_ST_NODE_ID(%rbx), %rsi
    call    discv5_lookup_start

    /* Lookups waiting for a free request slot. */
6:  lea     DISCV5_ST_LOOKUPS(%rbx), %rbp
    mov     $DISCV5_LOOKUP_SLOTS, %r12d
7:  mov     %r15, %rdi
    mov     %rbp, %rsi
    call    discv5_lookup_advance
    add     $DISCV5_L_SIZE, %rbp
    dec     %r12
    jnz     7b
    LEAVE   8
END_FUNCTION discv5_timers

/* discv5_wakeup(scratch): a WAKEUP action for the next timer: the next check, refresh or request deadline. rbx state, rbp time. */
LOCAL_FUNCTION discv5_wakeup
    ENTER   8
    mov     %rdi, %r15
    STATE   %rbx
    mov     DISCV5_ST_NEXT_PING(%rbx), %rbp
    mov     DISCV5_ST_NEXT_REFRESH(%rbx), %rax
    test    %rax, %rax
    jz      1f
    cmp     %rbp, %rax
    cmovb   %rax, %rbp
1:  lea     DISCV5_ST_REQUESTS(%rbx), %rcx
    mov     $DISCV5_REQUEST_SLOTS, %edx
2:  cmpb    $0, DISCV5_R_STATE(%rcx)
    je      3f
    mov     DISCV5_R_DEADLINE(%rcx), %rax
    cmp     %rbp, %rax
    cmovb   %rax, %rbp
3:  add     $DISCV5_R_SIZE, %rcx
    dec     %rdx
    jnz     2b
    mov     %r15, %rdi
    mov     $DISCV5_ACTION_WAKEUP, %esi
    mov     $DISCV5_ACT_WAKEUP_SIZE, %edx
    call    discv5_action
    test    %rax, %rax
    jz      9f
    mov     %rbp, DISCV5_ACT_WAKEUP_AT(%rax)
9:  LEAVE   8
END_FUNCTION discv5_wakeup

/* ---------------------------------------------------------------- discv5_step */

/*
 * discv5_step(state, tick, events, scratch, actions) -> status
 * Checks the scratch size, every event and the action room first; on error
 * nothing changes. Then takes the time (never below the last), reseeds the
 * DRBG, handles the events in order, runs the timers, and ends the actions
 * with WAKEUP. rbx state, rbp tick, r12 events, r13 scratch, r14 actions,
 * r15 event position. Locals: rsp the events end, rsp + 8 the event count,
 * rsp + 16 the event.
 */
FUNCTION discv5_step
    ENTER   24
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, %r14
    mov     $DISCV5_BUFFER_TOO_SMALL, %eax
    cmpq    $DISCV5_SCRATCH_SIZE, (%r13)
    jb      99f

    /* Check the events. */
    mov     DISCV5_BL_OFFSET(%r12), %r15
    add     %r12, %r15
    mov     DISCV5_BL_COUNT(%r12), %rax
    add     %r15, %rax
    mov     %rax, (%rsp)
    movq    $0, 8(%rsp)
1:  mov     $DISCV5_INVALID_EVENT, %eax
    cmp     (%rsp), %r15
    jae     3f
    mov     (%rsp), %rcx
    sub     %r15, %rcx
    cmp     $16, %rcx
    jb      99f
    mov     DISCV5_EV_SIZE(%r15), %rdx
    cmp     $16, %rdx
    jb      99f
    test    $7, %dl
    jnz     99f
    cmp     %rcx, %rdx
    ja      99f
    mov     DISCV5_EV_KIND(%r15), %rcx
    cmp     $DISCV5_EVENT_DATAGRAM, %rcx
    jne     11f
    cmp     $DISCV5_EV_DG_DATA, %rdx
    jb      99f
    mov     DISCV5_EV_DG_LEN(%r15), %r8
    cmp     $DISCV5_MAX_PACKET, %r8
    ja      99f
    lea     -DISCV5_EV_DG_DATA(%rdx), %r9
    cmp     %r9, %r8
    ja      99f
    mov     DISCV5_EV_DG_FROM+DISCV5_EP_FAMILY(%r15), %r8
    cmp     $4, %r8
    je      2f
    cmp     $6, %r8
    je      2f
    jmp     99f
11: cmp     $DISCV5_EVENT_ADD_NODE, %rcx
    jne     12f
    cmp     $DISCV5_EV_ADD_DATA, %rdx
    jb      99f
    mov     DISCV5_EV_ADD_LEN(%r15), %r8
    lea     -DISCV5_EV_ADD_DATA(%rdx), %r9
    cmp     %r9, %r8
    ja      99f
    jmp     2f
12: cmp     $DISCV5_EVENT_LOOKUP, %rcx
    jne     13f
    cmp     $DISCV5_EV_LOOKUP_SIZE, %rdx
    jb      99f
    jmp     2f
13: cmp     $DISCV5_EVENT_SET_ENDPOINT, %rcx
    jne     14f
    cmp     $DISCV5_EV_ENDPOINT_SIZE, %rdx
    jb      99f
    mov     DISCV5_EV_ENDPOINT+DISCV5_EP_FAMILY(%r15), %r8
    cmp     $4, %r8
    je      131f
    cmp     $6, %r8
    jne     99f
131: cmpq   $0x10000, DISCV5_EV_ENDPOINT+DISCV5_EP_PORT(%r15)
    jae     99f
    jmp     2f
14: cmp     $DISCV5_EVENT_SET_ENTRY, %rcx
    jne     15f
    cmp     $DISCV5_EV_ENTRY_VALUE, %rdx
    jb      99f
    mov     DISCV5_EV_ENTRY_KEY_LEN(%r15), %r8
    test    %r8, %r8
    jz      99f
    cmp     $DISCV5_MAX_KEY, %r8
    ja      99f
    mov     DISCV5_EV_ENTRY_VALUE_LEN(%r15), %r9
    cmp     $DISCV5_MAX_VALUE, %r9
    ja      99f
    lea     -DISCV5_EV_ENTRY_VALUE(%rdx), %r10
    cmp     %r10, %r9
    ja      99f
    lea     DISCV5_EV_ENTRY_KEY(%r15), %rdi
    mov     %r8, %rsi
    call    discv5_owned_key
    mov     %rax, %rcx
    mov     $DISCV5_INVALID_EVENT, %eax
    test    %rcx, %rcx
    jnz     99f
    jmp     2f
15: cmp     $DISCV5_EVENT_OPENED, %rcx          /* shell results: well formed, then ignored */
    jne     16f
    cmp     $DISCV5_EV_OPENED_SIZE, %rdx
    jb      99f
    jmp     2f
16: cmp     $DISCV5_EVENT_SENT, %rcx
    jb      99f
    cmp     $DISCV5_EVENT_IDLE, %rcx
    ja      99f
    cmp     $DISCV5_EV_ERROR_SIZE, %rdx
    jb      99f
2:  add     DISCV5_EV_SIZE(%r15), %r15
    incq    8(%rsp)
    jmp     1b

    /* Check the action room. */
3:  mov     $DISCV5_BUFFER_TOO_SMALL, %eax
    mov     DISCV5_BL_SIZE(%r14), %rcx
    sub     $DISCV5_BL_FIXED, %rcx
    jb      99f
    mov     8(%rsp), %rdx
    imul    $DISCV5_ACTIONS_PER_EVENT, %rdx, %rdx
    add     $DISCV5_ACTIONS_BASE, %rdx
    cmp     %rdx, %rcx
    jb      99f

    /* Commit: the time, the DRBG, the context, empty actions. */
    mov     DISCV5_TICK_NOW(%rbp), %rax
    mov     DISCV5_ST_NOW(%rbx), %rcx
    cmp     %rcx, %rax
    cmovb   %rcx, %rax
    mov     %rax, DISCV5_ST_NOW(%rbx)
    mov     %rax, SC_CTX+CTX_NOW(%r13)
    mov     %rbx, SC_CTX+CTX_STATE(%r13)
    mov     %r14, SC_CTX+CTX_ACTIONS(%r13)
    mov     %rbx, %rdi
    lea     DISCV5_TICK_ENTROPY(%rbp), %rsi
    call    discv5_reseed
    movq    $DISCV5_BL_FIXED, DISCV5_BL_OFFSET(%r14)
    movq    $0, DISCV5_BL_COUNT(%r14)

    /* The events. */
    mov     DISCV5_BL_OFFSET(%r12), %r15
    add     %r12, %r15
4:  cmp     (%rsp), %r15
    jae     8f
    mov     %r15, 16(%rsp)
    add     DISCV5_EV_SIZE(%r15), %r15
    mov     16(%rsp), %rsi
    mov     DISCV5_EV_KIND(%rsi), %rax
    mov     %r13, %rdi
    cmp     $DISCV5_EVENT_DATAGRAM, %rax
    jne     41f
    call    discv5_on_datagram
    jmp     4b
41: cmp     $DISCV5_EVENT_ADD_NODE, %rax
    jne     42f
    call    discv5_on_add_node
    jmp     4b
42: cmp     $DISCV5_EVENT_LOOKUP, %rax
    jne     43f
    add     $DISCV5_EV_LOOKUP_TARGET, %rsi
    call    discv5_lookup_start
    jmp     4b
43: cmp     $DISCV5_EVENT_SET_ENTRY, %rax
    ja      4b
    call    discv5_record_change
    jmp     4b

    /* Timers, then WAKEUP. */
8:  mov     %r13, %rdi
    call    discv5_timers
    mov     %r13, %rdi
    call    discv5_wakeup
    xor     %eax, %eax
99: LEAVE   24
END_FUNCTION discv5_step
