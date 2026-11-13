/*
 * asm-discv5 shell for Linux on RISC-V: one UDP socket, the clock and random
 * bytes, through direct system calls. Requirements: docs/reference/shell.md.
 * Layouts: include/discv5.inc.
 *
 * System calls: the number in a7, arguments in a0 to a5, "ecall"; a0 holds
 * the result, or minus the error number (-4095 to -1).
 */
.set ISA_RISCV64, 1
.include "discv5.inc"
.include "platform.inc"

/* Linux numbers: asm-generic/unistd.h and the uapi headers. */
.set SYS_CLOSE, 57
.set SYS_PPOLL, 73
.set SYS_CLOCK_GETTIME, 113
.set SYS_SOCKET, 198
.set SYS_BIND, 200
.set SYS_GETSOCKNAME, 204
.set SYS_SENDTO, 206
.set SYS_RECVFROM, 207
.set SYS_SETSOCKOPT, 208
.set SYS_GETRANDOM, 278
.set OS_AF_INET, 2                  /* bits/socket.h */
.set OS_AF_INET6, 10                /* bits/socket.h */
.set OS_SOCK_DGRAM, 2               /* bits/socket_type.h */
.set OS_MSG_DONTWAIT, 0x40          /* bits/socket.h */
.set OS_IPPROTO_IPV6, 41            /* netinet/in.h */
.set OS_IPV6_V6ONLY, 26             /* linux/in6.h */
.set OS_POLLIN, 1                   /* asm-generic/poll.h */
.set OS_CLOCK_MONOTONIC, 1          /* linux/time.h */
.set OS_EINVAL, 22                  /* asm-generic/errno-base.h */
.set OS_EAFNOSUPPORT, 97            /* asm-generic/errno.h */
.set OS_SOCKADDR_SIZE, 128          /* sizeof(struct sockaddr_storage) */

/* a0 = the system call's result. */
.macro SYSCALL number
    li      a7, \number
    ecall
.endm

/* Branch to label when a0 holds an error (-4095 to -1). Uses t6. */
.macro IF_ERROR label
    li      t6, -4095
    bgeu    a0, t6, \label
.endm

.set SL, 64                         /* locals start at sp + SL */

/* Frame: ra and s1-s6 at sp, then bytes of locals at sp + SL. bytes is a multiple of 16. */
.macro SENTER bytes
    addi    sp, sp, -(\bytes + SL)
    UNWIND_ALLOC (\bytes + SL)
    sd      ra, 0(sp)
    UNWIND_SAVE ra, 0
    sd      s1, 8(sp)
    UNWIND_SAVE s1, 8
    sd      s2, 16(sp)
    UNWIND_SAVE s2, 16
    sd      s3, 24(sp)
    UNWIND_SAVE s3, 24
    sd      s4, 32(sp)
    UNWIND_SAVE s4, 32
    sd      s5, 40(sp)
    UNWIND_SAVE s5, 40
    sd      s6, 48(sp)
    UNWIND_SAVE s6, 48
    UNWIND_END_PROLOGUE
.endm

.macro SLEAVE bytes
    UNWIND_BEGIN_EPILOGUE
    ld      ra, 0(sp)
    UNWIND_RESTORE ra
    ld      s1, 8(sp)
    UNWIND_RESTORE s1
    ld      s2, 16(sp)
    UNWIND_RESTORE s2
    ld      s3, 24(sp)
    UNWIND_RESTORE s3
    ld      s4, 32(sp)
    UNWIND_RESTORE s4
    ld      s5, 40(sp)
    UNWIND_RESTORE s5
    ld      s6, 48(sp)
    UNWIND_RESTORE s6
    addi    sp, sp, (\bytes + SL)
    UNWIND_FREE (\bytes + SL)
    UNWIND_END_EPILOGUE
    ret
.endm

/* d = the low 16 bits of s with their two bytes swapped. Uses t. */
.macro SWAP16 d, s, t
    andi    \t, \s, 0xFF
    slli    \t, \t, 8
    srli    \d, \s, 8
    andi    \d, \d, 0xFF
    or      \d, \d, \t
.endm

/*
 * discv5_shell_sockaddr(endpoint, family, sockaddr) -> the sockaddr length,
 * or 0 when the endpoint does not fit a socket of the family (4 or 6). On a
 * family 6 socket an IPv4 endpoint becomes an IPv4-mapped IPv6 address.
 */
LOCAL_FUNCTION discv5_shell_sockaddr
    UNWIND_END_PROLOGUE
    ld      t0, DISCV5_EP_FAMILY(a0)
    ld      t1, DISCV5_EP_PORT(a0)
    SWAP16  t1, t1, t2
    sd      zero, 0(a2)
    sd      zero, 8(a2)
    sd      zero, 16(a2)
    sd      zero, 24(a2)
    li      t2, 4
    bne     a1, t2, 1f
    bne     t0, t2, 8f
    li      t2, OS_AF_INET
    sh      t2, 0(a2)
    sh      t1, 2(a2)
    lwu     t2, DISCV5_EP_ADDRESS(a0)
    sw      t2, 4(a2)
    li      a0, 16
    ret
1:  li      t2, 6
    bne     a1, t2, 8f
    li      t3, OS_AF_INET6
    sh      t3, 0(a2)
    sh      t1, 2(a2)
    bne     t0, t2, 2f
    ld      t3, DISCV5_EP_ADDRESS(a0)
    sd      t3, 8(a2)
    ld      t3, DISCV5_EP_ADDRESS+8(a0)
    sd      t3, 16(a2)
    li      a0, 28
    ret
2:  li      t2, 4
    bne     t0, t2, 8f
    li      t3, -1
    sh      t3, 18(a2)
    lwu     t3, DISCV5_EP_ADDRESS(a0)
    sw      t3, 20(a2)
    li      a0, 28
    ret
8:  li      a0, 0
    ret
END_FUNCTION discv5_shell_sockaddr

/*
 * discv5_shell_endpoint(sockaddr, endpoint) -> 1 when the address is IPv4 or
 * IPv6, written as an endpoint; an IPv4-mapped IPv6 address becomes IPv4.
 */
LOCAL_FUNCTION discv5_shell_endpoint
    UNWIND_END_PROLOGUE
    sd      zero, 0(a1)
    sd      zero, 8(a1)
    sd      zero, 16(a1)
    sd      zero, 24(a1)
    lhu     t1, 2(a0)
    SWAP16  t1, t1, t2
    sd      t1, DISCV5_EP_PORT(a1)
    lhu     t0, 0(a0)
    li      t2, OS_AF_INET
    bne     t0, t2, 1f
    lwu     t3, 4(a0)
    j       3f
1:  li      t2, OS_AF_INET6
    bne     t0, t2, 8f
    ld      t3, 8(a0)                       # address bytes 0 to 9 zero, 10 and 11 all ones
    lhu     t4, 16(a0)
    or      t3, t3, t4
    bnez    t3, 2f
    lhu     t4, 18(a0)
    li      t2, 0xFFFF
    bne     t4, t2, 2f
    lwu     t3, 20(a0)                      # IPv4-mapped
3:  sw      t3, DISCV5_EP_ADDRESS(a1)
    li      t2, 4
    sd      t2, DISCV5_EP_FAMILY(a1)
    li      a0, 1
    ret
2:  ld      t3, 8(a0)
    sd      t3, DISCV5_EP_ADDRESS(a1)
    ld      t3, 16(a0)
    sd      t3, DISCV5_EP_ADDRESS+8(a1)
    li      t2, 6
    sd      t2, DISCV5_EP_FAMILY(a1)
    li      a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION discv5_shell_endpoint

/* discv5_shell_now() -> milliseconds of CLOCK_MONOTONIC, or 0 when the clock fails. The timespec at sp. */
LOCAL_FUNCTION discv5_shell_now
    addi    sp, sp, -16
    UNWIND_ALLOC 16
    UNWIND_END_PROLOGUE
    li      a0, OS_CLOCK_MONOTONIC
    mv      a1, sp
    SYSCALL SYS_CLOCK_GETTIME
    mv      t0, a0
    li      a0, 0
    bnez    t0, 9f
    ld      t0, 0(sp)
    ld      t1, 8(sp)
    li      t2, 1000
    mul     a0, t0, t2
    li      t2, 1000000
    divu    t1, t1, t2
    add     a0, a0, t1
9:  UNWIND_BEGIN_EPILOGUE
    addi    sp, sp, 16
    UNWIND_FREE 16
    UNWIND_END_EPILOGUE
    ret
END_FUNCTION discv5_shell_now

/*
 * discv5_shell_clock(tick) -> status: the time in milliseconds and 32 random
 * bytes from getrandom. OS_ERROR when either fails. s1 tick, s2 status.
 */
FUNCTION discv5_shell_clock
    SENTER  0
    mv      s1, a0
    li      s2, DISCV5_OS_ERROR
    call    discv5_shell_now
    beqz    a0, 9f
    sd      a0, DISCV5_TICK_NOW(s1)
    addi    a0, s1, DISCV5_TICK_ENTROPY
    li      a1, 32
    li      a2, 0
    SYSCALL SYS_GETRANDOM
    li      t0, 32
    bne     a0, t0, 9f
    li      s2, DISCV5_OK
9:  mv      a0, s2
    SLEAVE  0
END_FUNCTION discv5_shell_clock

/*
 * discv5_shell_open(endpoint, context, event) -> status 0: a UDP socket bound
 * to the endpoint. An IPv6 socket also takes IPv4. The OPENED event holds 0
 * and the bound endpoint, or the OS error.
 * s1 endpoint, s2 context, s3 event, s4 socket, s5 error.
 * Locals: sp + SL the sockaddr, sp + SL + 128 its length, sp + SL + 132 an int.
 */
FUNCTION discv5_shell_open
    SENTER  144
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    li      t0, DISCV5_EV_OPENED_SIZE
    sd      t0, DISCV5_EV_SIZE(s3)
    li      t0, DISCV5_EVENT_OPENED
    sd      t0, DISCV5_EV_KIND(s3)
    sd      zero, DISCV5_EV_ERROR(s3)
    sd      zero, DISCV5_EV_OPENED_ENDPOINT(s3)
    sd      zero, DISCV5_EV_OPENED_ENDPOINT+8(s3)
    sd      zero, DISCV5_EV_OPENED_ENDPOINT+16(s3)
    sd      zero, DISCV5_EV_OPENED_ENDPOINT+24(s3)
    li      s4, -1
    sd      s4, DISCV5_SHELL_SOCKET(s2)
    ld      t0, DISCV5_EP_FAMILY(s1)
    sd      t0, DISCV5_SHELL_FAMILY(s2)
    li      s5, OS_EAFNOSUPPORT
    li      a0, OS_AF_INET
    li      t1, 4
    beq     t0, t1, 1f
    li      a0, OS_AF_INET6
    li      t1, 6
    bne     t0, t1, 8f
1:  li      a1, OS_SOCK_DGRAM
    li      a2, 0
    SYSCALL SYS_SOCKET
    IF_ERROR 7f
    mv      s4, a0
    ld      t0, DISCV5_SHELL_FAMILY(s2)
    li      t1, 6
    bne     t0, t1, 2f
    sw      zero, SL+132(sp)
    mv      a0, s4
    li      a1, OS_IPPROTO_IPV6
    li      a2, OS_IPV6_V6ONLY
    addi    a3, sp, SL+132
    li      a4, 4
    SYSCALL SYS_SETSOCKOPT
    IF_ERROR 6f
2:  mv      a0, s1
    ld      a1, DISCV5_SHELL_FAMILY(s2)
    addi    a2, sp, SL
    call    discv5_shell_sockaddr
    mv      a2, a0
    mv      a0, s4
    addi    a1, sp, SL
    SYSCALL SYS_BIND
    IF_ERROR 6f
    li      t0, OS_SOCKADDR_SIZE
    sw      t0, SL+128(sp)
    mv      a0, s4
    addi    a1, sp, SL
    addi    a2, sp, SL+128
    SYSCALL SYS_GETSOCKNAME
    IF_ERROR 6f
    addi    a0, sp, SL
    addi    a1, s3, DISCV5_EV_OPENED_ENDPOINT
    call    discv5_shell_endpoint
    sd      s4, DISCV5_SHELL_SOCKET(s2)
    j       9f
6:  neg     s5, a0                          # close the socket, keep the error
    mv      a0, s4
    SYSCALL SYS_CLOSE
    j       8f
7:  neg     s5, a0
8:  sd      s5, DISCV5_EV_ERROR(s3)
9:  li      a0, DISCV5_OK
    SLEAVE  144
END_FUNCTION discv5_shell_open

/*
 * discv5_shell_send(context, action, event) -> status 0: sends a SEND action's
 * datagram. The SENT event holds 0, or the OS error.
 * s1 context, s2 action, s3 event, s4 error. The sockaddr at sp + SL.
 */
FUNCTION discv5_shell_send
    SENTER  128
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    li      t0, DISCV5_EV_ERROR_SIZE
    sd      t0, DISCV5_EV_SIZE(s3)
    li      t0, DISCV5_EVENT_SENT
    sd      t0, DISCV5_EV_KIND(s3)
    sd      zero, DISCV5_EV_ERROR(s3)
    li      s4, OS_EINVAL
    ld      t0, DISCV5_ACT_KIND(s2)
    li      t1, DISCV5_ACTION_SEND
    bne     t0, t1, 8f
    addi    a0, s2, DISCV5_ACT_SEND_TO
    ld      a1, DISCV5_SHELL_FAMILY(s1)
    addi    a2, sp, SL
    call    discv5_shell_sockaddr
    li      s4, OS_EAFNOSUPPORT
    beqz    a0, 8f
    mv      a5, a0
    ld      a0, DISCV5_SHELL_SOCKET(s1)
    addi    a1, s2, DISCV5_ACT_SEND_DATA
    ld      a2, DISCV5_ACT_SEND_LEN(s2)
    li      a3, 0
    addi    a4, sp, SL
    SYSCALL SYS_SENDTO
    IF_ERROR 7f
    j       9f
7:  neg     s4, a0
8:  sd      s4, DISCV5_EV_ERROR(s3)
9:  li      a0, DISCV5_OK
    SLEAVE  128
END_FUNCTION discv5_shell_send

/*
 * discv5_shell_receive(context, until, event) -> status 0: waits until a
 * datagram arrives or the time until (milliseconds, the clock of
 * discv5_shell_clock) passes. The event is a DATAGRAM, or IDLE holding 0
 * when the time passed, else the OS error. Bytes past 1280 are cut off.
 * s1 context, s2 until, s3 event, s4 error, s5 count.
 * Locals: sp + SL the sockaddr, + 128 its length, + 136 the pollfd,
 * + 144 the timespec.
 */
FUNCTION discv5_shell_receive
    SENTER  160
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    call    discv5_shell_now
    ld      t0, 0(s2)
    sub     t1, t0, a0
    bltu    a0, t0, 1f
    li      t1, 0
1:  li      t2, 1000
    divu    t3, t1, t2
    remu    t4, t1, t2
    li      t2, 1000000
    mul     t4, t4, t2
    sd      t3, SL+144(sp)
    sd      t4, SL+152(sp)
    ld      t0, DISCV5_SHELL_SOCKET(s1)
    sw      t0, SL+136(sp)
    li      t0, OS_POLLIN
    sw      t0, SL+140(sp)                  # events, then revents 0
    addi    a0, sp, SL+136
    li      a1, 1
    addi    a2, sp, SL+144
    li      a3, 0
    li      a4, 8
    SYSCALL SYS_PPOLL
    IF_ERROR 7f
    li      s4, 0
    beqz    a0, 8f
    li      t0, OS_SOCKADDR_SIZE
    sw      t0, SL+128(sp)
    ld      a0, DISCV5_SHELL_SOCKET(s1)
    addi    a1, s3, DISCV5_EV_DG_DATA
    li      a2, DISCV5_MAX_PACKET
    li      a3, OS_MSG_DONTWAIT
    addi    a4, sp, SL
    addi    a5, sp, SL+128
    SYSCALL SYS_RECVFROM
    IF_ERROR 7f
    mv      s5, a0
    addi    a0, sp, SL
    addi    a1, s3, DISCV5_EV_DG_FROM
    call    discv5_shell_endpoint
    li      s4, OS_EAFNOSUPPORT
    beqz    a0, 8f
    sd      s5, DISCV5_EV_DG_LEN(s3)
    addi    t0, s5, DISCV5_EV_DG_DATA+7
    andi    t0, t0, -8
    sd      t0, DISCV5_EV_SIZE(s3)
    li      t1, DISCV5_EVENT_DATAGRAM
    sd      t1, DISCV5_EV_KIND(s3)
    addi    t1, s3, DISCV5_EV_DG_DATA       # zero the bytes after the datagram
    add     t1, t1, s5
    add     t2, s3, t0
2:  bgeu    t1, t2, 9f
    sb      zero, 0(t1)
    addi    t1, t1, 1
    j       2b
7:  neg     s4, a0
8:  li      t0, DISCV5_EV_ERROR_SIZE
    sd      t0, DISCV5_EV_SIZE(s3)
    li      t0, DISCV5_EVENT_IDLE
    sd      t0, DISCV5_EV_KIND(s3)
    sd      s4, DISCV5_EV_ERROR(s3)
9:  li      a0, DISCV5_OK
    SLEAVE  160
END_FUNCTION discv5_shell_receive

/* discv5_shell_close(context) -> status 0: closes the socket. */
FUNCTION discv5_shell_close
    UNWIND_END_PROLOGUE
    ld      t0, DISCV5_SHELL_SOCKET(a0)
    li      t1, -1
    beq     t0, t1, 9f
    sd      t1, DISCV5_SHELL_SOCKET(a0)
    mv      a0, t0
    SYSCALL SYS_CLOSE
9:  li      a0, DISCV5_OK
    ret
END_FUNCTION discv5_shell_close
