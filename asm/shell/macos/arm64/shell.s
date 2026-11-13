/*
 * asm-discv5 shell for macOS on ARM64: one UDP socket, the clock and random
 * bytes, through libSystem. Requirements: docs/reference/shell.md.
 * Layouts: include/discv5.inc.
 *
 * The functions use AAPCS64 and call libSystem with the same convention.
 * errno comes from __error().
 */
.set ISA_ARM64, 1
.include "discv5.inc"
.include "platform.inc"

/* libSystem numbers: the macOS SDK headers. */
.set OS_AF_INET, 2                  /* sys/socket.h */
.set OS_AF_INET6, 30                /* sys/socket.h */
.set OS_SOCK_DGRAM, 2               /* sys/socket.h */
.set OS_MSG_DONTWAIT, 0x80          /* sys/socket.h */
.set OS_IPPROTO_IPV6, 41            /* netinet/in.h */
.set OS_IPV6_V6ONLY, 27             /* netinet6/in6.h */
.set OS_POLLIN, 1                   /* sys/poll.h */
.set OS_CLOCK_MONOTONIC, 6          /* time.h */
.set OS_EINVAL, 22                  /* sys/errno.h */
.set OS_EAFNOSUPPORT, 47            /* sys/errno.h */
.set OS_SOCKADDR_SIZE, 128          /* sizeof(struct sockaddr_storage) */

/* Frame: x29, x30, x19-x24, then locals at sp + 64. */
.macro SENTER locals
    stp     x29, x30, [sp, #-(64 + \locals)]!
    UNWIND_SAVE_FPLR_X (64 + \locals)
    mov     x29, sp
    UNWIND_SET_FP
    stp     x19, x20, [sp, #16]
    UNWIND_SAVE_REGP x19, x20, 16, (64 + \locals)
    stp     x21, x22, [sp, #32]
    UNWIND_SAVE_REGP x21, x22, 32, (64 + \locals)
    stp     x23, x24, [sp, #48]
    UNWIND_SAVE_REGP x23, x24, 48, (64 + \locals)
    UNWIND_END_PROLOGUE
.endm

.macro SLEAVE locals
    UNWIND_BEGIN_EPILOGUE
    ldp     x23, x24, [sp, #48]
    UNWIND_RESTORE_REGP x23, x24, 48
    ldp     x21, x22, [sp, #32]
    UNWIND_RESTORE_REGP x21, x22, 32
    ldp     x19, x20, [sp, #16]
    UNWIND_RESTORE_REGP x19, x20, 16
    ldp     x29, x30, [sp], #(64 + \locals)
    UNWIND_RESTORE_FPLR_X (64 + \locals)
    UNWIND_END_EPILOGUE
    ret
.endm

/* w0 = errno. */
.macro ERRNO
    CALL_GLOBAL __error
    ldr     w0, [x0]
.endm

/*
 * discv5_shell_sockaddr(endpoint, family, sockaddr) -> the sockaddr length,
 * or 0 when the endpoint does not fit a socket of the family (4 or 6). On a
 * family 6 socket an IPv4 endpoint becomes an IPv4-mapped IPv6 address.
 */
LOCAL_FUNCTION discv5_shell_sockaddr
    UNWIND_END_PROLOGUE
    ldr     x9, [x0, #DISCV5_EP_FAMILY]
    ldr     x10, [x0, #DISCV5_EP_PORT]
    rev16   w10, w10
    stp     xzr, xzr, [x2]
    stp     xzr, xzr, [x2, #16]
    cmp     x1, #4
    b.ne    1f
    cmp     x9, #4
    b.ne    8f
    mov     w11, #16
    strb    w11, [x2]
    mov     w11, #OS_AF_INET
    strb    w11, [x2, #1]
    strh    w10, [x2, #2]
    ldr     w11, [x0, #DISCV5_EP_ADDRESS]
    str     w11, [x2, #4]
    mov     x0, #16
    ret
1:  cmp     x1, #6
    b.ne    8f
    mov     w11, #28
    strb    w11, [x2]
    mov     w11, #OS_AF_INET6
    strb    w11, [x2, #1]
    strh    w10, [x2, #2]
    cmp     x9, #6
    b.ne    2f
    ldp     x11, x12, [x0, #DISCV5_EP_ADDRESS]
    stp     x11, x12, [x2, #8]
    mov     x0, #28
    ret
2:  cmp     x9, #4
    b.ne    8f
    mov     w11, #0xFFFF
    strh    w11, [x2, #18]
    ldr     w11, [x0, #DISCV5_EP_ADDRESS]
    str     w11, [x2, #20]
    mov     x0, #28
    ret
8:  mov     x0, #0
    ret
END_FUNCTION discv5_shell_sockaddr

/*
 * discv5_shell_endpoint(sockaddr, endpoint) -> 1 when the address is IPv4 or
 * IPv6, written as an endpoint; an IPv4-mapped IPv6 address becomes IPv4.
 */
LOCAL_FUNCTION discv5_shell_endpoint
    UNWIND_END_PROLOGUE
    stp     xzr, xzr, [x1]
    stp     xzr, xzr, [x1, #16]
    ldrh    w10, [x0, #2]
    rev16   w10, w10
    str     x10, [x1, #DISCV5_EP_PORT]
    ldrb    w9, [x0, #1]
    cmp     w9, #OS_AF_INET
    b.ne    1f
    ldr     w11, [x0, #4]
    b       3f
1:  cmp     w9, #OS_AF_INET6
    b.ne    8f
    ldr     x11, [x0, #8]                   /* address bytes 0 to 9 zero, 10 and 11 all ones */
    ldrh    w12, [x0, #16]
    ldrh    w13, [x0, #18]
    orr     x11, x11, x12
    cbnz    x11, 2f
    mov     w12, #0xFFFF
    cmp     w13, w12
    b.ne    2f
    ldr     w11, [x0, #20]                  /* IPv4-mapped */
3:  str     w11, [x1, #DISCV5_EP_ADDRESS]
    mov     x9, #4
    str     x9, [x1, #DISCV5_EP_FAMILY]
    mov     x0, #1
    ret
2:  ldp     x11, x12, [x0, #8]
    stp     x11, x12, [x1, #DISCV5_EP_ADDRESS]
    mov     x9, #6
    str     x9, [x1, #DISCV5_EP_FAMILY]
    mov     x0, #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION discv5_shell_endpoint

/* discv5_shell_now() -> milliseconds of CLOCK_MONOTONIC, or 0 when the clock fails. */
LOCAL_FUNCTION discv5_shell_now
    SENTER  0
    mov     x0, #OS_CLOCK_MONOTONIC
    CALL_GLOBAL clock_gettime_nsec_np
    mov     x9, #16960
    movk    x9, #15, lsl #16                /* 1000000 */
    udiv    x0, x0, x9
    SLEAVE  0
END_FUNCTION discv5_shell_now

/*
 * discv5_shell_clock(tick) -> status: the time in milliseconds and 32 random
 * bytes from getentropy. OS_ERROR when either fails.
 */
FUNCTION discv5_shell_clock
    SENTER  0
    mov     x19, x0
    mov     x20, #DISCV5_OS_ERROR
    bl      discv5_shell_now
    cbz     x0, 9f
    str     x0, [x19, #DISCV5_TICK_NOW]
    add     x0, x19, #DISCV5_TICK_ENTROPY
    mov     x1, #32
    CALL_GLOBAL getentropy
    cbnz    w0, 9f
    mov     x20, #DISCV5_OK
9:  mov     x0, x20
    SLEAVE  0
END_FUNCTION discv5_shell_clock

/*
 * discv5_shell_open(endpoint, context, event) -> status 0: a UDP socket bound
 * to the endpoint. An IPv6 socket also takes IPv4. The OPENED event holds 0
 * and the bound endpoint, or the OS error.
 * x19 endpoint, x20 context, x21 event, x22 socket, x23 error.
 * Locals: sp + 64 the sockaddr, sp + 192 its length, sp + 196 an int.
 */
FUNCTION discv5_shell_open
    SENTER  144
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x9, #DISCV5_EV_OPENED_SIZE
    str     x9, [x21, #DISCV5_EV_SIZE]
    mov     x9, #DISCV5_EVENT_OPENED
    str     x9, [x21, #DISCV5_EV_KIND]
    str     xzr, [x21, #DISCV5_EV_ERROR]
    add     x9, x21, #DISCV5_EV_OPENED_ENDPOINT
    stp     xzr, xzr, [x9]
    stp     xzr, xzr, [x9, #16]
    mov     x22, #-1
    str     x22, [x20, #DISCV5_SHELL_SOCKET]
    ldr     x9, [x19, #DISCV5_EP_FAMILY]
    str     x9, [x20, #DISCV5_SHELL_FAMILY]
    mov     x23, #OS_EAFNOSUPPORT
    mov     w0, #OS_AF_INET
    cmp     x9, #4
    b.eq    1f
    mov     w0, #OS_AF_INET6
    cmp     x9, #6
    b.ne    8f
1:  mov     w1, #OS_SOCK_DGRAM
    mov     w2, #0
    CALL_GLOBAL socket
    tbnz    w0, #31, 7f
    sxtw    x22, w0
    ldr     x9, [x20, #DISCV5_SHELL_FAMILY]
    cmp     x9, #6
    b.ne    2f
    str     wzr, [sp, #196]
    mov     w0, w22
    mov     w1, #OS_IPPROTO_IPV6
    mov     w2, #OS_IPV6_V6ONLY
    add     x3, sp, #196
    mov     w4, #4
    CALL_GLOBAL setsockopt
    tbnz    w0, #31, 6f
2:  mov     x0, x19
    ldr     x1, [x20, #DISCV5_SHELL_FAMILY]
    add     x2, sp, #64
    bl      discv5_shell_sockaddr
    mov     x2, x0
    mov     w0, w22
    add     x1, sp, #64
    CALL_GLOBAL bind
    tbnz    w0, #31, 6f
    mov     w9, #OS_SOCKADDR_SIZE
    str     w9, [sp, #192]
    mov     w0, w22
    add     x1, sp, #64
    add     x2, sp, #192
    CALL_GLOBAL getsockname
    tbnz    w0, #31, 6f
    add     x0, sp, #64
    add     x1, x21, #DISCV5_EV_OPENED_ENDPOINT
    bl      discv5_shell_endpoint
    str     x22, [x20, #DISCV5_SHELL_SOCKET]
    b       9f
6:  ERRNO                                   /* close the socket, keep the error */
    mov     w23, w0
    mov     w0, w22
    CALL_GLOBAL close
    b       8f
7:  ERRNO
    mov     w23, w0
8:  str     x23, [x21, #DISCV5_EV_ERROR]
9:  mov     x0, #DISCV5_OK
    SLEAVE  144
END_FUNCTION discv5_shell_open

/*
 * discv5_shell_send(context, action, event) -> status 0: sends a SEND action's
 * datagram. The SENT event holds 0, or the OS error.
 * x19 context, x20 action, x21 event. Locals: sp + 64 the sockaddr.
 */
FUNCTION discv5_shell_send
    SENTER  128
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x9, #DISCV5_EV_ERROR_SIZE
    str     x9, [x21, #DISCV5_EV_SIZE]
    mov     x9, #DISCV5_EVENT_SENT
    str     x9, [x21, #DISCV5_EV_KIND]
    str     xzr, [x21, #DISCV5_EV_ERROR]
    mov     x9, #OS_EINVAL
    ldr     x10, [x20, #DISCV5_ACT_KIND]
    cmp     x10, #DISCV5_ACTION_SEND
    b.ne    8f
    add     x0, x20, #DISCV5_ACT_SEND_TO
    ldr     x1, [x19, #DISCV5_SHELL_FAMILY]
    add     x2, sp, #64
    bl      discv5_shell_sockaddr
    mov     x9, #OS_EAFNOSUPPORT
    cbz     x0, 8f
    mov     x5, x0
    ldr     x0, [x19, #DISCV5_SHELL_SOCKET]
    add     x1, x20, #DISCV5_ACT_SEND_DATA
    ldr     x2, [x20, #DISCV5_ACT_SEND_LEN]
    mov     w3, #0
    add     x4, sp, #64
    CALL_GLOBAL sendto
    tbz     x0, #63, 9f
    ERRNO
    mov     w9, w0
8:  str     x9, [x21, #DISCV5_EV_ERROR]
9:  mov     x0, #DISCV5_OK
    SLEAVE  128
END_FUNCTION discv5_shell_send

/*
 * discv5_shell_receive(context, until, event) -> status 0: waits until a
 * datagram arrives or the time until (milliseconds, the clock of
 * discv5_shell_clock) passes. The event is a DATAGRAM, or IDLE holding 0
 * when the time passed, else the OS error. Bytes past 1280 are cut off.
 * x19 context, x20 until, x21 event, x22 count.
 * Locals: sp + 64 the sockaddr, sp + 192 its length, sp + 200 the pollfd.
 */
FUNCTION discv5_shell_receive
    SENTER  144
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    bl      discv5_shell_now
    ldr     x9, [x20]
    subs    x2, x9, x0
    csel    x2, x2, xzr, hi
    mov     x9, #0x7FFFFFFF
    cmp     x2, x9
    csel    x2, x2, x9, lo
    ldr     x9, [x19, #DISCV5_SHELL_SOCKET]
    str     w9, [sp, #200]
    mov     w9, #OS_POLLIN
    str     w9, [sp, #204]                  /* events, then revents 0 */
    add     x0, sp, #200
    mov     w1, #1
    CALL_GLOBAL poll
    tbnz    w0, #31, 7f
    mov     x9, #0
    cbz     w0, 8f
    mov     w9, #OS_SOCKADDR_SIZE
    str     w9, [sp, #192]
    ldr     x0, [x19, #DISCV5_SHELL_SOCKET]
    add     x1, x21, #DISCV5_EV_DG_DATA
    mov     x2, #DISCV5_MAX_PACKET
    mov     w3, #OS_MSG_DONTWAIT
    add     x4, sp, #64
    add     x5, sp, #192
    CALL_GLOBAL recvfrom
    tbnz    x0, #63, 7f
    mov     x22, x0
    add     x0, sp, #64
    add     x1, x21, #DISCV5_EV_DG_FROM
    bl      discv5_shell_endpoint
    mov     x9, #OS_EAFNOSUPPORT
    cbz     x0, 8f
    str     x22, [x21, #DISCV5_EV_DG_LEN]
    add     x9, x22, #(DISCV5_EV_DG_DATA + 7)
    and     x9, x9, #~7
    str     x9, [x21, #DISCV5_EV_SIZE]
    mov     x10, #DISCV5_EVENT_DATAGRAM
    str     x10, [x21, #DISCV5_EV_KIND]
    add     x10, x21, #DISCV5_EV_DG_DATA    /* zero the bytes after the datagram */
    add     x10, x10, x22
    add     x11, x21, x9
1:  cmp     x10, x11
    b.hs    9f
    strb    wzr, [x10], #1
    b       1b
7:  ERRNO
    mov     w9, w0
8:  mov     x10, #DISCV5_EV_ERROR_SIZE
    str     x10, [x21, #DISCV5_EV_SIZE]
    mov     x10, #DISCV5_EVENT_IDLE
    str     x10, [x21, #DISCV5_EV_KIND]
    str     x9, [x21, #DISCV5_EV_ERROR]
9:  mov     x0, #DISCV5_OK
    SLEAVE  144
END_FUNCTION discv5_shell_receive

/* discv5_shell_close(context) -> status 0: closes the socket. */
FUNCTION discv5_shell_close
    SENTER  0
    mov     x19, x0
    ldr     x0, [x19, #DISCV5_SHELL_SOCKET]
    cmn     x0, #1
    b.eq    9f
    CALL_GLOBAL close
    mov     x9, #-1
    str     x9, [x19, #DISCV5_SHELL_SOCKET]
9:  mov     x0, #DISCV5_OK
    SLEAVE  0
END_FUNCTION discv5_shell_close
