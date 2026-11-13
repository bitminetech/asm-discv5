/*
 * asm-discv5 shell for Windows on ARM64: one UDP socket, the clock and random
 * bytes, through Winsock 2, kernel32 and bcrypt.
 * Requirements: docs/reference/shell.md. Layouts: include/discv5.inc.
 *
 * The functions use AAPCS64 and call the Windows APIs with the same
 * convention. x18 is never used.
 */
.set ISA_ARM64, 1
.include "discv5.inc"
.include "platform.inc"

/* Windows numbers: the llvm-mingw headers. */
.set OS_AF_INET, 2                  /* winsock2.h */
.set OS_AF_INET6, 23                /* winsock2.h */
.set OS_SOCK_DGRAM, 2               /* winsock2.h */
.set OS_IPPROTO_IPV6, 41            /* winsock2.h */
.set OS_IPV6_V6ONLY, 27             /* ws2ipdef.h */
.set OS_POLLRDNORM, 0x0100          /* winsock2.h */
.set OS_WSAEINVAL, 10022            /* winerror.h */
.set OS_WSAEAFNOSUPPORT, 10047      /* winerror.h */
.set OS_RNG_FLAGS, 2                /* bcrypt.h: BCRYPT_USE_SYSTEM_PREFERRED_RNG */
.set OS_WINSOCK_VERSION, 0x0202
.set OS_SOCKADDR_SIZE, 128          /* sizeof(SOCKADDR_STORAGE) */
.set OS_WSADATA_SIZE, 416           /* sizeof(WSADATA) on 64-bit Windows: 408 */

/* Frame: x29, x30, x19-x24, then extra bytes of locals at sp, below the frame record. */
.macro SENTER extra
    stp     x29, x30, [sp, #-64]!
    UNWIND_SAVE_FPLR_X 64
    mov     x29, sp
    UNWIND_SET_FP
    stp     x19, x20, [sp, #16]
    UNWIND_SAVE_REGP x19, x20, 16, 64
    stp     x21, x22, [sp, #32]
    UNWIND_SAVE_REGP x21, x22, 32, 64
    stp     x23, x24, [sp, #48]
    UNWIND_SAVE_REGP x23, x24, 48, 64
    .if \extra
    sub     sp, sp, #\extra
    UNWIND_ALLOC \extra
    .endif
    UNWIND_END_PROLOGUE
.endm

.macro SLEAVE extra
    UNWIND_BEGIN_EPILOGUE
    .if \extra
    add     sp, sp, #\extra
    UNWIND_FREE \extra
    .endif
    ldp     x23, x24, [sp, #48]
    UNWIND_RESTORE_REGP x23, x24, 48
    ldp     x21, x22, [sp, #32]
    UNWIND_RESTORE_REGP x21, x22, 32
    ldp     x19, x20, [sp, #16]
    UNWIND_RESTORE_REGP x19, x20, 16
    ldp     x29, x30, [sp], #64
    UNWIND_RESTORE_FPLR_X 64
    UNWIND_END_EPILOGUE
    ret
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
    mov     w11, #OS_AF_INET
    strh    w11, [x2]
    strh    w10, [x2, #2]
    ldr     w11, [x0, #DISCV5_EP_ADDRESS]
    str     w11, [x2, #4]
    mov     x0, #16
    ret
1:  cmp     x1, #6
    b.ne    8f
    mov     w11, #OS_AF_INET6
    strh    w11, [x2]
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
    ldrh    w9, [x0]
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

/* discv5_shell_now() -> milliseconds since boot, from GetTickCount64. */
LOCAL_FUNCTION discv5_shell_now
    SENTER  0
    CALL_GLOBAL GetTickCount64
    SLEAVE  0
END_FUNCTION discv5_shell_now

/*
 * discv5_shell_clock(tick) -> status: the time in milliseconds and 32 random
 * bytes from BCryptGenRandom. OS_ERROR when either fails. x19 tick, x20 status.
 */
FUNCTION discv5_shell_clock
    SENTER  0
    mov     x19, x0
    mov     x20, #DISCV5_OS_ERROR
    bl      discv5_shell_now
    cbz     x0, 9f
    str     x0, [x19, #DISCV5_TICK_NOW]
    mov     x0, #0
    add     x1, x19, #DISCV5_TICK_ENTROPY
    mov     w2, #32
    mov     w3, #OS_RNG_FLAGS
    CALL_GLOBAL BCryptGenRandom
    cbnz    w0, 9f
    mov     x20, #DISCV5_OK
9:  mov     x0, x20
    SLEAVE  0
END_FUNCTION discv5_shell_clock

/* discv5_shell_open locals, at sp. */
.set OP_ADDR, 0                     /* the sockaddr */
.set OP_LEN, 128                    /* its length */
.set OP_INT, 132                    /* an int */
.set OP_WSA, 136                    /* WSADATA */
.set OP_FRAME, 560

/*
 * discv5_shell_open(endpoint, context, event) -> status 0: starts Winsock,
 * then a UDP socket bound to the endpoint. An IPv6 socket also takes IPv4.
 * The OPENED event holds 0 and the bound endpoint, or the Winsock error.
 * x19 endpoint, x20 context, x21 event, x22 socket, x23 error.
 */
FUNCTION discv5_shell_open
    SENTER  OP_FRAME
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
    str     xzr, [x20, #DISCV5_SHELL_STARTED]
    ldr     x9, [x19, #DISCV5_EP_FAMILY]
    str     x9, [x20, #DISCV5_SHELL_FAMILY]
    mov     x23, #OS_WSAEAFNOSUPPORT
    cmp     x9, #4
    b.eq    1f
    cmp     x9, #6
    b.ne    8f
1:  mov     w0, #OS_WINSOCK_VERSION
    add     x1, sp, #OP_WSA
    CALL_GLOBAL WSAStartup
    cbz     w0, 11f
    mov     w23, w0                         /* WSAStartup returns its error */
    b       8f
11: mov     x9, #1
    str     x9, [x20, #DISCV5_SHELL_STARTED]
    ldr     x9, [x20, #DISCV5_SHELL_FAMILY]
    mov     w0, #OS_AF_INET
    cmp     x9, #4
    b.eq    12f
    mov     w0, #OS_AF_INET6
12: mov     w1, #OS_SOCK_DGRAM
    mov     w2, #0
    CALL_GLOBAL socket
    cmn     x0, #1
    b.eq    7f
    mov     x22, x0
    ldr     x9, [x20, #DISCV5_SHELL_FAMILY]
    cmp     x9, #6
    b.ne    2f
    str     wzr, [sp, #OP_INT]
    mov     x0, x22
    mov     w1, #OS_IPPROTO_IPV6
    mov     w2, #OS_IPV6_V6ONLY
    add     x3, sp, #OP_INT
    mov     w4, #4
    CALL_GLOBAL setsockopt
    cbnz    w0, 6f
2:  mov     x0, x19
    ldr     x1, [x20, #DISCV5_SHELL_FAMILY]
    add     x2, sp, #OP_ADDR
    bl      discv5_shell_sockaddr
    mov     w2, w0
    mov     x0, x22
    add     x1, sp, #OP_ADDR
    CALL_GLOBAL bind
    cbnz    w0, 6f
    mov     w9, #OS_SOCKADDR_SIZE
    str     w9, [sp, #OP_LEN]
    mov     x0, x22
    add     x1, sp, #OP_ADDR
    add     x2, sp, #OP_LEN
    CALL_GLOBAL getsockname
    cbnz    w0, 6f
    add     x0, sp, #OP_ADDR
    add     x1, x21, #DISCV5_EV_OPENED_ENDPOINT
    bl      discv5_shell_endpoint
    str     x22, [x20, #DISCV5_SHELL_SOCKET]
    b       9f
6:  CALL_GLOBAL WSAGetLastError             /* close the socket, keep the error */
    mov     w23, w0
    mov     x0, x22
    CALL_GLOBAL closesocket
    b       8f
7:  CALL_GLOBAL WSAGetLastError
    mov     w23, w0
8:  str     x23, [x21, #DISCV5_EV_ERROR]
9:  mov     x0, #DISCV5_OK
    SLEAVE  OP_FRAME
END_FUNCTION discv5_shell_open

/*
 * discv5_shell_send(context, action, event) -> status 0: sends a SEND action's
 * datagram. The SENT event holds 0, or the Winsock error.
 * x19 context, x20 action, x21 event, x23 error. The sockaddr at sp.
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
    mov     x23, #OS_WSAEINVAL
    ldr     x10, [x20, #DISCV5_ACT_KIND]
    cmp     x10, #DISCV5_ACTION_SEND
    b.ne    8f
    add     x0, x20, #DISCV5_ACT_SEND_TO
    ldr     x1, [x19, #DISCV5_SHELL_FAMILY]
    mov     x2, sp
    bl      discv5_shell_sockaddr
    mov     x23, #OS_WSAEAFNOSUPPORT
    cbz     x0, 8f
    mov     w5, w0
    ldr     x0, [x19, #DISCV5_SHELL_SOCKET]
    add     x1, x20, #DISCV5_ACT_SEND_DATA
    ldr     x2, [x20, #DISCV5_ACT_SEND_LEN]
    mov     w3, #0
    mov     x4, sp
    CALL_GLOBAL sendto
    cmn     w0, #1
    b.ne    9f
    CALL_GLOBAL WSAGetLastError
    mov     w23, w0
8:  str     x23, [x21, #DISCV5_EV_ERROR]
9:  mov     x0, #DISCV5_OK
    SLEAVE  128
END_FUNCTION discv5_shell_send

/*
 * discv5_shell_receive(context, until, event) -> status 0: waits until a
 * datagram arrives or the time until (milliseconds, the clock of
 * discv5_shell_clock) passes. The event is a DATAGRAM, or IDLE holding 0
 * when the time passed, else the Winsock error. A datagram over 1280 bytes
 * gives IDLE with the error. x19 context, x20 until, x21 event, x22 count,
 * x23 error. Locals at sp: the sockaddr, + 128 its length, + 136 the WSAPOLLFD.
 */
FUNCTION discv5_shell_receive
    SENTER  160
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
    str     x9, [sp, #136]
    mov     w9, #OS_POLLRDNORM
    str     w9, [sp, #144]                  /* events, then revents 0 */
    add     x0, sp, #136
    mov     w1, #1
    CALL_GLOBAL WSAPoll
    mov     x23, #0
    cmn     w0, #1
    b.eq    7f
    cbz     w0, 8f
    mov     w9, #OS_SOCKADDR_SIZE
    str     w9, [sp, #128]
    ldr     x0, [x19, #DISCV5_SHELL_SOCKET]
    add     x1, x21, #DISCV5_EV_DG_DATA
    mov     w2, #DISCV5_MAX_PACKET
    mov     w3, #0
    mov     x4, sp
    add     x5, sp, #128
    CALL_GLOBAL recvfrom
    cmn     w0, #1
    b.eq    7f
    mov     w22, w0
    mov     x0, sp
    add     x1, x21, #DISCV5_EV_DG_FROM
    bl      discv5_shell_endpoint
    mov     x23, #OS_WSAEAFNOSUPPORT
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
7:  CALL_GLOBAL WSAGetLastError
    mov     w23, w0
8:  mov     x10, #DISCV5_EV_ERROR_SIZE
    str     x10, [x21, #DISCV5_EV_SIZE]
    mov     x10, #DISCV5_EVENT_IDLE
    str     x10, [x21, #DISCV5_EV_KIND]
    str     x23, [x21, #DISCV5_EV_ERROR]
9:  mov     x0, #DISCV5_OK
    SLEAVE  160
END_FUNCTION discv5_shell_receive

/* discv5_shell_close(context) -> status 0: closes the socket, then stops Winsock when open started it. x19 context. */
FUNCTION discv5_shell_close
    SENTER  0
    mov     x19, x0
    ldr     x0, [x19, #DISCV5_SHELL_SOCKET]
    cmn     x0, #1
    b.eq    1f
    mov     x9, #-1
    str     x9, [x19, #DISCV5_SHELL_SOCKET]
    CALL_GLOBAL closesocket
1:  ldr     x9, [x19, #DISCV5_SHELL_STARTED]
    cbz     x9, 9f
    str     xzr, [x19, #DISCV5_SHELL_STARTED]
    CALL_GLOBAL WSACleanup
9:  mov     x0, #DISCV5_OK
    SLEAVE  0
END_FUNCTION discv5_shell_close
