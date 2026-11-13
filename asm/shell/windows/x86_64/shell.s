/*
 * asm-discv5 shell for Windows on x86-64: one UDP socket, the clock and
 * random bytes, through Winsock 2, kernel32 and bcrypt. AT&T syntax.
 * Requirements: docs/reference/shell.md. Layouts: include/discv5.inc.
 *
 * The functions use the System V AMD64 psABI like the core, and call the
 * Windows APIs with the Windows x64 convention: arguments in rcx, rdx, r8,
 * r9, then on the stack after 32 bytes of shadow space. Those APIs keep
 * rbx, rbp, rdi, rsi and r12-r15, so they keep what System V callers need.
 *
 * Every macro has a named parameter. In a macro without one, the Mach-O
 * assembler reads $0 to $9 as positional arguments.
 */
.set ISA_X86_64, 1
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

/* Locals start after the shadow space and two stack arguments. */
.set ARG5, 32
.set ARG6, 40
.set LOC, 48

/* Frame: rbx, rbp, r12-r15, then bytes of locals at rsp. bytes is 8 more than a multiple of 16. */
.macro SENTER bytes
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

.macro SLEAVE bytes
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

/*
 * discv5_shell_sockaddr(endpoint, family, sockaddr) -> the sockaddr length,
 * or 0 when the endpoint does not fit a socket of the family (4 or 6). On a
 * family 6 socket an IPv4 endpoint becomes an IPv4-mapped IPv6 address.
 */
LOCAL_FUNCTION discv5_shell_sockaddr
    UNWIND_END_PROLOGUE
    mov     DISCV5_EP_FAMILY(%rdi), %r8
    movzwl  DISCV5_EP_PORT(%rdi), %r9d
    rol     $8, %r9w
    xor     %eax, %eax
    mov     %rax, (%rdx)
    mov     %rax, 8(%rdx)
    mov     %rax, 16(%rdx)
    mov     %rax, 24(%rdx)
    cmp     $4, %rsi
    jne     1f
    cmp     $4, %r8
    jne     8f
    movw    $OS_AF_INET, (%rdx)
    mov     %r9w, 2(%rdx)
    mov     DISCV5_EP_ADDRESS(%rdi), %ecx
    mov     %ecx, 4(%rdx)
    mov     $16, %eax
    ret
1:  cmp     $6, %rsi
    jne     8f
    movw    $OS_AF_INET6, (%rdx)
    mov     %r9w, 2(%rdx)
    cmp     $6, %r8
    jne     2f
    mov     DISCV5_EP_ADDRESS(%rdi), %rcx
    mov     %rcx, 8(%rdx)
    mov     DISCV5_EP_ADDRESS+8(%rdi), %rcx
    mov     %rcx, 16(%rdx)
    mov     $28, %eax
    ret
2:  cmp     $4, %r8
    jne     8f
    movw    $0xFFFF, 18(%rdx)
    mov     DISCV5_EP_ADDRESS(%rdi), %ecx
    mov     %ecx, 20(%rdx)
    mov     $28, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION discv5_shell_sockaddr

/*
 * discv5_shell_endpoint(sockaddr, endpoint) -> 1 when the address is IPv4 or
 * IPv6, written as an endpoint; an IPv4-mapped IPv6 address becomes IPv4.
 */
LOCAL_FUNCTION discv5_shell_endpoint
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
    mov     %rax, (%rsi)
    mov     %rax, 8(%rsi)
    mov     %rax, 16(%rsi)
    mov     %rax, 24(%rsi)
    movzwl  2(%rdi), %ecx
    rol     $8, %cx
    mov     %rcx, DISCV5_EP_PORT(%rsi)
    movzwl  (%rdi), %ecx
    cmp     $OS_AF_INET, %ecx
    jne     1f
    mov     4(%rdi), %edx
    jmp     3f
1:  cmp     $OS_AF_INET6, %ecx
    jne     8f
    mov     8(%rdi), %rdx                   /* address bytes 0 to 9 zero, 10 and 11 all ones */
    movzwl  16(%rdi), %ecx
    or      %rcx, %rdx
    jnz     2f
    cmpw    $-1, 18(%rdi)
    jne     2f
    mov     20(%rdi), %edx                  /* IPv4-mapped */
3:  mov     %edx, DISCV5_EP_ADDRESS(%rsi)
    movq    $4, DISCV5_EP_FAMILY(%rsi)
    mov     $1, %eax
    ret
2:  mov     8(%rdi), %rdx
    mov     %rdx, DISCV5_EP_ADDRESS(%rsi)
    mov     16(%rdi), %rdx
    mov     %rdx, DISCV5_EP_ADDRESS+8(%rsi)
    movq    $6, DISCV5_EP_FAMILY(%rsi)
    mov     $1, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION discv5_shell_endpoint

/* discv5_shell_now() -> milliseconds since boot, from GetTickCount64. */
LOCAL_FUNCTION discv5_shell_now
    sub     $40, %rsp
    UNWIND_ALLOC 40
    UNWIND_END_PROLOGUE
    CALL_GLOBAL GetTickCount64
    UNWIND_BEGIN_EPILOGUE
    add     $40, %rsp
    UNWIND_FREE 40
    UNWIND_END_EPILOGUE
    ret
END_FUNCTION discv5_shell_now

/*
 * discv5_shell_clock(tick) -> status: the time in milliseconds and 32 random
 * bytes from BCryptGenRandom. OS_ERROR when either fails. rbx tick, rbp status.
 */
FUNCTION discv5_shell_clock
    SENTER  40
    mov     %rdi, %rbx
    mov     $DISCV5_OS_ERROR, %ebp
    call    discv5_shell_now
    test    %rax, %rax
    jz      9f
    mov     %rax, DISCV5_TICK_NOW(%rbx)
    xor     %ecx, %ecx
    lea     DISCV5_TICK_ENTROPY(%rbx), %rdx
    mov     $32, %r8d
    mov     $OS_RNG_FLAGS, %r9d
    CALL_GLOBAL BCryptGenRandom
    test    %eax, %eax
    jnz     9f
    xor     %ebp, %ebp
9:  mov     %rbp, %rax
    SLEAVE  40
END_FUNCTION discv5_shell_clock

/* discv5_shell_open locals. */
.set OP_ADDR, LOC                   /* the sockaddr */
.set OP_LEN, LOC + 128              /* its length */
.set OP_INT, LOC + 132              /* an int */
.set OP_WSA, LOC + 136              /* WSADATA */
.set OP_FRAME, LOC + 136 + OS_WSADATA_SIZE

/*
 * discv5_shell_open(endpoint, context, event) -> status 0: starts Winsock,
 * then a UDP socket bound to the endpoint. An IPv6 socket also takes IPv4.
 * The OPENED event holds 0 and the bound endpoint, or the Winsock error.
 * rbx endpoint, rbp context, r12 event, r13 socket, r14 error.
 */
FUNCTION discv5_shell_open
    SENTER  OP_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    movq    $DISCV5_EV_OPENED_SIZE, DISCV5_EV_SIZE(%r12)
    movq    $DISCV5_EVENT_OPENED, DISCV5_EV_KIND(%r12)
    xor     %eax, %eax
    mov     %rax, DISCV5_EV_ERROR(%r12)
    mov     %rax, DISCV5_EV_OPENED_ENDPOINT(%r12)
    mov     %rax, DISCV5_EV_OPENED_ENDPOINT+8(%r12)
    mov     %rax, DISCV5_EV_OPENED_ENDPOINT+16(%r12)
    mov     %rax, DISCV5_EV_OPENED_ENDPOINT+24(%r12)
    movq    $-1, DISCV5_SHELL_SOCKET(%rbp)
    movq    $0, DISCV5_SHELL_STARTED(%rbp)
    mov     $-1, %r13
    mov     DISCV5_EP_FAMILY(%rbx), %rax
    mov     %rax, DISCV5_SHELL_FAMILY(%rbp)
    mov     $OS_WSAEAFNOSUPPORT, %r14d
    cmp     $4, %rax
    je      1f
    cmp     $6, %rax
    jne     8f
1:  mov     $OS_WINSOCK_VERSION, %ecx
    lea     OP_WSA(%rsp), %rdx
    CALL_GLOBAL WSAStartup
    test    %eax, %eax
    jz      11f
    mov     %eax, %r14d                     /* WSAStartup returns its error */
    jmp     8f
11: movq    $1, DISCV5_SHELL_STARTED(%rbp)
    mov     $OS_AF_INET, %ecx
    cmpq    $4, DISCV5_SHELL_FAMILY(%rbp)
    je      12f
    mov     $OS_AF_INET6, %ecx
12: mov     $OS_SOCK_DGRAM, %edx
    xor     %r8d, %r8d
    CALL_GLOBAL socket
    cmp     $-1, %rax
    je      7f
    mov     %rax, %r13
    cmpq    $6, DISCV5_SHELL_FAMILY(%rbp)
    jne     2f
    movl    $0, OP_INT(%rsp)
    mov     %r13, %rcx
    mov     $OS_IPPROTO_IPV6, %edx
    mov     $OS_IPV6_V6ONLY, %r8d
    lea     OP_INT(%rsp), %r9
    movq    $4, ARG5(%rsp)
    CALL_GLOBAL setsockopt
    test    %eax, %eax
    jnz     6f
2:  mov     %rbx, %rdi
    mov     DISCV5_SHELL_FAMILY(%rbp), %rsi
    lea     OP_ADDR(%rsp), %rdx
    call    discv5_shell_sockaddr
    mov     %eax, %r8d
    mov     %r13, %rcx
    lea     OP_ADDR(%rsp), %rdx
    CALL_GLOBAL bind
    test    %eax, %eax
    jnz     6f
    movl    $OS_SOCKADDR_SIZE, OP_LEN(%rsp)
    mov     %r13, %rcx
    lea     OP_ADDR(%rsp), %rdx
    lea     OP_LEN(%rsp), %r8
    CALL_GLOBAL getsockname
    test    %eax, %eax
    jnz     6f
    lea     OP_ADDR(%rsp), %rdi
    lea     DISCV5_EV_OPENED_ENDPOINT(%r12), %rsi
    call    discv5_shell_endpoint
    mov     %r13, DISCV5_SHELL_SOCKET(%rbp)
    jmp     9f
6:  CALL_GLOBAL WSAGetLastError             /* close the socket, keep the error */
    mov     %eax, %r14d
    mov     %r13, %rcx
    CALL_GLOBAL closesocket
    jmp     8f
7:  CALL_GLOBAL WSAGetLastError
    mov     %eax, %r14d
8:  mov     %r14, DISCV5_EV_ERROR(%r12)
9:  xor     %eax, %eax
    SLEAVE  OP_FRAME
END_FUNCTION discv5_shell_open

/*
 * discv5_shell_send(context, action, event) -> status 0: sends a SEND action's
 * datagram. The SENT event holds 0, or the Winsock error.
 * rbx context, rbp action, r12 event, r13 error. The sockaddr at rsp + LOC.
 */
FUNCTION discv5_shell_send
    SENTER  LOC+136
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    movq    $DISCV5_EV_ERROR_SIZE, DISCV5_EV_SIZE(%r12)
    movq    $DISCV5_EVENT_SENT, DISCV5_EV_KIND(%r12)
    movq    $0, DISCV5_EV_ERROR(%r12)
    mov     $OS_WSAEINVAL, %r13d
    cmpq    $DISCV5_ACTION_SEND, DISCV5_ACT_KIND(%rbp)
    jne     8f
    lea     DISCV5_ACT_SEND_TO(%rbp), %rdi
    mov     DISCV5_SHELL_FAMILY(%rbx), %rsi
    lea     LOC(%rsp), %rdx
    call    discv5_shell_sockaddr
    mov     $OS_WSAEAFNOSUPPORT, %r13d
    test    %rax, %rax
    jz      8f
    mov     %rax, ARG6(%rsp)
    lea     LOC(%rsp), %rcx
    mov     %rcx, ARG5(%rsp)
    mov     DISCV5_SHELL_SOCKET(%rbx), %rcx
    lea     DISCV5_ACT_SEND_DATA(%rbp), %rdx
    mov     DISCV5_ACT_SEND_LEN(%rbp), %r8d
    xor     %r9d, %r9d
    CALL_GLOBAL sendto
    cmp     $-1, %eax
    jne     9f
    CALL_GLOBAL WSAGetLastError
    mov     %eax, %r13d
8:  mov     %r13, DISCV5_EV_ERROR(%r12)
9:  xor     %eax, %eax
    SLEAVE  LOC+136
END_FUNCTION discv5_shell_send

/* discv5_shell_receive locals. */
.set RV_ADDR, LOC                   /* the sockaddr */
.set RV_LEN, LOC + 128              /* its length */
.set RV_POLL, LOC + 136             /* WSAPOLLFD: socket, events, revents */
.set RV_FRAME, LOC + 152

/*
 * discv5_shell_receive(context, until, event) -> status 0: waits until a
 * datagram arrives or the time until (milliseconds, the clock of
 * discv5_shell_clock) passes. The event is a DATAGRAM, or IDLE holding 0
 * when the time passed, else the Winsock error. A datagram over 1280 bytes
 * gives IDLE with the error. rbx context, rbp until, r12 event, r13 error,
 * r14 count.
 */
FUNCTION discv5_shell_receive
    SENTER  RV_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    call    discv5_shell_now
    mov     %rax, %rcx
    mov     (%rbp), %r8
    sub     %rcx, %r8
    jae     1f
    xor     %r8d, %r8d
1:  mov     $0x7FFFFFFF, %eax
    cmp     %rax, %r8
    cmova   %rax, %r8
    mov     DISCV5_SHELL_SOCKET(%rbx), %rax
    mov     %rax, RV_POLL(%rsp)
    movl    $OS_POLLRDNORM, RV_POLL+8(%rsp)    /* events, then revents 0 */
    lea     RV_POLL(%rsp), %rcx
    mov     $1, %edx
    CALL_GLOBAL WSAPoll
    xor     %r13d, %r13d
    cmp     $-1, %eax
    je      7f
    test    %eax, %eax
    jz      8f
    movl    $OS_SOCKADDR_SIZE, RV_LEN(%rsp)
    lea     RV_ADDR(%rsp), %rax
    mov     %rax, ARG5(%rsp)
    lea     RV_LEN(%rsp), %rax
    mov     %rax, ARG6(%rsp)
    mov     DISCV5_SHELL_SOCKET(%rbx), %rcx
    lea     DISCV5_EV_DG_DATA(%r12), %rdx
    mov     $DISCV5_MAX_PACKET, %r8d
    xor     %r9d, %r9d
    CALL_GLOBAL recvfrom
    cmp     $-1, %eax
    je      7f
    mov     %eax, %r14d
    lea     RV_ADDR(%rsp), %rdi
    lea     DISCV5_EV_DG_FROM(%r12), %rsi
    call    discv5_shell_endpoint
    mov     $OS_WSAEAFNOSUPPORT, %r13d
    test    %rax, %rax
    jz      8f
    mov     %r14, DISCV5_EV_DG_LEN(%r12)
    lea     DISCV5_EV_DG_DATA+7(%r14), %rax
    and     $~7, %rax
    mov     %rax, DISCV5_EV_SIZE(%r12)
    movq    $DISCV5_EVENT_DATAGRAM, DISCV5_EV_KIND(%r12)
    lea     DISCV5_EV_DG_DATA(%r12,%r14), %rdi  /* zero the bytes after the datagram */
    lea     (%r12,%rax), %rcx
    sub     %rdi, %rcx
    xor     %eax, %eax
    rep stosb
    jmp     9f
7:  CALL_GLOBAL WSAGetLastError
    mov     %eax, %r13d
8:  movq    $DISCV5_EV_ERROR_SIZE, DISCV5_EV_SIZE(%r12)
    movq    $DISCV5_EVENT_IDLE, DISCV5_EV_KIND(%r12)
    mov     %r13, DISCV5_EV_ERROR(%r12)
9:  xor     %eax, %eax
    SLEAVE  RV_FRAME
END_FUNCTION discv5_shell_receive

/* discv5_shell_close(context) -> status 0: closes the socket, then stops Winsock when open started it. rbx context. */
FUNCTION discv5_shell_close
    SENTER  40
    mov     %rdi, %rbx
    mov     DISCV5_SHELL_SOCKET(%rbx), %rcx
    cmp     $-1, %rcx
    je      1f
    movq    $-1, DISCV5_SHELL_SOCKET(%rbx)
    CALL_GLOBAL closesocket
1:  cmpq    $0, DISCV5_SHELL_STARTED(%rbx)
    je      9f
    movq    $0, DISCV5_SHELL_STARTED(%rbx)
    CALL_GLOBAL WSACleanup
9:  xor     %eax, %eax
    SLEAVE  40
END_FUNCTION discv5_shell_close
