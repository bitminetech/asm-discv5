/*
 * asm-discv5 shell for Linux on x86-64: one UDP socket, the clock and random
 * bytes, through direct system calls. AT&T syntax.
 * Requirements: docs/reference/shell.md. Layouts: include/discv5.inc.
 *
 * System calls: the number in rax, arguments in rdi, rsi, rdx, r10, r8, r9,
 * "syscall"; rax holds the result, or minus the error number (-4095 to -1).
 * The call changes rcx and r11.
 *
 * Every macro has a named parameter. In a macro without one, the Mach-O
 * assembler reads $0 to $9 as positional arguments.
 */
.set ISA_X86_64, 1
.include "discv5.inc"
.include "platform.inc"

/* Linux numbers: asm/unistd_64.h and the uapi headers. */
.set SYS_CLOSE, 3
.set SYS_SOCKET, 41
.set SYS_SENDTO, 44
.set SYS_RECVFROM, 45
.set SYS_BIND, 49
.set SYS_GETSOCKNAME, 51
.set SYS_SETSOCKOPT, 54
.set SYS_CLOCK_GETTIME, 228
.set SYS_PPOLL, 271
.set SYS_GETRANDOM, 318
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

/* rax = the system call's result. */
.macro SYSCALL number
    mov     $\number, %eax
    syscall
.endm

/* Branch to label when rax holds an error (-4095 to -1). */
.macro IF_ERROR label
    cmp     $-4095, %rax
    jae     \label
.endm

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

/* discv5_shell_now() -> milliseconds of CLOCK_MONOTONIC, or 0 when the clock fails. The timespec at rsp. */
LOCAL_FUNCTION discv5_shell_now
    sub     $24, %rsp
    UNWIND_ALLOC 24
    UNWIND_END_PROLOGUE
    mov     $OS_CLOCK_MONOTONIC, %edi
    mov     %rsp, %rsi
    SYSCALL SYS_CLOCK_GETTIME
    mov     %rax, %rcx
    xor     %eax, %eax
    test    %rcx, %rcx
    jnz     9f
    imul    $1000, (%rsp), %rcx
    mov     8(%rsp), %rax
    xor     %edx, %edx
    mov     $1000000, %r8d
    div     %r8
    add     %rcx, %rax
9:  UNWIND_BEGIN_EPILOGUE
    add     $24, %rsp
    UNWIND_FREE 24
    UNWIND_END_EPILOGUE
    ret
END_FUNCTION discv5_shell_now

/*
 * discv5_shell_clock(tick) -> status: the time in milliseconds and 32 random
 * bytes from getrandom. OS_ERROR when either fails. rbx tick, rbp status.
 */
FUNCTION discv5_shell_clock
    SENTER  8
    mov     %rdi, %rbx
    mov     $DISCV5_OS_ERROR, %ebp
    call    discv5_shell_now
    test    %rax, %rax
    jz      9f
    mov     %rax, DISCV5_TICK_NOW(%rbx)
    lea     DISCV5_TICK_ENTROPY(%rbx), %rdi
    mov     $32, %esi
    xor     %edx, %edx
    SYSCALL SYS_GETRANDOM
    cmp     $32, %rax
    jne     9f
    xor     %ebp, %ebp
9:  mov     %rbp, %rax
    SLEAVE  8
END_FUNCTION discv5_shell_clock

/*
 * discv5_shell_open(endpoint, context, event) -> status 0: a UDP socket bound
 * to the endpoint. An IPv6 socket also takes IPv4. The OPENED event holds 0
 * and the bound endpoint, or the OS error.
 * rbx endpoint, rbp context, r12 event, r13 socket, r14 error.
 * Locals: rsp the sockaddr, rsp + 128 its length, rsp + 132 an int.
 */
FUNCTION discv5_shell_open
    SENTER  152
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
    mov     $-1, %r13
    mov     DISCV5_EP_FAMILY(%rbx), %rax
    mov     %rax, DISCV5_SHELL_FAMILY(%rbp)
    mov     $OS_EAFNOSUPPORT, %r14d
    mov     $OS_AF_INET, %edi
    cmp     $4, %rax
    je      1f
    mov     $OS_AF_INET6, %edi
    cmp     $6, %rax
    jne     8f
1:  mov     $OS_SOCK_DGRAM, %esi
    xor     %edx, %edx
    SYSCALL SYS_SOCKET
    IF_ERROR 7f
    mov     %rax, %r13
    cmpq    $6, DISCV5_SHELL_FAMILY(%rbp)
    jne     2f
    movl    $0, 132(%rsp)
    mov     %r13, %rdi
    mov     $OS_IPPROTO_IPV6, %esi
    mov     $OS_IPV6_V6ONLY, %edx
    lea     132(%rsp), %r10
    mov     $4, %r8d
    SYSCALL SYS_SETSOCKOPT
    IF_ERROR 6f
2:  mov     %rbx, %rdi
    mov     DISCV5_SHELL_FAMILY(%rbp), %rsi
    mov     %rsp, %rdx
    call    discv5_shell_sockaddr
    mov     %rax, %rdx
    mov     %r13, %rdi
    mov     %rsp, %rsi
    SYSCALL SYS_BIND
    IF_ERROR 6f
    movl    $OS_SOCKADDR_SIZE, 128(%rsp)
    mov     %r13, %rdi
    mov     %rsp, %rsi
    lea     128(%rsp), %rdx
    SYSCALL SYS_GETSOCKNAME
    IF_ERROR 6f
    mov     %rsp, %rdi
    lea     DISCV5_EV_OPENED_ENDPOINT(%r12), %rsi
    call    discv5_shell_endpoint
    mov     %r13, DISCV5_SHELL_SOCKET(%rbp)
    jmp     9f
6:  mov     %rax, %r14                      /* close the socket, keep the error */
    neg     %r14
    mov     %r13, %rdi
    SYSCALL SYS_CLOSE
    jmp     8f
7:  mov     %rax, %r14
    neg     %r14
8:  mov     %r14, DISCV5_EV_ERROR(%r12)
9:  xor     %eax, %eax
    SLEAVE  152
END_FUNCTION discv5_shell_open

/*
 * discv5_shell_send(context, action, event) -> status 0: sends a SEND action's
 * datagram. The SENT event holds 0, or the OS error.
 * rbx context, rbp action, r12 event, r13 error. The sockaddr at rsp.
 */
FUNCTION discv5_shell_send
    SENTER  136
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    movq    $DISCV5_EV_ERROR_SIZE, DISCV5_EV_SIZE(%r12)
    movq    $DISCV5_EVENT_SENT, DISCV5_EV_KIND(%r12)
    movq    $0, DISCV5_EV_ERROR(%r12)
    mov     $OS_EINVAL, %r13d
    cmpq    $DISCV5_ACTION_SEND, DISCV5_ACT_KIND(%rbp)
    jne     8f
    lea     DISCV5_ACT_SEND_TO(%rbp), %rdi
    mov     DISCV5_SHELL_FAMILY(%rbx), %rsi
    mov     %rsp, %rdx
    call    discv5_shell_sockaddr
    mov     $OS_EAFNOSUPPORT, %r13d
    test    %rax, %rax
    jz      8f
    mov     %rax, %r9
    mov     DISCV5_SHELL_SOCKET(%rbx), %rdi
    lea     DISCV5_ACT_SEND_DATA(%rbp), %rsi
    mov     DISCV5_ACT_SEND_LEN(%rbp), %rdx
    xor     %r10d, %r10d
    mov     %rsp, %r8
    SYSCALL SYS_SENDTO
    IF_ERROR 7f
    jmp     9f
7:  mov     %rax, %r13
    neg     %r13
8:  mov     %r13, DISCV5_EV_ERROR(%r12)
9:  xor     %eax, %eax
    SLEAVE  136
END_FUNCTION discv5_shell_send

/*
 * discv5_shell_receive(context, until, event) -> status 0: waits until a
 * datagram arrives or the time until (milliseconds, the clock of
 * discv5_shell_clock) passes. The event is a DATAGRAM, or IDLE holding 0
 * when the time passed, else the OS error. Bytes past 1280 are cut off.
 * rbx context, rbp until, r12 event, r13 error, r14 count.
 * Locals: rsp the sockaddr, rsp + 128 its length, rsp + 136 the pollfd,
 * rsp + 144 the timespec.
 */
FUNCTION discv5_shell_receive
    SENTER  168
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    call    discv5_shell_now
    mov     %rax, %rcx
    mov     (%rbp), %rax
    sub     %rcx, %rax
    jae     1f
    xor     %eax, %eax
1:  xor     %edx, %edx
    mov     $1000, %ecx
    div     %rcx
    mov     %rax, 144(%rsp)
    imul    $1000000, %rdx, %rdx
    mov     %rdx, 152(%rsp)
    mov     DISCV5_SHELL_SOCKET(%rbx), %rax
    mov     %eax, 136(%rsp)
    movl    $OS_POLLIN, 140(%rsp)           /* events, then revents 0 */
    lea     136(%rsp), %rdi
    mov     $1, %esi
    lea     144(%rsp), %rdx
    xor     %r10d, %r10d
    mov     $8, %r8d
    SYSCALL SYS_PPOLL
    IF_ERROR 7f
    xor     %r13d, %r13d
    test    %rax, %rax
    jz      8f
    movl    $OS_SOCKADDR_SIZE, 128(%rsp)
    mov     DISCV5_SHELL_SOCKET(%rbx), %rdi
    lea     DISCV5_EV_DG_DATA(%r12), %rsi
    mov     $DISCV5_MAX_PACKET, %edx
    mov     $OS_MSG_DONTWAIT, %r10d
    mov     %rsp, %r8
    lea     128(%rsp), %r9
    SYSCALL SYS_RECVFROM
    IF_ERROR 7f
    mov     %rax, %r14
    mov     %rsp, %rdi
    lea     DISCV5_EV_DG_FROM(%r12), %rsi
    call    discv5_shell_endpoint
    mov     $OS_EAFNOSUPPORT, %r13d
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
7:  mov     %rax, %r13
    neg     %r13
8:  movq    $DISCV5_EV_ERROR_SIZE, DISCV5_EV_SIZE(%r12)
    movq    $DISCV5_EVENT_IDLE, DISCV5_EV_KIND(%r12)
    mov     %r13, DISCV5_EV_ERROR(%r12)
9:  xor     %eax, %eax
    SLEAVE  168
END_FUNCTION discv5_shell_receive

/* discv5_shell_close(context) -> status 0: closes the socket. */
FUNCTION discv5_shell_close
    UNWIND_END_PROLOGUE
    mov     DISCV5_SHELL_SOCKET(%rdi), %rax
    cmp     $-1, %rax
    je      9f
    movq    $-1, DISCV5_SHELL_SOCKET(%rdi)
    mov     %rax, %rdi
    SYSCALL SYS_CLOSE
9:  xor     %eax, %eax
    ret
END_FUNCTION discv5_shell_close
