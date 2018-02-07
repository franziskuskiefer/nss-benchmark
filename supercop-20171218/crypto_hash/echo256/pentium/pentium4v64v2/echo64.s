#------------------------------------------------------------------------------------ #
# Implementation of the double pipe ECHO hash function in its 256-bit outputs variant.#
# Optimized for Pentium4, 64-bit mode                                                 #
#                                                                                     #
# Date:     2010-07-23                                                                #
#                                                                                     #
# Authors:  Ryad Benadjila  <ryadbenadjila@gmail.com>                                 #
#           Olivier Billet  <billet@eurecom.fr>                                       #
#------------------------------------------------------------------------------------ #
	.file	"echo64.c"
	.text
	.p2align 4,,15
.globl Compress
	.type	Compress, @function
Compress:
.LFB528:
	.cfi_startproc
#APP
# 521 "echo64.c" 1
	.intel_syntax noprefix
# 0 "" 2
# 522 "echo64.c" 1
	push r8
# 0 "" 2
# 522 "echo64.c" 1
	push r9
# 0 "" 2
# 522 "echo64.c" 1
	push r10
# 0 "" 2
# 522 "echo64.c" 1
	push r11
# 0 "" 2
# 522 "echo64.c" 1
	push r12
# 0 "" 2
# 522 "echo64.c" 1
	push r13
# 0 "" 2
# 522 "echo64.c" 1
	push r14
# 0 "" 2
# 522 "echo64.c" 1
	push r15
# 0 "" 2
# 522 "echo64.c" 1
	push rbp
# 0 "" 2
# 522 "echo64.c" 1
	push rdi
# 0 "" 2
# 522 "echo64.c" 1
	push rsi
# 0 "" 2
# 522 "echo64.c" 1
	push rdx
# 0 "" 2
# 522 "echo64.c" 1
	push rcx
# 0 "" 2
# 522 "echo64.c" 1
	push rbx
# 0 "" 2
# 522 "echo64.c" 1
	push rax
# 0 "" 2
# 524 "echo64.c" 1
	mov    dword ptr [SHA3_R], 8
# 0 "" 2
# 529 "echo64.c" 1
	mov    eax, dword ptr [SHA3_S+264]
# 0 "" 2
# 530 "echo64.c" 1
	mov    ecx, dword ptr [SHA3_S+264]
# 0 "" 2
# 531 "echo64.c" 1
	mov    edx, eax
# 0 "" 2
# 532 "echo64.c" 1
	sar    edx, 31
# 0 "" 2
# 533 "echo64.c" 1
	add    eax, dword ptr [SHA3_S+256]
# 0 "" 2
# 534 "echo64.c" 1
	adc    edx, dword ptr [SHA3_S+260]
# 0 "" 2
# 535 "echo64.c" 1
	mov    dword ptr [SHA3_CNT],   0
# 0 "" 2
# 536 "echo64.c" 1
	mov    dword ptr [SHA3_CNT+4], 0
# 0 "" 2
# 537 "echo64.c" 1
	test   ecx, ecx
# 0 "" 2
# 538 "echo64.c" 1
	mov    dword ptr [SHA3_S+256], eax
# 0 "" 2
# 539 "echo64.c" 1
	mov    dword ptr [SHA3_S+260], edx
# 0 "" 2
# 540 "echo64.c" 1
	je     L2
# 0 "" 2
# 541 "echo64.c" 1
	mov    dword ptr [SHA3_CNT],   eax
# 0 "" 2
# 542 "echo64.c" 1
	mov    dword ptr [SHA3_CNT+4], edx
# 0 "" 2
# 543 "echo64.c" 1
	L2:
# 0 "" 2
# 544 "echo64.c" 1
	mov    edx, dword ptr [SHA3_CNT+4]
# 0 "" 2
# 545 "echo64.c" 1
	mov    dword ptr [SHA3_S+264], 0
# 0 "" 2
# 546 "echo64.c" 1
	mov    eax, dword ptr [SHA3_CNT]
# 0 "" 2
# 547 "echo64.c" 1
	cmp    edx, 0
# 0 "" 2
# 548 "echo64.c" 1
	ja     OVERFLOW
# 0 "" 2
# 550 "echo64.c" 1
	cmp    eax, -130
# 0 "" 2
# 555 "echo64.c" 1
	ja     OVERFLOW
# 0 "" 2
# 558 "echo64.c" 1
	NO_OVERFLOW1:
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm0,  [SHA3_S]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm1,  [SHA3_S+16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm2,  [SHA3_S+2*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm3,  [SHA3_S+3*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm4,  [SHA3_S+4*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm5,  [SHA3_S+5*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm6,  [SHA3_S+6*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm7,  [SHA3_S+7*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm8,  [SHA3_S+8*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm9,  [SHA3_S+9*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm10, [SHA3_S+10*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm11, [SHA3_S+11*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm12, [SHA3_S+12*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm13, [SHA3_S+13*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm14, [SHA3_S+14*16]
# 0 "" 2
# 560 "echo64.c" 1
	movaps  xmm15, [SHA3_S+15*16]
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm0,      xmm4
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm1,      xmm5
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm2,      xmm6
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm3,      xmm7
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm0,      xmm8
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm1,      xmm9
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm2,      xmm10
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm3,      xmm11
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm0,      xmm12
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm1,      xmm13
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm2,      xmm14
# 0 "" 2
# 560 "echo64.c" 1
	pxor  xmm3,      xmm15
# 0 "" 2
# 560 "echo64.c" 1
	movaps  [OLDCV],      xmm0
# 0 "" 2
# 560 "echo64.c" 1
	movaps  [OLDCV+16],   xmm1
# 0 "" 2
# 560 "echo64.c" 1
	movaps  [OLDCV+2*16], xmm2
# 0 "" 2
# 560 "echo64.c" 1
	movaps  [OLDCV+3*16], xmm3
# 0 "" 2
# 565 "echo64.c" 1
	xor    ebx,ebx
# 0 "" 2
# 566 "echo64.c" 1
	xor    edx,edx
# 0 "" 2
# 568 "echo64.c" 1
	mov    [SHA3_RSP], rsp
# 0 "" 2
# 570 "echo64.c" 1
	LABEL_BIG_ROUND_NO1:
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+0]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+0+4]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+0+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+0+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+0+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+0+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+0+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+0+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+0],    edi
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+0+4],  esp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+0+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+0+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+16]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+16+4]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+16+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+16+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+16+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+16+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+16+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+16+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+16],    edi
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+16+4],  esp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+16+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+16+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+32]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+32+4]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+32+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+32+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+32+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+32+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+32+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+32+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+32],    edi
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+32+4],  esp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+32+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+32+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+48]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+48+4]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+48+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+48+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+48+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+48+12], esi
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    ecx, [SHA3_S+48+8]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	mov    eax, [SHA3_S+48+12]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 571 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 571 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 571 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 571 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 571 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 571 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+48],    edi
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+48+4],  esp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+48+8],  ebp
# 0 "" 2
# 571 "echo64.c" 1
	mov    [SHA3_S+48+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+64]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+64+4]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+64+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+64+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+64+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+64+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+64+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+64+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+64],    edi
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+64+4],  esp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+64+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+64+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+80]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+80+4]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+80+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+80+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+80+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+80+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+80+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+80+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+80],    edi
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+80+4],  esp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+80+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+80+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+96]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+96+4]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+96+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+96+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+96+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+96+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+96+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+96+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+96],    edi
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+96+4],  esp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+96+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+96+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+112]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+112+4]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+112+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+112+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+112+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+112+12], esi
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    ecx, [SHA3_S+112+8]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	mov    eax, [SHA3_S+112+12]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 572 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 572 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 572 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 572 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 572 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 572 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+112],    edi
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+112+4],  esp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+112+8],  ebp
# 0 "" 2
# 572 "echo64.c" 1
	mov    [SHA3_S+112+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+128]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+128+4]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+128+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+128+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+128+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+128+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+128+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+128+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+128],    edi
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+128+4],  esp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+128+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+128+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+144]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+144+4]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+144+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+144+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+144+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+144+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+144+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+144+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+144],    edi
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+144+4],  esp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+144+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+144+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+160]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+160+4]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+160+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+160+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+160+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+160+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+160+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+160+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+160],    edi
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+160+4],  esp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+160+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+160+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+176]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+176+4]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+176+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+176+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+176+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+176+12], esi
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    ecx, [SHA3_S+176+8]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	mov    eax, [SHA3_S+176+12]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 573 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 573 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 573 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 573 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 573 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 573 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+176],    edi
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+176+4],  esp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+176+8],  ebp
# 0 "" 2
# 573 "echo64.c" 1
	mov    [SHA3_S+176+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+192]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+192+4]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+192+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+192+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+192+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+192+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+192+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+192+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+192],    edi
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+192+4],  esp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+192+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+192+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+208]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+208+4]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+208+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+208+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+208+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+208+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+208+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+208+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+208],    edi
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+208+4],  esp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+208+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+208+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+224]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+224+4]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+224+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+224+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+224+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+224+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+224+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+224+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+224],    edi
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+224+4],  esp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+224+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+224+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+240]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+240+4]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+240+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+240+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+240+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+240+12], esi
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    ecx, [SHA3_S+240+8]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	mov    eax, [SHA3_S+240+12]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 574 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 574 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 574 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 574 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 574 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 574 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+240],    edi
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+240+4],  esp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+240+8],  ebp
# 0 "" 2
# 574 "echo64.c" 1
	mov    [SHA3_S+240+12], esi
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm0, [SHA3_S]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm1, [SHA3_S+ 5*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm2, [SHA3_S+10*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm3, [SHA3_S+15*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm0, xmm1
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm2, xmm3
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm3, [SHA3_S+16*0]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm1, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm1, xmm2
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm4, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm0, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm0, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm0, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm0, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm4, xmm2
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm2, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm2, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm2, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm2, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm4, xmm3
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm3, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm3, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm3, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm3, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm4, xmm2
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm0, xmm1
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm4, xmm3
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm2, xmm1
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm4, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm3, xmm1
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm1, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm0, [SHA3_S]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm2, [SHA3_S+10*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm1, [SHA3_S+5*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm3, [SHA3_S+15*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm4, [SHA3_S+4*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm5, [SHA3_S+9*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm6, [SHA3_S+14*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm7, [SHA3_S+3*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm4, xmm5
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm6, xmm7
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm7, [SHA3_S+16*4]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm5, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm5, xmm6
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm8, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm4, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm4, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm4, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm4, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm8, xmm6
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm6, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm6, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm6, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm6, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm8, xmm7
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm7, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm7, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm7, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm7, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm8, xmm6
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm4, xmm5
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm8, xmm7
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm6, xmm5
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm8, xmm4
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm7, xmm5
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm5, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm10, [SHA3_S+2*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm11, [SHA3_S+7*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm7, [SHA3_S+3*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm4, [SHA3_S+4*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm8, [SHA3_S+8*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm9, [SHA3_S+13*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm5, [SHA3_S+9*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm6, [SHA3_S+14*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm8, xmm9
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm10, xmm11
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm11, [SHA3_S+16*8]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm9, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm9, xmm10
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm12, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm8, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm8, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm8, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm8, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm12, xmm10
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm10, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm10, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm10, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm10, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm12, xmm11
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm11, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm11, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm11, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm11, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm12, xmm10
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm8, xmm9
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm12, xmm11
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm10, xmm9
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm12, xmm8
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm11, xmm9
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm9, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm13, [SHA3_S+1*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm14, [SHA3_S+6*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm10, [SHA3_S+2*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm11, [SHA3_S+7*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm15,  [SHA3_S+11*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  xmm12,  [SHA3_S+12*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor    xmm8,  [SHA3_S+8*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor    xmm9,  [SHA3_S+13*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps  [SHA3_S], xmm0
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm12, xmm13
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm14, xmm15
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm15, [SHA3_S+16*12]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm13, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm13, xmm14
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm0, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm12, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm12, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm12, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm12, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm0, xmm14
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm14, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm14, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm14, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm14, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm0, xmm15
# 0 "" 2
# 575 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 575 "echo64.c" 1
	psrlw    xmm15, 7
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 575 "echo64.c" 1
	pand     xmm15, [MEM_CST+16]
# 0 "" 2
# 575 "echo64.c" 1
	pmullw   xmm15, [MEM_CST+32]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm15, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm0, xmm14
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm12, xmm13
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm0, xmm15
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm14, xmm13
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm0, xmm12
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm15, xmm13
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm13, xmm0
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm14, [SHA3_S+6*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm12, [SHA3_S+12*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm13, [SHA3_S+1*16]
# 0 "" 2
# 575 "echo64.c" 1
	pxor     xmm15, [SHA3_S+11*16]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   xmm0,  [SHA3_S]
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+1*16],  xmm1
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+2*16],  xmm2
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+3*16],  xmm3
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+4*16],  xmm4
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+5*16],  xmm5
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+6*16],  xmm6
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+7*16],  xmm7
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+8*16],  xmm8
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+9*16],  xmm9
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+10*16], xmm10
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+11*16], xmm11
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+12*16], xmm12
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+13*16], xmm13
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+14*16], xmm14
# 0 "" 2
# 575 "echo64.c" 1
	movaps   [SHA3_S+15*16], xmm15
# 0 "" 2
# 576 "echo64.c" 1
	subd [SHA3_R], 1
# 0 "" 2
# 577 "echo64.c" 1
	jne LABEL_BIG_ROUND_NO1
# 0 "" 2
# 578 "echo64.c" 1
	jmp END
# 0 "" 2
# 580 "echo64.c" 1
	OVERFLOW:
# 0 "" 2
# 581 "echo64.c" 1
	mov    ecx, eax
# 0 "" 2
# 582 "echo64.c" 1
	mov    ebx, edx
# 0 "" 2
# 584 "echo64.c" 1
	add    ecx, 128
# 0 "" 2
# 589 "echo64.c" 1
	adc    ebx, 0
# 0 "" 2
# 590 "echo64.c" 1
	cmp    ebx, edx
# 0 "" 2
# 591 "echo64.c" 1
	je     NO_OVERFLOW2
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm0,  [SHA3_S]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm1,  [SHA3_S+16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm2,  [SHA3_S+2*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm3,  [SHA3_S+3*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm4,  [SHA3_S+4*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm5,  [SHA3_S+5*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm6,  [SHA3_S+6*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm7,  [SHA3_S+7*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm8,  [SHA3_S+8*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm9,  [SHA3_S+9*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm10, [SHA3_S+10*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm11, [SHA3_S+11*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm12, [SHA3_S+12*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm13, [SHA3_S+13*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm14, [SHA3_S+14*16]
# 0 "" 2
# 593 "echo64.c" 1
	movaps  xmm15, [SHA3_S+15*16]
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm0,      xmm4
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm1,      xmm5
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm2,      xmm6
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm3,      xmm7
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm0,      xmm8
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm1,      xmm9
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm2,      xmm10
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm3,      xmm11
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm0,      xmm12
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm1,      xmm13
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm2,      xmm14
# 0 "" 2
# 593 "echo64.c" 1
	pxor  xmm3,      xmm15
# 0 "" 2
# 593 "echo64.c" 1
	movaps  [OLDCV],      xmm0
# 0 "" 2
# 593 "echo64.c" 1
	movaps  [OLDCV+16],   xmm1
# 0 "" 2
# 593 "echo64.c" 1
	movaps  [OLDCV+2*16], xmm2
# 0 "" 2
# 593 "echo64.c" 1
	movaps  [OLDCV+3*16], xmm3
# 0 "" 2
# 598 "echo64.c" 1
	xor    ebx,ebx
# 0 "" 2
# 599 "echo64.c" 1
	xor    edx,edx
# 0 "" 2
# 601 "echo64.c" 1
	mov    [SHA3_RSP], rsp
# 0 "" 2
# 603 "echo64.c" 1
	LABEL_BIG_ROUND_O:
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+0]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+0+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+0+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+0+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+0+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+0+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+0+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+0+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+0],    edi
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+0+4],  esp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+0+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+0+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+16]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+16+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+16+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+16+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+16+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+16+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+16+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+16+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+16],    edi
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+16+4],  esp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+16+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+16+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+32]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+32+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+32+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+32+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+32+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+32+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+32+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+32+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+32],    edi
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+32+4],  esp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+32+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+32+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+48]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+48+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+48+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+48+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 604 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 604 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+48+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+48+12], esi
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    ecx, [SHA3_S+48+8]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	mov    eax, [SHA3_S+48+12]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 604 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 604 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 604 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 604 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 604 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 604 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+48],    edi
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+48+4],  esp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+48+8],  ebp
# 0 "" 2
# 604 "echo64.c" 1
	mov    [SHA3_S+48+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+64]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+64+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+64+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+64+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+64+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+64+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+64+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+64+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+64],    edi
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+64+4],  esp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+64+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+64+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+80]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+80+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+80+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+80+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+80+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+80+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+80+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+80+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+80],    edi
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+80+4],  esp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+80+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+80+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+96]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+96+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+96+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+96+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+96+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+96+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+96+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+96+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+96],    edi
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+96+4],  esp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+96+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+96+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+112]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+112+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+112+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+112+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 605 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 605 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+112+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+112+12], esi
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    ecx, [SHA3_S+112+8]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	mov    eax, [SHA3_S+112+12]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 605 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 605 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 605 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 605 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 605 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 605 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+112],    edi
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+112+4],  esp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+112+8],  ebp
# 0 "" 2
# 605 "echo64.c" 1
	mov    [SHA3_S+112+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+128]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+128+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+128+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+128+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+128+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+128+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+128+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+128+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+128],    edi
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+128+4],  esp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+128+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+128+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+144]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+144+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+144+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+144+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+144+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+144+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+144+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+144+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+144],    edi
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+144+4],  esp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+144+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+144+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+160]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+160+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+160+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+160+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+160+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+160+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+160+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+160+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+160],    edi
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+160+4],  esp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+160+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+160+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+176]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+176+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+176+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+176+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 606 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 606 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+176+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+176+12], esi
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    ecx, [SHA3_S+176+8]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	mov    eax, [SHA3_S+176+12]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 606 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 606 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 606 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 606 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 606 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 606 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+176],    edi
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+176+4],  esp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+176+8],  ebp
# 0 "" 2
# 606 "echo64.c" 1
	mov    [SHA3_S+176+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+192]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+192+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+192+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+192+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+192+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+192+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+192+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+192+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+192],    edi
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+192+4],  esp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+192+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+192+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+208]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+208+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+208+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+208+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+208+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+208+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+208+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+208+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+208],    edi
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+208+4],  esp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+208+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+208+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+224]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+224+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+224+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+224+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+224+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+224+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+224+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+224+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+224],    edi
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+224+4],  esp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+224+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+224+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+240]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+240+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+240+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+240+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 607 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 607 "echo64.c" 1
	addd   [SHA3_CNT+4], 1
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+240+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+240+12], esi
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    ecx, [SHA3_S+240+8]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	mov    eax, [SHA3_S+240+12]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 607 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 607 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 607 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 607 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 607 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 607 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+240],    edi
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+240+4],  esp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+240+8],  ebp
# 0 "" 2
# 607 "echo64.c" 1
	mov    [SHA3_S+240+12], esi
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm0, [SHA3_S]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm1, [SHA3_S+ 5*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm2, [SHA3_S+10*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm3, [SHA3_S+15*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm0, xmm1
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm2, xmm3
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm3, [SHA3_S+16*0]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm1, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm1, xmm2
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm4, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm0, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm0, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm0, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm0, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm4, xmm2
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm2, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm2, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm2, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm2, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm4, xmm3
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm3, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm3, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm3, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm3, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm4, xmm2
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm0, xmm1
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm4, xmm3
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm2, xmm1
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm4, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm3, xmm1
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm1, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm0, [SHA3_S]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm2, [SHA3_S+10*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm1, [SHA3_S+5*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm3, [SHA3_S+15*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm4, [SHA3_S+4*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm5, [SHA3_S+9*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm6, [SHA3_S+14*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm7, [SHA3_S+3*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm4, xmm5
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm6, xmm7
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm7, [SHA3_S+16*4]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm5, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm5, xmm6
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm8, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm4, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm4, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm4, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm4, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm8, xmm6
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm6, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm6, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm6, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm6, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm8, xmm7
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm7, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm7, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm7, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm7, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm8, xmm6
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm4, xmm5
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm8, xmm7
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm6, xmm5
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm8, xmm4
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm7, xmm5
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm5, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm10, [SHA3_S+2*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm11, [SHA3_S+7*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm7, [SHA3_S+3*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm4, [SHA3_S+4*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm8, [SHA3_S+8*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm9, [SHA3_S+13*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm5, [SHA3_S+9*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm6, [SHA3_S+14*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm8, xmm9
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm10, xmm11
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm11, [SHA3_S+16*8]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm9, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm9, xmm10
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm12, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm8, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm8, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm8, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm8, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm12, xmm10
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm10, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm10, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm10, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm10, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm12, xmm11
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm11, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm11, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm11, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm11, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm12, xmm10
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm8, xmm9
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm12, xmm11
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm10, xmm9
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm12, xmm8
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm11, xmm9
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm9, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm13, [SHA3_S+1*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm14, [SHA3_S+6*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm10, [SHA3_S+2*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm11, [SHA3_S+7*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm15,  [SHA3_S+11*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  xmm12,  [SHA3_S+12*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor    xmm8,  [SHA3_S+8*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor    xmm9,  [SHA3_S+13*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps  [SHA3_S], xmm0
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm12, xmm13
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm14, xmm15
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm15, [SHA3_S+16*12]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm13, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm13, xmm14
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm0, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm12, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm12, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm12, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm12, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm0, xmm14
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm14, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm14, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm14, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm14, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm0, xmm15
# 0 "" 2
# 608 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 608 "echo64.c" 1
	psrlw    xmm15, 7
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 608 "echo64.c" 1
	pand     xmm15, [MEM_CST+16]
# 0 "" 2
# 608 "echo64.c" 1
	pmullw   xmm15, [MEM_CST+32]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm15, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm0, xmm14
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm12, xmm13
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm0, xmm15
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm14, xmm13
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm0, xmm12
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm15, xmm13
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm13, xmm0
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm14, [SHA3_S+6*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm12, [SHA3_S+12*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm13, [SHA3_S+1*16]
# 0 "" 2
# 608 "echo64.c" 1
	pxor     xmm15, [SHA3_S+11*16]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   xmm0,  [SHA3_S]
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+1*16],  xmm1
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+2*16],  xmm2
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+3*16],  xmm3
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+4*16],  xmm4
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+5*16],  xmm5
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+6*16],  xmm6
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+7*16],  xmm7
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+8*16],  xmm8
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+9*16],  xmm9
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+10*16], xmm10
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+11*16], xmm11
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+12*16], xmm12
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+13*16], xmm13
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+14*16], xmm14
# 0 "" 2
# 608 "echo64.c" 1
	movaps   [SHA3_S+15*16], xmm15
# 0 "" 2
# 609 "echo64.c" 1
	subd [SHA3_R], 1
# 0 "" 2
# 610 "echo64.c" 1
	jne LABEL_BIG_ROUND_O
# 0 "" 2
# 611 "echo64.c" 1
	jmp END
# 0 "" 2
# 613 "echo64.c" 1
	NO_OVERFLOW2:
# 0 "" 2
# 614 "echo64.c" 1
	mov    dword ptr [SHA3_S+264], 0
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm0,  [SHA3_S]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm1,  [SHA3_S+16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm2,  [SHA3_S+2*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm3,  [SHA3_S+3*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm4,  [SHA3_S+4*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm5,  [SHA3_S+5*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm6,  [SHA3_S+6*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm7,  [SHA3_S+7*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm8,  [SHA3_S+8*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm9,  [SHA3_S+9*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm10, [SHA3_S+10*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm11, [SHA3_S+11*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm12, [SHA3_S+12*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm13, [SHA3_S+13*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm14, [SHA3_S+14*16]
# 0 "" 2
# 616 "echo64.c" 1
	movaps  xmm15, [SHA3_S+15*16]
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm0,      xmm4
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm1,      xmm5
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm2,      xmm6
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm3,      xmm7
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm0,      xmm8
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm1,      xmm9
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm2,      xmm10
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm3,      xmm11
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm0,      xmm12
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm1,      xmm13
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm2,      xmm14
# 0 "" 2
# 616 "echo64.c" 1
	pxor  xmm3,      xmm15
# 0 "" 2
# 616 "echo64.c" 1
	movaps  [OLDCV],      xmm0
# 0 "" 2
# 616 "echo64.c" 1
	movaps  [OLDCV+16],   xmm1
# 0 "" 2
# 616 "echo64.c" 1
	movaps  [OLDCV+2*16], xmm2
# 0 "" 2
# 616 "echo64.c" 1
	movaps  [OLDCV+3*16], xmm3
# 0 "" 2
# 621 "echo64.c" 1
	xor    ebx,ebx
# 0 "" 2
# 622 "echo64.c" 1
	xor    edx,edx
# 0 "" 2
# 624 "echo64.c" 1
	mov    [SHA3_RSP], rsp
# 0 "" 2
# 626 "echo64.c" 1
	LABEL_BIG_ROUND_NO2:
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+0]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+0+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+0+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+0+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+0+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+0+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+0+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+0+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+0],    edi
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+0+4],  esp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+0+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+0+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+16]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+16+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+16+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+16+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+16+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+16+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+16+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+16+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+16],    edi
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+16+4],  esp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+16+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+16+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+32]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+32+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+32+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+32+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+32+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+32+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+32+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+32+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+32],    edi
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+32+4],  esp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+32+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+32+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+48]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+48+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+48+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+48+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 627 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+48+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+48+12], esi
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    ecx, [SHA3_S+48+8]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	mov    eax, [SHA3_S+48+12]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 627 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 627 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 627 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 627 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 627 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 627 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+48],    edi
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+48+4],  esp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+48+8],  ebp
# 0 "" 2
# 627 "echo64.c" 1
	mov    [SHA3_S+48+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+64]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+64+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+64+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+64+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+64+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+64+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+64+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+64+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+64],    edi
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+64+4],  esp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+64+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+64+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+80]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+80+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+80+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+80+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+80+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+80+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+80+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+80+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+80],    edi
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+80+4],  esp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+80+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+80+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+96]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+96+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+96+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+96+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+96+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+96+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+96+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+96+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+96],    edi
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+96+4],  esp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+96+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+96+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+112]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+112+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+112+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+112+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 628 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+112+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+112+12], esi
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    ecx, [SHA3_S+112+8]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	mov    eax, [SHA3_S+112+12]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 628 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 628 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 628 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 628 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 628 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 628 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+112],    edi
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+112+4],  esp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+112+8],  ebp
# 0 "" 2
# 628 "echo64.c" 1
	mov    [SHA3_S+112+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+128]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+128+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+128+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+128+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+128+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+128+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+128+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+128+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+128],    edi
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+128+4],  esp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+128+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+128+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+144]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+144+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+144+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+144+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+144+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+144+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+144+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+144+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+144],    edi
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+144+4],  esp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+144+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+144+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+160]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+160+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+160+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+160+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+160+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+160+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+160+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+160+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+160],    edi
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+160+4],  esp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+160+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+160+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+176]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+176+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+176+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+176+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 629 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+176+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+176+12], esi
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    ecx, [SHA3_S+176+8]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	mov    eax, [SHA3_S+176+12]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 629 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 629 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 629 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 629 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 629 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 629 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+176],    edi
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+176+4],  esp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+176+8],  ebp
# 0 "" 2
# 629 "echo64.c" 1
	mov    [SHA3_S+176+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+192]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+192+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+192+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+192+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+192+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+192+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+192+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+192+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+192],    edi
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+192+4],  esp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+192+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+192+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+208]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+208+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+208+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+208+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+208+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+208+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+208+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+208+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+208],    edi
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+208+4],  esp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+208+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+208+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+224]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+224+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+224+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+224+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+224+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+224+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+224+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+224+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+224],    edi
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+224+4],  esp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+224+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+224+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+240]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+240+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [SHA3_CNT]  
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+240+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+240+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [SHA3_CNT+4]
# 0 "" 2
# 630 "echo64.c" 1
	movzx   edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	addd   [SHA3_CNT],   1
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+240+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+240+12], esi
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, edi
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, esp
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	mov    edi, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	mov    esp, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	mov    esi, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    ebp, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    ecx, [SHA3_S+240+8]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	mov    eax, [SHA3_S+240+12]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*edx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, ch
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ebx]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, ah
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*edx+3]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 16
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 16
# 0 "" 2
# 630 "echo64.c" 1
	xor    ebp, [Te+8*ebx+3]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    edx, cl
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*edx+2]
# 0 "" 2
# 630 "echo64.c" 1
	movzx    ebx, al
# 0 "" 2
# 630 "echo64.c" 1
	xor    esp, [Te+8*ebx+2]
# 0 "" 2
# 630 "echo64.c" 1
	shr    ecx, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    esi, [Te+8*ecx+1]
# 0 "" 2
# 630 "echo64.c" 1
	shr    eax, 8
# 0 "" 2
# 630 "echo64.c" 1
	xor    edi, [Te+8*eax+1]
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+240],    edi
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+240+4],  esp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+240+8],  ebp
# 0 "" 2
# 630 "echo64.c" 1
	mov    [SHA3_S+240+12], esi
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm0, [SHA3_S]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm1, [SHA3_S+ 5*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm2, [SHA3_S+10*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm3, [SHA3_S+15*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm0, xmm1
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm2, xmm3
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm3, [SHA3_S+16*0]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm1, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm1, xmm2
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm4, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm0, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm0, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm0, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm0, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm4, xmm2
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm2, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm2, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm2, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm2, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm4, xmm3
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm4, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm3, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm4, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm3, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm3, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm3, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm4, xmm2
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm0, xmm1
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm4, xmm3
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm2, xmm1
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm4, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm3, xmm1
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm1, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm0, [SHA3_S]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm2, [SHA3_S+10*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm1, [SHA3_S+5*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm3, [SHA3_S+15*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm4, [SHA3_S+4*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm5, [SHA3_S+9*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm6, [SHA3_S+14*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm7, [SHA3_S+3*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm4, xmm5
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm6, xmm7
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm7, [SHA3_S+16*4]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm5, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm5, xmm6
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm8, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm4, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm4, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm4, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm4, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm8, xmm6
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm6, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm6, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm6, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm6, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm8, xmm7
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm8, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm7, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm8, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm7, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm7, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm7, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm8, xmm6
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm4, xmm5
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm8, xmm7
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm6, xmm5
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm8, xmm4
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm7, xmm5
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm5, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm10, [SHA3_S+2*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm11, [SHA3_S+7*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm7, [SHA3_S+3*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm4, [SHA3_S+4*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm8, [SHA3_S+8*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm9, [SHA3_S+13*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm5, [SHA3_S+9*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm6, [SHA3_S+14*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm8, xmm9
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm10, xmm11
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm11, [SHA3_S+16*8]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm9, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm9, xmm10
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm12, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm8, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm8, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm8, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm8, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm12, xmm10
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm10, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm10, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm10, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm10, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm12, xmm11
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm12, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm11, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm12, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm11, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm11, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm11, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm12, xmm10
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm8, xmm9
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm12, xmm11
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm10, xmm9
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm12, xmm8
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm11, xmm9
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm9, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm13, [SHA3_S+1*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm14, [SHA3_S+6*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm10, [SHA3_S+2*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm11, [SHA3_S+7*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm15,  [SHA3_S+11*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  xmm12,  [SHA3_S+12*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor    xmm8,  [SHA3_S+8*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor    xmm9,  [SHA3_S+13*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps  [SHA3_S], xmm0
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm12, xmm13
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm14, xmm15
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm15, [SHA3_S+16*12]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm13, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm13, xmm14
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm0, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm12, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm12, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm12, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm12, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm0, xmm14
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm14, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm14, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm14, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm14, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm0, xmm15
# 0 "" 2
# 631 "echo64.c" 1
	psllw    xmm0, 1
# 0 "" 2
# 631 "echo64.c" 1
	psrlw    xmm15, 7
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm0, [MEM_CST]
# 0 "" 2
# 631 "echo64.c" 1
	pand     xmm15, [MEM_CST+16]
# 0 "" 2
# 631 "echo64.c" 1
	pmullw   xmm15, [MEM_CST+32]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm15, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm0, xmm14
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm12, xmm13
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm0, xmm15
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm14, xmm13
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm0, xmm12
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm15, xmm13
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm13, xmm0
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm14, [SHA3_S+6*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm12, [SHA3_S+12*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm13, [SHA3_S+1*16]
# 0 "" 2
# 631 "echo64.c" 1
	pxor     xmm15, [SHA3_S+11*16]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   xmm0,  [SHA3_S]
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+1*16],  xmm1
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+2*16],  xmm2
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+3*16],  xmm3
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+4*16],  xmm4
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+5*16],  xmm5
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+6*16],  xmm6
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+7*16],  xmm7
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+8*16],  xmm8
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+9*16],  xmm9
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+10*16], xmm10
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+11*16], xmm11
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+12*16], xmm12
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+13*16], xmm13
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+14*16], xmm14
# 0 "" 2
# 631 "echo64.c" 1
	movaps   [SHA3_S+15*16], xmm15
# 0 "" 2
# 632 "echo64.c" 1
	subd [SHA3_R], 1
# 0 "" 2
# 633 "echo64.c" 1
	jne LABEL_BIG_ROUND_NO2
# 0 "" 2
# 635 "echo64.c" 1
	END:
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm0,      xmm4
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm1,      xmm5
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm2,      xmm6
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm3,      xmm7
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm0,      xmm8
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm1,      xmm9
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm2,      xmm10
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm3,      xmm11
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm0,     xmm12
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm1,     xmm13
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm2,     xmm14
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm3,     xmm15
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm0, [OLDCV]
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm1, [OLDCV+16]
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm2, [OLDCV+2*16]
# 0 "" 2
# 637 "echo64.c" 1
	pxor  xmm3, [OLDCV+3*16]
# 0 "" 2
# 637 "echo64.c" 1
	movaps  [SHA3_S],        xmm0
# 0 "" 2
# 637 "echo64.c" 1
	movaps  [SHA3_S+16],     xmm1
# 0 "" 2
# 637 "echo64.c" 1
	movaps  [SHA3_S+2*16],   xmm2
# 0 "" 2
# 637 "echo64.c" 1
	movaps  [SHA3_S+3*16],   xmm3
# 0 "" 2
# 643 "echo64.c" 1
	mov    rsp, [SHA3_RSP]
# 0 "" 2
# 644 "echo64.c" 1
	pop rax
# 0 "" 2
# 644 "echo64.c" 1
	pop rbx
# 0 "" 2
# 644 "echo64.c" 1
	pop rcx
# 0 "" 2
# 644 "echo64.c" 1
	pop rdx
# 0 "" 2
# 644 "echo64.c" 1
	pop rsi
# 0 "" 2
# 644 "echo64.c" 1
	pop rdi
# 0 "" 2
# 644 "echo64.c" 1
	pop rbp
# 0 "" 2
# 644 "echo64.c" 1
	pop r15
# 0 "" 2
# 644 "echo64.c" 1
	pop r14
# 0 "" 2
# 644 "echo64.c" 1
	pop r13
# 0 "" 2
# 644 "echo64.c" 1
	pop r12
# 0 "" 2
# 644 "echo64.c" 1
	pop r11
# 0 "" 2
# 644 "echo64.c" 1
	pop r10
# 0 "" 2
# 644 "echo64.c" 1
	pop r9
# 0 "" 2
# 644 "echo64.c" 1
	pop r8
# 0 "" 2
# 645 "echo64.c" 1
	.att_syntax noprefix
# 0 "" 2
#NO_APP
	ret
	.cfi_endproc
.LFE528:
	.size	Compress, .-Compress
	.p2align 4,,15
.globl Init
	.type	Init, @function
Init:
.LFB529:
	.cfi_startproc
	movq	SHA3_S+280(%rip), %rdx
	testq	%rdx, %rdx
	je	.L4
	cmpq	%rdi, %rdx
	je	.L4
	testb	$15, %dl
	je	.L23
.L5:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L8:
	movq	SHA3_S(%rax), %rcx
	movq	%rcx, (%rdx,%rax)
	addq	$8, %rax
	cmpq	$288, %rax
	jne	.L8
	.p2align 4,,10
	.p2align 3
.L4:
	leal	-160(%rsi), %edx
	movq	%rdi, SHA3_S+280(%rip)
	movl	$-16843010, MEM_CST(%rip)
	movl	$-16843010, MEM_CST+4(%rip)
	movl	$-16843010, MEM_CST+8(%rip)
	movl	$2, %eax
	cmpl	$352, %edx
	movl	$-16843010, MEM_CST+12(%rip)
	movl	$16843009, MEM_CST+16(%rip)
	movl	$16843009, MEM_CST+20(%rip)
	movl	$16843009, MEM_CST+24(%rip)
	movl	$16843009, MEM_CST+28(%rip)
	movl	$1769499, MEM_CST+32(%rip)
	movl	$1769499, MEM_CST+36(%rip)
	movl	$1769499, MEM_CST+40(%rip)
	movl	$1769499, MEM_CST+44(%rip)
	movl	$1, MEM_CST+48(%rip)
	movl	$0, MEM_CST+52(%rip)
	movl	$0, MEM_CST+56(%rip)
	movl	$0, MEM_CST+60(%rip)
	ja	.L10
	xorl	%eax, %eax
	cmpl	$257, %esi
	movl	%esi, SHA3_S+268(%rip)
	setge	%al
	movslq	%esi,%rsi
	movl	$SHA3_S, %edx
	leal	4(,%rax,4), %eax
	xorl	%ecx, %ecx
	movl	%eax, SHA3_S+272(%rip)
	.p2align 4,,10
	.p2align 3
.L13:
	addl	$1, %ecx
	movq	%rsi, (%rdx)
	movq	$0, 8(%rdx)
	addq	$16, %rdx
	cmpl	%ecx, %eax
	jg	.L13
	cmpl	$15, %eax
	jg	.L14
	addl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L15:
	movslq	%eax,%rdx
	movq	$0, SHA3_S(,%rdx,8)
	leal	1(%rax), %edx
	addl	$2, %eax
	cmpl	$32, %eax
	movslq	%edx,%rdx
	movq	$0, SHA3_S(,%rdx,8)
	jne	.L15
.L14:
	movq	$0, SHA3_S+256(%rip)
	movl	$0, SHA3_S+264(%rip)
	xorl	%eax, %eax
.L10:
	rep
	ret
	.p2align 4,,10
	.p2align 3
.L23:
	cmpq	$SHA3_S+16, %rdx
	jbe	.L24
.L17:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L7:
	movdqa	SHA3_S(%rax), %xmm0
	movdqa	%xmm0, (%rdx,%rax)
	addq	$16, %rax
	cmpq	$288, %rax
	jne	.L7
	jmp	.L4
.L24:
	leaq	16(%rdx), %rax
	movl	$SHA3_S, %ecx
	cmpq	%rax, %rcx
	jbe	.L5
	.p2align 4,,2
	jmp	.L17
	.cfi_endproc
.LFE529:
	.size	Init, .-Init
	.p2align 4,,15
.globl Update
	.type	Update, @function
Update:
.LFB530:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r13
	.cfi_def_cfa_offset 32
	pushq	%r12
	.cfi_def_cfa_offset 40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	movq	%rsi, %rbx
	.cfi_offset 3, -56
	.cfi_offset 6, -48
	.cfi_offset 12, -40
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	subq	$8, %rsp
	.cfi_def_cfa_offset 64
	movq	%rdx, (%rsp)
	movq	SHA3_S+280(%rip), %rdx
	cmpq	%rdi, %rdx
	je	.L26
	testb	$15, %dl
	movl	$SHA3_S, %esi
	je	.L77
.L27:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L31:
	movq	SHA3_S(%rax), %rcx
	movq	%rcx, (%rdx,%rax)
	addq	$8, %rax
	cmpq	$288, %rax
	jne	.L31
	.p2align 4,,10
	.p2align 3
.L30:
	leaq	16(%rdi), %rax
	cmpq	%rax, %rsi
	ja	.L60
	xorl	%eax, %eax
	cmpq	$SHA3_S+16, %rdi
	jbe	.L63
.L60:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L34:
	movdqu	(%rdi,%rax), %xmm0
	movdqa	%xmm0, SHA3_S(%rax)
	addq	$16, %rax
	cmpq	$288, %rax
	jne	.L34
.L35:
	movq	%rdi, SHA3_S+280(%rip)
.L26:
	movl	SHA3_S+272(%rip), %edx
	movq	(%rsp), %r12
	movl	SHA3_S+264(%rip), %eax
	sall	$4, %edx
	shrq	$3, %r12
	movslq	%edx,%rbp
	sarl	$3, %eax
	testq	%r12, %r12
	leaq	SHA3_S(%rbp), %r14
	jle	.L76
	movl	$256, %r15d
	subl	%edx, %r15d
	.p2align 4,,10
	.p2align 3
.L50:
	movl	%r15d, %r8d
	subl	%eax, %r8d
	movslq	%r8d,%r13
	cmpq	%r12, %r13
	jle	.L39
	movq	%r12, %rdi
	sarq	$3, %rdi
	testq	%rdi, %rdi
	jle	.L41
	movslq	%eax,%rsi
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	leaq	(%r14,%rsi), %r8
	.p2align 4,,10
	.p2align 3
.L51:
	movq	(%rbx,%rdx,8), %rsi
	addl	$1, %ecx
	movq	%rsi, (%r8,%rdx,8)
	mov	%ecx, %edx
	cmpq	%rdi, %rdx
	jl	.L51
.L41:
	movq	%r12, %rdx
	leal	0(,%rdi,8), %ecx
	andl	$7, %edx
	leaq	(%rdx,%rdi,8), %rdi
	mov	%ecx, %edx
	cmpq	%rdi, %rdx
	jge	.L52
	movslq	%eax,%rsi
	leaq	(%r14,%rsi), %r8
	.p2align 4,,10
	.p2align 3
.L53:
	movzbl	(%rbx,%rdx), %esi
	addl	$1, %ecx
	movb	%sil, (%r8,%rdx)
	mov	%ecx, %edx
	cmpq	%rdi, %rdx
	jl	.L53
.L52:
	addl	%r12d, %eax
	addq	%r12, %rbx
.L76:
	leal	0(,%rax,8), %edx
.L38:
	movq	(%rsp), %rcx
	movl	%edx, SHA3_S+264(%rip)
	andl	$7, %ecx
	je	.L54
	addl	%ecx, %edx
	movl	%edx, SHA3_S+264(%rip)
	xorl	%edx, %edx
	testl	%ecx, %ecx
	je	.L56
	movl	$7, %esi
	movl	$1, %edi
	subl	%ecx, %esi
	movl	$7, %ecx
	.p2align 4,,10
	.p2align 3
.L57:
	movl	%edi, %r8d
	sall	%cl, %r8d
	subl	$1, %ecx
	orl	%r8d, %edx
	cmpl	%esi, %ecx
	jne	.L57
	andb	(%rbx), %dl
.L56:
	cltq
	movb	%dl, SHA3_S(%rbp,%rax)
.L54:
	addq	$8, %rsp
	xorl	%eax, %eax
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
	.p2align 4,,10
	.p2align 3
.L39:
	leal	7(%r8), %edx
	testl	%r8d, %r8d
	cmovns	%r8d, %edx
	sarl	$3, %edx
	testl	%edx, %edx
	je	.L42
	movslq	%eax,%r9
	cmpl	$21, %edx
	leaq	(%r14,%r9), %r9
	ja	.L78
.L43:
	leal	-1(%rdx), %esi
	movq	%rbx, %rcx
	leaq	8(%rbx,%rsi,8), %rdi
	.p2align 4,,10
	.p2align 3
.L47:
	movq	(%rcx), %rsi
	addq	$8, %rcx
	movq	%rsi, (%r9)
	addq	$8, %r9
	cmpq	%rdi, %rcx
	jne	.L47
	.p2align 4,,10
	.p2align 3
.L42:
	movl	%r8d, %ecx
	sall	$3, %edx
	sarl	$31, %ecx
	shrl	$29, %ecx
	leal	(%r8,%rcx), %esi
	andl	$7, %esi
	subl	%ecx, %esi
	leal	(%rdx,%rsi), %esi
	cmpl	%esi, %edx
	jae	.L48
	cltq
	leaq	(%r14,%rax), %rdi
	.p2align 4,,10
	.p2align 3
.L49:
	mov	%edx, %eax
	addl	$1, %edx
	movzbl	(%rbx,%rax), %ecx
	cmpl	%esi, %edx
	movb	%cl, (%rdi,%rax)
	jb	.L49
.L48:
	xorl	%eax, %eax
	subq	%r13, %r12
	sall	$3, %r8d
	addq	%r13, %rbx
	addl	%r8d, SHA3_S+264(%rip)
	call	Compress
	xorl	%eax, %eax
	testq	%r12, %r12
	jg	.L50
	xorl	%edx, %edx
	jmp	.L38
	.p2align 4,,10
	.p2align 3
.L78:
	testb	$15, %r9b
	.p2align 4,,3
	jne	.L43
	leaq	16(%rbx), %rcx
	cmpq	%rcx, %r9
	.p2align 4,,3
	ja	.L61
	leaq	16(%r9), %rcx
	cmpq	%rcx, %rbx
	jbe	.L43
.L61:
	movl	%edx, %r10d
	shrl	%r10d
	movl	%r10d, %ecx
	addl	%ecx, %ecx
	je	.L62
	xorl	%esi, %esi
	xorl	%edi, %edi
	.p2align 4,,10
	.p2align 3
.L46:
	movdqu	(%rbx,%rsi), %xmm0
	addl	$1, %edi
	movdqa	%xmm0, (%r9,%rsi)
	addq	$16, %rsi
	cmpl	%r10d, %edi
	jb	.L46
	cmpl	%ecx, %edx
	je	.L42
	.p2align 4,,10
	.p2align 3
.L62:
	mov	%ecx, %esi
	addl	$1, %ecx
	movq	(%rbx,%rsi,8), %rdi
	cmpl	%ecx, %edx
	movq	%rdi, (%r9,%rsi,8)
	ja	.L62
	jmp	.L42
.L77:
	cmpq	$SHA3_S+16, %rdx
	ja	.L59
	leaq	16(%rdx), %rax
	cmpq	%rax, %rsi
	.p2align 4,,2
	jbe	.L27
.L59:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L29:
	movdqa	SHA3_S(%rax), %xmm0
	movdqa	%xmm0, (%rdx,%rax)
	addq	$16, %rax
	cmpq	$288, %rax
	jne	.L29
	jmp	.L30
	.p2align 4,,10
	.p2align 3
.L63:
	movq	(%rdi,%rax), %rdx
	movq	%rdx, SHA3_S(%rax)
	addq	$8, %rax
	cmpq	$288, %rax
	jne	.L63
	jmp	.L35
	.cfi_endproc
.LFE530:
	.size	Update, .-Update
	.p2align 4,,15
.globl Final
	.type	Final, @function
Final:
.LFB531:
	.cfi_startproc
	pushq	%r13
	.cfi_def_cfa_offset 16
	pushq	%r12
	.cfi_def_cfa_offset 24
	pushq	%rbp
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	movq	%rsi, %rbx
	.cfi_offset 3, -40
	.cfi_offset 6, -32
	.cfi_offset 12, -24
	.cfi_offset 13, -16
	subq	$8, %rsp
	.cfi_def_cfa_offset 48
	movq	SHA3_S+280(%rip), %rdx
	cmpq	%rdi, %rdx
	je	.L80
	testb	$15, %dl
	movl	$SHA3_S, %esi
	je	.L107
.L81:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L85:
	movq	SHA3_S(%rax), %rcx
	movq	%rcx, (%rdx,%rax)
	addq	$8, %rax
	cmpq	$288, %rax
	jne	.L85
.L84:
	leaq	16(%rdi), %rax
	cmpq	%rax, %rsi
	ja	.L100
	xorl	%eax, %eax
	cmpq	$SHA3_S+16, %rdi
	jbe	.L101
.L100:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L88:
	movdqu	(%rdi,%rax), %xmm0
	movdqa	%xmm0, SHA3_S(%rax)
	addq	$16, %rax
	cmpq	$288, %rax
	jne	.L88
.L89:
	movq	%rdi, SHA3_S+280(%rip)
.L80:
	movl	SHA3_S+272(%rip), %edx
	movl	$16, %ebp
	movl	SHA3_S+264(%rip), %eax
	subl	%edx, %ebp
	movl	%edx, %esi
	sall	$7, %ebp
	sall	$4, %esi
	movl	%ebp, %edx
	movslq	%esi,%rsi
	subl	%eax, %edx
	addq	$SHA3_S, %rsi
	cmpl	$144, %edx
	jg	.L91
	leal	7(%rax), %edx
	testl	%eax, %eax
	movl	$255, %edi
	cmovns	%eax, %edx
	sarl	$3, %edx
	movslq	%edx,%rdx
	leaq	(%rsi,%rdx), %r8
	movl	%eax, %edx
	sarl	$31, %edx
	shrl	$29, %edx
	leal	(%rax,%rdx), %ecx
	andl	$7, %ecx
	subl	%ecx, %edx
	leal	7(%rdx), %ecx
	movl	$1, %edx
	sall	%cl, %edx
	orb	(%r8), %dl
	leal	(%rcx,%rax), %eax
	sall	%cl, %edi
	andl	%edi, %edx
	testl	%eax, %eax
	movb	%dl, (%r8)
	jle	.L92
	movl	%ebp, %edx
	subl	%eax, %edx
	leal	7(%rdx), %ecx
	testl	%edx, %edx
	cmovs	%ecx, %edx
	sarl	$3, %eax
	cltq
	sarl	$3, %edx
	leaq	1(%rsi,%rax), %rdi
	movslq	%edx,%rdx
	xorl	%esi, %esi
	call	memset
	xorl	%eax, %eax
	call	Compress
	movl	SHA3_S+272(%rip), %eax
	movslq	SHA3_S+264(%rip),%r12
	addq	SHA3_S+256(%rip), %r12
	sall	$4, %eax
	cltq
	leaq	SHA3_S(%rax), %r13
.L93:
	subl	$144, %ebp
	movq	%r13, %rdi
	leal	7(%rbp), %eax
	testl	%ebp, %ebp
	cmovns	%ebp, %eax
	xorl	%esi, %esi
	sarl	$3, %eax
	movslq	%eax,%rdx
	call	memset
	jmp	.L95
	.p2align 4,,10
	.p2align 3
.L91:
	leal	7(%rax), %edx
	testl	%eax, %eax
	movl	$255, %edi
	cmovns	%eax, %edx
	sarl	$3, %edx
	movslq	%edx,%rdx
	addq	%rdx, %rsi
	movl	%eax, %edx
	sarl	$31, %edx
	shrl	$29, %edx
	leal	(%rax,%rdx), %ecx
	andl	$7, %ecx
	subl	%ecx, %edx
	leal	7(%rdx), %ecx
	movl	$1, %edx
	sall	%cl, %edx
	orb	(%rsi), %dl
	sall	%cl, %edi
	leal	(%rcx,%rax), %eax
	andl	%edi, %edx
	movb	%dl, (%rsi)
.L92:
	movl	SHA3_S+272(%rip), %r13d
	movslq	SHA3_S+264(%rip),%r12
	addq	SHA3_S+256(%rip), %r12
	sall	$4, %r13d
	movslq	%r13d,%r13
	addq	$SHA3_S, %r13
	testl	%eax, %eax
	je	.L93
	subl	$144, %ebp
	leal	7(%rax), %ecx
	subl	%eax, %ebp
	leal	7(%rbp), %edx
	testl	%ebp, %ebp
	cmovs	%edx, %ebp
	sarl	$3, %ebp
	testl	%eax, %eax
	cmovs	%ecx, %eax
	movslq	%ebp,%rdx
	xorl	%esi, %esi
	sarl	$3, %eax
	cltq
	leaq	1(%r13,%rax), %rdi
	call	memset
.L95:
	movl	$16, %eax
	subl	SHA3_S+272(%rip), %eax
	movl	SHA3_S+268(%rip), %edx
	sall	$4, %eax
	cltq
	leaq	-18(%r13,%rax), %rax
	movb	%dl, (%rax)
	movl	SHA3_S+268(%rip), %edx
	movb	%r12b, 2(%rax)
	movb	$0, 10(%rax)
	movb	$0, 11(%rax)
	movb	$0, 12(%rax)
	sarl	$8, %edx
	movb	$0, 13(%rax)
	movb	$0, 14(%rax)
	movb	%dl, 1(%rax)
	movq	%r12, %rdx
	movb	$0, 15(%rax)
	shrq	$8, %rdx
	movb	$0, 16(%rax)
	movb	$0, 17(%rax)
	movb	%dl, 3(%rax)
	movq	%r12, %rdx
	shrq	$16, %rdx
	movb	%dl, 4(%rax)
	movq	%r12, %rdx
	shrq	$24, %rdx
	movb	%dl, 5(%rax)
	movq	%r12, %rdx
	shrq	$32, %rdx
	movb	%dl, 6(%rax)
	movq	%r12, %rdx
	shrq	$40, %rdx
	movb	%dl, 7(%rax)
	movq	%r12, %rdx
	shrq	$56, %r12
	shrq	$48, %rdx
	movb	%r12b, 9(%rax)
	movb	%dl, 8(%rax)
	xorl	%eax, %eax
	call	Compress
	movl	SHA3_S+268(%rip), %eax
	sarl	$3, %eax
	testl	%eax, %eax
	je	.L96
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L97:
	movl	%eax, %edx
	movl	%eax, %ecx
	mov	%eax, %esi
	shrl	$3, %edx
	andl	$7, %ecx
	addl	$1, %eax
	mov	%edx, %edx
	sall	$3, %ecx
	movq	SHA3_S(,%rdx,8), %rdx
	shrq	%cl, %rdx
	movb	%dl, (%rbx,%rsi)
	movl	SHA3_S+268(%rip), %edx
	sarl	$3, %edx
	cmpl	%eax, %edx
	ja	.L97
.L96:
	movq	$0, SHA3_S+280(%rip)
	addq	$8, %rsp
	xorl	%eax, %eax
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	ret
	.p2align 4,,10
	.p2align 3
.L107:
	cmpq	$SHA3_S+16, %rdx
	ja	.L99
	leaq	16(%rdx), %rax
	cmpq	%rax, %rsi
	jbe	.L81
.L99:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L83:
	movdqa	SHA3_S(%rax), %xmm0
	movdqa	%xmm0, (%rdx,%rax)
	addq	$16, %rax
	cmpq	$288, %rax
	jne	.L83
	jmp	.L84
	.p2align 4,,10
	.p2align 3
.L101:
	movq	(%rdi,%rax), %rdx
	movq	%rdx, SHA3_S(%rax)
	addq	$8, %rax
	cmpq	$288, %rax
	jne	.L101
	jmp	.L89
	.cfi_endproc
.LFE531:
	.size	Final, .-Final
	.p2align 4,,15
	.type	T.44, @function
T.44:
.LFB534:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	movq	%rdx, %rbp
	.cfi_offset 6, -16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$296, %rsp
	.cfi_def_cfa_offset 320
	movq	SHA3_S+280(%rip), %rax
	movq	%rsp, %rbx
	.cfi_offset 3, -24
	testq	%rax, %rax
	je	.L109
	cmpq	%rsp, %rax
	je	.L109
	testb	$15, %al
	je	.L120
.L110:
	xorl	%edx, %edx
.L113:
	movq	SHA3_S(%rdx), %rcx
	movq	%rcx, (%rax,%rdx)
	addq	$8, %rdx
	cmpq	$288, %rdx
	jne	.L113
	.p2align 4,,10
	.p2align 3
.L109:
	movdqa	.LC0(%rip), %xmm0
	movq	%rsi, %rdx
	movq	%rdi, %rsi
	movq	%rsp, %rdi
	movq	%rbx, SHA3_S+280(%rip)
	movdqa	%xmm0, SHA3_S(%rip)
	movl	$-16843010, MEM_CST(%rip)
	movl	$-16843010, MEM_CST+4(%rip)
	movdqa	%xmm0, SHA3_S+16(%rip)
	movdqa	%xmm0, SHA3_S+32(%rip)
	movdqa	%xmm0, SHA3_S+48(%rip)
	pxor	%xmm0, %xmm0
	movl	$-16843010, MEM_CST+8(%rip)
	movl	$-16843010, MEM_CST+12(%rip)
	movdqa	%xmm0, SHA3_S+64(%rip)
	movl	$16843009, MEM_CST+16(%rip)
	movl	$16843009, MEM_CST+20(%rip)
	movdqa	%xmm0, SHA3_S+80(%rip)
	movdqa	%xmm0, SHA3_S+96(%rip)
	movdqa	%xmm0, SHA3_S+112(%rip)
	movdqa	%xmm0, SHA3_S+128(%rip)
	movdqa	%xmm0, SHA3_S+144(%rip)
	movdqa	%xmm0, SHA3_S+160(%rip)
	movdqa	%xmm0, SHA3_S+176(%rip)
	movdqa	%xmm0, SHA3_S+192(%rip)
	movl	$16843009, MEM_CST+24(%rip)
	movl	$16843009, MEM_CST+28(%rip)
	movl	$1769499, MEM_CST+32(%rip)
	movl	$1769499, MEM_CST+36(%rip)
	movl	$1769499, MEM_CST+40(%rip)
	movl	$1769499, MEM_CST+44(%rip)
	movl	$1, MEM_CST+48(%rip)
	movl	$0, MEM_CST+52(%rip)
	movl	$0, MEM_CST+56(%rip)
	movl	$0, MEM_CST+60(%rip)
	movl	$256, SHA3_S+268(%rip)
	movl	$4, SHA3_S+272(%rip)
	movdqa	%xmm0, SHA3_S+208(%rip)
	movq	$0, SHA3_S+256(%rip)
	movl	$0, SHA3_S+264(%rip)
	movdqa	%xmm0, SHA3_S+224(%rip)
	movdqa	%xmm0, SHA3_S+240(%rip)
	call	Update
	testl	%eax, %eax
	je	.L121
	addq	$296, %rsp
	popq	%rbx
	popq	%rbp
	ret
.L120:
	cmpq	$SHA3_S+16, %rax
	jbe	.L122
.L116:
	xorl	%edx, %edx
.L112:
	movdqa	SHA3_S(%rdx), %xmm0
	movdqa	%xmm0, (%rax,%rdx)
	addq	$16, %rdx
	cmpq	$288, %rdx
	jne	.L112
	jmp	.L109
.L122:
	leaq	16(%rax), %rdx
	movl	$SHA3_S, %ecx
	cmpq	%rdx, %rcx
	jbe	.L110
	.p2align 4,,2
	jmp	.L116
	.p2align 4,,10
	.p2align 3
.L121:
	movq	%rbp, %rsi
	movq	%rsp, %rdi
	call	Final
	addq	$296, %rsp
	popq	%rbx
	popq	%rbp
	ret
	.cfi_endproc
.LFE534:
	.size	T.44, .-T.44
	.p2align 4,,15
.globl crypto_hash_echo256_pentium_pentium4v64v2
	.type	crypto_hash_echo256_pentium_pentium4v64v2, @function
crypto_hash_echo256_pentium_pentium4v64v2:
.LFB533:
	.cfi_startproc
	movq	%rdi, %rax
	movq	%rsi, %rdi
	leaq	0(,%rdx,8), %rsi
	subq	$8, %rsp
	.cfi_def_cfa_offset 16
	movq	%rax, %rdx
	call	T.44
	cmpl	$1, %eax
	sbbl	%eax, %eax
	addq	$8, %rsp
	notl	%eax
	ret
	.cfi_endproc
.LFE533:
	.size	crypto_hash_echo256_pentium_pentium4v64v2, .-crypto_hash_echo256_pentium_pentium4v64v2
	.p2align 4,,15
.globl Hash
	.type	Hash, @function
Hash:
.LFB532:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	movq	%rcx, %rbp
	.cfi_offset 6, -16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	subq	$296, %rsp
	.cfi_def_cfa_offset 320
	movq	SHA3_S+280(%rip), %rcx
	movq	%rsp, %rbx
	.cfi_offset 3, -24
	testq	%rcx, %rcx
	je	.L128
	cmpq	%rsp, %rcx
	je	.L128
	testb	$15, %cl
	je	.L147
.L129:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L132:
	movq	SHA3_S(%rax), %r8
	movq	%r8, (%rcx,%rax)
	addq	$8, %rax
	cmpq	$288, %rax
	jne	.L132
	.p2align 4,,10
	.p2align 3
.L128:
	leal	-160(%rdi), %ecx
	movq	%rbx, SHA3_S+280(%rip)
	movl	$-16843010, MEM_CST(%rip)
	movl	$-16843010, MEM_CST+4(%rip)
	movl	$-16843010, MEM_CST+8(%rip)
	movl	$2, %eax
	cmpl	$352, %ecx
	movl	$-16843010, MEM_CST+12(%rip)
	movl	$16843009, MEM_CST+16(%rip)
	movl	$16843009, MEM_CST+20(%rip)
	movl	$16843009, MEM_CST+24(%rip)
	movl	$16843009, MEM_CST+28(%rip)
	movl	$1769499, MEM_CST+32(%rip)
	movl	$1769499, MEM_CST+36(%rip)
	movl	$1769499, MEM_CST+40(%rip)
	movl	$1769499, MEM_CST+44(%rip)
	movl	$1, MEM_CST+48(%rip)
	movl	$0, MEM_CST+52(%rip)
	movl	$0, MEM_CST+56(%rip)
	movl	$0, MEM_CST+60(%rip)
	ja	.L134
	xorl	%eax, %eax
	cmpl	$257, %edi
	movl	%edi, SHA3_S+268(%rip)
	setge	%al
	movslq	%edi,%rdi
	movl	$SHA3_S, %ecx
	leal	4(,%rax,4), %eax
	xorl	%r8d, %r8d
	movl	%eax, SHA3_S+272(%rip)
	.p2align 4,,10
	.p2align 3
.L136:
	addl	$1, %r8d
	movq	%rdi, (%rcx)
	movq	$0, 8(%rcx)
	addq	$16, %rcx
	cmpl	%eax, %r8d
	jl	.L136
	cmpl	$15, %eax
	jg	.L138
	addl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L139:
	movslq	%eax,%rcx
	movq	$0, SHA3_S(,%rcx,8)
	leal	1(%rax), %ecx
	addl	$2, %eax
	cmpl	$32, %eax
	movslq	%ecx,%rcx
	movq	$0, SHA3_S(,%rcx,8)
	jne	.L139
.L138:
	movq	%rsp, %rdi
	movq	$0, SHA3_S+256(%rip)
	movl	$0, SHA3_S+264(%rip)
	call	Update
	testl	%eax, %eax
	je	.L148
.L134:
	addq	$296, %rsp
	popq	%rbx
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L147:
	cmpq	$SHA3_S+16, %rcx
	jbe	.L149
.L141:
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L131:
	movdqa	SHA3_S(%rax), %xmm0
	movdqa	%xmm0, (%rcx,%rax)
	addq	$16, %rax
	cmpq	$288, %rax
	jne	.L131
	jmp	.L128
	.p2align 4,,10
	.p2align 3
.L148:
	movq	%rbp, %rsi
	movq	%rsp, %rdi
	call	Final
	addq	$296, %rsp
	popq	%rbx
	popq	%rbp
	ret
.L149:
	leaq	16(%rcx), %rax
	movl	$SHA3_S, %r8d
	cmpq	%rax, %r8
	jbe	.L129
	jmp	.L141
	.cfi_endproc
.LFE532:
	.size	Hash, .-Hash
.globl Te
	.data
	.align 32
	.type	Te, @object
	.size	Te, 2048
Te:
	.quad	-6529265329927658554
	.quad	-8900101356774458120
	.quad	-7388304797017344018
	.quad	-8251865593360450570
	.quad	1005132844121649919
	.quad	-4797622407988024362
	.quad	-5661183204331130914
	.quad	6108505697581122961
	.quad	5778171512136675424
	.quad	216455365242454274
	.quad	-6239904621395482674
	.quad	9019350329206713174
	.quad	1873214763559747303
	.quad	7122398509757093813
	.quad	-1825176872897762483
	.quad	-7316529786040977684
	.quad	5029054650612632207
	.quad	-7096966990484307425
	.quad	4668484080080898441
	.quad	-8683645991532003846
	.quad	1583854123747048175
	.quad	-1488059576881686094
	.quad	-3943104270151759986
	.quad	860452489855561979
	.quad	-1392266211132330687
	.quad	7481838747975472307
	.quad	-170395302725770657
	.quad	-1535816233085063355
	.quad	-4639661838745953245
	.quad	-602175769616800685
	.quad	-7605890494573153564
	.quad	6611496026471710875
	.quad	-4415859193207605387
	.quad	2089104945465654753
	.quad	-5867183996402429123
	.quad	7648843126775621196
	.quad	6500442951153759852
	.quad	4701546347491180414
	.quad	213912139012241397
	.quad	5750195688596884611
	.quad	6643992973106492520
	.quad	-818065985882446511
	.quad	3811705346337400273
	.quad	644562273589916153
	.quad	-7822345859815607838
	.quad	8347660140225812651
	.quad	5994626877379129698
	.quad	4545562670091539754
	.quad	865821460969817096
	.quad	5964955675628390293
	.quad	7287707407267078982
	.quad	6828516540690973597
	.quad	2889085756068337712
	.quad	-6803085021418187209
	.quad	1082276826212271370
	.quad	-5360802876730205649
	.quad	650496428040718094
	.quad	3896196574364176932
	.quad	-7241647344750395365
	.quad	4459376029494076127
	.quad	2804594459322084301
	.quad	7577068115799254862
	.quad	-3624638488098196865
	.quad	-6956524398845790742
	.quad	1948098287182088466
	.quad	-7024626830531132643
	.quad	8371114565792705624
	.quad	3321996486553246260
	.quad	3250221475576879926
	.quad	-5589408193354764580
	.quad	-1271604211639231820
	.quad	-315075656991858597
	.quad	-697404123828301148
	.quad	5565107143834286966
	.quad	7050058349803919031
	.quad	-3552298328145022083
	.quad	8874669974940625234
	.quad	4531716189447250909
	.quad	8155789532863606622
	.quad	-7528747457375337453
	.quad	-769179134804667482
	.quad	7553048644334768569
	.quad	0
	.quad	3237505121087516097
	.quad	6926571687758536768
	.quad	2304995161731300579
	.quad	-3985209058629930631
	.quad	-1343379222615598154
	.quad	-4725847397011658028
	.quad	5101394810565806989
	.quad	-2756556568660099481
	.quad	5420426789568199026
	.quad	-2429047045767935340
	.quad	-3149057820158309224
	.quad	-1704514942124140368
	.quad	5390755450378506117
	.quad	7768938860600414395
	.quad	3093955099134783429
	.quad	-1897517032850937265
	.quad	1656194283700222957
	.quad	-4232464978683935866
	.quad	-2932602454915854950
	.quad	6139307231645217638
	.quad	-7744637673640983279
	.quad	-3511323871980206710
	.quad	1223283553215314409
	.quad	432910730484908548
	.quad	-9115426389703557122
	.quad	-1130314854313209696
	.quad	4916871380420279416
	.quad	-4999102076964331739
	.quad	-2042197387117025205
	.quad	-913859489070755422
	.quad	-98055142772595875
	.quad	-4593600698192478080
	.quad	-8462387920843600123
	.quad	-5939524156355603905
	.quad	-4855552055011599071
	.quad	5203971424325744752
	.quad	357462160964974065
	.quad	-2324776170488546205
	.quad	-4488199353160780169
	.quad	8492340494491900591
	.quad	7143027053000991042
	.quad	3463285843879268384
	.quad	1945554923512922085
	.quad	1077473004074824701
	.quad	7913619214866502335
	.quad	5534305472331238785
	.quad	1444542878034168856
	.quad	3824421563387810598
	.quad	3453395337353161923
	.quad	-2206940018958704706
	.quad	-6730744861465012427
	.quad	-3727779237222660984
	.quad	4113782271919986478
	.quad	6324395913846768787
	.quad	-961616007835179179
	.quad	-9043651378727190788
	.quad	5133326745662733690
	.quad	-6024579588466383672
	.quad	-1775159620787151430
	.quad	3105541121310791986
	.quad	-7677665505549519898
	.quad	-6890401049436200768
	.quad	-7457537561016041191
	.quad	-3364382853087408226
	.quad	9213481532476152995
	.quad	7359482418243445316
	.quad	9091125340183079508
	.quad	-6084204510621691845
	.quad	-8968769074875561973
	.quad	-3871329259175393652
	.quad	3021614939181608647
	.quad	-3190597562738886549
	.quad	4329107304849085480
	.quad	8781701134304599719
	.quad	-2135165007982338372
	.quad	2092778641448176406
	.quad	8564680654445075373
	.quad	4314695675227988187
	.quad	6211082242621583972
	.quad	5636882154810653300
	.quad	2164553652424542740
	.quad	-2645502411010389614
	.quad	722271439017084428
	.quad	7792393148728353864
	.quad	-1991614986029605704
	.quad	6756176380737798815
	.quad	7985959374819677117
	.quad	-1176375994866684861
	.quad	-6457490318951292220
	.quad	-6300094726887337671
	.quad	-6587194839512279759
	.quad	4027595562603046099
	.quad	-8396545947626538510
	.quad	3668155324384667605
	.quad	4884374296346544267
	.quad	6428667940177393518
	.quad	-5229402806159577638
	.quad	-8318837898890867455
	.quad	7265948531709826481
	.quad	-3292607842111041892
	.quad	-2258087603382671031
	.quad	-5445858171402031912
	.quad	-408043415296125268
	.quad	573352377230619891
	.quad	2732254299368909519
	.quad	-5808124223223929398
	.quad	-8180090582384084236
	.quad	-1608156393038238137
	.quad	1731642921939634192
	.quad	-3045917208472798609
	.quad	-8613001312868992784
	.quad	8008848513970808138
	.quad	8227564543839972956
	.quad	2601985712162872376
	.quad	-1033956167788353961
	.quad	-4056418954989226893
	.quad	5892615515675215511
	.quad	2587573945102821579
	.quad	8997591316210507169
	.quad	-7172979764088245016
	.quad	2386660679233773374
	.quad	-2500822056744301674
	.quad	-2540666386754192031
	.quad	-8751748560656299251
	.quad	-8824088720609474033
	.quad	-8038801225058062112
	.quad	4773321358467546748
	.quad	-4272309171254872719
	.quad	-6168129610419116340
	.quad	-2861957776252843888
	.quad	361135719508542214
	.quad	141571979059066615
	.quad	1300992856081436188
	.quad	-6673945684193746494
	.quad	6860448338348946794
	.quad	-479818426272491602
	.quad	-3406487779004532375
	.quad	-7960527855546890729
	.quad	6395605810206065049
	.quad	2818441077405326650
	.quad	-5071442236917506521
	.quad	4098805458962342361
	.quad	1439173769480960235
	.quad	-5505483230996293589
	.quad	3679741209121722658
	.quad	-4942302762254112302
	.quad	8131769923960166825
	.quad	-8534728080796774905
	.quad	-6371304623246633933
	.quad	-5288462716777030867
	.quad	2458435690210139708
	.quad	-7888187695593715947
	.quad	2371683728837175753
	.quad	5318415290425331335
	.quad	-48038028100938326
	.quad	8658214609698170960
	.quad	8854041294257774501
	.quad	-8102947682625221629
	.quad	-530965873257504423
	.quad	-9184659291141207799
	.quad	1660998243276623130
	.quad	-2684216408706924699
	.quad	3595815164431492823
	.quad	-4160689967707569532
	.quad	-5158758127496566576
	.quad	-4377145332950023806
	.quad	-5721373447261939415
	.quad	8587569931035159898
	.quad	1229217845105069854
	.quad	-3769318842364284805
	.quad	-264493393343392600
	.quad	-2973577048519623827
	.quad	4185557282896352812
	.comm	OLDCV,64,32
	.comm	MEM_CST,64,32
	.comm	SHA3_CNT,8,8
	.comm	SHA3_RSP,8,8
	.comm	SHA3_EAX,4,4
	.comm	SHA3_EBX,4,4
	.comm	SHA3_ECX,4,4
	.comm	SHA3_EDX,4,4
	.comm	SHA3_ESI,4,4
	.comm	SHA3_EDI,4,4
	.comm	SHA3_EBP,4,4
	.comm	SHA3_R,4,4
	.comm	SHA3_S,288,32
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC0:
	.quad	256
	.quad	0
	.ident	"GCC: (Debian 4.4.3-3) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
