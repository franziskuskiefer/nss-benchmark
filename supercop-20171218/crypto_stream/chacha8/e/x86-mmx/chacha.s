
# qhasm: stack32 arg1

# qhasm: stack32 arg2

# qhasm: stack32 arg3

# qhasm: stack32 arg4

# qhasm: input arg1

# qhasm: input arg2

# qhasm: input arg3

# qhasm: input arg4

# qhasm: int32 eax

# qhasm: int32 ebx

# qhasm: int32 esi

# qhasm: int32 edi

# qhasm: int32 ebp

# qhasm: caller eax

# qhasm: caller ebx

# qhasm: caller esi

# qhasm: caller edi

# qhasm: caller ebp

# qhasm: int32 k

# qhasm: int32 kbits

# qhasm: int32 iv

# qhasm: int32 i

# qhasm: stack32 x_backup

# qhasm: int32 x

# qhasm: stack32 m_backup

# qhasm: int32 m

# qhasm: stack32 out_backup

# qhasm: int32 out

# qhasm: stack32 bytes_backup

# qhasm: int32 bytes

# qhasm: stack32 eax_stack

# qhasm: stack32 ebx_stack

# qhasm: stack32 esi_stack

# qhasm: stack32 edi_stack

# qhasm: stack32 ebp_stack

# qhasm: int32 a

# qhasm: int32 in0

# qhasm: int32 in1

# qhasm: int32 in2

# qhasm: int32 in3

# qhasm: int32 in4

# qhasm: int32 in5

# qhasm: int32 in6

# qhasm: int32 in7

# qhasm: int32 in8

# qhasm: int32 in9

# qhasm: int32 in10

# qhasm: int32 in11

# qhasm: int32 in12

# qhasm: int32 in13

# qhasm: int32 in14

# qhasm: int32 in15

# qhasm: int32 i0

# qhasm: int32 i1

# qhasm: int32 i2

# qhasm: int32 i3

# qhasm: int32 i4

# qhasm: int32 i5

# qhasm: int32 i6

# qhasm: int32 i7

# qhasm: int32 i8

# qhasm: int32 i9

# qhasm: int32 i10

# qhasm: int32 i11

# qhasm: int32 i12

# qhasm: int32 i13

# qhasm: int32 i14

# qhasm: int32 i15

# qhasm: stack32 x0

# qhasm: int3232 x1

# qhasm: int3232 x2

# qhasm: stack32 x3

# qhasm: stack32 x4

# qhasm: stack32 x5

# qhasm: int3232 x6

# qhasm: int3232 x7

# qhasm: stack32 x8

# qhasm: stack32 x9

# qhasm: stack32 x10

# qhasm: int3232 x11

# qhasm: int3232 x12

# qhasm: stack32 x13

# qhasm: stack32 x14

# qhasm: stack32 x15

# qhasm: stack32 j0

# qhasm: stack32 j1

# qhasm: stack32 j2

# qhasm: stack32 j3

# qhasm: stack32 j4

# qhasm: stack32 j5

# qhasm: stack32 j6

# qhasm: stack32 j7

# qhasm: stack32 j8

# qhasm: stack32 j9

# qhasm: stack32 j10

# qhasm: stack32 j11

# qhasm: stack32 j12

# qhasm: stack32 j13

# qhasm: stack32 j14

# qhasm: stack32 j15

# qhasm: stack512 tmp

# qhasm: stack32 ctarget

# qhasm: enter crypto_stream_chacha8_e_x86_mmx_ECRYPT_keystream_bytes
.text
.p2align 5
.globl _crypto_stream_chacha8_e_x86_mmx_ECRYPT_keystream_bytes
.globl crypto_stream_chacha8_e_x86_mmx_ECRYPT_keystream_bytes
_crypto_stream_chacha8_e_x86_mmx_ECRYPT_keystream_bytes:
crypto_stream_chacha8_e_x86_mmx_ECRYPT_keystream_bytes:
mov %esp,%eax
and $31,%eax
add $224,%eax
sub %eax,%esp

# qhasm: eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm: ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm: esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm: edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm: ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm: x = arg1
# asm 1: movl <arg1=stack32#-1,>x=int32#3
# asm 2: movl <arg1=4(%esp,%eax),>x=%edx
movl 4(%esp,%eax),%edx

# qhasm: m = arg2
# asm 1: movl <arg2=stack32#-2,>m=int32#5
# asm 2: movl <arg2=8(%esp,%eax),>m=%esi
movl 8(%esp,%eax),%esi

# qhasm: out = m
# asm 1: mov  <m=int32#5,>out=int32#6
# asm 2: mov  <m=%esi,>out=%edi
mov  %esi,%edi

# qhasm: bytes = arg3
# asm 1: movl <arg3=stack32#-3,>bytes=int32#4
# asm 2: movl <arg3=12(%esp,%eax),>bytes=%ebx
movl 12(%esp,%eax),%ebx

# qhasm:               unsigned>? bytes - 0
# asm 1: cmp  $0,<bytes=int32#4
# asm 2: cmp  $0,<bytes=%ebx
cmp  $0,%ebx
# comment:fp stack unchanged by jump

# qhasm: goto done if !unsigned>
jbe ._done

# qhasm: a = 0
# asm 1: mov  $0,>a=int32#1
# asm 2: mov  $0,>a=%eax
mov  $0,%eax

# qhasm: i = bytes
# asm 1: mov  <bytes=int32#4,>i=int32#2
# asm 2: mov  <bytes=%ebx,>i=%ecx
mov  %ebx,%ecx

# qhasm: while (i) { *out++ = a; --i }
rep stosb

# qhasm: out -= bytes
# asm 1: subl <bytes=int32#4,<out=int32#6
# asm 2: subl <bytes=%ebx,<out=%edi
subl %ebx,%edi
# comment:fp stack unchanged by jump

# qhasm: goto start
jmp ._start

# qhasm: enter crypto_stream_chacha8_e_x86_mmx_ECRYPT_decrypt_bytes
.text
.p2align 5
.globl _crypto_stream_chacha8_e_x86_mmx_ECRYPT_decrypt_bytes
.globl crypto_stream_chacha8_e_x86_mmx_ECRYPT_decrypt_bytes
_crypto_stream_chacha8_e_x86_mmx_ECRYPT_decrypt_bytes:
crypto_stream_chacha8_e_x86_mmx_ECRYPT_decrypt_bytes:
mov %esp,%eax
and $31,%eax
add $224,%eax
sub %eax,%esp

# qhasm: eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm: ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm: esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm: edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm: ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm: x = arg1
# asm 1: movl <arg1=stack32#-1,>x=int32#3
# asm 2: movl <arg1=4(%esp,%eax),>x=%edx
movl 4(%esp,%eax),%edx

# qhasm: m = arg2
# asm 1: movl <arg2=stack32#-2,>m=int32#5
# asm 2: movl <arg2=8(%esp,%eax),>m=%esi
movl 8(%esp,%eax),%esi

# qhasm: out = arg3
# asm 1: movl <arg3=stack32#-3,>out=int32#6
# asm 2: movl <arg3=12(%esp,%eax),>out=%edi
movl 12(%esp,%eax),%edi

# qhasm: bytes = arg4
# asm 1: movl <arg4=stack32#-4,>bytes=int32#4
# asm 2: movl <arg4=16(%esp,%eax),>bytes=%ebx
movl 16(%esp,%eax),%ebx

# qhasm:               unsigned>? bytes - 0
# asm 1: cmp  $0,<bytes=int32#4
# asm 2: cmp  $0,<bytes=%ebx
cmp  $0,%ebx
# comment:fp stack unchanged by jump

# qhasm: goto done if !unsigned>
jbe ._done
# comment:fp stack unchanged by jump

# qhasm: goto start
jmp ._start

# qhasm: enter crypto_stream_chacha8_e_x86_mmx_ECRYPT_encrypt_bytes
.text
.p2align 5
.globl _crypto_stream_chacha8_e_x86_mmx_ECRYPT_encrypt_bytes
.globl crypto_stream_chacha8_e_x86_mmx_ECRYPT_encrypt_bytes
_crypto_stream_chacha8_e_x86_mmx_ECRYPT_encrypt_bytes:
crypto_stream_chacha8_e_x86_mmx_ECRYPT_encrypt_bytes:
mov %esp,%eax
and $31,%eax
add $224,%eax
sub %eax,%esp

# qhasm: eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm: ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm: esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm: edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm: ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm: x = arg1
# asm 1: movl <arg1=stack32#-1,>x=int32#3
# asm 2: movl <arg1=4(%esp,%eax),>x=%edx
movl 4(%esp,%eax),%edx

# qhasm: m = arg2
# asm 1: movl <arg2=stack32#-2,>m=int32#5
# asm 2: movl <arg2=8(%esp,%eax),>m=%esi
movl 8(%esp,%eax),%esi

# qhasm: out = arg3
# asm 1: movl <arg3=stack32#-3,>out=int32#6
# asm 2: movl <arg3=12(%esp,%eax),>out=%edi
movl 12(%esp,%eax),%edi

# qhasm: bytes = arg4
# asm 1: movl <arg4=stack32#-4,>bytes=int32#4
# asm 2: movl <arg4=16(%esp,%eax),>bytes=%ebx
movl 16(%esp,%eax),%ebx

# qhasm:               unsigned>? bytes - 0
# asm 1: cmp  $0,<bytes=int32#4
# asm 2: cmp  $0,<bytes=%ebx
cmp  $0,%ebx
# comment:fp stack unchanged by jump

# qhasm: goto done if !unsigned>
jbe ._done
# comment:fp stack unchanged by fallthrough

# qhasm: start:
._start:

# qhasm: in0 = *(uint32 *) (x + 0)
# asm 1: movl 0(<x=int32#3),>in0=int32#1
# asm 2: movl 0(<x=%edx),>in0=%eax
movl 0(%edx),%eax

# qhasm: in1 = *(uint32 *) (x + 4)
# asm 1: movl 4(<x=int32#3),>in1=int32#2
# asm 2: movl 4(<x=%edx),>in1=%ecx
movl 4(%edx),%ecx

# qhasm: in2 = *(uint32 *) (x + 8)
# asm 1: movl 8(<x=int32#3),>in2=int32#7
# asm 2: movl 8(<x=%edx),>in2=%ebp
movl 8(%edx),%ebp

# qhasm: j0 = in0
# asm 1: movl <in0=int32#1,>j0=stack32#6
# asm 2: movl <in0=%eax,>j0=20(%esp)
movl %eax,20(%esp)

# qhasm: in3 = *(uint32 *) (x + 12)
# asm 1: movl 12(<x=int32#3),>in3=int32#1
# asm 2: movl 12(<x=%edx),>in3=%eax
movl 12(%edx),%eax

# qhasm: j1 = in1
# asm 1: movl <in1=int32#2,>j1=stack32#7
# asm 2: movl <in1=%ecx,>j1=24(%esp)
movl %ecx,24(%esp)

# qhasm: in4 = *(uint32 *) (x + 16)
# asm 1: movl 16(<x=int32#3),>in4=int32#2
# asm 2: movl 16(<x=%edx),>in4=%ecx
movl 16(%edx),%ecx

# qhasm: j2 = in2
# asm 1: movl <in2=int32#7,>j2=stack32#8
# asm 2: movl <in2=%ebp,>j2=28(%esp)
movl %ebp,28(%esp)

# qhasm: in5 = *(uint32 *) (x + 20)
# asm 1: movl 20(<x=int32#3),>in5=int32#7
# asm 2: movl 20(<x=%edx),>in5=%ebp
movl 20(%edx),%ebp

# qhasm: j3 = in3
# asm 1: movl <in3=int32#1,>j3=stack32#9
# asm 2: movl <in3=%eax,>j3=32(%esp)
movl %eax,32(%esp)

# qhasm: in6 = *(uint32 *) (x + 24)
# asm 1: movl 24(<x=int32#3),>in6=int32#1
# asm 2: movl 24(<x=%edx),>in6=%eax
movl 24(%edx),%eax

# qhasm: j4 = in4
# asm 1: movl <in4=int32#2,>j4=stack32#10
# asm 2: movl <in4=%ecx,>j4=36(%esp)
movl %ecx,36(%esp)

# qhasm: in7 = *(uint32 *) (x + 28)
# asm 1: movl 28(<x=int32#3),>in7=int32#2
# asm 2: movl 28(<x=%edx),>in7=%ecx
movl 28(%edx),%ecx

# qhasm: j5 = in5
# asm 1: movl <in5=int32#7,>j5=stack32#11
# asm 2: movl <in5=%ebp,>j5=40(%esp)
movl %ebp,40(%esp)

# qhasm: in8 = *(uint32 *) (x + 32)
# asm 1: movl 32(<x=int32#3),>in8=int32#7
# asm 2: movl 32(<x=%edx),>in8=%ebp
movl 32(%edx),%ebp

# qhasm: j6 = in6
# asm 1: movl <in6=int32#1,>j6=stack32#12
# asm 2: movl <in6=%eax,>j6=44(%esp)
movl %eax,44(%esp)

# qhasm: in9 = *(uint32 *) (x + 36)
# asm 1: movl 36(<x=int32#3),>in9=int32#1
# asm 2: movl 36(<x=%edx),>in9=%eax
movl 36(%edx),%eax

# qhasm: j7 = in7
# asm 1: movl <in7=int32#2,>j7=stack32#13
# asm 2: movl <in7=%ecx,>j7=48(%esp)
movl %ecx,48(%esp)

# qhasm: in10 = *(uint32 *) (x + 40)
# asm 1: movl 40(<x=int32#3),>in10=int32#2
# asm 2: movl 40(<x=%edx),>in10=%ecx
movl 40(%edx),%ecx

# qhasm: j8 = in8
# asm 1: movl <in8=int32#7,>j8=stack32#14
# asm 2: movl <in8=%ebp,>j8=52(%esp)
movl %ebp,52(%esp)

# qhasm: in11 = *(uint32 *) (x + 44)
# asm 1: movl 44(<x=int32#3),>in11=int32#7
# asm 2: movl 44(<x=%edx),>in11=%ebp
movl 44(%edx),%ebp

# qhasm: j9 = in9
# asm 1: movl <in9=int32#1,>j9=stack32#15
# asm 2: movl <in9=%eax,>j9=56(%esp)
movl %eax,56(%esp)

# qhasm: in12 = *(uint32 *) (x + 48)
# asm 1: movl 48(<x=int32#3),>in12=int32#1
# asm 2: movl 48(<x=%edx),>in12=%eax
movl 48(%edx),%eax

# qhasm: j10 = in10
# asm 1: movl <in10=int32#2,>j10=stack32#16
# asm 2: movl <in10=%ecx,>j10=60(%esp)
movl %ecx,60(%esp)

# qhasm: in13 = *(uint32 *) (x + 52)
# asm 1: movl 52(<x=int32#3),>in13=int32#2
# asm 2: movl 52(<x=%edx),>in13=%ecx
movl 52(%edx),%ecx

# qhasm: j11 = in11
# asm 1: movl <in11=int32#7,>j11=stack32#17
# asm 2: movl <in11=%ebp,>j11=64(%esp)
movl %ebp,64(%esp)

# qhasm: in14 = *(uint32 *) (x + 56)
# asm 1: movl 56(<x=int32#3),>in14=int32#7
# asm 2: movl 56(<x=%edx),>in14=%ebp
movl 56(%edx),%ebp

# qhasm: j12 = in12
# asm 1: movl <in12=int32#1,>j12=stack32#18
# asm 2: movl <in12=%eax,>j12=68(%esp)
movl %eax,68(%esp)

# qhasm: in15 = *(uint32 *) (x + 60)
# asm 1: movl 60(<x=int32#3),>in15=int32#1
# asm 2: movl 60(<x=%edx),>in15=%eax
movl 60(%edx),%eax

# qhasm: j13 = in13
# asm 1: movl <in13=int32#2,>j13=stack32#19
# asm 2: movl <in13=%ecx,>j13=72(%esp)
movl %ecx,72(%esp)

# qhasm: j14 = in14
# asm 1: movl <in14=int32#7,>j14=stack32#20
# asm 2: movl <in14=%ebp,>j14=76(%esp)
movl %ebp,76(%esp)

# qhasm: j15 = in15
# asm 1: movl <in15=int32#1,>j15=stack32#21
# asm 2: movl <in15=%eax,>j15=80(%esp)
movl %eax,80(%esp)

# qhasm: x_backup = x
# asm 1: movl <x=int32#3,>x_backup=stack32#22
# asm 2: movl <x=%edx,>x_backup=84(%esp)
movl %edx,84(%esp)

# qhasm: bytesatleast1:
._bytesatleast1:

# qhasm:                   unsigned<? bytes - 64
# asm 1: cmp  $64,<bytes=int32#4
# asm 2: cmp  $64,<bytes=%ebx
cmp  $64,%ebx
# comment:fp stack unchanged by jump

# qhasm:   goto nocopy if !unsigned<
jae ._nocopy

# qhasm:     ctarget = out
# asm 1: movl <out=int32#6,>ctarget=stack32#23
# asm 2: movl <out=%edi,>ctarget=88(%esp)
movl %edi,88(%esp)

# qhasm:     out = &tmp
# asm 1: leal <tmp=stack512#1,>out=int32#6
# asm 2: leal <tmp=160(%esp),>out=%edi
leal 160(%esp),%edi

# qhasm:     i = bytes
# asm 1: mov  <bytes=int32#4,>i=int32#2
# asm 2: mov  <bytes=%ebx,>i=%ecx
mov  %ebx,%ecx

# qhasm:     while (i) { *out++ = *m++; --i }
rep movsb

# qhasm:     out = &tmp
# asm 1: leal <tmp=stack512#1,>out=int32#6
# asm 2: leal <tmp=160(%esp),>out=%edi
leal 160(%esp),%edi

# qhasm:     m = &tmp
# asm 1: leal <tmp=stack512#1,>m=int32#5
# asm 2: leal <tmp=160(%esp),>m=%esi
leal 160(%esp),%esi
# comment:fp stack unchanged by fallthrough

# qhasm:   nocopy:
._nocopy:

# qhasm:   out_backup = out
# asm 1: movl <out=int32#6,>out_backup=stack32#24
# asm 2: movl <out=%edi,>out_backup=92(%esp)
movl %edi,92(%esp)

# qhasm:   m_backup = m
# asm 1: movl <m=int32#5,>m_backup=stack32#25
# asm 2: movl <m=%esi,>m_backup=96(%esp)
movl %esi,96(%esp)

# qhasm:   bytes_backup = bytes
# asm 1: movl <bytes=int32#4,>bytes_backup=stack32#26
# asm 2: movl <bytes=%ebx,>bytes_backup=100(%esp)
movl %ebx,100(%esp)

# qhasm:   in0 = j0
# asm 1: movl <j0=stack32#6,>in0=int32#1
# asm 2: movl <j0=20(%esp),>in0=%eax
movl 20(%esp),%eax

# qhasm:   in1 = j1
# asm 1: movl <j1=stack32#7,>in1=int32#2
# asm 2: movl <j1=24(%esp),>in1=%ecx
movl 24(%esp),%ecx

# qhasm:   in2 = j2
# asm 1: movl <j2=stack32#8,>in2=int32#3
# asm 2: movl <j2=28(%esp),>in2=%edx
movl 28(%esp),%edx

# qhasm:   in3 = j3
# asm 1: movl <j3=stack32#9,>in3=int32#4
# asm 2: movl <j3=32(%esp),>in3=%ebx
movl 32(%esp),%ebx

# qhasm:   x0 = in0
# asm 1: movl <in0=int32#1,>x0=stack32#27
# asm 2: movl <in0=%eax,>x0=104(%esp)
movl %eax,104(%esp)

# qhasm:   x1 = in1
# asm 1: movd <in1=int32#2,>x1=int3232#1
# asm 2: movd <in1=%ecx,>x1=%mm0
movd %ecx,%mm0

# qhasm:   x2 = in2
# asm 1: movd <in2=int32#3,>x2=int3232#2
# asm 2: movd <in2=%edx,>x2=%mm1
movd %edx,%mm1

# qhasm:   x3 = in3
# asm 1: movl <in3=int32#4,>x3=stack32#28
# asm 2: movl <in3=%ebx,>x3=108(%esp)
movl %ebx,108(%esp)

# qhasm:   in4 = j4
# asm 1: movl <j4=stack32#10,>in4=int32#1
# asm 2: movl <j4=36(%esp),>in4=%eax
movl 36(%esp),%eax

# qhasm:   in5 = j5
# asm 1: movl <j5=stack32#11,>in5=int32#2
# asm 2: movl <j5=40(%esp),>in5=%ecx
movl 40(%esp),%ecx

# qhasm:   in6 = j6
# asm 1: movl <j6=stack32#12,>in6=int32#3
# asm 2: movl <j6=44(%esp),>in6=%edx
movl 44(%esp),%edx

# qhasm:   in7 = j7
# asm 1: movl <j7=stack32#13,>in7=int32#4
# asm 2: movl <j7=48(%esp),>in7=%ebx
movl 48(%esp),%ebx

# qhasm:   x4 = in4
# asm 1: movl <in4=int32#1,>x4=stack32#29
# asm 2: movl <in4=%eax,>x4=112(%esp)
movl %eax,112(%esp)

# qhasm:   x5 = in5
# asm 1: movl <in5=int32#2,>x5=stack32#30
# asm 2: movl <in5=%ecx,>x5=116(%esp)
movl %ecx,116(%esp)

# qhasm:   x6 = in6
# asm 1: movd <in6=int32#3,>x6=int3232#3
# asm 2: movd <in6=%edx,>x6=%mm2
movd %edx,%mm2

# qhasm:   x7 = in7
# asm 1: movd <in7=int32#4,>x7=int3232#4
# asm 2: movd <in7=%ebx,>x7=%mm3
movd %ebx,%mm3

# qhasm:   in8 = j8
# asm 1: movl <j8=stack32#14,>in8=int32#1
# asm 2: movl <j8=52(%esp),>in8=%eax
movl 52(%esp),%eax

# qhasm:   in9 = j9
# asm 1: movl <j9=stack32#15,>in9=int32#2
# asm 2: movl <j9=56(%esp),>in9=%ecx
movl 56(%esp),%ecx

# qhasm:   in10 = j10
# asm 1: movl <j10=stack32#16,>in10=int32#3
# asm 2: movl <j10=60(%esp),>in10=%edx
movl 60(%esp),%edx

# qhasm:   in11 = j11
# asm 1: movl <j11=stack32#17,>in11=int32#4
# asm 2: movl <j11=64(%esp),>in11=%ebx
movl 64(%esp),%ebx

# qhasm:   x8 = in8
# asm 1: movl <in8=int32#1,>x8=stack32#31
# asm 2: movl <in8=%eax,>x8=120(%esp)
movl %eax,120(%esp)

# qhasm:   x9 = in9
# asm 1: movl <in9=int32#2,>x9=stack32#32
# asm 2: movl <in9=%ecx,>x9=124(%esp)
movl %ecx,124(%esp)

# qhasm:   x10 = in10
# asm 1: movl <in10=int32#3,>x10=stack32#33
# asm 2: movl <in10=%edx,>x10=128(%esp)
movl %edx,128(%esp)

# qhasm:   x11 = in11
# asm 1: movd <in11=int32#4,>x11=int3232#5
# asm 2: movd <in11=%ebx,>x11=%mm4
movd %ebx,%mm4

# qhasm:   in12 = j12
# asm 1: movl <j12=stack32#18,>in12=int32#1
# asm 2: movl <j12=68(%esp),>in12=%eax
movl 68(%esp),%eax

# qhasm:   in13 = j13
# asm 1: movl <j13=stack32#19,>in13=int32#2
# asm 2: movl <j13=72(%esp),>in13=%ecx
movl 72(%esp),%ecx

# qhasm:   in14 = j14
# asm 1: movl <j14=stack32#20,>in14=int32#3
# asm 2: movl <j14=76(%esp),>in14=%edx
movl 76(%esp),%edx

# qhasm:   in15 = j15
# asm 1: movl <j15=stack32#21,>in15=int32#4
# asm 2: movl <j15=80(%esp),>in15=%ebx
movl 80(%esp),%ebx

# qhasm:   x12 = in12
# asm 1: movd <in12=int32#1,>x12=int3232#6
# asm 2: movd <in12=%eax,>x12=%mm5
movd %eax,%mm5

# qhasm:   x13 = in13
# asm 1: movl <in13=int32#2,>x13=stack32#34
# asm 2: movl <in13=%ecx,>x13=132(%esp)
movl %ecx,132(%esp)

# qhasm:   x14 = in14
# asm 1: movl <in14=int32#3,>x14=stack32#35
# asm 2: movl <in14=%edx,>x14=136(%esp)
movl %edx,136(%esp)

# qhasm:   x15 = in15
# asm 1: movl <in15=int32#4,>x15=stack32#36
# asm 2: movl <in15=%ebx,>x15=140(%esp)
movl %ebx,140(%esp)

# qhasm:   i = 8
# asm 1: mov  $8,>i=int32#1
# asm 2: mov  $8,>i=%eax
mov  $8,%eax

# qhasm:   mainloop:
._mainloop:

# qhasm: i0 = x0
# asm 1: movl <x0=stack32#27,>i0=int32#2
# asm 2: movl <x0=104(%esp),>i0=%ecx
movl 104(%esp),%ecx

# qhasm: i4 = x4
# asm 1: movl <x4=stack32#29,>i4=int32#3
# asm 2: movl <x4=112(%esp),>i4=%edx
movl 112(%esp),%edx

# qhasm: i0 += i4
# asm 1: addl <i4=int32#3,<i0=int32#2
# asm 2: addl <i4=%edx,<i0=%ecx
addl %edx,%ecx

# qhasm: i12 = x12
# asm 1: movd <x12=int3232#6,>i12=int32#4
# asm 2: movd <x12=%mm5,>i12=%ebx
movd %mm5,%ebx

# qhasm: i12 ^= i0
# asm 1: xorl <i0=int32#2,<i12=int32#4
# asm 2: xorl <i0=%ecx,<i12=%ebx
xorl %ecx,%ebx

# qhasm: i12 <<<= 16
# asm 1: rol  $16,<i12=int32#4
# asm 2: rol  $16,<i12=%ebx
rol  $16,%ebx

# qhasm: i8 = x8
# asm 1: movl <x8=stack32#31,>i8=int32#5
# asm 2: movl <x8=120(%esp),>i8=%esi
movl 120(%esp),%esi

# qhasm: i8 += i12
# asm 1: addl <i12=int32#4,<i8=int32#5
# asm 2: addl <i12=%ebx,<i8=%esi
addl %ebx,%esi

# qhasm: i4 ^= i8
# asm 1: xorl <i8=int32#5,<i4=int32#3
# asm 2: xorl <i8=%esi,<i4=%edx
xorl %esi,%edx

# qhasm: i4 <<<= 12
# asm 1: rol  $12,<i4=int32#3
# asm 2: rol  $12,<i4=%edx
rol  $12,%edx

# qhasm: i0 += i4
# asm 1: addl <i4=int32#3,<i0=int32#2
# asm 2: addl <i4=%edx,<i0=%ecx
addl %edx,%ecx

# qhasm: x0 = i0
# asm 1: movl <i0=int32#2,>x0=stack32#27
# asm 2: movl <i0=%ecx,>x0=104(%esp)
movl %ecx,104(%esp)

# qhasm: i12 ^= i0
# asm 1: xorl <i0=int32#2,<i12=int32#4
# asm 2: xorl <i0=%ecx,<i12=%ebx
xorl %ecx,%ebx

# qhasm: 		i1 = x1
# asm 1: movd <x1=int3232#1,>i1=int32#2
# asm 2: movd <x1=%mm0,>i1=%ecx
movd %mm0,%ecx

# qhasm: 		i5 = x5
# asm 1: movl <x5=stack32#30,>i5=int32#6
# asm 2: movl <x5=116(%esp),>i5=%edi
movl 116(%esp),%edi

# qhasm: 		i1 += i5
# asm 1: addl <i5=int32#6,<i1=int32#2
# asm 2: addl <i5=%edi,<i1=%ecx
addl %edi,%ecx

# qhasm: 		i13 = x13
# asm 1: movl <x13=stack32#34,>i13=int32#7
# asm 2: movl <x13=132(%esp),>i13=%ebp
movl 132(%esp),%ebp

# qhasm: 		i13 ^= i1
# asm 1: xorl <i1=int32#2,<i13=int32#7
# asm 2: xorl <i1=%ecx,<i13=%ebp
xorl %ecx,%ebp

# qhasm: 		i13 <<<= 16
# asm 1: rol  $16,<i13=int32#7
# asm 2: rol  $16,<i13=%ebp
rol  $16,%ebp

# qhasm: i12 <<<= 8
# asm 1: rol  $8,<i12=int32#4
# asm 2: rol  $8,<i12=%ebx
rol  $8,%ebx

# qhasm: x12 = i12
# asm 1: movd <i12=int32#4,>x12=int3232#1
# asm 2: movd <i12=%ebx,>x12=%mm0
movd %ebx,%mm0

# qhasm: i8 += i12
# asm 1: addl <i12=int32#4,<i8=int32#5
# asm 2: addl <i12=%ebx,<i8=%esi
addl %ebx,%esi

# qhasm: 		i9 = x9
# asm 1: movl <x9=stack32#32,>i9=int32#4
# asm 2: movl <x9=124(%esp),>i9=%ebx
movl 124(%esp),%ebx

# qhasm: 		i9 += i13
# asm 1: addl <i13=int32#7,<i9=int32#4
# asm 2: addl <i13=%ebp,<i9=%ebx
addl %ebp,%ebx

# qhasm: 		i5 ^= i9
# asm 1: xorl <i9=int32#4,<i5=int32#6
# asm 2: xorl <i9=%ebx,<i5=%edi
xorl %ebx,%edi

# qhasm: 		i5 <<<= 12
# asm 1: rol  $12,<i5=int32#6
# asm 2: rol  $12,<i5=%edi
rol  $12,%edi

# qhasm: 		i1 += i5
# asm 1: addl <i5=int32#6,<i1=int32#2
# asm 2: addl <i5=%edi,<i1=%ecx
addl %edi,%ecx

# qhasm: 		x1 = i1
# asm 1: movd <i1=int32#2,>x1=int3232#6
# asm 2: movd <i1=%ecx,>x1=%mm5
movd %ecx,%mm5

# qhasm: 		i13 ^= i1
# asm 1: xorl <i1=int32#2,<i13=int32#7
# asm 2: xorl <i1=%ecx,<i13=%ebp
xorl %ecx,%ebp

# qhasm: x8 = i8
# asm 1: movl <i8=int32#5,>x8=stack32#29
# asm 2: movl <i8=%esi,>x8=112(%esp)
movl %esi,112(%esp)

# qhasm: i4 ^= i8
# asm 1: xorl <i8=int32#5,<i4=int32#3
# asm 2: xorl <i8=%esi,<i4=%edx
xorl %esi,%edx

# qhasm: i4 <<<= 7
# asm 1: rol  $7,<i4=int32#3
# asm 2: rol  $7,<i4=%edx
rol  $7,%edx

# qhasm: x4 = i4
# asm 1: movl <i4=int32#3,>x4=stack32#31
# asm 2: movl <i4=%edx,>x4=120(%esp)
movl %edx,120(%esp)

# qhasm: 				i2 = x2
# asm 1: movd <x2=int3232#2,>i2=int32#2
# asm 2: movd <x2=%mm1,>i2=%ecx
movd %mm1,%ecx

# qhasm: 				i6 = x6
# asm 1: movd <x6=int3232#3,>i6=int32#3
# asm 2: movd <x6=%mm2,>i6=%edx
movd %mm2,%edx

# qhasm: 				i2 += i6
# asm 1: addl <i6=int32#3,<i2=int32#2
# asm 2: addl <i6=%edx,<i2=%ecx
addl %edx,%ecx

# qhasm: 				i14 = x14
# asm 1: movl <x14=stack32#35,>i14=int32#5
# asm 2: movl <x14=136(%esp),>i14=%esi
movl 136(%esp),%esi

# qhasm: 				i14 ^= i2
# asm 1: xorl <i2=int32#2,<i14=int32#5
# asm 2: xorl <i2=%ecx,<i14=%esi
xorl %ecx,%esi

# qhasm: 				i14 <<<= 16
# asm 1: rol  $16,<i14=int32#5
# asm 2: rol  $16,<i14=%esi
rol  $16,%esi

# qhasm: 		i13 <<<= 8
# asm 1: rol  $8,<i13=int32#7
# asm 2: rol  $8,<i13=%ebp
rol  $8,%ebp

# qhasm: 		x13 = i13
# asm 1: movl <i13=int32#7,>x13=stack32#32
# asm 2: movl <i13=%ebp,>x13=124(%esp)
movl %ebp,124(%esp)

# qhasm: 		i9 += i13
# asm 1: addl <i13=int32#7,<i9=int32#4
# asm 2: addl <i13=%ebp,<i9=%ebx
addl %ebp,%ebx

# qhasm: 				i10 = x10
# asm 1: movl <x10=stack32#33,>i10=int32#7
# asm 2: movl <x10=128(%esp),>i10=%ebp
movl 128(%esp),%ebp

# qhasm: 				i10 += i14
# asm 1: addl <i14=int32#5,<i10=int32#7
# asm 2: addl <i14=%esi,<i10=%ebp
addl %esi,%ebp

# qhasm: 				i6 ^= i10
# asm 1: xorl <i10=int32#7,<i6=int32#3
# asm 2: xorl <i10=%ebp,<i6=%edx
xorl %ebp,%edx

# qhasm: 				i6 <<<= 12
# asm 1: rol  $12,<i6=int32#3
# asm 2: rol  $12,<i6=%edx
rol  $12,%edx

# qhasm: 				i2 += i6
# asm 1: addl <i6=int32#3,<i2=int32#2
# asm 2: addl <i6=%edx,<i2=%ecx
addl %edx,%ecx

# qhasm: 				x2 = i2
# asm 1: movd <i2=int32#2,>x2=int3232#2
# asm 2: movd <i2=%ecx,>x2=%mm1
movd %ecx,%mm1

# qhasm: 				i14 ^= i2
# asm 1: xorl <i2=int32#2,<i14=int32#5
# asm 2: xorl <i2=%ecx,<i14=%esi
xorl %ecx,%esi

# qhasm: 		x9 = i9
# asm 1: movl <i9=int32#4,>x9=stack32#35
# asm 2: movl <i9=%ebx,>x9=136(%esp)
movl %ebx,136(%esp)

# qhasm: 		i5 ^= i9
# asm 1: xorl <i9=int32#4,<i5=int32#6
# asm 2: xorl <i9=%ebx,<i5=%edi
xorl %ebx,%edi

# qhasm: 		i5 <<<= 7
# asm 1: rol  $7,<i5=int32#6
# asm 2: rol  $7,<i5=%edi
rol  $7,%edi

# qhasm: 		x5 = i5
# asm 1: movl <i5=int32#6,>x5=stack32#30
# asm 2: movl <i5=%edi,>x5=116(%esp)
movl %edi,116(%esp)

# qhasm: 						i3 = x3
# asm 1: movl <x3=stack32#28,>i3=int32#2
# asm 2: movl <x3=108(%esp),>i3=%ecx
movl 108(%esp),%ecx

# qhasm: 						i7 = x7
# asm 1: movd <x7=int3232#4,>i7=int32#4
# asm 2: movd <x7=%mm3,>i7=%ebx
movd %mm3,%ebx

# qhasm: 						i3 += i7
# asm 1: addl <i7=int32#4,<i3=int32#2
# asm 2: addl <i7=%ebx,<i3=%ecx
addl %ebx,%ecx

# qhasm: 						i15 = x15
# asm 1: movl <x15=stack32#36,>i15=int32#6
# asm 2: movl <x15=140(%esp),>i15=%edi
movl 140(%esp),%edi

# qhasm: 						i15 ^= i3
# asm 1: xorl <i3=int32#2,<i15=int32#6
# asm 2: xorl <i3=%ecx,<i15=%edi
xorl %ecx,%edi

# qhasm: 						i15 <<<= 16
# asm 1: rol  $16,<i15=int32#6
# asm 2: rol  $16,<i15=%edi
rol  $16,%edi

# qhasm: 				i14 <<<= 8
# asm 1: rol  $8,<i14=int32#5
# asm 2: rol  $8,<i14=%esi
rol  $8,%esi

# qhasm: 				x14 = i14
# asm 1: movl <i14=int32#5,>x14=stack32#28
# asm 2: movl <i14=%esi,>x14=108(%esp)
movl %esi,108(%esp)

# qhasm: 				i10 += i14
# asm 1: addl <i14=int32#5,<i10=int32#7
# asm 2: addl <i14=%esi,<i10=%ebp
addl %esi,%ebp

# qhasm: 						i11 = x11
# asm 1: movd <x11=int3232#5,>i11=int32#5
# asm 2: movd <x11=%mm4,>i11=%esi
movd %mm4,%esi

# qhasm: 						i11 += i15
# asm 1: addl <i15=int32#6,<i11=int32#5
# asm 2: addl <i15=%edi,<i11=%esi
addl %edi,%esi

# qhasm: 						i7 ^= i11
# asm 1: xorl <i11=int32#5,<i7=int32#4
# asm 2: xorl <i11=%esi,<i7=%ebx
xorl %esi,%ebx

# qhasm: 						i7 <<<= 12
# asm 1: rol  $12,<i7=int32#4
# asm 2: rol  $12,<i7=%ebx
rol  $12,%ebx

# qhasm: 						i3 += i7
# asm 1: addl <i7=int32#4,<i3=int32#2
# asm 2: addl <i7=%ebx,<i3=%ecx
addl %ebx,%ecx

# qhasm: 						x3 = i3
# asm 1: movl <i3=int32#2,>x3=stack32#34
# asm 2: movl <i3=%ecx,>x3=132(%esp)
movl %ecx,132(%esp)

# qhasm: 						i15 ^= i3
# asm 1: xorl <i3=int32#2,<i15=int32#6
# asm 2: xorl <i3=%ecx,<i15=%edi
xorl %ecx,%edi

# qhasm: 						i15 <<<= 8
# asm 1: rol  $8,<i15=int32#6
# asm 2: rol  $8,<i15=%edi
rol  $8,%edi

# qhasm: 						i11 += i15
# asm 1: addl <i15=int32#6,<i11=int32#5
# asm 2: addl <i15=%edi,<i11=%esi
addl %edi,%esi

# qhasm: 						x11 = i11
# asm 1: movd <i11=int32#5,>x11=int3232#3
# asm 2: movd <i11=%esi,>x11=%mm2
movd %esi,%mm2

# qhasm: 						i7 ^= i11
# asm 1: xorl <i11=int32#5,<i7=int32#4
# asm 2: xorl <i11=%esi,<i7=%ebx
xorl %esi,%ebx

# qhasm: 						i7 <<<= 7
# asm 1: rol  $7,<i7=int32#4
# asm 2: rol  $7,<i7=%ebx
rol  $7,%ebx

# qhasm: 						x7 = i7
# asm 1: movd <i7=int32#4,>x7=int3232#4
# asm 2: movd <i7=%ebx,>x7=%mm3
movd %ebx,%mm3

# qhasm: 				x10 = i10
# asm 1: movl <i10=int32#7,>x10=stack32#33
# asm 2: movl <i10=%ebp,>x10=128(%esp)
movl %ebp,128(%esp)

# qhasm: 				i6 ^= i10
# asm 1: xorl <i10=int32#7,<i6=int32#3
# asm 2: xorl <i10=%ebp,<i6=%edx
xorl %ebp,%edx

# qhasm: 				i6 <<<= 7
# asm 1: rol  $7,<i6=int32#3
# asm 2: rol  $7,<i6=%edx
rol  $7,%edx

# qhasm: i0 = x0
# asm 1: movl <x0=stack32#27,>i0=int32#2
# asm 2: movl <x0=104(%esp),>i0=%ecx
movl 104(%esp),%ecx

# qhasm: i5 = x5
# asm 1: movl <x5=stack32#30,>i5=int32#4
# asm 2: movl <x5=116(%esp),>i5=%ebx
movl 116(%esp),%ebx

# qhasm: i0 += i5
# asm 1: addl <i5=int32#4,<i0=int32#2
# asm 2: addl <i5=%ebx,<i0=%ecx
addl %ebx,%ecx

# qhasm: i15 ^= i0
# asm 1: xorl <i0=int32#2,<i15=int32#6
# asm 2: xorl <i0=%ecx,<i15=%edi
xorl %ecx,%edi

# qhasm: i15 <<<= 16
# asm 1: rol  $16,<i15=int32#6
# asm 2: rol  $16,<i15=%edi
rol  $16,%edi

# qhasm: i10 = x10
# asm 1: movl <x10=stack32#33,>i10=int32#5
# asm 2: movl <x10=128(%esp),>i10=%esi
movl 128(%esp),%esi

# qhasm: i10 += i15
# asm 1: addl <i15=int32#6,<i10=int32#5
# asm 2: addl <i15=%edi,<i10=%esi
addl %edi,%esi

# qhasm: i5 ^= i10
# asm 1: xorl <i10=int32#5,<i5=int32#4
# asm 2: xorl <i10=%esi,<i5=%ebx
xorl %esi,%ebx

# qhasm: i5 <<<= 12
# asm 1: rol  $12,<i5=int32#4
# asm 2: rol  $12,<i5=%ebx
rol  $12,%ebx

# qhasm: i0 += i5
# asm 1: addl <i5=int32#4,<i0=int32#2
# asm 2: addl <i5=%ebx,<i0=%ecx
addl %ebx,%ecx

# qhasm: x0 = i0
# asm 1: movl <i0=int32#2,>x0=stack32#27
# asm 2: movl <i0=%ecx,>x0=104(%esp)
movl %ecx,104(%esp)

# qhasm: i15 ^= i0
# asm 1: xorl <i0=int32#2,<i15=int32#6
# asm 2: xorl <i0=%ecx,<i15=%edi
xorl %ecx,%edi

# qhasm: 		i1 = x1
# asm 1: movd <x1=int3232#6,>i1=int32#2
# asm 2: movd <x1=%mm5,>i1=%ecx
movd %mm5,%ecx

# qhasm: 		i1 += i6
# asm 1: addl <i6=int32#3,<i1=int32#2
# asm 2: addl <i6=%edx,<i1=%ecx
addl %edx,%ecx

# qhasm: 		i12 = x12
# asm 1: movd <x12=int3232#1,>i12=int32#7
# asm 2: movd <x12=%mm0,>i12=%ebp
movd %mm0,%ebp

# qhasm: 		i12 ^= i1
# asm 1: xorl <i1=int32#2,<i12=int32#7
# asm 2: xorl <i1=%ecx,<i12=%ebp
xorl %ecx,%ebp

# qhasm: 		i12 <<<= 16
# asm 1: rol  $16,<i12=int32#7
# asm 2: rol  $16,<i12=%ebp
rol  $16,%ebp

# qhasm: i15 <<<= 8
# asm 1: rol  $8,<i15=int32#6
# asm 2: rol  $8,<i15=%edi
rol  $8,%edi

# qhasm: x15 = i15
# asm 1: movl <i15=int32#6,>x15=stack32#36
# asm 2: movl <i15=%edi,>x15=140(%esp)
movl %edi,140(%esp)

# qhasm: i10 += i15
# asm 1: addl <i15=int32#6,<i10=int32#5
# asm 2: addl <i15=%edi,<i10=%esi
addl %edi,%esi

# qhasm: 		i11 = x11
# asm 1: movd <x11=int3232#3,>i11=int32#6
# asm 2: movd <x11=%mm2,>i11=%edi
movd %mm2,%edi

# qhasm: 		i11 += i12
# asm 1: addl <i12=int32#7,<i11=int32#6
# asm 2: addl <i12=%ebp,<i11=%edi
addl %ebp,%edi

# qhasm: 		i6 ^= i11
# asm 1: xorl <i11=int32#6,<i6=int32#3
# asm 2: xorl <i11=%edi,<i6=%edx
xorl %edi,%edx

# qhasm: 		i6 <<<= 12
# asm 1: rol  $12,<i6=int32#3
# asm 2: rol  $12,<i6=%edx
rol  $12,%edx

# qhasm: 		i1 += i6
# asm 1: addl <i6=int32#3,<i1=int32#2
# asm 2: addl <i6=%edx,<i1=%ecx
addl %edx,%ecx

# qhasm: 		x1 = i1
# asm 1: movd <i1=int32#2,>x1=int3232#1
# asm 2: movd <i1=%ecx,>x1=%mm0
movd %ecx,%mm0

# qhasm: 		i12 ^= i1
# asm 1: xorl <i1=int32#2,<i12=int32#7
# asm 2: xorl <i1=%ecx,<i12=%ebp
xorl %ecx,%ebp

# qhasm: x10 = i10
# asm 1: movl <i10=int32#5,>x10=stack32#33
# asm 2: movl <i10=%esi,>x10=128(%esp)
movl %esi,128(%esp)

# qhasm: i5 ^= i10
# asm 1: xorl <i10=int32#5,<i5=int32#4
# asm 2: xorl <i10=%esi,<i5=%ebx
xorl %esi,%ebx

# qhasm: i5 <<<= 7
# asm 1: rol  $7,<i5=int32#4
# asm 2: rol  $7,<i5=%ebx
rol  $7,%ebx

# qhasm: x5 = i5
# asm 1: movl <i5=int32#4,>x5=stack32#30
# asm 2: movl <i5=%ebx,>x5=116(%esp)
movl %ebx,116(%esp)

# qhasm: 				i2 = x2
# asm 1: movd <x2=int3232#2,>i2=int32#2
# asm 2: movd <x2=%mm1,>i2=%ecx
movd %mm1,%ecx

# qhasm: 				i7 = x7
# asm 1: movd <x7=int3232#4,>i7=int32#4
# asm 2: movd <x7=%mm3,>i7=%ebx
movd %mm3,%ebx

# qhasm: 				i2 += i7
# asm 1: addl <i7=int32#4,<i2=int32#2
# asm 2: addl <i7=%ebx,<i2=%ecx
addl %ebx,%ecx

# qhasm: 				i13 = x13
# asm 1: movl <x13=stack32#32,>i13=int32#5
# asm 2: movl <x13=124(%esp),>i13=%esi
movl 124(%esp),%esi

# qhasm: 				i13 ^= i2
# asm 1: xorl <i2=int32#2,<i13=int32#5
# asm 2: xorl <i2=%ecx,<i13=%esi
xorl %ecx,%esi

# qhasm: 				i13 <<<= 16
# asm 1: rol  $16,<i13=int32#5
# asm 2: rol  $16,<i13=%esi
rol  $16,%esi

# qhasm: 		i12 <<<= 8
# asm 1: rol  $8,<i12=int32#7
# asm 2: rol  $8,<i12=%ebp
rol  $8,%ebp

# qhasm: 		x12 = i12
# asm 1: movd <i12=int32#7,>x12=int3232#6
# asm 2: movd <i12=%ebp,>x12=%mm5
movd %ebp,%mm5

# qhasm: 		i11 += i12
# asm 1: addl <i12=int32#7,<i11=int32#6
# asm 2: addl <i12=%ebp,<i11=%edi
addl %ebp,%edi

# qhasm: 				i8 = x8
# asm 1: movl <x8=stack32#29,>i8=int32#7
# asm 2: movl <x8=112(%esp),>i8=%ebp
movl 112(%esp),%ebp

# qhasm: 				i8 += i13
# asm 1: addl <i13=int32#5,<i8=int32#7
# asm 2: addl <i13=%esi,<i8=%ebp
addl %esi,%ebp

# qhasm: 				i7 ^= i8
# asm 1: xorl <i8=int32#7,<i7=int32#4
# asm 2: xorl <i8=%ebp,<i7=%ebx
xorl %ebp,%ebx

# qhasm: 				i7 <<<= 12
# asm 1: rol  $12,<i7=int32#4
# asm 2: rol  $12,<i7=%ebx
rol  $12,%ebx

# qhasm: 				i2 += i7
# asm 1: addl <i7=int32#4,<i2=int32#2
# asm 2: addl <i7=%ebx,<i2=%ecx
addl %ebx,%ecx

# qhasm: 				x2 = i2
# asm 1: movd <i2=int32#2,>x2=int3232#2
# asm 2: movd <i2=%ecx,>x2=%mm1
movd %ecx,%mm1

# qhasm: 				i13 ^= i2
# asm 1: xorl <i2=int32#2,<i13=int32#5
# asm 2: xorl <i2=%ecx,<i13=%esi
xorl %ecx,%esi

# qhasm: 		x11 = i11
# asm 1: movd <i11=int32#6,>x11=int3232#5
# asm 2: movd <i11=%edi,>x11=%mm4
movd %edi,%mm4

# qhasm: 		i6 ^= i11
# asm 1: xorl <i11=int32#6,<i6=int32#3
# asm 2: xorl <i11=%edi,<i6=%edx
xorl %edi,%edx

# qhasm: 		i6 <<<= 7
# asm 1: rol  $7,<i6=int32#3
# asm 2: rol  $7,<i6=%edx
rol  $7,%edx

# qhasm: 		x6 = i6
# asm 1: movd <i6=int32#3,>x6=int3232#3
# asm 2: movd <i6=%edx,>x6=%mm2
movd %edx,%mm2

# qhasm: 						i3 = x3
# asm 1: movl <x3=stack32#34,>i3=int32#2
# asm 2: movl <x3=132(%esp),>i3=%ecx
movl 132(%esp),%ecx

# qhasm: 						i4 = x4
# asm 1: movl <x4=stack32#31,>i4=int32#3
# asm 2: movl <x4=120(%esp),>i4=%edx
movl 120(%esp),%edx

# qhasm: 						i3 += i4
# asm 1: addl <i4=int32#3,<i3=int32#2
# asm 2: addl <i4=%edx,<i3=%ecx
addl %edx,%ecx

# qhasm: 						i14 = x14
# asm 1: movl <x14=stack32#28,>i14=int32#6
# asm 2: movl <x14=108(%esp),>i14=%edi
movl 108(%esp),%edi

# qhasm: 						i14 ^= i3
# asm 1: xorl <i3=int32#2,<i14=int32#6
# asm 2: xorl <i3=%ecx,<i14=%edi
xorl %ecx,%edi

# qhasm: 						i14 <<<= 16
# asm 1: rol  $16,<i14=int32#6
# asm 2: rol  $16,<i14=%edi
rol  $16,%edi

# qhasm: 				i13 <<<= 8
# asm 1: rol  $8,<i13=int32#5
# asm 2: rol  $8,<i13=%esi
rol  $8,%esi

# qhasm: 				x13 = i13
# asm 1: movl <i13=int32#5,>x13=stack32#34
# asm 2: movl <i13=%esi,>x13=132(%esp)
movl %esi,132(%esp)

# qhasm: 				i8 += i13
# asm 1: addl <i13=int32#5,<i8=int32#7
# asm 2: addl <i13=%esi,<i8=%ebp
addl %esi,%ebp

# qhasm: 						i9 = x9
# asm 1: movl <x9=stack32#35,>i9=int32#5
# asm 2: movl <x9=136(%esp),>i9=%esi
movl 136(%esp),%esi

# qhasm: 						i9 += i14
# asm 1: addl <i14=int32#6,<i9=int32#5
# asm 2: addl <i14=%edi,<i9=%esi
addl %edi,%esi

# qhasm: 						i4 ^= i9
# asm 1: xorl <i9=int32#5,<i4=int32#3
# asm 2: xorl <i9=%esi,<i4=%edx
xorl %esi,%edx

# qhasm: 						i4 <<<= 12
# asm 1: rol  $12,<i4=int32#3
# asm 2: rol  $12,<i4=%edx
rol  $12,%edx

# qhasm: 						i3 += i4
# asm 1: addl <i4=int32#3,<i3=int32#2
# asm 2: addl <i4=%edx,<i3=%ecx
addl %edx,%ecx

# qhasm: 						x3 = i3
# asm 1: movl <i3=int32#2,>x3=stack32#28
# asm 2: movl <i3=%ecx,>x3=108(%esp)
movl %ecx,108(%esp)

# qhasm: 						i14 ^= i3
# asm 1: xorl <i3=int32#2,<i14=int32#6
# asm 2: xorl <i3=%ecx,<i14=%edi
xorl %ecx,%edi

# qhasm: 						i14 <<<= 8
# asm 1: rol  $8,<i14=int32#6
# asm 2: rol  $8,<i14=%edi
rol  $8,%edi

# qhasm: 						x14 = i14
# asm 1: movl <i14=int32#6,>x14=stack32#35
# asm 2: movl <i14=%edi,>x14=136(%esp)
movl %edi,136(%esp)

# qhasm: 						i9 += i14
# asm 1: addl <i14=int32#6,<i9=int32#5
# asm 2: addl <i14=%edi,<i9=%esi
addl %edi,%esi

# qhasm: 				x8 = i8
# asm 1: movl <i8=int32#7,>x8=stack32#31
# asm 2: movl <i8=%ebp,>x8=120(%esp)
movl %ebp,120(%esp)

# qhasm: 				i7 ^= i8
# asm 1: xorl <i8=int32#7,<i7=int32#4
# asm 2: xorl <i8=%ebp,<i7=%ebx
xorl %ebp,%ebx

# qhasm: 				i7 <<<= 7
# asm 1: rol  $7,<i7=int32#4
# asm 2: rol  $7,<i7=%ebx
rol  $7,%ebx

# qhasm: 				x7 = i7
# asm 1: movd <i7=int32#4,>x7=int3232#4
# asm 2: movd <i7=%ebx,>x7=%mm3
movd %ebx,%mm3

# qhasm: 						x9 = i9
# asm 1: movl <i9=int32#5,>x9=stack32#32
# asm 2: movl <i9=%esi,>x9=124(%esp)
movl %esi,124(%esp)

# qhasm: 						i4 ^= i9
# asm 1: xorl <i9=int32#5,<i4=int32#3
# asm 2: xorl <i9=%esi,<i4=%edx
xorl %esi,%edx

# qhasm: 						i4 <<<= 7
# asm 1: rol  $7,<i4=int32#3
# asm 2: rol  $7,<i4=%edx
rol  $7,%edx

# qhasm: 						x4 = i4
# asm 1: movl <i4=int32#3,>x4=stack32#29
# asm 2: movl <i4=%edx,>x4=112(%esp)
movl %edx,112(%esp)

# qhasm:                  unsigned>? i -= 2
# asm 1: sub  $2,<i=int32#1
# asm 2: sub  $2,<i=%eax
sub  $2,%eax
# comment:fp stack unchanged by jump

# qhasm: goto mainloop if unsigned>
ja ._mainloop

# qhasm:   out = out_backup
# asm 1: movl <out_backup=stack32#24,>out=int32#6
# asm 2: movl <out_backup=92(%esp),>out=%edi
movl 92(%esp),%edi

# qhasm:   m = m_backup
# asm 1: movl <m_backup=stack32#25,>m=int32#5
# asm 2: movl <m_backup=96(%esp),>m=%esi
movl 96(%esp),%esi

# qhasm:   in0 = x0
# asm 1: movl <x0=stack32#27,>in0=int32#1
# asm 2: movl <x0=104(%esp),>in0=%eax
movl 104(%esp),%eax

# qhasm:   in1 = x1
# asm 1: movd <x1=int3232#1,>in1=int32#2
# asm 2: movd <x1=%mm0,>in1=%ecx
movd %mm0,%ecx

# qhasm:   in0 += j0
# asm 1: addl <j0=stack32#6,<in0=int32#1
# asm 2: addl <j0=20(%esp),<in0=%eax
addl 20(%esp),%eax

# qhasm:   in1 += j1
# asm 1: addl <j1=stack32#7,<in1=int32#2
# asm 2: addl <j1=24(%esp),<in1=%ecx
addl 24(%esp),%ecx

# qhasm:   in0 ^= *(uint32 *) (m + 0)
# asm 1: xorl 0(<m=int32#5),<in0=int32#1
# asm 2: xorl 0(<m=%esi),<in0=%eax
xorl 0(%esi),%eax

# qhasm:   in1 ^= *(uint32 *) (m + 4)
# asm 1: xorl 4(<m=int32#5),<in1=int32#2
# asm 2: xorl 4(<m=%esi),<in1=%ecx
xorl 4(%esi),%ecx

# qhasm:   *(uint32 *) (out + 0) = in0
# asm 1: movl <in0=int32#1,0(<out=int32#6)
# asm 2: movl <in0=%eax,0(<out=%edi)
movl %eax,0(%edi)

# qhasm:   *(uint32 *) (out + 4) = in1
# asm 1: movl <in1=int32#2,4(<out=int32#6)
# asm 2: movl <in1=%ecx,4(<out=%edi)
movl %ecx,4(%edi)

# qhasm:   in2 = x2
# asm 1: movd <x2=int3232#2,>in2=int32#1
# asm 2: movd <x2=%mm1,>in2=%eax
movd %mm1,%eax

# qhasm:   in3 = x3
# asm 1: movl <x3=stack32#28,>in3=int32#2
# asm 2: movl <x3=108(%esp),>in3=%ecx
movl 108(%esp),%ecx

# qhasm:   in2 += j2
# asm 1: addl <j2=stack32#8,<in2=int32#1
# asm 2: addl <j2=28(%esp),<in2=%eax
addl 28(%esp),%eax

# qhasm:   in3 += j3
# asm 1: addl <j3=stack32#9,<in3=int32#2
# asm 2: addl <j3=32(%esp),<in3=%ecx
addl 32(%esp),%ecx

# qhasm:   in2 ^= *(uint32 *) (m + 8)
# asm 1: xorl 8(<m=int32#5),<in2=int32#1
# asm 2: xorl 8(<m=%esi),<in2=%eax
xorl 8(%esi),%eax

# qhasm:   in3 ^= *(uint32 *) (m + 12)
# asm 1: xorl 12(<m=int32#5),<in3=int32#2
# asm 2: xorl 12(<m=%esi),<in3=%ecx
xorl 12(%esi),%ecx

# qhasm:   *(uint32 *) (out + 8) = in2
# asm 1: movl <in2=int32#1,8(<out=int32#6)
# asm 2: movl <in2=%eax,8(<out=%edi)
movl %eax,8(%edi)

# qhasm:   *(uint32 *) (out + 12) = in3
# asm 1: movl <in3=int32#2,12(<out=int32#6)
# asm 2: movl <in3=%ecx,12(<out=%edi)
movl %ecx,12(%edi)

# qhasm:   in4 = x4
# asm 1: movl <x4=stack32#29,>in4=int32#1
# asm 2: movl <x4=112(%esp),>in4=%eax
movl 112(%esp),%eax

# qhasm:   in5 = x5
# asm 1: movl <x5=stack32#30,>in5=int32#2
# asm 2: movl <x5=116(%esp),>in5=%ecx
movl 116(%esp),%ecx

# qhasm:   in4 += j4
# asm 1: addl <j4=stack32#10,<in4=int32#1
# asm 2: addl <j4=36(%esp),<in4=%eax
addl 36(%esp),%eax

# qhasm:   in5 += j5
# asm 1: addl <j5=stack32#11,<in5=int32#2
# asm 2: addl <j5=40(%esp),<in5=%ecx
addl 40(%esp),%ecx

# qhasm:   in4 ^= *(uint32 *) (m + 16)
# asm 1: xorl 16(<m=int32#5),<in4=int32#1
# asm 2: xorl 16(<m=%esi),<in4=%eax
xorl 16(%esi),%eax

# qhasm:   in5 ^= *(uint32 *) (m + 20)
# asm 1: xorl 20(<m=int32#5),<in5=int32#2
# asm 2: xorl 20(<m=%esi),<in5=%ecx
xorl 20(%esi),%ecx

# qhasm:   *(uint32 *) (out + 16) = in4
# asm 1: movl <in4=int32#1,16(<out=int32#6)
# asm 2: movl <in4=%eax,16(<out=%edi)
movl %eax,16(%edi)

# qhasm:   *(uint32 *) (out + 20) = in5
# asm 1: movl <in5=int32#2,20(<out=int32#6)
# asm 2: movl <in5=%ecx,20(<out=%edi)
movl %ecx,20(%edi)

# qhasm:   in6 = x6
# asm 1: movd <x6=int3232#3,>in6=int32#1
# asm 2: movd <x6=%mm2,>in6=%eax
movd %mm2,%eax

# qhasm:   in7 = x7
# asm 1: movd <x7=int3232#4,>in7=int32#2
# asm 2: movd <x7=%mm3,>in7=%ecx
movd %mm3,%ecx

# qhasm:   in6 += j6
# asm 1: addl <j6=stack32#12,<in6=int32#1
# asm 2: addl <j6=44(%esp),<in6=%eax
addl 44(%esp),%eax

# qhasm:   in7 += j7
# asm 1: addl <j7=stack32#13,<in7=int32#2
# asm 2: addl <j7=48(%esp),<in7=%ecx
addl 48(%esp),%ecx

# qhasm:   in6 ^= *(uint32 *) (m + 24)
# asm 1: xorl 24(<m=int32#5),<in6=int32#1
# asm 2: xorl 24(<m=%esi),<in6=%eax
xorl 24(%esi),%eax

# qhasm:   in7 ^= *(uint32 *) (m + 28)
# asm 1: xorl 28(<m=int32#5),<in7=int32#2
# asm 2: xorl 28(<m=%esi),<in7=%ecx
xorl 28(%esi),%ecx

# qhasm:   *(uint32 *) (out + 24) = in6
# asm 1: movl <in6=int32#1,24(<out=int32#6)
# asm 2: movl <in6=%eax,24(<out=%edi)
movl %eax,24(%edi)

# qhasm:   *(uint32 *) (out + 28) = in7
# asm 1: movl <in7=int32#2,28(<out=int32#6)
# asm 2: movl <in7=%ecx,28(<out=%edi)
movl %ecx,28(%edi)

# qhasm:   in8 = x8
# asm 1: movl <x8=stack32#31,>in8=int32#1
# asm 2: movl <x8=120(%esp),>in8=%eax
movl 120(%esp),%eax

# qhasm:   in9 = x9
# asm 1: movl <x9=stack32#32,>in9=int32#2
# asm 2: movl <x9=124(%esp),>in9=%ecx
movl 124(%esp),%ecx

# qhasm:   in8 += j8
# asm 1: addl <j8=stack32#14,<in8=int32#1
# asm 2: addl <j8=52(%esp),<in8=%eax
addl 52(%esp),%eax

# qhasm:   in9 += j9
# asm 1: addl <j9=stack32#15,<in9=int32#2
# asm 2: addl <j9=56(%esp),<in9=%ecx
addl 56(%esp),%ecx

# qhasm:   in8 ^= *(uint32 *) (m + 32)
# asm 1: xorl 32(<m=int32#5),<in8=int32#1
# asm 2: xorl 32(<m=%esi),<in8=%eax
xorl 32(%esi),%eax

# qhasm:   in9 ^= *(uint32 *) (m + 36)
# asm 1: xorl 36(<m=int32#5),<in9=int32#2
# asm 2: xorl 36(<m=%esi),<in9=%ecx
xorl 36(%esi),%ecx

# qhasm:   *(uint32 *) (out + 32) = in8
# asm 1: movl <in8=int32#1,32(<out=int32#6)
# asm 2: movl <in8=%eax,32(<out=%edi)
movl %eax,32(%edi)

# qhasm:   *(uint32 *) (out + 36) = in9
# asm 1: movl <in9=int32#2,36(<out=int32#6)
# asm 2: movl <in9=%ecx,36(<out=%edi)
movl %ecx,36(%edi)

# qhasm:   in10 = x10
# asm 1: movl <x10=stack32#33,>in10=int32#1
# asm 2: movl <x10=128(%esp),>in10=%eax
movl 128(%esp),%eax

# qhasm:   in11 = x11
# asm 1: movd <x11=int3232#5,>in11=int32#2
# asm 2: movd <x11=%mm4,>in11=%ecx
movd %mm4,%ecx

# qhasm:   in10 += j10
# asm 1: addl <j10=stack32#16,<in10=int32#1
# asm 2: addl <j10=60(%esp),<in10=%eax
addl 60(%esp),%eax

# qhasm:   in11 += j11
# asm 1: addl <j11=stack32#17,<in11=int32#2
# asm 2: addl <j11=64(%esp),<in11=%ecx
addl 64(%esp),%ecx

# qhasm:   in10 ^= *(uint32 *) (m + 40)
# asm 1: xorl 40(<m=int32#5),<in10=int32#1
# asm 2: xorl 40(<m=%esi),<in10=%eax
xorl 40(%esi),%eax

# qhasm:   in11 ^= *(uint32 *) (m + 44)
# asm 1: xorl 44(<m=int32#5),<in11=int32#2
# asm 2: xorl 44(<m=%esi),<in11=%ecx
xorl 44(%esi),%ecx

# qhasm:   *(uint32 *) (out + 40) = in10
# asm 1: movl <in10=int32#1,40(<out=int32#6)
# asm 2: movl <in10=%eax,40(<out=%edi)
movl %eax,40(%edi)

# qhasm:   *(uint32 *) (out + 44) = in11
# asm 1: movl <in11=int32#2,44(<out=int32#6)
# asm 2: movl <in11=%ecx,44(<out=%edi)
movl %ecx,44(%edi)

# qhasm:   in12 = x12
# asm 1: movd <x12=int3232#6,>in12=int32#1
# asm 2: movd <x12=%mm5,>in12=%eax
movd %mm5,%eax

# qhasm:   in13 = x13
# asm 1: movl <x13=stack32#34,>in13=int32#2
# asm 2: movl <x13=132(%esp),>in13=%ecx
movl 132(%esp),%ecx

# qhasm:   in12 += j12
# asm 1: addl <j12=stack32#18,<in12=int32#1
# asm 2: addl <j12=68(%esp),<in12=%eax
addl 68(%esp),%eax

# qhasm:   in13 += j13
# asm 1: addl <j13=stack32#19,<in13=int32#2
# asm 2: addl <j13=72(%esp),<in13=%ecx
addl 72(%esp),%ecx

# qhasm:   in12 ^= *(uint32 *) (m + 48)
# asm 1: xorl 48(<m=int32#5),<in12=int32#1
# asm 2: xorl 48(<m=%esi),<in12=%eax
xorl 48(%esi),%eax

# qhasm:   in13 ^= *(uint32 *) (m + 52)
# asm 1: xorl 52(<m=int32#5),<in13=int32#2
# asm 2: xorl 52(<m=%esi),<in13=%ecx
xorl 52(%esi),%ecx

# qhasm:   *(uint32 *) (out + 48) = in12
# asm 1: movl <in12=int32#1,48(<out=int32#6)
# asm 2: movl <in12=%eax,48(<out=%edi)
movl %eax,48(%edi)

# qhasm:   *(uint32 *) (out + 52) = in13
# asm 1: movl <in13=int32#2,52(<out=int32#6)
# asm 2: movl <in13=%ecx,52(<out=%edi)
movl %ecx,52(%edi)

# qhasm:   in14 = x14
# asm 1: movl <x14=stack32#35,>in14=int32#1
# asm 2: movl <x14=136(%esp),>in14=%eax
movl 136(%esp),%eax

# qhasm:   in15 = x15
# asm 1: movl <x15=stack32#36,>in15=int32#2
# asm 2: movl <x15=140(%esp),>in15=%ecx
movl 140(%esp),%ecx

# qhasm:   in14 += j14
# asm 1: addl <j14=stack32#20,<in14=int32#1
# asm 2: addl <j14=76(%esp),<in14=%eax
addl 76(%esp),%eax

# qhasm:   in15 += j15
# asm 1: addl <j15=stack32#21,<in15=int32#2
# asm 2: addl <j15=80(%esp),<in15=%ecx
addl 80(%esp),%ecx

# qhasm:   in14 ^= *(uint32 *) (m + 56)
# asm 1: xorl 56(<m=int32#5),<in14=int32#1
# asm 2: xorl 56(<m=%esi),<in14=%eax
xorl 56(%esi),%eax

# qhasm:   in15 ^= *(uint32 *) (m + 60)
# asm 1: xorl 60(<m=int32#5),<in15=int32#2
# asm 2: xorl 60(<m=%esi),<in15=%ecx
xorl 60(%esi),%ecx

# qhasm:   *(uint32 *) (out + 56) = in14
# asm 1: movl <in14=int32#1,56(<out=int32#6)
# asm 2: movl <in14=%eax,56(<out=%edi)
movl %eax,56(%edi)

# qhasm:   *(uint32 *) (out + 60) = in15
# asm 1: movl <in15=int32#2,60(<out=int32#6)
# asm 2: movl <in15=%ecx,60(<out=%edi)
movl %ecx,60(%edi)

# qhasm:   bytes = bytes_backup
# asm 1: movl <bytes_backup=stack32#26,>bytes=int32#4
# asm 2: movl <bytes_backup=100(%esp),>bytes=%ebx
movl 100(%esp),%ebx

# qhasm:   in12 = j12
# asm 1: movl <j12=stack32#18,>in12=int32#1
# asm 2: movl <j12=68(%esp),>in12=%eax
movl 68(%esp),%eax

# qhasm:   in13 = j13
# asm 1: movl <j13=stack32#19,>in13=int32#2
# asm 2: movl <j13=72(%esp),>in13=%ecx
movl 72(%esp),%ecx

# qhasm:   carry? in12 += 1
# asm 1: add  $1,<in12=int32#1
# asm 2: add  $1,<in12=%eax
add  $1,%eax

# qhasm:   in13 += 0 + carry
# asm 1: adc $0,<in13=int32#2
# asm 2: adc $0,<in13=%ecx
adc $0,%ecx

# qhasm:   j12 = in12
# asm 1: movl <in12=int32#1,>j12=stack32#18
# asm 2: movl <in12=%eax,>j12=68(%esp)
movl %eax,68(%esp)

# qhasm:   j13 = in13
# asm 1: movl <in13=int32#2,>j13=stack32#19
# asm 2: movl <in13=%ecx,>j13=72(%esp)
movl %ecx,72(%esp)

# qhasm:                          unsigned>? unsigned<? bytes - 64
# asm 1: cmp  $64,<bytes=int32#4
# asm 2: cmp  $64,<bytes=%ebx
cmp  $64,%ebx
# comment:fp stack unchanged by jump

# qhasm:   goto bytesatleast65 if unsigned>
ja ._bytesatleast65
# comment:fp stack unchanged by jump

# qhasm:     goto bytesatleast64 if !unsigned<
jae ._bytesatleast64

# qhasm:       m = out
# asm 1: mov  <out=int32#6,>m=int32#5
# asm 2: mov  <out=%edi,>m=%esi
mov  %edi,%esi

# qhasm:       out = ctarget
# asm 1: movl <ctarget=stack32#23,>out=int32#6
# asm 2: movl <ctarget=88(%esp),>out=%edi
movl 88(%esp),%edi

# qhasm:       i = bytes
# asm 1: mov  <bytes=int32#4,>i=int32#2
# asm 2: mov  <bytes=%ebx,>i=%ecx
mov  %ebx,%ecx

# qhasm:       while (i) { *out++ = *m++; --i }
rep movsb
# comment:fp stack unchanged by fallthrough

# qhasm:     bytesatleast64:
._bytesatleast64:

# qhasm:     x = x_backup
# asm 1: movl <x_backup=stack32#22,>x=int32#1
# asm 2: movl <x_backup=84(%esp),>x=%eax
movl 84(%esp),%eax

# qhasm:     in12 = j12
# asm 1: movl <j12=stack32#18,>in12=int32#2
# asm 2: movl <j12=68(%esp),>in12=%ecx
movl 68(%esp),%ecx

# qhasm:     in13 = j13
# asm 1: movl <j13=stack32#19,>in13=int32#3
# asm 2: movl <j13=72(%esp),>in13=%edx
movl 72(%esp),%edx

# qhasm:     *(uint32 *) (x + 48) = in12
# asm 1: movl <in12=int32#2,48(<x=int32#1)
# asm 2: movl <in12=%ecx,48(<x=%eax)
movl %ecx,48(%eax)

# qhasm:     *(uint32 *) (x + 52) = in13
# asm 1: movl <in13=int32#3,52(<x=int32#1)
# asm 2: movl <in13=%edx,52(<x=%eax)
movl %edx,52(%eax)
# comment:fp stack unchanged by fallthrough

# qhasm:     done:
._done:

# qhasm:     emms
emms

# qhasm:     eax = eax_stack
# asm 1: movl <eax_stack=stack32#1,>eax=int32#1
# asm 2: movl <eax_stack=0(%esp),>eax=%eax
movl 0(%esp),%eax

# qhasm:     ebx = ebx_stack
# asm 1: movl <ebx_stack=stack32#2,>ebx=int32#4
# asm 2: movl <ebx_stack=4(%esp),>ebx=%ebx
movl 4(%esp),%ebx

# qhasm:     esi = esi_stack
# asm 1: movl <esi_stack=stack32#3,>esi=int32#5
# asm 2: movl <esi_stack=8(%esp),>esi=%esi
movl 8(%esp),%esi

# qhasm:     edi = edi_stack
# asm 1: movl <edi_stack=stack32#4,>edi=int32#6
# asm 2: movl <edi_stack=12(%esp),>edi=%edi
movl 12(%esp),%edi

# qhasm:     ebp = ebp_stack
# asm 1: movl <ebp_stack=stack32#5,>ebp=int32#7
# asm 2: movl <ebp_stack=16(%esp),>ebp=%ebp
movl 16(%esp),%ebp

# qhasm:     leave
add %eax,%esp
ret

# qhasm:   bytesatleast65:
._bytesatleast65:

# qhasm:   bytes -= 64
# asm 1: sub  $64,<bytes=int32#4
# asm 2: sub  $64,<bytes=%ebx
sub  $64,%ebx

# qhasm:   out += 64
# asm 1: add  $64,<out=int32#6
# asm 2: add  $64,<out=%edi
add  $64,%edi

# qhasm:   m += 64
# asm 1: add  $64,<m=int32#5
# asm 2: add  $64,<m=%esi
add  $64,%esi
# comment:fp stack unchanged by jump

# qhasm: goto bytesatleast1
jmp ._bytesatleast1

# qhasm: enter crypto_stream_chacha8_e_x86_mmx_ECRYPT_init
.text
.p2align 5
.globl _crypto_stream_chacha8_e_x86_mmx_ECRYPT_init
.globl crypto_stream_chacha8_e_x86_mmx_ECRYPT_init
_crypto_stream_chacha8_e_x86_mmx_ECRYPT_init:
crypto_stream_chacha8_e_x86_mmx_ECRYPT_init:
mov %esp,%eax
and $31,%eax
add $224,%eax
sub %eax,%esp

# qhasm: leave
add %eax,%esp
ret

# qhasm: enter crypto_stream_chacha8_e_x86_mmx_ECRYPT_keysetup
.text
.p2align 5
.globl _crypto_stream_chacha8_e_x86_mmx_ECRYPT_keysetup
.globl crypto_stream_chacha8_e_x86_mmx_ECRYPT_keysetup
_crypto_stream_chacha8_e_x86_mmx_ECRYPT_keysetup:
crypto_stream_chacha8_e_x86_mmx_ECRYPT_keysetup:
mov %esp,%eax
and $31,%eax
add $224,%eax
sub %eax,%esp

# qhasm:   eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm:   ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm:   esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm:   edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm:   ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm:   k = arg2
# asm 1: movl <arg2=stack32#-2,>k=int32#2
# asm 2: movl <arg2=8(%esp,%eax),>k=%ecx
movl 8(%esp,%eax),%ecx

# qhasm:   kbits = arg3
# asm 1: movl <arg3=stack32#-3,>kbits=int32#3
# asm 2: movl <arg3=12(%esp,%eax),>kbits=%edx
movl 12(%esp,%eax),%edx

# qhasm:   x = arg1
# asm 1: movl <arg1=stack32#-1,>x=int32#1
# asm 2: movl <arg1=4(%esp,%eax),>x=%eax
movl 4(%esp,%eax),%eax

# qhasm:   in4 = *(uint32 *) (k + 0)
# asm 1: movl 0(<k=int32#2),>in4=int32#4
# asm 2: movl 0(<k=%ecx),>in4=%ebx
movl 0(%ecx),%ebx

# qhasm:   in5 = *(uint32 *) (k + 4)
# asm 1: movl 4(<k=int32#2),>in5=int32#5
# asm 2: movl 4(<k=%ecx),>in5=%esi
movl 4(%ecx),%esi

# qhasm:   in6 = *(uint32 *) (k + 8)
# asm 1: movl 8(<k=int32#2),>in6=int32#6
# asm 2: movl 8(<k=%ecx),>in6=%edi
movl 8(%ecx),%edi

# qhasm:   in7 = *(uint32 *) (k + 12)
# asm 1: movl 12(<k=int32#2),>in7=int32#7
# asm 2: movl 12(<k=%ecx),>in7=%ebp
movl 12(%ecx),%ebp

# qhasm:   *(uint32 *) (x + 16) = in4
# asm 1: movl <in4=int32#4,16(<x=int32#1)
# asm 2: movl <in4=%ebx,16(<x=%eax)
movl %ebx,16(%eax)

# qhasm:   *(uint32 *) (x + 20) = in5
# asm 1: movl <in5=int32#5,20(<x=int32#1)
# asm 2: movl <in5=%esi,20(<x=%eax)
movl %esi,20(%eax)

# qhasm:   *(uint32 *) (x + 24) = in6
# asm 1: movl <in6=int32#6,24(<x=int32#1)
# asm 2: movl <in6=%edi,24(<x=%eax)
movl %edi,24(%eax)

# qhasm:   *(uint32 *) (x + 28) = in7
# asm 1: movl <in7=int32#7,28(<x=int32#1)
# asm 2: movl <in7=%ebp,28(<x=%eax)
movl %ebp,28(%eax)

# qhasm:                    unsigned<? kbits - 256
# asm 1: cmp  $256,<kbits=int32#3
# asm 2: cmp  $256,<kbits=%edx
cmp  $256,%edx
# comment:fp stack unchanged by jump

# qhasm:   goto kbits128 if unsigned<
jb ._kbits128

# qhasm:   kbits256:
._kbits256:

# qhasm:     in8 = *(uint32 *) (k + 16)
# asm 1: movl 16(<k=int32#2),>in8=int32#3
# asm 2: movl 16(<k=%ecx),>in8=%edx
movl 16(%ecx),%edx

# qhasm:     in9 = *(uint32 *) (k + 20)
# asm 1: movl 20(<k=int32#2),>in9=int32#4
# asm 2: movl 20(<k=%ecx),>in9=%ebx
movl 20(%ecx),%ebx

# qhasm:     in10 = *(uint32 *) (k + 24)
# asm 1: movl 24(<k=int32#2),>in10=int32#5
# asm 2: movl 24(<k=%ecx),>in10=%esi
movl 24(%ecx),%esi

# qhasm:     in11 = *(uint32 *) (k + 28)
# asm 1: movl 28(<k=int32#2),>in11=int32#2
# asm 2: movl 28(<k=%ecx),>in11=%ecx
movl 28(%ecx),%ecx

# qhasm:     *(uint32 *) (x + 32) = in8
# asm 1: movl <in8=int32#3,32(<x=int32#1)
# asm 2: movl <in8=%edx,32(<x=%eax)
movl %edx,32(%eax)

# qhasm:     *(uint32 *) (x + 36) = in9
# asm 1: movl <in9=int32#4,36(<x=int32#1)
# asm 2: movl <in9=%ebx,36(<x=%eax)
movl %ebx,36(%eax)

# qhasm:     *(uint32 *) (x + 40) = in10
# asm 1: movl <in10=int32#5,40(<x=int32#1)
# asm 2: movl <in10=%esi,40(<x=%eax)
movl %esi,40(%eax)

# qhasm:     *(uint32 *) (x + 44) = in11
# asm 1: movl <in11=int32#2,44(<x=int32#1)
# asm 2: movl <in11=%ecx,44(<x=%eax)
movl %ecx,44(%eax)

# qhasm:     in0 = 1634760805
# asm 1: mov  $1634760805,>in0=int32#2
# asm 2: mov  $1634760805,>in0=%ecx
mov  $1634760805,%ecx

# qhasm:     in1 = 857760878
# asm 1: mov  $857760878,>in1=int32#3
# asm 2: mov  $857760878,>in1=%edx
mov  $857760878,%edx

# qhasm:     in2 = 2036477234
# asm 1: mov  $2036477234,>in2=int32#4
# asm 2: mov  $2036477234,>in2=%ebx
mov  $2036477234,%ebx

# qhasm:     in3 = 1797285236
# asm 1: mov  $1797285236,>in3=int32#5
# asm 2: mov  $1797285236,>in3=%esi
mov  $1797285236,%esi

# qhasm:     *(uint32 *) (x + 0) = in0
# asm 1: movl <in0=int32#2,0(<x=int32#1)
# asm 2: movl <in0=%ecx,0(<x=%eax)
movl %ecx,0(%eax)

# qhasm:     *(uint32 *) (x + 4) = in1
# asm 1: movl <in1=int32#3,4(<x=int32#1)
# asm 2: movl <in1=%edx,4(<x=%eax)
movl %edx,4(%eax)

# qhasm:     *(uint32 *) (x + 8) = in2
# asm 1: movl <in2=int32#4,8(<x=int32#1)
# asm 2: movl <in2=%ebx,8(<x=%eax)
movl %ebx,8(%eax)

# qhasm:     *(uint32 *) (x + 12) = in3
# asm 1: movl <in3=int32#5,12(<x=int32#1)
# asm 2: movl <in3=%esi,12(<x=%eax)
movl %esi,12(%eax)
# comment:fp stack unchanged by jump

# qhasm:   goto keysetupdone
jmp ._keysetupdone

# qhasm:   kbits128:
._kbits128:

# qhasm:     in8 = *(uint32 *) (k + 0)
# asm 1: movl 0(<k=int32#2),>in8=int32#3
# asm 2: movl 0(<k=%ecx),>in8=%edx
movl 0(%ecx),%edx

# qhasm:     in9 = *(uint32 *) (k + 4)
# asm 1: movl 4(<k=int32#2),>in9=int32#4
# asm 2: movl 4(<k=%ecx),>in9=%ebx
movl 4(%ecx),%ebx

# qhasm:     in10 = *(uint32 *) (k + 8)
# asm 1: movl 8(<k=int32#2),>in10=int32#5
# asm 2: movl 8(<k=%ecx),>in10=%esi
movl 8(%ecx),%esi

# qhasm:     in11 = *(uint32 *) (k + 12)
# asm 1: movl 12(<k=int32#2),>in11=int32#2
# asm 2: movl 12(<k=%ecx),>in11=%ecx
movl 12(%ecx),%ecx

# qhasm:     *(uint32 *) (x + 32) = in8
# asm 1: movl <in8=int32#3,32(<x=int32#1)
# asm 2: movl <in8=%edx,32(<x=%eax)
movl %edx,32(%eax)

# qhasm:     *(uint32 *) (x + 36) = in9
# asm 1: movl <in9=int32#4,36(<x=int32#1)
# asm 2: movl <in9=%ebx,36(<x=%eax)
movl %ebx,36(%eax)

# qhasm:     *(uint32 *) (x + 40) = in10
# asm 1: movl <in10=int32#5,40(<x=int32#1)
# asm 2: movl <in10=%esi,40(<x=%eax)
movl %esi,40(%eax)

# qhasm:     *(uint32 *) (x + 44) = in11
# asm 1: movl <in11=int32#2,44(<x=int32#1)
# asm 2: movl <in11=%ecx,44(<x=%eax)
movl %ecx,44(%eax)

# qhasm:     in0 = 1634760805
# asm 1: mov  $1634760805,>in0=int32#2
# asm 2: mov  $1634760805,>in0=%ecx
mov  $1634760805,%ecx

# qhasm:     in1 = 824206446
# asm 1: mov  $824206446,>in1=int32#3
# asm 2: mov  $824206446,>in1=%edx
mov  $824206446,%edx

# qhasm:     in2 = 2036477238
# asm 1: mov  $2036477238,>in2=int32#4
# asm 2: mov  $2036477238,>in2=%ebx
mov  $2036477238,%ebx

# qhasm:     in3 = 1797285236
# asm 1: mov  $1797285236,>in3=int32#5
# asm 2: mov  $1797285236,>in3=%esi
mov  $1797285236,%esi

# qhasm:     *(uint32 *) (x + 0) = in0
# asm 1: movl <in0=int32#2,0(<x=int32#1)
# asm 2: movl <in0=%ecx,0(<x=%eax)
movl %ecx,0(%eax)

# qhasm:     *(uint32 *) (x + 4) = in1
# asm 1: movl <in1=int32#3,4(<x=int32#1)
# asm 2: movl <in1=%edx,4(<x=%eax)
movl %edx,4(%eax)

# qhasm:     *(uint32 *) (x + 8) = in2
# asm 1: movl <in2=int32#4,8(<x=int32#1)
# asm 2: movl <in2=%ebx,8(<x=%eax)
movl %ebx,8(%eax)

# qhasm:     *(uint32 *) (x + 12) = in3
# asm 1: movl <in3=int32#5,12(<x=int32#1)
# asm 2: movl <in3=%esi,12(<x=%eax)
movl %esi,12(%eax)

# qhasm:   keysetupdone:
._keysetupdone:

# qhasm:   eax = eax_stack
# asm 1: movl <eax_stack=stack32#1,>eax=int32#1
# asm 2: movl <eax_stack=0(%esp),>eax=%eax
movl 0(%esp),%eax

# qhasm:   ebx = ebx_stack
# asm 1: movl <ebx_stack=stack32#2,>ebx=int32#4
# asm 2: movl <ebx_stack=4(%esp),>ebx=%ebx
movl 4(%esp),%ebx

# qhasm:   esi = esi_stack
# asm 1: movl <esi_stack=stack32#3,>esi=int32#5
# asm 2: movl <esi_stack=8(%esp),>esi=%esi
movl 8(%esp),%esi

# qhasm:   edi = edi_stack
# asm 1: movl <edi_stack=stack32#4,>edi=int32#6
# asm 2: movl <edi_stack=12(%esp),>edi=%edi
movl 12(%esp),%edi

# qhasm:   ebp = ebp_stack
# asm 1: movl <ebp_stack=stack32#5,>ebp=int32#7
# asm 2: movl <ebp_stack=16(%esp),>ebp=%ebp
movl 16(%esp),%ebp

# qhasm: leave
add %eax,%esp
ret

# qhasm: enter crypto_stream_chacha8_e_x86_mmx_ECRYPT_ivsetup
.text
.p2align 5
.globl _crypto_stream_chacha8_e_x86_mmx_ECRYPT_ivsetup
.globl crypto_stream_chacha8_e_x86_mmx_ECRYPT_ivsetup
_crypto_stream_chacha8_e_x86_mmx_ECRYPT_ivsetup:
crypto_stream_chacha8_e_x86_mmx_ECRYPT_ivsetup:
mov %esp,%eax
and $31,%eax
add $224,%eax
sub %eax,%esp

# qhasm:   eax_stack = eax
# asm 1: movl <eax=int32#1,>eax_stack=stack32#1
# asm 2: movl <eax=%eax,>eax_stack=0(%esp)
movl %eax,0(%esp)

# qhasm:   ebx_stack = ebx
# asm 1: movl <ebx=int32#4,>ebx_stack=stack32#2
# asm 2: movl <ebx=%ebx,>ebx_stack=4(%esp)
movl %ebx,4(%esp)

# qhasm:   esi_stack = esi
# asm 1: movl <esi=int32#5,>esi_stack=stack32#3
# asm 2: movl <esi=%esi,>esi_stack=8(%esp)
movl %esi,8(%esp)

# qhasm:   edi_stack = edi
# asm 1: movl <edi=int32#6,>edi_stack=stack32#4
# asm 2: movl <edi=%edi,>edi_stack=12(%esp)
movl %edi,12(%esp)

# qhasm:   ebp_stack = ebp
# asm 1: movl <ebp=int32#7,>ebp_stack=stack32#5
# asm 2: movl <ebp=%ebp,>ebp_stack=16(%esp)
movl %ebp,16(%esp)

# qhasm:   iv = arg2
# asm 1: movl <arg2=stack32#-2,>iv=int32#2
# asm 2: movl <arg2=8(%esp,%eax),>iv=%ecx
movl 8(%esp,%eax),%ecx

# qhasm:   x = arg1
# asm 1: movl <arg1=stack32#-1,>x=int32#1
# asm 2: movl <arg1=4(%esp,%eax),>x=%eax
movl 4(%esp,%eax),%eax

# qhasm:   in12 = 0
# asm 1: mov  $0,>in12=int32#3
# asm 2: mov  $0,>in12=%edx
mov  $0,%edx

# qhasm:   in13 = 0
# asm 1: mov  $0,>in13=int32#4
# asm 2: mov  $0,>in13=%ebx
mov  $0,%ebx

# qhasm:   in14 = *(uint32 *) (iv + 0)
# asm 1: movl 0(<iv=int32#2),>in14=int32#5
# asm 2: movl 0(<iv=%ecx),>in14=%esi
movl 0(%ecx),%esi

# qhasm:   in15 = *(uint32 *) (iv + 4)
# asm 1: movl 4(<iv=int32#2),>in15=int32#2
# asm 2: movl 4(<iv=%ecx),>in15=%ecx
movl 4(%ecx),%ecx

# qhasm:   *(uint32 *) (x + 48) = in12
# asm 1: movl <in12=int32#3,48(<x=int32#1)
# asm 2: movl <in12=%edx,48(<x=%eax)
movl %edx,48(%eax)

# qhasm:   *(uint32 *) (x + 52) = in13
# asm 1: movl <in13=int32#4,52(<x=int32#1)
# asm 2: movl <in13=%ebx,52(<x=%eax)
movl %ebx,52(%eax)

# qhasm:   *(uint32 *) (x + 56) = in14
# asm 1: movl <in14=int32#5,56(<x=int32#1)
# asm 2: movl <in14=%esi,56(<x=%eax)
movl %esi,56(%eax)

# qhasm:   *(uint32 *) (x + 60) = in15
# asm 1: movl <in15=int32#2,60(<x=int32#1)
# asm 2: movl <in15=%ecx,60(<x=%eax)
movl %ecx,60(%eax)

# qhasm:   eax = eax_stack
# asm 1: movl <eax_stack=stack32#1,>eax=int32#1
# asm 2: movl <eax_stack=0(%esp),>eax=%eax
movl 0(%esp),%eax

# qhasm:   ebx = ebx_stack
# asm 1: movl <ebx_stack=stack32#2,>ebx=int32#4
# asm 2: movl <ebx_stack=4(%esp),>ebx=%ebx
movl 4(%esp),%ebx

# qhasm:   esi = esi_stack
# asm 1: movl <esi_stack=stack32#3,>esi=int32#5
# asm 2: movl <esi_stack=8(%esp),>esi=%esi
movl 8(%esp),%esi

# qhasm:   edi = edi_stack
# asm 1: movl <edi_stack=stack32#4,>edi=int32#6
# asm 2: movl <edi_stack=12(%esp),>edi=%edi
movl 12(%esp),%edi

# qhasm:   ebp = ebp_stack
# asm 1: movl <ebp_stack=stack32#5,>ebp=int32#7
# asm 2: movl <ebp_stack=16(%esp),>ebp=%ebp
movl 16(%esp),%ebp

# qhasm: leave
add %eax,%esp
ret
