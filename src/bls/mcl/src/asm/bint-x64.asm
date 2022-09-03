; for nasm
segment .text
align 16
export mclb_add1
global mclb_add1
global _mclb_add1
mclb_add1:
_mclb_add1:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
setc al
movzx eax, al
ret
align 16
export mclb_add2
global mclb_add2
global _mclb_add2
mclb_add2:
_mclb_add2:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
setc al
movzx eax, al
ret
align 16
export mclb_add3
global mclb_add3
global _mclb_add3
mclb_add3:
_mclb_add3:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
setc al
movzx eax, al
ret
align 16
export mclb_add4
global mclb_add4
global _mclb_add4
mclb_add4:
_mclb_add4:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
setc al
movzx eax, al
ret
align 16
export mclb_add5
global mclb_add5
global _mclb_add5
mclb_add5:
_mclb_add5:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
setc al
movzx eax, al
ret
align 16
export mclb_add6
global mclb_add6
global _mclb_add6
mclb_add6:
_mclb_add6:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
setc al
movzx eax, al
ret
align 16
export mclb_add7
global mclb_add7
global _mclb_add7
mclb_add7:
_mclb_add7:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
setc al
movzx eax, al
ret
align 16
export mclb_add8
global mclb_add8
global _mclb_add8
mclb_add8:
_mclb_add8:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
setc al
movzx eax, al
ret
align 16
export mclb_add9
global mclb_add9
global _mclb_add9
mclb_add9:
_mclb_add9:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
setc al
movzx eax, al
ret
align 16
export mclb_add10
global mclb_add10
global _mclb_add10
mclb_add10:
_mclb_add10:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
setc al
movzx eax, al
ret
align 16
export mclb_add11
global mclb_add11
global _mclb_add11
mclb_add11:
_mclb_add11:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
setc al
movzx eax, al
ret
align 16
export mclb_add12
global mclb_add12
global _mclb_add12
mclb_add12:
_mclb_add12:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
setc al
movzx eax, al
ret
align 16
export mclb_add13
global mclb_add13
global _mclb_add13
mclb_add13:
_mclb_add13:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
setc al
movzx eax, al
ret
align 16
export mclb_add14
global mclb_add14
global _mclb_add14
mclb_add14:
_mclb_add14:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
adc rax, [r8+104]
mov [rcx+104], rax
setc al
movzx eax, al
ret
align 16
export mclb_add15
global mclb_add15
global _mclb_add15
mclb_add15:
_mclb_add15:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
adc rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
adc rax, [r8+112]
mov [rcx+112], rax
setc al
movzx eax, al
ret
align 16
export mclb_add16
global mclb_add16
global _mclb_add16
mclb_add16:
_mclb_add16:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
adc rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
adc rax, [r8+112]
mov [rcx+112], rax
mov rax, [rdx+120]
adc rax, [r8+120]
mov [rcx+120], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub1
global mclb_sub1
global _mclb_sub1
mclb_sub1:
_mclb_sub1:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub2
global mclb_sub2
global _mclb_sub2
mclb_sub2:
_mclb_sub2:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub3
global mclb_sub3
global _mclb_sub3
mclb_sub3:
_mclb_sub3:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub4
global mclb_sub4
global _mclb_sub4
mclb_sub4:
_mclb_sub4:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub5
global mclb_sub5
global _mclb_sub5
mclb_sub5:
_mclb_sub5:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub6
global mclb_sub6
global _mclb_sub6
mclb_sub6:
_mclb_sub6:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub7
global mclb_sub7
global _mclb_sub7
mclb_sub7:
_mclb_sub7:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub8
global mclb_sub8
global _mclb_sub8
mclb_sub8:
_mclb_sub8:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub9
global mclb_sub9
global _mclb_sub9
mclb_sub9:
_mclb_sub9:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub10
global mclb_sub10
global _mclb_sub10
mclb_sub10:
_mclb_sub10:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub11
global mclb_sub11
global _mclb_sub11
mclb_sub11:
_mclb_sub11:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub12
global mclb_sub12
global _mclb_sub12
mclb_sub12:
_mclb_sub12:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub13
global mclb_sub13
global _mclb_sub13
mclb_sub13:
_mclb_sub13:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub14
global mclb_sub14
global _mclb_sub14
mclb_sub14:
_mclb_sub14:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
sbb rax, [r8+104]
mov [rcx+104], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub15
global mclb_sub15
global _mclb_sub15
mclb_sub15:
_mclb_sub15:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
sbb rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
sbb rax, [r8+112]
mov [rcx+112], rax
setc al
movzx eax, al
ret
align 16
export mclb_sub16
global mclb_sub16
global _mclb_sub16
mclb_sub16:
_mclb_sub16:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
sbb rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
sbb rax, [r8+112]
mov [rcx+112], rax
mov rax, [rdx+120]
sbb rax, [r8+120]
mov [rcx+120], rax
setc al
movzx eax, al
ret
align 16
export mclb_addNF1
global mclb_addNF1
global _mclb_addNF1
mclb_addNF1:
_mclb_addNF1:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
ret
align 16
export mclb_addNF2
global mclb_addNF2
global _mclb_addNF2
mclb_addNF2:
_mclb_addNF2:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
ret
align 16
export mclb_addNF3
global mclb_addNF3
global _mclb_addNF3
mclb_addNF3:
_mclb_addNF3:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
ret
align 16
export mclb_addNF4
global mclb_addNF4
global _mclb_addNF4
mclb_addNF4:
_mclb_addNF4:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
ret
align 16
export mclb_addNF5
global mclb_addNF5
global _mclb_addNF5
mclb_addNF5:
_mclb_addNF5:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
ret
align 16
export mclb_addNF6
global mclb_addNF6
global _mclb_addNF6
mclb_addNF6:
_mclb_addNF6:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
ret
align 16
export mclb_addNF7
global mclb_addNF7
global _mclb_addNF7
mclb_addNF7:
_mclb_addNF7:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
ret
align 16
export mclb_addNF8
global mclb_addNF8
global _mclb_addNF8
mclb_addNF8:
_mclb_addNF8:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
ret
align 16
export mclb_addNF9
global mclb_addNF9
global _mclb_addNF9
mclb_addNF9:
_mclb_addNF9:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
ret
align 16
export mclb_addNF10
global mclb_addNF10
global _mclb_addNF10
mclb_addNF10:
_mclb_addNF10:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
ret
align 16
export mclb_addNF11
global mclb_addNF11
global _mclb_addNF11
mclb_addNF11:
_mclb_addNF11:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
ret
align 16
export mclb_addNF12
global mclb_addNF12
global _mclb_addNF12
mclb_addNF12:
_mclb_addNF12:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
ret
align 16
export mclb_addNF13
global mclb_addNF13
global _mclb_addNF13
mclb_addNF13:
_mclb_addNF13:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
ret
align 16
export mclb_addNF14
global mclb_addNF14
global _mclb_addNF14
mclb_addNF14:
_mclb_addNF14:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
adc rax, [r8+104]
mov [rcx+104], rax
ret
align 16
export mclb_addNF15
global mclb_addNF15
global _mclb_addNF15
mclb_addNF15:
_mclb_addNF15:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
adc rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
adc rax, [r8+112]
mov [rcx+112], rax
ret
align 16
export mclb_addNF16
global mclb_addNF16
global _mclb_addNF16
mclb_addNF16:
_mclb_addNF16:
mov rax, [rdx]
add rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
adc rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
adc rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
adc rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
adc rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
adc rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
adc rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
adc rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
adc rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
adc rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
adc rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
adc rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
adc rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
adc rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
adc rax, [r8+112]
mov [rcx+112], rax
mov rax, [rdx+120]
adc rax, [r8+120]
mov [rcx+120], rax
ret
align 16
export mclb_subNF1
global mclb_subNF1
global _mclb_subNF1
mclb_subNF1:
_mclb_subNF1:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF2
global mclb_subNF2
global _mclb_subNF2
mclb_subNF2:
_mclb_subNF2:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF3
global mclb_subNF3
global _mclb_subNF3
mclb_subNF3:
_mclb_subNF3:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF4
global mclb_subNF4
global _mclb_subNF4
mclb_subNF4:
_mclb_subNF4:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF5
global mclb_subNF5
global _mclb_subNF5
mclb_subNF5:
_mclb_subNF5:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF6
global mclb_subNF6
global _mclb_subNF6
mclb_subNF6:
_mclb_subNF6:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF7
global mclb_subNF7
global _mclb_subNF7
mclb_subNF7:
_mclb_subNF7:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF8
global mclb_subNF8
global _mclb_subNF8
mclb_subNF8:
_mclb_subNF8:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF9
global mclb_subNF9
global _mclb_subNF9
mclb_subNF9:
_mclb_subNF9:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF10
global mclb_subNF10
global _mclb_subNF10
mclb_subNF10:
_mclb_subNF10:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF11
global mclb_subNF11
global _mclb_subNF11
mclb_subNF11:
_mclb_subNF11:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF12
global mclb_subNF12
global _mclb_subNF12
mclb_subNF12:
_mclb_subNF12:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF13
global mclb_subNF13
global _mclb_subNF13
mclb_subNF13:
_mclb_subNF13:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF14
global mclb_subNF14
global _mclb_subNF14
mclb_subNF14:
_mclb_subNF14:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
sbb rax, [r8+104]
mov [rcx+104], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF15
global mclb_subNF15
global _mclb_subNF15
mclb_subNF15:
_mclb_subNF15:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
sbb rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
sbb rax, [r8+112]
mov [rcx+112], rax
setc al
movzx eax, al
ret
align 16
export mclb_subNF16
global mclb_subNF16
global _mclb_subNF16
mclb_subNF16:
_mclb_subNF16:
mov rax, [rdx]
sub rax, [r8]
mov [rcx], rax
mov rax, [rdx+8]
sbb rax, [r8+8]
mov [rcx+8], rax
mov rax, [rdx+16]
sbb rax, [r8+16]
mov [rcx+16], rax
mov rax, [rdx+24]
sbb rax, [r8+24]
mov [rcx+24], rax
mov rax, [rdx+32]
sbb rax, [r8+32]
mov [rcx+32], rax
mov rax, [rdx+40]
sbb rax, [r8+40]
mov [rcx+40], rax
mov rax, [rdx+48]
sbb rax, [r8+48]
mov [rcx+48], rax
mov rax, [rdx+56]
sbb rax, [r8+56]
mov [rcx+56], rax
mov rax, [rdx+64]
sbb rax, [r8+64]
mov [rcx+64], rax
mov rax, [rdx+72]
sbb rax, [r8+72]
mov [rcx+72], rax
mov rax, [rdx+80]
sbb rax, [r8+80]
mov [rcx+80], rax
mov rax, [rdx+88]
sbb rax, [r8+88]
mov [rcx+88], rax
mov rax, [rdx+96]
sbb rax, [r8+96]
mov [rcx+96], rax
mov rax, [rdx+104]
sbb rax, [r8+104]
mov [rcx+104], rax
mov rax, [rdx+112]
sbb rax, [r8+112]
mov [rcx+112], rax
mov rax, [rdx+120]
sbb rax, [r8+120]
mov [rcx+120], rax
setc al
movzx eax, al
ret
align 16
export mclb_mulUnit_fast1
global mclb_mulUnit_fast1
global _mclb_mulUnit_fast1
mclb_mulUnit_fast1:
_mclb_mulUnit_fast1:
mov rax, [rdx]
mul r8
mov [rcx], rax
mov rax, rdx
ret
align 16
export mclb_mulUnit_fast2
global mclb_mulUnit_fast2
global _mclb_mulUnit_fast2
mclb_mulUnit_fast2:
_mclb_mulUnit_fast2:
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov r9, rdx
mov rax, [r11+8]
mul r8
add rax, r9
adc rdx, 0
mov [rcx+8], rax
mov rax, rdx
ret
align 16
export mclb_mulUnit_fast3
global mclb_mulUnit_fast3
global _mclb_mulUnit_fast3
mclb_mulUnit_fast3:
_mclb_mulUnit_fast3:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx rax, rdx, [r11+16]
adc rdx, r9
mov [rcx+16], rdx
adc rax, 0
ret
align 16
export mclb_mulUnit_fast4
global mclb_mulUnit_fast4
global _mclb_mulUnit_fast4
mclb_mulUnit_fast4:
_mclb_mulUnit_fast4:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx r10, rax, [r11+16]
adc rax, r9
mov [rcx+16], rax
mulx rax, rdx, [r11+24]
adc rdx, r10
mov [rcx+24], rdx
adc rax, 0
ret
align 16
export mclb_mulUnit_fast5
global mclb_mulUnit_fast5
global _mclb_mulUnit_fast5
mclb_mulUnit_fast5:
_mclb_mulUnit_fast5:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx r10, rax, [r11+16]
adc rax, r9
mov [rcx+16], rax
mulx r9, rax, [r11+24]
adc rax, r10
mov [rcx+24], rax
mulx rax, rdx, [r11+32]
adc rdx, r9
mov [rcx+32], rdx
adc rax, 0
ret
align 16
export mclb_mulUnit_fast6
global mclb_mulUnit_fast6
global _mclb_mulUnit_fast6
mclb_mulUnit_fast6:
_mclb_mulUnit_fast6:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx r10, rax, [r11+16]
adc rax, r9
mov [rcx+16], rax
mulx r9, rax, [r11+24]
adc rax, r10
mov [rcx+24], rax
mulx r10, rax, [r11+32]
adc rax, r9
mov [rcx+32], rax
mulx rax, rdx, [r11+40]
adc rdx, r10
mov [rcx+40], rdx
adc rax, 0
ret
align 16
export mclb_mulUnit_fast7
global mclb_mulUnit_fast7
global _mclb_mulUnit_fast7
mclb_mulUnit_fast7:
_mclb_mulUnit_fast7:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx r10, rax, [r11+16]
adc rax, r9
mov [rcx+16], rax
mulx r9, rax, [r11+24]
adc rax, r10
mov [rcx+24], rax
mulx r10, rax, [r11+32]
adc rax, r9
mov [rcx+32], rax
mulx r9, rax, [r11+40]
adc rax, r10
mov [rcx+40], rax
mulx rax, rdx, [r11+48]
adc rdx, r9
mov [rcx+48], rdx
adc rax, 0
ret
align 16
export mclb_mulUnit_fast8
global mclb_mulUnit_fast8
global _mclb_mulUnit_fast8
mclb_mulUnit_fast8:
_mclb_mulUnit_fast8:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx r10, rax, [r11+16]
adc rax, r9
mov [rcx+16], rax
mulx r9, rax, [r11+24]
adc rax, r10
mov [rcx+24], rax
mulx r10, rax, [r11+32]
adc rax, r9
mov [rcx+32], rax
mulx r9, rax, [r11+40]
adc rax, r10
mov [rcx+40], rax
mulx r10, rax, [r11+48]
adc rax, r9
mov [rcx+48], rax
mulx rax, rdx, [r11+56]
adc rdx, r10
mov [rcx+56], rdx
adc rax, 0
ret
align 16
export mclb_mulUnit_fast9
global mclb_mulUnit_fast9
global _mclb_mulUnit_fast9
mclb_mulUnit_fast9:
_mclb_mulUnit_fast9:
mov r11, rdx
mov rdx, r8
mulx r10, rax, [r11]
mov [rcx], rax
mulx r9, rax, [r11+8]
add rax, r10
mov [rcx+8], rax
mulx r10, rax, [r11+16]
adc rax, r9
mov [rcx+16], rax
mulx r9, rax, [r11+24]
adc rax, r10
mov [rcx+24], rax
mulx r10, rax, [r11+32]
adc rax, r9
mov [rcx+32], rax
mulx r9, rax, [r11+40]
adc rax, r10
mov [rcx+40], rax
mulx r10, rax, [r11+48]
adc rax, r9
mov [rcx+48], rax
mulx r9, rax, [r11+56]
adc rax, r10
mov [rcx+56], rax
mulx rax, rdx, [r11+64]
adc rdx, r9
mov [rcx+64], rdx
adc rax, 0
ret
align 16
export mclb_mulUnitAdd_fast1
global mclb_mulUnitAdd_fast1
global _mclb_mulUnitAdd_fast1
mclb_mulUnitAdd_fast1:
_mclb_mulUnitAdd_fast1:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast2
global mclb_mulUnitAdd_fast2
global _mclb_mulUnitAdd_fast2
mclb_mulUnitAdd_fast2:
_mclb_mulUnitAdd_fast2:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast3
global mclb_mulUnitAdd_fast3
global _mclb_mulUnitAdd_fast3
mclb_mulUnitAdd_fast3:
_mclb_mulUnitAdd_fast3:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast4
global mclb_mulUnitAdd_fast4
global _mclb_mulUnitAdd_fast4
mclb_mulUnitAdd_fast4:
_mclb_mulUnitAdd_fast4:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, [rcx+24]
adcx r9, rax
mulx rax, r10, [r11+24]
adox r9, r10
mov [rcx+24], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast5
global mclb_mulUnitAdd_fast5
global _mclb_mulUnitAdd_fast5
mclb_mulUnitAdd_fast5:
_mclb_mulUnitAdd_fast5:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, [rcx+24]
adcx r9, rax
mulx rax, r10, [r11+24]
adox r9, r10
mov [rcx+24], r9
mov r9, [rcx+32]
adcx r9, rax
mulx rax, r10, [r11+32]
adox r9, r10
mov [rcx+32], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast6
global mclb_mulUnitAdd_fast6
global _mclb_mulUnitAdd_fast6
mclb_mulUnitAdd_fast6:
_mclb_mulUnitAdd_fast6:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, [rcx+24]
adcx r9, rax
mulx rax, r10, [r11+24]
adox r9, r10
mov [rcx+24], r9
mov r9, [rcx+32]
adcx r9, rax
mulx rax, r10, [r11+32]
adox r9, r10
mov [rcx+32], r9
mov r9, [rcx+40]
adcx r9, rax
mulx rax, r10, [r11+40]
adox r9, r10
mov [rcx+40], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast7
global mclb_mulUnitAdd_fast7
global _mclb_mulUnitAdd_fast7
mclb_mulUnitAdd_fast7:
_mclb_mulUnitAdd_fast7:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, [rcx+24]
adcx r9, rax
mulx rax, r10, [r11+24]
adox r9, r10
mov [rcx+24], r9
mov r9, [rcx+32]
adcx r9, rax
mulx rax, r10, [r11+32]
adox r9, r10
mov [rcx+32], r9
mov r9, [rcx+40]
adcx r9, rax
mulx rax, r10, [r11+40]
adox r9, r10
mov [rcx+40], r9
mov r9, [rcx+48]
adcx r9, rax
mulx rax, r10, [r11+48]
adox r9, r10
mov [rcx+48], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast8
global mclb_mulUnitAdd_fast8
global _mclb_mulUnitAdd_fast8
mclb_mulUnitAdd_fast8:
_mclb_mulUnitAdd_fast8:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, [rcx+24]
adcx r9, rax
mulx rax, r10, [r11+24]
adox r9, r10
mov [rcx+24], r9
mov r9, [rcx+32]
adcx r9, rax
mulx rax, r10, [r11+32]
adox r9, r10
mov [rcx+32], r9
mov r9, [rcx+40]
adcx r9, rax
mulx rax, r10, [r11+40]
adox r9, r10
mov [rcx+40], r9
mov r9, [rcx+48]
adcx r9, rax
mulx rax, r10, [r11+48]
adox r9, r10
mov [rcx+48], r9
mov r9, [rcx+56]
adcx r9, rax
mulx rax, r10, [r11+56]
adox r9, r10
mov [rcx+56], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnitAdd_fast9
global mclb_mulUnitAdd_fast9
global _mclb_mulUnitAdd_fast9
mclb_mulUnitAdd_fast9:
_mclb_mulUnitAdd_fast9:
mov r11, rdx
mov rdx, r8
xor eax, eax
mov r9, [rcx]
mulx rax, r10, [r11]
adox r9, r10
mov [rcx], r9
mov r9, [rcx+8]
adcx r9, rax
mulx rax, r10, [r11+8]
adox r9, r10
mov [rcx+8], r9
mov r9, [rcx+16]
adcx r9, rax
mulx rax, r10, [r11+16]
adox r9, r10
mov [rcx+16], r9
mov r9, [rcx+24]
adcx r9, rax
mulx rax, r10, [r11+24]
adox r9, r10
mov [rcx+24], r9
mov r9, [rcx+32]
adcx r9, rax
mulx rax, r10, [r11+32]
adox r9, r10
mov [rcx+32], r9
mov r9, [rcx+40]
adcx r9, rax
mulx rax, r10, [r11+40]
adox r9, r10
mov [rcx+40], r9
mov r9, [rcx+48]
adcx r9, rax
mulx rax, r10, [r11+48]
adox r9, r10
mov [rcx+48], r9
mov r9, [rcx+56]
adcx r9, rax
mulx rax, r10, [r11+56]
adox r9, r10
mov [rcx+56], r9
mov r9, [rcx+64]
adcx r9, rax
mulx rax, r10, [r11+64]
adox r9, r10
mov [rcx+64], r9
mov r9, 0
adcx rax, r9
adox rax, r9
ret
align 16
export mclb_mulUnit_slow1
global mclb_mulUnit_slow1
global _mclb_mulUnit_slow1
mclb_mulUnit_slow1:
_mclb_mulUnit_slow1:
mov rax, [rdx]
mul r8
mov [rcx], rax
mov rax, rdx
ret
align 16
export mclb_mulUnit_slow2
global mclb_mulUnit_slow2
global _mclb_mulUnit_slow2
mclb_mulUnit_slow2:
_mclb_mulUnit_slow2:
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov r9, rdx
mov rax, [r11+8]
mul r8
add rax, r9
adc rdx, 0
mov [rcx+8], rax
mov rax, rdx
ret
align 16
export mclb_mulUnit_slow3
global mclb_mulUnit_slow3
global _mclb_mulUnit_slow3
mclb_mulUnit_slow3:
_mclb_mulUnit_slow3:
sub rsp, 40
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+16], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+24], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov rax, [rsp+16]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+24]
adc rax, [rsp+8]
mov [rcx+16], rax
adc rdx, 0
mov rax, rdx
add rsp, 40
ret
align 16
export mclb_mulUnit_slow4
global mclb_mulUnit_slow4
global _mclb_mulUnit_slow4
mclb_mulUnit_slow4:
_mclb_mulUnit_slow4:
sub rsp, 56
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+24], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+32], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov [rsp+40], rdx
mov rax, [r11+24]
mul r8
mov [rsp+16], rax
mov rax, [rsp+24]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+32]
adc rax, [rsp+8]
mov [rcx+16], rax
mov rax, [rsp+40]
adc rax, [rsp+16]
mov [rcx+24], rax
adc rdx, 0
mov rax, rdx
add rsp, 56
ret
align 16
export mclb_mulUnit_slow5
global mclb_mulUnit_slow5
global _mclb_mulUnit_slow5
mclb_mulUnit_slow5:
_mclb_mulUnit_slow5:
sub rsp, 72
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+32], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+40], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov [rsp+48], rdx
mov rax, [r11+24]
mul r8
mov [rsp+16], rax
mov [rsp+56], rdx
mov rax, [r11+32]
mul r8
mov [rsp+24], rax
mov rax, [rsp+32]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+40]
adc rax, [rsp+8]
mov [rcx+16], rax
mov rax, [rsp+48]
adc rax, [rsp+16]
mov [rcx+24], rax
mov rax, [rsp+56]
adc rax, [rsp+24]
mov [rcx+32], rax
adc rdx, 0
mov rax, rdx
add rsp, 72
ret
align 16
export mclb_mulUnit_slow6
global mclb_mulUnit_slow6
global _mclb_mulUnit_slow6
mclb_mulUnit_slow6:
_mclb_mulUnit_slow6:
sub rsp, 88
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+40], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+48], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov [rsp+56], rdx
mov rax, [r11+24]
mul r8
mov [rsp+16], rax
mov [rsp+64], rdx
mov rax, [r11+32]
mul r8
mov [rsp+24], rax
mov [rsp+72], rdx
mov rax, [r11+40]
mul r8
mov [rsp+32], rax
mov rax, [rsp+40]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+48]
adc rax, [rsp+8]
mov [rcx+16], rax
mov rax, [rsp+56]
adc rax, [rsp+16]
mov [rcx+24], rax
mov rax, [rsp+64]
adc rax, [rsp+24]
mov [rcx+32], rax
mov rax, [rsp+72]
adc rax, [rsp+32]
mov [rcx+40], rax
adc rdx, 0
mov rax, rdx
add rsp, 88
ret
align 16
export mclb_mulUnit_slow7
global mclb_mulUnit_slow7
global _mclb_mulUnit_slow7
mclb_mulUnit_slow7:
_mclb_mulUnit_slow7:
sub rsp, 104
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+48], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+56], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov [rsp+64], rdx
mov rax, [r11+24]
mul r8
mov [rsp+16], rax
mov [rsp+72], rdx
mov rax, [r11+32]
mul r8
mov [rsp+24], rax
mov [rsp+80], rdx
mov rax, [r11+40]
mul r8
mov [rsp+32], rax
mov [rsp+88], rdx
mov rax, [r11+48]
mul r8
mov [rsp+40], rax
mov rax, [rsp+48]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+56]
adc rax, [rsp+8]
mov [rcx+16], rax
mov rax, [rsp+64]
adc rax, [rsp+16]
mov [rcx+24], rax
mov rax, [rsp+72]
adc rax, [rsp+24]
mov [rcx+32], rax
mov rax, [rsp+80]
adc rax, [rsp+32]
mov [rcx+40], rax
mov rax, [rsp+88]
adc rax, [rsp+40]
mov [rcx+48], rax
adc rdx, 0
mov rax, rdx
add rsp, 104
ret
align 16
export mclb_mulUnit_slow8
global mclb_mulUnit_slow8
global _mclb_mulUnit_slow8
mclb_mulUnit_slow8:
_mclb_mulUnit_slow8:
sub rsp, 120
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+56], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+64], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov [rsp+72], rdx
mov rax, [r11+24]
mul r8
mov [rsp+16], rax
mov [rsp+80], rdx
mov rax, [r11+32]
mul r8
mov [rsp+24], rax
mov [rsp+88], rdx
mov rax, [r11+40]
mul r8
mov [rsp+32], rax
mov [rsp+96], rdx
mov rax, [r11+48]
mul r8
mov [rsp+40], rax
mov [rsp+104], rdx
mov rax, [r11+56]
mul r8
mov [rsp+48], rax
mov rax, [rsp+56]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+64]
adc rax, [rsp+8]
mov [rcx+16], rax
mov rax, [rsp+72]
adc rax, [rsp+16]
mov [rcx+24], rax
mov rax, [rsp+80]
adc rax, [rsp+24]
mov [rcx+32], rax
mov rax, [rsp+88]
adc rax, [rsp+32]
mov [rcx+40], rax
mov rax, [rsp+96]
adc rax, [rsp+40]
mov [rcx+48], rax
mov rax, [rsp+104]
adc rax, [rsp+48]
mov [rcx+56], rax
adc rdx, 0
mov rax, rdx
add rsp, 120
ret
align 16
export mclb_mulUnit_slow9
global mclb_mulUnit_slow9
global _mclb_mulUnit_slow9
mclb_mulUnit_slow9:
_mclb_mulUnit_slow9:
sub rsp, 136
mov r11, rdx
mov rax, [r11]
mul r8
mov [rcx], rax
mov [rsp+64], rdx
mov rax, [r11+8]
mul r8
mov [rsp], rax
mov [rsp+72], rdx
mov rax, [r11+16]
mul r8
mov [rsp+8], rax
mov [rsp+80], rdx
mov rax, [r11+24]
mul r8
mov [rsp+16], rax
mov [rsp+88], rdx
mov rax, [r11+32]
mul r8
mov [rsp+24], rax
mov [rsp+96], rdx
mov rax, [r11+40]
mul r8
mov [rsp+32], rax
mov [rsp+104], rdx
mov rax, [r11+48]
mul r8
mov [rsp+40], rax
mov [rsp+112], rdx
mov rax, [r11+56]
mul r8
mov [rsp+48], rax
mov [rsp+120], rdx
mov rax, [r11+64]
mul r8
mov [rsp+56], rax
mov rax, [rsp+64]
add rax, [rsp]
mov [rcx+8], rax
mov rax, [rsp+72]
adc rax, [rsp+8]
mov [rcx+16], rax
mov rax, [rsp+80]
adc rax, [rsp+16]
mov [rcx+24], rax
mov rax, [rsp+88]
adc rax, [rsp+24]
mov [rcx+32], rax
mov rax, [rsp+96]
adc rax, [rsp+32]
mov [rcx+40], rax
mov rax, [rsp+104]
adc rax, [rsp+40]
mov [rcx+48], rax
mov rax, [rsp+112]
adc rax, [rsp+48]
mov [rcx+56], rax
mov rax, [rsp+120]
adc rax, [rsp+56]
mov [rcx+64], rax
adc rdx, 0
mov rax, rdx
add rsp, 136
ret
align 16
export mclb_mulUnitAdd_slow1
global mclb_mulUnitAdd_slow1
global _mclb_mulUnitAdd_slow1
mclb_mulUnitAdd_slow1:
_mclb_mulUnitAdd_slow1:
sub rsp, 8
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov rax, [rsp]
add [rcx], rax
adc rdx, 0
mov rax, rdx
add rsp, 8
ret
align 16
export mclb_mulUnitAdd_slow2
global mclb_mulUnitAdd_slow2
global _mclb_mulUnitAdd_slow2
mclb_mulUnitAdd_slow2:
_mclb_mulUnitAdd_slow2:
sub rsp, 24
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+16], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov rax, [rsp+8]
add rax, [rsp+16]
mov [rsp+8], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
adc rdx, 0
mov rax, rdx
add rsp, 24
ret
align 16
export mclb_mulUnitAdd_slow3
global mclb_mulUnitAdd_slow3
global _mclb_mulUnitAdd_slow3
mclb_mulUnitAdd_slow3:
_mclb_mulUnitAdd_slow3:
sub rsp, 40
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+24], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+32], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov rax, [rsp+8]
add rax, [rsp+24]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+32]
mov [rsp+16], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
adc rdx, 0
mov rax, rdx
add rsp, 40
ret
align 16
export mclb_mulUnitAdd_slow4
global mclb_mulUnitAdd_slow4
global _mclb_mulUnitAdd_slow4
mclb_mulUnitAdd_slow4:
_mclb_mulUnitAdd_slow4:
sub rsp, 56
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+32], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+40], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov [rsp+48], rdx
mov rax, [r11+24]
mul r8
mov [rsp+24], rax
mov rax, [rsp+8]
add rax, [rsp+32]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+40]
mov [rsp+16], rax
mov rax, [rsp+24]
adc rax, [rsp+48]
mov [rsp+24], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
mov rax, [rsp+24]
adc [rcx+24], rax
adc rdx, 0
mov rax, rdx
add rsp, 56
ret
align 16
export mclb_mulUnitAdd_slow5
global mclb_mulUnitAdd_slow5
global _mclb_mulUnitAdd_slow5
mclb_mulUnitAdd_slow5:
_mclb_mulUnitAdd_slow5:
sub rsp, 72
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+40], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+48], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov [rsp+56], rdx
mov rax, [r11+24]
mul r8
mov [rsp+24], rax
mov [rsp+64], rdx
mov rax, [r11+32]
mul r8
mov [rsp+32], rax
mov rax, [rsp+8]
add rax, [rsp+40]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+48]
mov [rsp+16], rax
mov rax, [rsp+24]
adc rax, [rsp+56]
mov [rsp+24], rax
mov rax, [rsp+32]
adc rax, [rsp+64]
mov [rsp+32], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
mov rax, [rsp+24]
adc [rcx+24], rax
mov rax, [rsp+32]
adc [rcx+32], rax
adc rdx, 0
mov rax, rdx
add rsp, 72
ret
align 16
export mclb_mulUnitAdd_slow6
global mclb_mulUnitAdd_slow6
global _mclb_mulUnitAdd_slow6
mclb_mulUnitAdd_slow6:
_mclb_mulUnitAdd_slow6:
sub rsp, 88
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+48], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+56], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov [rsp+64], rdx
mov rax, [r11+24]
mul r8
mov [rsp+24], rax
mov [rsp+72], rdx
mov rax, [r11+32]
mul r8
mov [rsp+32], rax
mov [rsp+80], rdx
mov rax, [r11+40]
mul r8
mov [rsp+40], rax
mov rax, [rsp+8]
add rax, [rsp+48]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+56]
mov [rsp+16], rax
mov rax, [rsp+24]
adc rax, [rsp+64]
mov [rsp+24], rax
mov rax, [rsp+32]
adc rax, [rsp+72]
mov [rsp+32], rax
mov rax, [rsp+40]
adc rax, [rsp+80]
mov [rsp+40], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
mov rax, [rsp+24]
adc [rcx+24], rax
mov rax, [rsp+32]
adc [rcx+32], rax
mov rax, [rsp+40]
adc [rcx+40], rax
adc rdx, 0
mov rax, rdx
add rsp, 88
ret
align 16
export mclb_mulUnitAdd_slow7
global mclb_mulUnitAdd_slow7
global _mclb_mulUnitAdd_slow7
mclb_mulUnitAdd_slow7:
_mclb_mulUnitAdd_slow7:
sub rsp, 104
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+56], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+64], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov [rsp+72], rdx
mov rax, [r11+24]
mul r8
mov [rsp+24], rax
mov [rsp+80], rdx
mov rax, [r11+32]
mul r8
mov [rsp+32], rax
mov [rsp+88], rdx
mov rax, [r11+40]
mul r8
mov [rsp+40], rax
mov [rsp+96], rdx
mov rax, [r11+48]
mul r8
mov [rsp+48], rax
mov rax, [rsp+8]
add rax, [rsp+56]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+64]
mov [rsp+16], rax
mov rax, [rsp+24]
adc rax, [rsp+72]
mov [rsp+24], rax
mov rax, [rsp+32]
adc rax, [rsp+80]
mov [rsp+32], rax
mov rax, [rsp+40]
adc rax, [rsp+88]
mov [rsp+40], rax
mov rax, [rsp+48]
adc rax, [rsp+96]
mov [rsp+48], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
mov rax, [rsp+24]
adc [rcx+24], rax
mov rax, [rsp+32]
adc [rcx+32], rax
mov rax, [rsp+40]
adc [rcx+40], rax
mov rax, [rsp+48]
adc [rcx+48], rax
adc rdx, 0
mov rax, rdx
add rsp, 104
ret
align 16
export mclb_mulUnitAdd_slow8
global mclb_mulUnitAdd_slow8
global _mclb_mulUnitAdd_slow8
mclb_mulUnitAdd_slow8:
_mclb_mulUnitAdd_slow8:
sub rsp, 120
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+64], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+72], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov [rsp+80], rdx
mov rax, [r11+24]
mul r8
mov [rsp+24], rax
mov [rsp+88], rdx
mov rax, [r11+32]
mul r8
mov [rsp+32], rax
mov [rsp+96], rdx
mov rax, [r11+40]
mul r8
mov [rsp+40], rax
mov [rsp+104], rdx
mov rax, [r11+48]
mul r8
mov [rsp+48], rax
mov [rsp+112], rdx
mov rax, [r11+56]
mul r8
mov [rsp+56], rax
mov rax, [rsp+8]
add rax, [rsp+64]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+72]
mov [rsp+16], rax
mov rax, [rsp+24]
adc rax, [rsp+80]
mov [rsp+24], rax
mov rax, [rsp+32]
adc rax, [rsp+88]
mov [rsp+32], rax
mov rax, [rsp+40]
adc rax, [rsp+96]
mov [rsp+40], rax
mov rax, [rsp+48]
adc rax, [rsp+104]
mov [rsp+48], rax
mov rax, [rsp+56]
adc rax, [rsp+112]
mov [rsp+56], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
mov rax, [rsp+24]
adc [rcx+24], rax
mov rax, [rsp+32]
adc [rcx+32], rax
mov rax, [rsp+40]
adc [rcx+40], rax
mov rax, [rsp+48]
adc [rcx+48], rax
mov rax, [rsp+56]
adc [rcx+56], rax
adc rdx, 0
mov rax, rdx
add rsp, 120
ret
align 16
export mclb_mulUnitAdd_slow9
global mclb_mulUnitAdd_slow9
global _mclb_mulUnitAdd_slow9
mclb_mulUnitAdd_slow9:
_mclb_mulUnitAdd_slow9:
sub rsp, 136
mov r11, rdx
mov rax, [r11]
mul r8
mov [rsp], rax
mov [rsp+72], rdx
mov rax, [r11+8]
mul r8
mov [rsp+8], rax
mov [rsp+80], rdx
mov rax, [r11+16]
mul r8
mov [rsp+16], rax
mov [rsp+88], rdx
mov rax, [r11+24]
mul r8
mov [rsp+24], rax
mov [rsp+96], rdx
mov rax, [r11+32]
mul r8
mov [rsp+32], rax
mov [rsp+104], rdx
mov rax, [r11+40]
mul r8
mov [rsp+40], rax
mov [rsp+112], rdx
mov rax, [r11+48]
mul r8
mov [rsp+48], rax
mov [rsp+120], rdx
mov rax, [r11+56]
mul r8
mov [rsp+56], rax
mov [rsp+128], rdx
mov rax, [r11+64]
mul r8
mov [rsp+64], rax
mov rax, [rsp+8]
add rax, [rsp+72]
mov [rsp+8], rax
mov rax, [rsp+16]
adc rax, [rsp+80]
mov [rsp+16], rax
mov rax, [rsp+24]
adc rax, [rsp+88]
mov [rsp+24], rax
mov rax, [rsp+32]
adc rax, [rsp+96]
mov [rsp+32], rax
mov rax, [rsp+40]
adc rax, [rsp+104]
mov [rsp+40], rax
mov rax, [rsp+48]
adc rax, [rsp+112]
mov [rsp+48], rax
mov rax, [rsp+56]
adc rax, [rsp+120]
mov [rsp+56], rax
mov rax, [rsp+64]
adc rax, [rsp+128]
mov [rsp+64], rax
adc rdx, 0
mov rax, [rsp]
add [rcx], rax
mov rax, [rsp+8]
adc [rcx+8], rax
mov rax, [rsp+16]
adc [rcx+16], rax
mov rax, [rsp+24]
adc [rcx+24], rax
mov rax, [rsp+32]
adc [rcx+32], rax
mov rax, [rsp+40]
adc [rcx+40], rax
mov rax, [rsp+48]
adc [rcx+48], rax
mov rax, [rsp+56]
adc [rcx+56], rax
mov rax, [rsp+64]
adc [rcx+64], rax
adc rdx, 0
mov rax, rdx
add rsp, 136
ret
align 16
export mclb_mul_fast1
global mclb_mul_fast1
global _mclb_mul_fast1
mclb_mul_fast1:
_mclb_mul_fast1:
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
adc r9, 0
mov [rcx+8], r9
ret
align 16
export mclb_mul_fast2
global mclb_mul_fast2
global _mclb_mul_fast2
mclb_mul_fast2:
_mclb_mul_fast2:
push rdi
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
adc r10, 0
mov rdx, [r11+8]
xor rax, rax
mulx rdi, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, rdi
mulx rdi, rax, [r8+8]
adox r10, rax
mov rax, 0
adox rdi, rax
adc rdi, rax
mov [rcx+16], r10
mov [rcx+24], rdi
pop rdi
ret
align 16
export mclb_mul_fast3
global mclb_mul_fast3
global _mclb_mul_fast3
mclb_mul_fast3:
_mclb_mul_fast3:
push rdi
push rsi
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
adc rdi, 0
mov rdx, [r11+8]
xor rax, rax
mulx rsi, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, rsi
mulx rsi, rax, [r8+8]
adox r10, rax
adcx rdi, rsi
mulx rsi, rax, [r8+16]
adox rdi, rax
mov rax, 0
adox rsi, rax
adc rsi, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov [rcx+24], rdi
mov [rcx+32], rsi
mov [rcx+40], r9
pop rsi
pop rdi
ret
align 16
export mclb_mul_fast4
global mclb_mul_fast4
global _mclb_mul_fast4
mclb_mul_fast4:
_mclb_mul_fast4:
push rdi
push rsi
push rbx
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
mulx rsi, rax, [r8+24]
adcx rdi, rax
adc rsi, 0
mov rdx, [r11+8]
xor rax, rax
mulx rbx, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, rbx
mulx rbx, rax, [r8+8]
adox r10, rax
adcx rdi, rbx
mulx rbx, rax, [r8+16]
adox rdi, rax
adcx rsi, rbx
mulx rbx, rax, [r8+24]
adox rsi, rax
mov rax, 0
adox rbx, rax
adc rbx, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
adcx rbx, r9
mulx r9, rax, [r8+24]
adox rbx, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov rdx, [r11+24]
xor rax, rax
mulx r10, rax, [r8]
adox rdi, rax
mov [rcx+24], rdi
adcx rsi, r10
mulx r10, rax, [r8+8]
adox rsi, rax
adcx rbx, r10
mulx r10, rax, [r8+16]
adox rbx, rax
adcx r9, r10
mulx r10, rax, [r8+24]
adox r9, rax
mov rax, 0
adox r10, rax
adc r10, rax
mov [rcx+32], rsi
mov [rcx+40], rbx
mov [rcx+48], r9
mov [rcx+56], r10
pop rbx
pop rsi
pop rdi
ret
align 16
export mclb_mul_fast5
global mclb_mul_fast5
global _mclb_mul_fast5
mclb_mul_fast5:
_mclb_mul_fast5:
push rdi
push rsi
push rbx
push rbp
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
mulx rsi, rax, [r8+24]
adcx rdi, rax
mulx rbx, rax, [r8+32]
adcx rsi, rax
adc rbx, 0
mov rdx, [r11+8]
xor rax, rax
mulx rbp, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, rbp
mulx rbp, rax, [r8+8]
adox r10, rax
adcx rdi, rbp
mulx rbp, rax, [r8+16]
adox rdi, rax
adcx rsi, rbp
mulx rbp, rax, [r8+24]
adox rsi, rax
adcx rbx, rbp
mulx rbp, rax, [r8+32]
adox rbx, rax
mov rax, 0
adox rbp, rax
adc rbp, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
adcx rbx, r9
mulx r9, rax, [r8+24]
adox rbx, rax
adcx rbp, r9
mulx r9, rax, [r8+32]
adox rbp, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov rdx, [r11+24]
xor rax, rax
mulx r10, rax, [r8]
adox rdi, rax
mov [rcx+24], rdi
adcx rsi, r10
mulx r10, rax, [r8+8]
adox rsi, rax
adcx rbx, r10
mulx r10, rax, [r8+16]
adox rbx, rax
adcx rbp, r10
mulx r10, rax, [r8+24]
adox rbp, rax
adcx r9, r10
mulx r10, rax, [r8+32]
adox r9, rax
mov rax, 0
adox r10, rax
adc r10, rax
mov rdx, [r11+32]
xor rax, rax
mulx rdi, rax, [r8]
adox rsi, rax
mov [rcx+32], rsi
adcx rbx, rdi
mulx rdi, rax, [r8+8]
adox rbx, rax
adcx rbp, rdi
mulx rdi, rax, [r8+16]
adox rbp, rax
adcx r9, rdi
mulx rdi, rax, [r8+24]
adox r9, rax
adcx r10, rdi
mulx rdi, rax, [r8+32]
adox r10, rax
mov rax, 0
adox rdi, rax
adc rdi, rax
mov [rcx+40], rbx
mov [rcx+48], rbp
mov [rcx+56], r9
mov [rcx+64], r10
mov [rcx+72], rdi
pop rbp
pop rbx
pop rsi
pop rdi
ret
align 16
export mclb_mul_fast6
global mclb_mul_fast6
global _mclb_mul_fast6
mclb_mul_fast6:
_mclb_mul_fast6:
push rdi
push rsi
push rbx
push rbp
push r12
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
mulx rsi, rax, [r8+24]
adcx rdi, rax
mulx rbx, rax, [r8+32]
adcx rsi, rax
mulx rbp, rax, [r8+40]
adcx rbx, rax
adc rbp, 0
mov rdx, [r11+8]
xor rax, rax
mulx r12, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, r12
mulx r12, rax, [r8+8]
adox r10, rax
adcx rdi, r12
mulx r12, rax, [r8+16]
adox rdi, rax
adcx rsi, r12
mulx r12, rax, [r8+24]
adox rsi, rax
adcx rbx, r12
mulx r12, rax, [r8+32]
adox rbx, rax
adcx rbp, r12
mulx r12, rax, [r8+40]
adox rbp, rax
mov rax, 0
adox r12, rax
adc r12, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
adcx rbx, r9
mulx r9, rax, [r8+24]
adox rbx, rax
adcx rbp, r9
mulx r9, rax, [r8+32]
adox rbp, rax
adcx r12, r9
mulx r9, rax, [r8+40]
adox r12, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov rdx, [r11+24]
xor rax, rax
mulx r10, rax, [r8]
adox rdi, rax
mov [rcx+24], rdi
adcx rsi, r10
mulx r10, rax, [r8+8]
adox rsi, rax
adcx rbx, r10
mulx r10, rax, [r8+16]
adox rbx, rax
adcx rbp, r10
mulx r10, rax, [r8+24]
adox rbp, rax
adcx r12, r10
mulx r10, rax, [r8+32]
adox r12, rax
adcx r9, r10
mulx r10, rax, [r8+40]
adox r9, rax
mov rax, 0
adox r10, rax
adc r10, rax
mov rdx, [r11+32]
xor rax, rax
mulx rdi, rax, [r8]
adox rsi, rax
mov [rcx+32], rsi
adcx rbx, rdi
mulx rdi, rax, [r8+8]
adox rbx, rax
adcx rbp, rdi
mulx rdi, rax, [r8+16]
adox rbp, rax
adcx r12, rdi
mulx rdi, rax, [r8+24]
adox r12, rax
adcx r9, rdi
mulx rdi, rax, [r8+32]
adox r9, rax
adcx r10, rdi
mulx rdi, rax, [r8+40]
adox r10, rax
mov rax, 0
adox rdi, rax
adc rdi, rax
mov rdx, [r11+40]
xor rax, rax
mulx rsi, rax, [r8]
adox rbx, rax
mov [rcx+40], rbx
adcx rbp, rsi
mulx rsi, rax, [r8+8]
adox rbp, rax
adcx r12, rsi
mulx rsi, rax, [r8+16]
adox r12, rax
adcx r9, rsi
mulx rsi, rax, [r8+24]
adox r9, rax
adcx r10, rsi
mulx rsi, rax, [r8+32]
adox r10, rax
adcx rdi, rsi
mulx rsi, rax, [r8+40]
adox rdi, rax
mov rax, 0
adox rsi, rax
adc rsi, rax
mov [rcx+48], rbp
mov [rcx+56], r12
mov [rcx+64], r9
mov [rcx+72], r10
mov [rcx+80], rdi
mov [rcx+88], rsi
pop r12
pop rbp
pop rbx
pop rsi
pop rdi
ret
align 16
export mclb_mul_fast7
global mclb_mul_fast7
global _mclb_mul_fast7
mclb_mul_fast7:
_mclb_mul_fast7:
push rdi
push rsi
push rbx
push rbp
push r12
push r13
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
mulx rsi, rax, [r8+24]
adcx rdi, rax
mulx rbx, rax, [r8+32]
adcx rsi, rax
mulx rbp, rax, [r8+40]
adcx rbx, rax
mulx r12, rax, [r8+48]
adcx rbp, rax
adc r12, 0
mov rdx, [r11+8]
xor rax, rax
mulx r13, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, r13
mulx r13, rax, [r8+8]
adox r10, rax
adcx rdi, r13
mulx r13, rax, [r8+16]
adox rdi, rax
adcx rsi, r13
mulx r13, rax, [r8+24]
adox rsi, rax
adcx rbx, r13
mulx r13, rax, [r8+32]
adox rbx, rax
adcx rbp, r13
mulx r13, rax, [r8+40]
adox rbp, rax
adcx r12, r13
mulx r13, rax, [r8+48]
adox r12, rax
mov rax, 0
adox r13, rax
adc r13, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
adcx rbx, r9
mulx r9, rax, [r8+24]
adox rbx, rax
adcx rbp, r9
mulx r9, rax, [r8+32]
adox rbp, rax
adcx r12, r9
mulx r9, rax, [r8+40]
adox r12, rax
adcx r13, r9
mulx r9, rax, [r8+48]
adox r13, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov rdx, [r11+24]
xor rax, rax
mulx r10, rax, [r8]
adox rdi, rax
mov [rcx+24], rdi
adcx rsi, r10
mulx r10, rax, [r8+8]
adox rsi, rax
adcx rbx, r10
mulx r10, rax, [r8+16]
adox rbx, rax
adcx rbp, r10
mulx r10, rax, [r8+24]
adox rbp, rax
adcx r12, r10
mulx r10, rax, [r8+32]
adox r12, rax
adcx r13, r10
mulx r10, rax, [r8+40]
adox r13, rax
adcx r9, r10
mulx r10, rax, [r8+48]
adox r9, rax
mov rax, 0
adox r10, rax
adc r10, rax
mov rdx, [r11+32]
xor rax, rax
mulx rdi, rax, [r8]
adox rsi, rax
mov [rcx+32], rsi
adcx rbx, rdi
mulx rdi, rax, [r8+8]
adox rbx, rax
adcx rbp, rdi
mulx rdi, rax, [r8+16]
adox rbp, rax
adcx r12, rdi
mulx rdi, rax, [r8+24]
adox r12, rax
adcx r13, rdi
mulx rdi, rax, [r8+32]
adox r13, rax
adcx r9, rdi
mulx rdi, rax, [r8+40]
adox r9, rax
adcx r10, rdi
mulx rdi, rax, [r8+48]
adox r10, rax
mov rax, 0
adox rdi, rax
adc rdi, rax
mov rdx, [r11+40]
xor rax, rax
mulx rsi, rax, [r8]
adox rbx, rax
mov [rcx+40], rbx
adcx rbp, rsi
mulx rsi, rax, [r8+8]
adox rbp, rax
adcx r12, rsi
mulx rsi, rax, [r8+16]
adox r12, rax
adcx r13, rsi
mulx rsi, rax, [r8+24]
adox r13, rax
adcx r9, rsi
mulx rsi, rax, [r8+32]
adox r9, rax
adcx r10, rsi
mulx rsi, rax, [r8+40]
adox r10, rax
adcx rdi, rsi
mulx rsi, rax, [r8+48]
adox rdi, rax
mov rax, 0
adox rsi, rax
adc rsi, rax
mov rdx, [r11+48]
xor rax, rax
mulx rbx, rax, [r8]
adox rbp, rax
mov [rcx+48], rbp
adcx r12, rbx
mulx rbx, rax, [r8+8]
adox r12, rax
adcx r13, rbx
mulx rbx, rax, [r8+16]
adox r13, rax
adcx r9, rbx
mulx rbx, rax, [r8+24]
adox r9, rax
adcx r10, rbx
mulx rbx, rax, [r8+32]
adox r10, rax
adcx rdi, rbx
mulx rbx, rax, [r8+40]
adox rdi, rax
adcx rsi, rbx
mulx rbx, rax, [r8+48]
adox rsi, rax
mov rax, 0
adox rbx, rax
adc rbx, rax
mov [rcx+56], r12
mov [rcx+64], r13
mov [rcx+72], r9
mov [rcx+80], r10
mov [rcx+88], rdi
mov [rcx+96], rsi
mov [rcx+104], rbx
pop r13
pop r12
pop rbp
pop rbx
pop rsi
pop rdi
ret
align 16
export mclb_mul_fast8
global mclb_mul_fast8
global _mclb_mul_fast8
mclb_mul_fast8:
_mclb_mul_fast8:
push rdi
push rsi
push rbx
push rbp
push r12
push r13
push r14
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
mulx rsi, rax, [r8+24]
adcx rdi, rax
mulx rbx, rax, [r8+32]
adcx rsi, rax
mulx rbp, rax, [r8+40]
adcx rbx, rax
mulx r12, rax, [r8+48]
adcx rbp, rax
mulx r13, rax, [r8+56]
adcx r12, rax
adc r13, 0
mov rdx, [r11+8]
xor rax, rax
mulx r14, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, r14
mulx r14, rax, [r8+8]
adox r10, rax
adcx rdi, r14
mulx r14, rax, [r8+16]
adox rdi, rax
adcx rsi, r14
mulx r14, rax, [r8+24]
adox rsi, rax
adcx rbx, r14
mulx r14, rax, [r8+32]
adox rbx, rax
adcx rbp, r14
mulx r14, rax, [r8+40]
adox rbp, rax
adcx r12, r14
mulx r14, rax, [r8+48]
adox r12, rax
adcx r13, r14
mulx r14, rax, [r8+56]
adox r13, rax
mov rax, 0
adox r14, rax
adc r14, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
adcx rbx, r9
mulx r9, rax, [r8+24]
adox rbx, rax
adcx rbp, r9
mulx r9, rax, [r8+32]
adox rbp, rax
adcx r12, r9
mulx r9, rax, [r8+40]
adox r12, rax
adcx r13, r9
mulx r9, rax, [r8+48]
adox r13, rax
adcx r14, r9
mulx r9, rax, [r8+56]
adox r14, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov rdx, [r11+24]
xor rax, rax
mulx r10, rax, [r8]
adox rdi, rax
mov [rcx+24], rdi
adcx rsi, r10
mulx r10, rax, [r8+8]
adox rsi, rax
adcx rbx, r10
mulx r10, rax, [r8+16]
adox rbx, rax
adcx rbp, r10
mulx r10, rax, [r8+24]
adox rbp, rax
adcx r12, r10
mulx r10, rax, [r8+32]
adox r12, rax
adcx r13, r10
mulx r10, rax, [r8+40]
adox r13, rax
adcx r14, r10
mulx r10, rax, [r8+48]
adox r14, rax
adcx r9, r10
mulx r10, rax, [r8+56]
adox r9, rax
mov rax, 0
adox r10, rax
adc r10, rax
mov rdx, [r11+32]
xor rax, rax
mulx rdi, rax, [r8]
adox rsi, rax
mov [rcx+32], rsi
adcx rbx, rdi
mulx rdi, rax, [r8+8]
adox rbx, rax
adcx rbp, rdi
mulx rdi, rax, [r8+16]
adox rbp, rax
adcx r12, rdi
mulx rdi, rax, [r8+24]
adox r12, rax
adcx r13, rdi
mulx rdi, rax, [r8+32]
adox r13, rax
adcx r14, rdi
mulx rdi, rax, [r8+40]
adox r14, rax
adcx r9, rdi
mulx rdi, rax, [r8+48]
adox r9, rax
adcx r10, rdi
mulx rdi, rax, [r8+56]
adox r10, rax
mov rax, 0
adox rdi, rax
adc rdi, rax
mov rdx, [r11+40]
xor rax, rax
mulx rsi, rax, [r8]
adox rbx, rax
mov [rcx+40], rbx
adcx rbp, rsi
mulx rsi, rax, [r8+8]
adox rbp, rax
adcx r12, rsi
mulx rsi, rax, [r8+16]
adox r12, rax
adcx r13, rsi
mulx rsi, rax, [r8+24]
adox r13, rax
adcx r14, rsi
mulx rsi, rax, [r8+32]
adox r14, rax
adcx r9, rsi
mulx rsi, rax, [r8+40]
adox r9, rax
adcx r10, rsi
mulx rsi, rax, [r8+48]
adox r10, rax
adcx rdi, rsi
mulx rsi, rax, [r8+56]
adox rdi, rax
mov rax, 0
adox rsi, rax
adc rsi, rax
mov rdx, [r11+48]
xor rax, rax
mulx rbx, rax, [r8]
adox rbp, rax
mov [rcx+48], rbp
adcx r12, rbx
mulx rbx, rax, [r8+8]
adox r12, rax
adcx r13, rbx
mulx rbx, rax, [r8+16]
adox r13, rax
adcx r14, rbx
mulx rbx, rax, [r8+24]
adox r14, rax
adcx r9, rbx
mulx rbx, rax, [r8+32]
adox r9, rax
adcx r10, rbx
mulx rbx, rax, [r8+40]
adox r10, rax
adcx rdi, rbx
mulx rbx, rax, [r8+48]
adox rdi, rax
adcx rsi, rbx
mulx rbx, rax, [r8+56]
adox rsi, rax
mov rax, 0
adox rbx, rax
adc rbx, rax
mov rdx, [r11+56]
xor rax, rax
mulx rbp, rax, [r8]
adox r12, rax
mov [rcx+56], r12
adcx r13, rbp
mulx rbp, rax, [r8+8]
adox r13, rax
adcx r14, rbp
mulx rbp, rax, [r8+16]
adox r14, rax
adcx r9, rbp
mulx rbp, rax, [r8+24]
adox r9, rax
adcx r10, rbp
mulx rbp, rax, [r8+32]
adox r10, rax
adcx rdi, rbp
mulx rbp, rax, [r8+40]
adox rdi, rax
adcx rsi, rbp
mulx rbp, rax, [r8+48]
adox rsi, rax
adcx rbx, rbp
mulx rbp, rax, [r8+56]
adox rbx, rax
mov rax, 0
adox rbp, rax
adc rbp, rax
mov [rcx+64], r13
mov [rcx+72], r14
mov [rcx+80], r9
mov [rcx+88], r10
mov [rcx+96], rdi
mov [rcx+104], rsi
mov [rcx+112], rbx
mov [rcx+120], rbp
pop r14
pop r13
pop r12
pop rbp
pop rbx
pop rsi
pop rdi
ret
align 16
export mclb_mul_fast9
global mclb_mul_fast9
global _mclb_mul_fast9
mclb_mul_fast9:
_mclb_mul_fast9:
push rdi
push rsi
push rbx
push rbp
push r12
push r13
push r14
push r15
mov r11, rdx
mov rdx, [r11]
mulx r9, rax, [r8]
mov [rcx], rax
xor rax, rax
mulx r10, rax, [r8+8]
adcx r9, rax
mulx rdi, rax, [r8+16]
adcx r10, rax
mulx rsi, rax, [r8+24]
adcx rdi, rax
mulx rbx, rax, [r8+32]
adcx rsi, rax
mulx rbp, rax, [r8+40]
adcx rbx, rax
mulx r12, rax, [r8+48]
adcx rbp, rax
mulx r13, rax, [r8+56]
adcx r12, rax
mulx r14, rax, [r8+64]
adcx r13, rax
adc r14, 0
mov rdx, [r11+8]
xor rax, rax
mulx r15, rax, [r8]
adox r9, rax
mov [rcx+8], r9
adcx r10, r15
mulx r15, rax, [r8+8]
adox r10, rax
adcx rdi, r15
mulx r15, rax, [r8+16]
adox rdi, rax
adcx rsi, r15
mulx r15, rax, [r8+24]
adox rsi, rax
adcx rbx, r15
mulx r15, rax, [r8+32]
adox rbx, rax
adcx rbp, r15
mulx r15, rax, [r8+40]
adox rbp, rax
adcx r12, r15
mulx r15, rax, [r8+48]
adox r12, rax
adcx r13, r15
mulx r15, rax, [r8+56]
adox r13, rax
adcx r14, r15
mulx r15, rax, [r8+64]
adox r14, rax
mov rax, 0
adox r15, rax
adc r15, rax
mov rdx, [r11+16]
xor rax, rax
mulx r9, rax, [r8]
adox r10, rax
mov [rcx+16], r10
adcx rdi, r9
mulx r9, rax, [r8+8]
adox rdi, rax
adcx rsi, r9
mulx r9, rax, [r8+16]
adox rsi, rax
adcx rbx, r9
mulx r9, rax, [r8+24]
adox rbx, rax
adcx rbp, r9
mulx r9, rax, [r8+32]
adox rbp, rax
adcx r12, r9
mulx r9, rax, [r8+40]
adox r12, rax
adcx r13, r9
mulx r9, rax, [r8+48]
adox r13, rax
adcx r14, r9
mulx r9, rax, [r8+56]
adox r14, rax
adcx r15, r9
mulx r9, rax, [r8+64]
adox r15, rax
mov rax, 0
adox r9, rax
adc r9, rax
mov rdx, [r11+24]
xor rax, rax
mulx r10, rax, [r8]
adox rdi, rax
mov [rcx+24], rdi
adcx rsi, r10
mulx r10, rax, [r8+8]
adox rsi, rax
adcx rbx, r10
mulx r10, rax, [r8+16]
adox rbx, rax
adcx rbp, r10
mulx r10, rax, [r8+24]
adox rbp, rax
adcx r12, r10
mulx r10, rax, [r8+32]
adox r12, rax
adcx r13, r10
mulx r10, rax, [r8+40]
adox r13, rax
adcx r14, r10
mulx r10, rax, [r8+48]
adox r14, rax
adcx r15, r10
mulx r10, rax, [r8+56]
adox r15, rax
adcx r9, r10
mulx r10, rax, [r8+64]
adox r9, rax
mov rax, 0
adox r10, rax
adc r10, rax
mov rdx, [r11+32]
xor rax, rax
mulx rdi, rax, [r8]
adox rsi, rax
mov [rcx+32], rsi
adcx rbx, rdi
mulx rdi, rax, [r8+8]
adox rbx, rax
adcx rbp, rdi
mulx rdi, rax, [r8+16]
adox rbp, rax
adcx r12, rdi
mulx rdi, rax, [r8+24]
adox r12, rax
adcx r13, rdi
mulx rdi, rax, [r8+32]
adox r13, rax
adcx r14, rdi
mulx rdi, rax, [r8+40]
adox r14, rax
adcx r15, rdi
mulx rdi, rax, [r8+48]
adox r15, rax
adcx r9, rdi
mulx rdi, rax, [r8+56]
adox r9, rax
adcx r10, rdi
mulx rdi, rax, [r8+64]
adox r10, rax
mov rax, 0
adox rdi, rax
adc rdi, rax
mov rdx, [r11+40]
xor rax, rax
mulx rsi, rax, [r8]
adox rbx, rax
mov [rcx+40], rbx
adcx rbp, rsi
mulx rsi, rax, [r8+8]
adox rbp, rax
adcx r12, rsi
mulx rsi, rax, [r8+16]
adox r12, rax
adcx r13, rsi
mulx rsi, rax, [r8+24]
adox r13, rax
adcx r14, rsi
mulx rsi, rax, [r8+32]
adox r14, rax
adcx r15, rsi
mulx rsi, rax, [r8+40]
adox r15, rax
adcx r9, rsi
mulx rsi, rax, [r8+48]
adox r9, rax
adcx r10, rsi
mulx rsi, rax, [r8+56]
adox r10, rax
adcx rdi, rsi
mulx rsi, rax, [r8+64]
adox rdi, rax
mov rax, 0
adox rsi, rax
adc rsi, rax
mov rdx, [r11+48]
xor rax, rax
mulx rbx, rax, [r8]
adox rbp, rax
mov [rcx+48], rbp
adcx r12, rbx
mulx rbx, rax, [r8+8]
adox r12, rax
adcx r13, rbx
mulx rbx, rax, [r8+16]
adox r13, rax
adcx r14, rbx
mulx rbx, rax, [r8+24]
adox r14, rax
adcx r15, rbx
mulx rbx, rax, [r8+32]
adox r15, rax
adcx r9, rbx
mulx rbx, rax, [r8+40]
adox r9, rax
adcx r10, rbx
mulx rbx, rax, [r8+48]
adox r10, rax
adcx rdi, rbx
mulx rbx, rax, [r8+56]
adox rdi, rax
adcx rsi, rbx
mulx rbx, rax, [r8+64]
adox rsi, rax
mov rax, 0
adox rbx, rax
adc rbx, rax
mov rdx, [r11+56]
xor rax, rax
mulx rbp, rax, [r8]
adox r12, rax
mov [rcx+56], r12
adcx r13, rbp
mulx rbp, rax, [r8+8]
adox r13, rax
adcx r14, rbp
mulx rbp, rax, [r8+16]
adox r14, rax
adcx r15, rbp
mulx rbp, rax, [r8+24]
adox r15, rax
adcx r9, rbp
mulx rbp, rax, [r8+32]
adox r9, rax
adcx r10, rbp
mulx rbp, rax, [r8+40]
adox r10, rax
adcx rdi, rbp
mulx rbp, rax, [r8+48]
adox rdi, rax
adcx rsi, rbp
mulx rbp, rax, [r8+56]
adox rsi, rax
adcx rbx, rbp
mulx rbp, rax, [r8+64]
adox rbx, rax
mov rax, 0
adox rbp, rax
adc rbp, rax
mov rdx, [r11+64]
xor rax, rax
mulx r12, rax, [r8]
adox r13, rax
mov [rcx+64], r13
adcx r14, r12
mulx r12, rax, [r8+8]
adox r14, rax
adcx r15, r12
mulx r12, rax, [r8+16]
adox r15, rax
adcx r9, r12
mulx r12, rax, [r8+24]
adox r9, rax
adcx r10, r12
mulx r12, rax, [r8+32]
adox r10, rax
adcx rdi, r12
mulx r12, rax, [r8+40]
adox rdi, rax
adcx rsi, r12
mulx r12, rax, [r8+48]
adox rsi, rax
adcx rbx, r12
mulx r12, rax, [r8+56]
adox rbx, rax
adcx rbp, r12
mulx r12, rax, [r8+64]
adox rbp, rax
mov rax, 0
adox r12, rax
adc r12, rax
mov [rcx+72], r14
mov [rcx+80], r15
mov [rcx+88], r9
mov [rcx+96], r10
mov [rcx+104], rdi
mov [rcx+112], rsi
mov [rcx+120], rbx
mov [rcx+128], rbp
mov [rcx+136], r12
pop r15
pop r14
pop r13
pop r12
pop rbp
pop rbx
pop rsi
pop rdi
ret
align 16
export mclb_sqr_fast1
global mclb_sqr_fast1
global _mclb_sqr_fast1
mclb_sqr_fast1:
_mclb_sqr_fast1:
mov r8, rdx
jmp mclb_mul_fast1
align 16
export mclb_sqr_fast2
global mclb_sqr_fast2
global _mclb_sqr_fast2
mclb_sqr_fast2:
_mclb_sqr_fast2:
mov r8, rdx
jmp mclb_mul_fast2
align 16
export mclb_sqr_fast3
global mclb_sqr_fast3
global _mclb_sqr_fast3
mclb_sqr_fast3:
_mclb_sqr_fast3:
mov r8, rdx
jmp mclb_mul_fast3
align 16
export mclb_sqr_fast4
global mclb_sqr_fast4
global _mclb_sqr_fast4
mclb_sqr_fast4:
_mclb_sqr_fast4:
mov r8, rdx
jmp mclb_mul_fast4
align 16
export mclb_sqr_fast5
global mclb_sqr_fast5
global _mclb_sqr_fast5
mclb_sqr_fast5:
_mclb_sqr_fast5:
mov r8, rdx
jmp mclb_mul_fast5
align 16
export mclb_sqr_fast6
global mclb_sqr_fast6
global _mclb_sqr_fast6
mclb_sqr_fast6:
_mclb_sqr_fast6:
mov r8, rdx
jmp mclb_mul_fast6
align 16
export mclb_sqr_fast7
global mclb_sqr_fast7
global _mclb_sqr_fast7
mclb_sqr_fast7:
_mclb_sqr_fast7:
mov r8, rdx
jmp mclb_mul_fast7
align 16
export mclb_sqr_fast8
global mclb_sqr_fast8
global _mclb_sqr_fast8
mclb_sqr_fast8:
_mclb_sqr_fast8:
mov r8, rdx
jmp mclb_mul_fast8
align 16
export mclb_sqr_fast9
global mclb_sqr_fast9
global _mclb_sqr_fast9
mclb_sqr_fast9:
_mclb_sqr_fast9:
mov r8, rdx
jmp mclb_mul_fast9
align 16
export mclb_udiv128
global mclb_udiv128
global _mclb_udiv128
mclb_udiv128:
_mclb_udiv128:
mov rax, rdx
mov rdx, rcx
div r8
mov [r9], rdx
ret
