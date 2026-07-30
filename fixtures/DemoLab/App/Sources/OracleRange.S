.section __TEXT,__oprobe,regular,pure_instructions
.p2align 2
.globl _oprobe_main_anchor
.no_dead_strip _oprobe_main_anchor
_oprobe_main_anchor:
#if defined(__arm64__)
    mov x0, x0
    .rept 62
    nop
    .endr
    ret
#elif defined(__x86_64__)
    mov %r8, %r8
    .rept 252
    nop
    .endr
    ret
#else
#error Unsupported LAB-002 fixture architecture
#endif
