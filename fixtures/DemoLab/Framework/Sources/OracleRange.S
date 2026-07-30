.section __TEXT,__oprobe,regular,pure_instructions
.p2align 2
.globl _oprobe_framework_anchor
.no_dead_strip _oprobe_framework_anchor
_oprobe_framework_anchor:
#if defined(__arm64__)
    mov x1, x1
    .rept 62
    nop
    .endr
    ret
#elif defined(__x86_64__)
    mov %r9, %r9
    .rept 252
    nop
    .endr
    ret
#else
#error Unsupported LAB-002 fixture architecture
#endif
