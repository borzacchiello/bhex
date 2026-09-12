// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// The near and far returns, and the one of an interrupt handler. A "jmp" out
// of the function (a tail call) is left out on purpose: it is a jump like any
// other, and stopping on it would cut every listing at the first jump table
int disas_x86_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    switch (insn->id) {
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
        case X86_INS_IRET:
        case X86_INS_IRETD:
        case X86_INS_IRETQ:
            return 1;
        default:
            return 0;
    }
}

#endif
