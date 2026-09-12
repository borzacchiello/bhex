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

// "[rip + 0xcd96b]", the way x86-64 code reaches its own data. The program
// counter is worth the address of the *next* instruction while this one runs,
// which is what the assembler counted the displacement from
int disas_x86_pc_relative(csh handle, const cs_insn* insn, u64_t* out)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL)
        return 0;

    for (int i = 0; i < d->x86.op_count; ++i) {
        const cs_x86_op* o = &d->x86.operands[i];
        if (o->type != X86_OP_MEM)
            continue;
        // eip is the base of the same thing under an address-size override
        if (o->mem.base != X86_REG_RIP && o->mem.base != X86_REG_EIP)
            continue;

        *out = insn->address + insn->size + (u64_t)o->mem.disp;
        return 1;
    }
    return 0;
}

#endif
