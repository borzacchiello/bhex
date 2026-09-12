// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// s390x returns by branching to the register the caller left the return
// address in, %r14: a plain "br", which is a jump through a register like any
// other unless that register is %r14
int disas_systemz_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL || insn->id != SYSTEMZ_INS_BR)
        return 0;

    for (int i = 0; i < d->systemz.op_count; ++i)
        if (d->systemz.operands[i].type == SYSTEMZ_OP_REG &&
            d->systemz.operands[i].reg == SYSTEMZ_REG_R14D)
            return 1;
    return 0;
}

#endif
