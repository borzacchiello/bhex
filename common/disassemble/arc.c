// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// ARC returns by jumping to blink, the register the branch-and-link
// instructions leave the return address in. Capstone decodes it as ARC_INS_J
// and prints it as "j [%blink]", so the operand is what tells it from any
// other indirect jump
int disas_arc_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL || insn->id != ARC_INS_J)
        return 0;

    return d->arc.op_count == 1 && d->arc.operands[0].type == ARC_OP_REG &&
           d->arc.operands[0].reg == ARC_REG_BLINK;
}

#endif
