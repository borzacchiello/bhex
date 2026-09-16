// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// The c64x has no return instruction: a function ends by branching to the
// register holding the address it was called from, which the calling
// convention makes B3. Capstone decodes every branch as TMS320C64X_INS_B, so
// the register is what tells a return from any other branch -- the same shape
// as mips returning through $ra.
//
// Only B3 is treated as one: a branch through some other register is a
// computed jump, and stopping on it would cut the listing at the first switch
int disas_tms320c64x_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL || insn->id != TMS320C64X_INS_B)
        return 0;

    return d->tms320c64x.op_count == 1 &&
           d->tms320c64x.operands[0].type == TMS320C64X_OP_REG &&
           d->tms320c64x.operands[0].reg == TMS320C64X_REG_B3;
}

#endif
