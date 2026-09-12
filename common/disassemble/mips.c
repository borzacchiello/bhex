// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// mips returns by jumping to the register holding the return address: the
// same "jr" that jumps through any other register, so the operand is what
// makes it a return. The ".hb" flavour clears the hazard barrier on the way.
//
// The instruction in the delay slot is executed before the jump is taken, see
// disas_delay_slots()
int disas_mips_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL)
        return 0;
    if (insn->id != MIPS_INS_JR && insn->id != MIPS_INS_JR_HB)
        return 0;

    for (int i = 0; i < d->mips.op_count; ++i)
        if (d->mips.operands[i].type == MIPS_OP_REG &&
            d->mips.operands[i].reg == MIPS_REG_RA)
            return 1;
    return 0;
}

#endif
