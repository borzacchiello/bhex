// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <string.h>
#include <disassemble/disassemble.h>

// hppa returns by branching to the register the call left the return address
// in, which the calling convention makes r2 -- capstone names it "rp". The
// instruction is a "bv", printed as "bv <index>(rp)": the base of the memory
// operand is the register branched through, and only rp is a return. A "bv"
// through anything else is a computed jump
int disas_hppa_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL || insn->id != HPPA_INS_BV)
        return 0;

    for (uint8_t i = 0; i < d->hppa.op_count; ++i) {
        const cs_hppa_op* o = &d->hppa.operands[i];
        if (o->type == HPPA_OP_MEM && o->mem.base == HPPA_REG_GR2)
            return 1;
    }
    return 0;
}

// A hppa branch runs the instruction behind it unless it is nullified, which
// is what the ",n" that capstone prints on the mnemonic means
int disas_hppa_delay_slots(const cs_insn* insn)
{
    return strstr(insn->mnemonic, ",n") != NULL ? 0 : 1;
}

#endif
