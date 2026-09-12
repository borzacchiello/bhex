// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// alpha spells its return "ret $31,($26),1", an instruction of its own.
// Capstone names the constant with the architecture in mixed case
int disas_alpha_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    return insn->id == Alpha_INS_RET;
}

#endif
