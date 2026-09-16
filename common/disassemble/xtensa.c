// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// xtensa has a return per calling convention -- "ret" and "ret.n" for the
// call0 one, "retw" and "retw.n" for the windowed one -- and capstone puts
// all of them in CS_GRP_RET
int disas_xtensa_is_return(csh handle, const cs_insn* insn)
{
    return cs_insn_group(handle, insn, CS_GRP_RET);
}

#endif
