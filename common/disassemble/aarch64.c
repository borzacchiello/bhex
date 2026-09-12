// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// aarch64 has a return of its own, in three flavours: the plain one and the
// two that authenticate the address they return to. "eret" is the return of
// an exception handler
int disas_aarch64_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    switch (insn->id) {
        case AARCH64_INS_RET:
        case AARCH64_INS_RETAA:
        case AARCH64_INS_RETAB:
        case AARCH64_INS_ERET:
            return 1;
        default:
            return 0;
    }
}

#endif
