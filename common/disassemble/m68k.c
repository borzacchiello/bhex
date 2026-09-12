// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// "rts" returns, "rtd" returns dropping arguments, "rtr" restores the flags
// on the way out, and "rte" is the return of an exception handler
int disas_m68k_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    switch (insn->id) {
        case M68K_INS_RTS:
        case M68K_INS_RTD:
        case M68K_INS_RTR:
        case M68K_INS_RTE:
            return 1;
        default:
            return 0;
    }
}

#endif
