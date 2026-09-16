// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// tricore returns from a call with "ret" and from a trap or interrupt with
// "rfe"; "rfm" is the monitor's version of the same. Capstone reports no
// group at all for them
int disas_tricore_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    switch (insn->id) {
        case TRICORE_INS_RET:
        case TRICORE_INS_RFE:
        case TRICORE_INS_RFM:
            return 1;
        default:
            return 0;
    }
}

#endif
