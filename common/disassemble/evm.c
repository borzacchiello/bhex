// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// The four opcodes that end a call frame: "return" and "revert" hand back a
// memory range, "stop" ends it with nothing, and "selfdestruct" ends the
// contract itself. Capstone groups them under its own EVM groups rather than
// CS_GRP_RET, so the opcodes are named one by one
int disas_evm_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    switch (insn->id) {
        case EVM_INS_RETURN:
        case EVM_INS_REVERT:
        case EVM_INS_STOP:
        case EVM_INS_SELFDESTRUCT:
            return 1;
        default:
            return 0;
    }
}

#endif
