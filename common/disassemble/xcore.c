// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// xcore has one return, "retsp u6", which unwinds the stack by the operand it
// carries and jumps to the saved link register. Capstone reports no group for
// it
int disas_xcore_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    return insn->id == XCORE_INS_RETSP;
}

#endif
