// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// wasm returns with "return". "end" is left out on purpose: it closes a
// block, a loop and an "if" as well as the function body, and stopping on it
// would cut every listing at the first structured control instruction
int disas_wasm_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    return insn->id == WASM_INS_RETURN;
}

#endif
