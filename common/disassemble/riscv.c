// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <string.h>
#include <disassemble/disassemble.h>

// riscv has no return instruction: it jumps to the return address register,
// "jalr zero, ra, 0" (or "c.jr ra" once compressed), and both are printed as
// the "ret" pseudo-instruction. Capstone decodes them as JALR and C_JR, so
// the mnemonic is what tells a return from any other jump through a register.
// "mret" and "sret" leave a machine/supervisor trap handler
int disas_riscv_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    if (insn->id == RISCV_INS_MRET || insn->id == RISCV_INS_SRET)
        return 1;
    return (insn->id == RISCV_INS_JALR || insn->id == RISCV_INS_C_JR) &&
           strcmp(insn->mnemonic, "ret") == 0;
}

#endif
