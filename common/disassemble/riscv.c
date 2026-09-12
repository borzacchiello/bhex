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

// riscv builds an address out of two instructions, an "auipc" that adds the
// top twenty bits of the offset to the program counter and something that
// adds the last twelve. The first half is the one worth resolving: capstone
// prints the immediate before it is shifted into place
int disas_riscv_pc_relative(csh handle, const cs_insn* insn, u64_t* out)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL || insn->id != RISCV_INS_AUIPC)
        return 0;

    for (int i = 0; i < d->riscv.op_count; ++i)
        if (d->riscv.operands[i].type == RISCV_OP_IMM) {
            *out = insn->address + ((u64_t)d->riscv.operands[i].imm << 12);
            return 1;
        }
    return 0;
}

#endif
