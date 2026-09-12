// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <string.h>
#include <disassemble/disassemble.h>

// arm has no return instruction: it writes the return address into the
// program counter, and there are three ways of doing it
static int writes_pc(const cs_arm* arm)
{
    for (int i = 0; i < arm->op_count; ++i)
        if (arm->operands[i].type == ARM_OP_REG &&
            arm->operands[i].reg == ARM_REG_PC)
            return 1;
    return 0;
}

int disas_arm_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL)
        return 0;

    const cs_arm* arm = &d->arm;
    // a conditional return is not the end of the function: the instructions
    // after it are reached whenever the condition does not hold
    if (arm->cc != ARMCC_AL)
        return 0;

    switch (insn->id) {
        case ARM_INS_BX:
            // "bx lr", back to the address the caller left in the link
            // register. Capstone only groups this one as a return in arm
            // mode, never in thumb mode
            return arm->op_count == 1 && arm->operands[0].type == ARM_OP_REG &&
                   arm->operands[0].reg == ARM_REG_LR;
        case ARM_INS_MOV:
            // "mov pc, lr", the same thing spelled out
            return arm->op_count == 2 && arm->operands[0].type == ARM_OP_REG &&
                   arm->operands[0].reg == ARM_REG_PC &&
                   arm->operands[1].type == ARM_OP_REG &&
                   arm->operands[1].reg == ARM_REG_LR;
        case ARM_INS_POP:
        case ARM_INS_LDM:
        case ARM_INS_LDMDA:
        case ARM_INS_LDMDB:
        case ARM_INS_LDMIB:
            // the epilogue that restores the saved registers and returns in
            // one go: "pop {r4, pc}"
            return writes_pc(arm);
        case ARM_INS_LDR:
            // "ldr pc, [sp], #4", which capstone prints as a "pop" of the
            // program counter alone. A "ldr pc" from any other place is a
            // jump through a table, not a return
            return strcmp(insn->mnemonic, "pop") == 0 && writes_pc(arm);
        default:
            return 0;
    }
}

#endif
