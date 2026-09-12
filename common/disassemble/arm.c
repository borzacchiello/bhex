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

// What the program counter is worth while `insn` runs: two instructions
// ahead of it in arm mode, one in thumb mode -- and there rounded down to a
// word, as that is what the literal loads and "adr" are counted from
static u64_t arm_pc(cs_mode mode, const cs_insn* insn)
{
    if (mode & CS_MODE_THUMB)
        return (insn->address + 4) & ~(u64_t)3;
    return insn->address + 8;
}

// arm reaches its constants through the literal pool sitting in the middle of
// the code: "ldr r0, [pc, #8]" and the "adr" that takes the address of it
int disas_arm_pc_relative(cs_mode mode, csh handle, const cs_insn* insn,
                          u64_t* out)
{
    (void)handle;

    const cs_detail* d = insn->detail;
    if (d == NULL)
        return 0;

    const cs_arm* arm = &d->arm;
    for (int i = 0; i < arm->op_count; ++i) {
        const cs_arm_op* o = &arm->operands[i];

        // "ldr r0, [pc, #8]": the constant itself
        if (o->type == ARM_OP_MEM && o->mem.base == ARM_REG_PC &&
            o->mem.index == ARM_REG_INVALID) {
            *out = arm_pc(mode, insn) + (u64_t)(s64_t)o->mem.disp;
            return 1;
        }

        // "adr r0, #8", and the "add r0, pc, #8" it is written as in arm
        // mode: the address of the constant rather than the constant
        if (o->type == ARM_OP_IMM &&
            (insn->id == ARM_INS_ADR ||
             ((insn->id == ARM_INS_ADD || insn->id == ARM_INS_SUB) && i > 0 &&
              arm->operands[i - 1].type == ARM_OP_REG &&
              arm->operands[i - 1].reg == ARM_REG_PC))) {
            u64_t pc = arm_pc(mode, insn);
            *out     = insn->id == ARM_INS_SUB ? pc - (u64_t)o->imm
                                               : pc + (u64_t)o->imm;
            return 1;
        }
    }
    return 0;
}

#endif
