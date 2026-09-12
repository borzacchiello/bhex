// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

int disas_is_return(cs_arch arch, csh handle, const cs_insn* insn)
{
    switch (arch) {
        case CS_ARCH_X86:
            return disas_x86_is_return(handle, insn);
        case CS_ARCH_ARM:
            return disas_arm_is_return(handle, insn);
        case CS_ARCH_AARCH64:
            return disas_aarch64_is_return(handle, insn);
        case CS_ARCH_MIPS:
            return disas_mips_is_return(handle, insn);
        case CS_ARCH_PPC:
            return disas_ppc_is_return(handle, insn);
        case CS_ARCH_M68K:
            return disas_m68k_is_return(handle, insn);
        case CS_ARCH_ALPHA:
            return disas_alpha_is_return(handle, insn);
        case CS_ARCH_RISCV:
            return disas_riscv_is_return(handle, insn);
        case CS_ARCH_SYSTEMZ:
            return disas_systemz_is_return(handle, insn);
        case CS_ARCH_SPARC:
            return disas_sparc_is_return(handle, insn);
        case CS_ARCH_BPF:
            return disas_bpf_is_return(handle, insn);
        default:
            return 0;
    }
}

int disas_delay_slots(cs_arch arch)
{
    // the instruction after a branch is executed before the branch is taken,
    // so it is part of the function the return leaves
    return arch == CS_ARCH_MIPS || arch == CS_ARCH_SPARC ? 1 : 0;
}

#endif
