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
        case CS_ARCH_XCORE:
            return disas_xcore_is_return(handle, insn);
        case CS_ARCH_TMS320C64X:
            return disas_tms320c64x_is_return(handle, insn);
        case CS_ARCH_M680X:
            return disas_m680x_is_return(handle, insn);
        case CS_ARCH_EVM:
            return disas_evm_is_return(handle, insn);
        case CS_ARCH_MOS65XX:
            return disas_mos65xx_is_return(handle, insn);
        case CS_ARCH_WASM:
            return disas_wasm_is_return(handle, insn);
        case CS_ARCH_SH:
            return disas_sh_is_return(handle, insn);
        case CS_ARCH_TRICORE:
            return disas_tricore_is_return(handle, insn);
        case CS_ARCH_HPPA:
            return disas_hppa_is_return(handle, insn);
        case CS_ARCH_LOONGARCH:
            return disas_loongarch_is_return(handle, insn);
        case CS_ARCH_XTENSA:
            return disas_xtensa_is_return(handle, insn);
        case CS_ARCH_ARC:
            return disas_arc_is_return(handle, insn);
        default:
            return 0;
    }
}

int disas_pc_relative(cs_arch arch, cs_mode mode, csh handle,
                      const cs_insn* insn, u64_t* out)
{
    switch (arch) {
        case CS_ARCH_X86:
            return disas_x86_pc_relative(handle, insn, out);
        case CS_ARCH_ARM:
            return disas_arm_pc_relative(mode, handle, insn, out);
        case CS_ARCH_RISCV:
            return disas_riscv_pc_relative(handle, insn, out);
        default:
            // aarch64, m68k and s390x print the resolved address themselves,
            // and the rest (ppc, mips, sparc, alpha, bpf) reach their data
            // through a register rather than through the program counter
            return 0;
    }
}

int disas_delay_slots(cs_arch arch, csh handle, const cs_insn* insn)
{
    (void)handle;

    // the instruction after a branch is executed before the branch is taken,
    // so it is part of the function the return leaves
    switch (arch) {
        case CS_ARCH_MIPS:
        case CS_ARCH_SPARC:
            return 1;
        // a c64x branch is taken five instructions later, and all five of
        // them run
        case CS_ARCH_TMS320C64X:
            return 5;
        // these two say for themselves whether their slot runs
        case CS_ARCH_SH:
            return disas_sh_delay_slots(insn);
        case CS_ARCH_HPPA:
            return disas_hppa_delay_slots(insn);
        // arc has delayed jumps too, but capstone's printer does not carry
        // the ".d" that tells them apart, so there is nothing to read here
        default:
            return 0;
    }
}

#endif
