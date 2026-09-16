// Copyright (c) 2022-2026, bageyelet

#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#ifndef DISABLE_CAPSTONE

#include <capstone/capstone.h>
#include <defs.h>

/*
   Where a function ends, one architecture at a time.

   Capstone is not of one mind about returns. Some architectures put them in
   CS_GRP_RET and some do not; some decode the real instruction and print an
   alias for it (a ppc "blr" is a "bclr", a sparc "ret" a "jmpl", a riscv
   "ret" a "jalr"); and some leave the answer in the operands, a mips "jr"
   being a return only when it jumps to $ra. Hence one helper per
   architecture, each written against what capstone really hands back for it,
   rather than one group test that would be wrong for half of them.
*/

// Whether `insn` gives control back to the caller. The architectures that
// decide on the operands need the instruction details (CS_OPT_DETAIL): with
// them off, those answer 0
int disas_is_return(cs_arch arch, csh handle, const cs_insn* insn);

/*
   How many instructions following `insn` still belong to the function it
   returns from: mips and sparc execute the one in their delay slot before
   leaving, tms320c64x the next five.

   It takes the instruction and not just the architecture because two of them
   answer per instruction rather than per architecture: a hppa "bv" runs its
   delay slot and a "bv,n" nullifies it, and SH2A's "rts/n" is the undelayed
   spelling of "rts". `insn` must be the return itself -- what
   disas_is_return() just said yes to.
*/
int disas_delay_slots(cs_arch arch, csh handle, const cs_insn* insn);

/*
   The address a pc-relative operand points at.

   An instruction that reads its data "so many bytes from here" -- x86's
   "[rip + 0xcd96b]", the literal pools of arm, riscv's "auipc" -- is printed
   by capstone as the offset it carries, which says nothing about where the
   data actually is. Resolving it is the caller's job, and the answer is again
   one thing per architecture: what the program counter is worth while the
   instruction runs is not what the instruction is at.

   Returns 1 and fills `*out` when `insn` refers to one, 0 when it does not.
   The architectures that resolve their own (aarch64 prints the address of an
   "adrp", m68k that of a "(pc)" operand, s390x that of a "larl") answer 0:
   there is nothing left to say about them. So do the branches, whose target
   capstone always prints absolute.

   The address is the one of the listing: whatever the caller passed to
   cs_disasm() as the address of the first instruction is part of it, so a
   base address set with "setbase" carries over on its own.
*/
int disas_pc_relative(cs_arch arch, cs_mode mode, csh handle,
                      const cs_insn* insn, u64_t* out);

// The per architecture answers behind disas_is_return()
int disas_x86_is_return(csh handle, const cs_insn* insn);
int disas_arm_is_return(csh handle, const cs_insn* insn);
int disas_aarch64_is_return(csh handle, const cs_insn* insn);
int disas_mips_is_return(csh handle, const cs_insn* insn);
int disas_ppc_is_return(csh handle, const cs_insn* insn);
int disas_m68k_is_return(csh handle, const cs_insn* insn);
int disas_alpha_is_return(csh handle, const cs_insn* insn);
int disas_riscv_is_return(csh handle, const cs_insn* insn);
int disas_systemz_is_return(csh handle, const cs_insn* insn);
int disas_sparc_is_return(csh handle, const cs_insn* insn);
int disas_bpf_is_return(csh handle, const cs_insn* insn);
int disas_xcore_is_return(csh handle, const cs_insn* insn);
int disas_tms320c64x_is_return(csh handle, const cs_insn* insn);
int disas_m680x_is_return(csh handle, const cs_insn* insn);
int disas_evm_is_return(csh handle, const cs_insn* insn);
int disas_mos65xx_is_return(csh handle, const cs_insn* insn);
int disas_wasm_is_return(csh handle, const cs_insn* insn);
int disas_sh_is_return(csh handle, const cs_insn* insn);
int disas_tricore_is_return(csh handle, const cs_insn* insn);
int disas_hppa_is_return(csh handle, const cs_insn* insn);
int disas_loongarch_is_return(csh handle, const cs_insn* insn);
int disas_xtensa_is_return(csh handle, const cs_insn* insn);
int disas_arc_is_return(csh handle, const cs_insn* insn);

// The per architecture answers behind disas_delay_slots(). Only the two whose
// return says for itself whether its slot runs have one
int disas_sh_delay_slots(const cs_insn* insn);
int disas_hppa_delay_slots(const cs_insn* insn);

// The per architecture answers behind disas_pc_relative(). Only the
// architectures that leave something to resolve have one; arm needs the mode
// on top of the handle, as what the program counter is worth differs between
// arm and thumb
int disas_x86_pc_relative(csh handle, const cs_insn* insn, u64_t* out);
int disas_arm_pc_relative(cs_mode mode, csh handle, const cs_insn* insn,
                          u64_t* out);
int disas_riscv_pc_relative(csh handle, const cs_insn* insn, u64_t* out);

#endif

#endif
