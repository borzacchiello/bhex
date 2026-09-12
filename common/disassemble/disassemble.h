// Copyright (c) 2022-2026, bageyelet

#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#ifndef DISABLE_CAPSTONE

#include <capstone/capstone.h>

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

// How many instructions following a return still belong to the function:
// mips and sparc execute the one in the delay slot before leaving
int disas_delay_slots(cs_arch arch);

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

#endif

#endif
