// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <string.h>
#include <disassemble/disassemble.h>

// ppc returns by branching to the link register, which is a "bclr" with the
// condition that always holds. Capstone decodes it as PPC_INS_BCLR and prints
// the alias, so the mnemonic is what tells the unconditional return ("blr")
// from the conditional ones ("bltlr" and friends, which carry on when the
// condition does not hold) and from "blrl", which is a call
int disas_ppc_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    return strcmp(insn->mnemonic, "blr") == 0;
}

#endif
