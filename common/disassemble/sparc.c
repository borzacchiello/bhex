// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <string.h>
#include <disassemble/disassemble.h>

// sparc returns with a jump to the return address held in a register, which
// capstone decodes as SPARC_INS_JMPL and prints as "ret" (a function with a
// register window of its own) or "retl" (a leaf one). The mnemonic is what
// tells those two from every other "jmpl".
//
// The instruction in the delay slot -- the "restore" or the "nop" that
// follows -- is executed before the return is taken, see disas_delay_slots()
int disas_sparc_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    return strcmp(insn->mnemonic, "ret") == 0 ||
           strcmp(insn->mnemonic, "retl") == 0;
}

#endif
