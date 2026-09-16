// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// loongarch returns with "jirl $zero, $ra, 0", which capstone decodes as
// LOONGARCH_INS_JIRL, prints under its "ret" alias and -- unlike most of the
// architectures here -- does put in CS_GRP_RET. The plain register jumps it
// prints as "jr" stay out of that group, so the group test is enough
int disas_loongarch_is_return(csh handle, const cs_insn* insn)
{
    return cs_insn_group(handle, insn, CS_GRP_RET);
}

#endif
