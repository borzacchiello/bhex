// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// 6502 and its descendants return with "rts", which capstone puts in
// CS_GRP_RET. "rti" ends an interrupt handler and is CS_GRP_IRET instead, so
// the group test alone says what is wanted here
int disas_mos65xx_is_return(csh handle, const cs_insn* insn)
{
    return cs_insn_group(handle, insn, CS_GRP_RET);
}

#endif
