// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// The m680x family is one of the few where capstone fills CS_GRP_RET itself,
// and it has both of them right: "rts" on every cpu of the family and the
// "rtc" that HCS12 returns from a banked call with. "rti" is left to
// CS_GRP_IRET, where it belongs
int disas_m680x_is_return(csh handle, const cs_insn* insn)
{
    return cs_insn_group(handle, insn, CS_GRP_RET);
}

#endif
