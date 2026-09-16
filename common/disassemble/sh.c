// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// SuperH returns with "rts" from a call and "rte" from an exception. SH2A
// adds "rts/n" and "rtv/n", the undelayed spellings that do not run the
// instruction behind them (see disas_sh_delay_slots()). Capstone reports no
// group for any of them
int disas_sh_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    switch (insn->id) {
        case SH_INS_RTS:
        case SH_INS_RTE:
        case SH_INS_RTS_N:
        case SH_INS_RTV_N:
            return 1;
        default:
            return 0;
    }
}

// "rts" and "rte" are delayed branches: the instruction after them is
// executed before the jump is taken. The "/n" pair that SH2A added is the
// point of that suffix -- they take the jump straight away
int disas_sh_delay_slots(const cs_insn* insn)
{
    return insn->id == SH_INS_RTS || insn->id == SH_INS_RTE ? 1 : 0;
}

#endif
