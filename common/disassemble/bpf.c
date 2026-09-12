// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include <disassemble/disassemble.h>

// classic bpf ends a filter with "ret", extended bpf with "exit". Capstone
// reports no group for either of them
int disas_bpf_is_return(csh handle, const cs_insn* insn)
{
    (void)handle;

    return insn->id == BPF_INS_RET || insn->id == BPF_INS_EXIT;
}

#endif
