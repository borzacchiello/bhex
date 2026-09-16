#!/usr/bin/env python3
"""Regenerate cmd/disas_archs.inc from capstone's own architecture table.

capstone keeps the canonical list of what it can decode, and under which mode
bits, in cstool/cstool.c. Transcribing 150-odd entries by hand invites the
kind of silent mistake that a wrong mode bit is -- the listing still runs, it
just decodes the wrong instruction set -- so the table is generated from that
source instead, and regenerated whenever the submodule moves:

    scripts/gen_disas_archs.py

The names bhex already had keep their own meaning. Five of them disagree with
what capstone means by the same string (see BHEX_ARCHS below), and changing
them would quietly re-point a name people already use, so cstool's version of
those five is dropped rather than merged. Everything else capstone names is
appended.
"""

import os
import re
import textwrap
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CSTOOL = os.path.join(ROOT, "capstone", "cstool", "cstool.c")
OUT = os.path.join(ROOT, "cmd", "disas_archs.inc")

# The architectures bhex named before it mirrored capstone's list, kept exactly
# as they were. Where capstone uses the same name for something else, its entry
# is skipped and the disagreement recorded here:
#
#   ppc32/ppc64  capstone means little endian by them, bhex big endian; the
#                little endian pair is bhex's ppcle32/ppcle64
#   riscv32/64   capstone turns the compressed encodings on in them
#   m68k         capstone leaves the cpu unset, bhex pins it to the 68000
BHEX_ARCHS = [
    ("x64", "x86 64-bit mode", "CS_ARCH_X86", "CS_MODE_64"),
    ("x86", "x86 32-bit mode", "CS_ARCH_X86", "CS_MODE_32"),
    ("i8086", "x86 16-bit mode", "CS_ARCH_X86", "CS_MODE_16"),
    ("arm32", "ARM, little endian", "CS_ARCH_ARM", "CS_MODE_ARM"),
    ("aarch64", "AArch64", "CS_ARCH_AARCH64", "CS_MODE_ARM"),
    ("arm32-thumb", "ARM Thumb, little endian", "CS_ARCH_ARM",
     "CS_MODE_THUMB"),
    ("mips32", "Mips 32-bit (generic), big endian", "CS_ARCH_MIPS",
     "CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN"),
    ("mips64", "Mips 64-bit (generic), big endian", "CS_ARCH_MIPS",
     "CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN"),
    ("mipsel32", "Mips 32-bit (generic), little endian", "CS_ARCH_MIPS",
     "CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN"),
    ("mipsel64", "Mips 64-bit (generic), little endian", "CS_ARCH_MIPS",
     "CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN"),
    ("ppc32", "PowerPC 32-bit, big endian", "CS_ARCH_PPC",
     "CS_MODE_BIG_ENDIAN"),
    ("ppc64", "PowerPC 64-bit, big endian", "CS_ARCH_PPC",
     "CS_MODE_64 | CS_MODE_BIG_ENDIAN"),
    ("ppcle32", "PowerPC 32-bit, little endian", "CS_ARCH_PPC",
     "CS_MODE_LITTLE_ENDIAN"),
    ("ppcle64", "PowerPC 64-bit, little endian", "CS_ARCH_PPC",
     "CS_MODE_64 | CS_MODE_LITTLE_ENDIAN"),
    ("m68k", "m68k, 68000", "CS_ARCH_M68K",
     "CS_MODE_BIG_ENDIAN | CS_MODE_M68K_000"),
    ("alpha", "Alpha, little endian", "CS_ARCH_ALPHA",
     "CS_MODE_LITTLE_ENDIAN"),
    ("riscv32", "Risc-V 32-bit, little endian", "CS_ARCH_RISCV",
     "CS_MODE_RISCV32 | CS_MODE_LITTLE_ENDIAN"),
    ("riscv64", "Risc-V 64-bit, little endian", "CS_ARCH_RISCV",
     "CS_MODE_RISCV64 | CS_MODE_LITTLE_ENDIAN"),
    ("s390x", "SystemZ s390x, big endian", "CS_ARCH_SYSTEMZ",
     "CS_MODE_BIG_ENDIAN"),
    ("sparc", "Sparc, big endian", "CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN"),
    ("sparc64", "SparcV9, big endian", "CS_ARCH_SPARC",
     "CS_MODE_BIG_ENDIAN | CS_MODE_V9"),
    ("bpf", "Classic BPF", "CS_ARCH_BPF", "CS_MODE_BPF_CLASSIC"),
    ("ebpf", "Extended BPF", "CS_ARCH_BPF", "CS_MODE_BPF_EXTENDED"),
]

ENTRY_RE = re.compile(
    r'\{\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)",\s*(CS_ARCH_\w+),'
    r'\s*((?:[^{}]|\([^()]*\))*?)\s*\}')


def parse_cstool(path):
    src = open(path, encoding="utf8").read()
    try:
        body = src[src.index("} all_archs[] = {"):]
        body = body[:body.index("\n\t{ NULL }")]
    except ValueError:
        sys.exit("cannot find all_archs[] in %s" % path)
    out = []
    for name, descr, arch, mode in ENTRY_RE.findall(body):
        out.append((name, descr, arch, " ".join(mode.split())))
    if not out:
        sys.exit("parsed no entries out of %s" % path)
    return out


#: mode bits that are spelled out in one table and left implicit in the other.
#: All three are zero, so a name carrying them means the same either way
ZERO_MODES = {"CS_MODE_LITTLE_ENDIAN", "CS_MODE_ARM", "CS_MODE_BPF_CLASSIC"}


def mode_bits(mode):
    """The mode as a set of the bits it really sets, so that two spellings of
    the same thing -- CS_MODE_ARM and CS_MODE_LITTLE_ENDIAN, both zero --
    compare equal."""
    bits = {b.strip() for b in re.split(r"[|+]", mode)}
    return bits - ZERO_MODES - {""}


def wrap_comment(lead, text):
    return textwrap.fill(lead + " " + text, width=78,
                         initial_indent="// ", subsequent_indent="// ") + "\n"


def main():
    cstool = parse_cstool(CSTOOL)
    bhex = {a[0]: a for a in BHEX_ARCHS}

    rows = list(BHEX_ARCHS)
    clashed, redundant = [], []
    for name, descr, arch, mode in cstool:
        if name in bhex:
            _, _, barch, bmode = bhex[name]
            if barch == arch and mode_bits(bmode) == mode_bits(mode):
                redundant.append(name)
            else:
                clashed.append(name)
            continue
        if name in {r[0] for r in rows}:
            redundant.append(name)
            continue
        rows.append((name, descr, arch, mode))

    width = max(len(r[0]) for r in rows) + 3
    with open(OUT, "w", encoding="utf8") as f:
        f.write("// Generated by scripts/gen_disas_archs.py -- do not edit.\n"
                "//\n"
                "// Every architecture capstone can decode, taken from its own\n"
                "// cstool/cstool.c table: %d entries, %d of them names bhex\n"
                "// had before the mirror and %d added from capstone.\n"
                % (len(rows), len(BHEX_ARCHS), len(rows) - len(BHEX_ARCHS)))
        f.write("//\n")
        f.write(wrap_comment("capstone means something else by these, and "
                             "they keep bhex's meaning:",
                             ", ".join(clashed)))
        f.write("//\n")
        f.write(wrap_comment("capstone spells these the way bhex already "
                             "did:", ", ".join(redundant)))
        for name, descr, arch, mode in rows:
            entry = '{%-*s "%s", %s, %s},' % (width, '"%s",' % name, descr,
                                              arch, mode)
            if len(entry) <= 80:
                f.write(entry + "\n")
            else:
                f.write('{%-*s "%s",\n %s, %s},\n'
                        % (width, '"%s",' % name, descr, arch, mode))
    print("wrote %s: %d entries (%d bhex, %d from capstone; "
          "%d clashing and %d redundant cstool names dropped)"
          % (OUT, len(rows), len(BHEX_ARCHS), len(rows) - len(BHEX_ARCHS),
             len(clashed), len(redundant)))


if __name__ == "__main__":
    main()
