#!/usr/bin/env python3
# Copyright (c) 2022-2026, bageyelet

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT / "identify_sample.c"
DEFAULT_OUT = ROOT / "generated"

COMMON_CFLAGS = [
    "-O2",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-inline",
    "-fno-omit-frame-pointer",
    "-fno-optimize-sibling-calls",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-c",
]

TARGETS = [
    {
        "arch": "x64",
        "compiler": "clang",
        "cflags": ["--target=x86_64-linux-gnu", "-m64"],
        "accept": ["x64", "x86", "i8086"],
    },
    {
        "arch": "x86",
        "compiler": "clang",
        "cflags": ["--target=i386-linux-gnu", "-m32"],
        "accept": ["x86", "x64", "i8086"],
    },
    {
        "arch": "i8086",
        "compiler": "clang",
        "cflags": ["--target=i386-linux-gnu", "-m16"],
        "accept": ["i8086", "x86", "x64"],
        "note": "Clang -m16 produces 16-bit real-mode x86, which is the closest compiler-generated fixture to the i8086 bucket used by ds.",
    },
    {
        "arch": "arm32",
        "compiler": "clang",
        "cflags": ["--target=arm-linux-gnueabi", "-marm"],
        "accept": ["arm32"],
    },
    {
        "arch": "arm32-thumb",
        "compiler": "clang",
        "cflags": ["--target=arm-linux-gnueabi", "-mthumb"],
        "accept": ["arm32-thumb", "arm32"],
    },
    {
        "arch": "aarch64",
        "compiler": "clang",
        "cflags": ["--target=aarch64-linux-gnu"],
        "accept": ["aarch64"],
    },
    {
        "arch": "mips32",
        "compiler": "clang",
        "cflags": ["--target=mips-linux-gnu", "-mips32", "-EB"],
        "accept": ["mips32"],
    },
    {
        "arch": "mips64",
        "compiler": "clang",
        "cflags": ["--target=mips64-linux-gnuabi64", "-mips64", "-EB"],
        "accept": ["mips64"],
    },
    {
        "arch": "mipsel32",
        "compiler": "clang",
        "cflags": ["--target=mipsel-linux-gnu", "-mips32", "-EL"],
        "accept": ["mipsel32"],
    },
    {
        "arch": "mipsel64",
        "compiler": "clang",
        "cflags": ["--target=mips64el-linux-gnuabi64", "-mips64", "-EL"],
        "accept": ["mipsel64"],
    },
    {
        "arch": "ppc32",
        "compiler": "clang",
        "cflags": ["--target=powerpc-linux-gnu", "-m32", "-mbig-endian"],
        "accept": ["ppc32"],
    },
    {
        "arch": "ppc64",
        "compiler": "clang",
        "cflags": ["--target=powerpc64-linux-gnu", "-m64", "-mbig-endian"],
        "accept": ["ppc64"],
    },
    {
        "arch": "ppcle32",
        "compiler": "clang",
        "cflags": ["--target=powerpcle-linux-gnu", "-m32", "-mlittle-endian"],
        "accept": ["ppcle32", "ppcle64"],
    },
    {
        "arch": "ppcle64",
        "compiler": "clang",
        "cflags": ["--target=powerpc64le-linux-gnu", "-m64", "-mlittle-endian"],
        "accept": ["ppcle64", "ppcle32"],
    },
    {
        "arch": "m68k",
        "compiler": "clang",
        "cflags": ["--target=m68k-linux-gnu", "-m68000"],
        "accept": ["m68k"],
    },
]


def run(cmd):
    print("[+]", " ".join(cmd))
    subprocess.run(cmd, check=True)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fin:
        while True:
            chunk = fin.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Generate ISA-identification testcase binaries")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    objcopy = shutil.which("llvm-objcopy") or shutil.which("objcopy")
    objdump = shutil.which("llvm-objdump") or shutil.which("objdump")
    if not objcopy:
        print("error: neither llvm-objcopy nor objcopy was found", file=sys.stderr)
        return 1
    if not objdump:
        print("error: neither llvm-objdump nor objdump was found", file=sys.stderr)
        return 1

    manifest = []
    for target in TARGETS:
        compiler = shutil.which(target["compiler"])
        if not compiler:
            print(f"error: missing compiler {target['compiler']} for {target['arch']}", file=sys.stderr)
            return 1

        stem = out_dir / target["arch"]
        obj_path = stem.with_suffix(".o")
        bin_path = stem.with_suffix(".bin")
        dump_path = stem.with_suffix(".objdump.txt")

        cmd = [compiler, *COMMON_CFLAGS, *target["cflags"], str(SOURCE), "-o", str(obj_path)]
        run(cmd)
        run([objcopy, "--only-section=.text", "-O", "binary", str(obj_path), str(bin_path)])

        with open(dump_path, "w", encoding="utf-8") as fout:
            subprocess.run([objdump, "-d", str(obj_path)], check=True, stdout=fout)

        manifest.append(
            {
                "arch": target["arch"],
                "compiler": target["compiler"],
                "cflags": target["cflags"],
                "source": SOURCE.name,
                "object": obj_path.name,
                "binary": bin_path.name,
                "objdump": dump_path.name,
                "size": bin_path.stat().st_size,
                "sha256": sha256(bin_path),
                "accept": target["accept"],
                **({"note": target["note"]} if "note" in target else {}),
            }
        )

    manifest_path = out_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as fout:
        json.dump({"generated_from": SOURCE.name, "targets": manifest}, fout, indent=2)
        fout.write("\n")

    print(f"[+] wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
