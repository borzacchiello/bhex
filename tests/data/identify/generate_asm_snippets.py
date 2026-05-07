#!/usr/bin/env python3
# Copyright (c) 2022-2026, bageyelet

import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
DEFAULT_GENERATED_DIR = ROOT / "generated"
DEFAULT_OUTPUT = ROOT.parent / "asm_snippets.h"


def format_array(data: bytes) -> list[str]:
    lines: list[str] = []
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        suffix = "," if i + 12 < len(data) else ""
        lines.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + suffix)
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate tests/data/asm_snippets.h")
    parser.add_argument("--generated-dir", default=str(DEFAULT_GENERATED_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    generated_dir = pathlib.Path(args.generated_dir).resolve()
    output = pathlib.Path(args.output).resolve()
    manifest_path = generated_dir / "manifest.json"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    out: list[str] = [
        "// Copyright (c) 2022-2026, bageyelet\n",
        "/*\n",
        " * Machine-code snippets for architecture identification tests.\n",
        " *\n",
        " * This file is generated from tests/data/identify/generated/*.bin by\n",
        " * tests/data/identify/generate_asm_snippets.py.\n",
        " */\n\n",
        "#ifndef ASM_SNIPPETS_H\n",
        "#define ASM_SNIPPETS_H\n\n",
        "#include <defs.h>\n\n",
    ]

    for target in manifest["targets"]:
        arch = target["arch"]
        data = (generated_dir / target["binary"]).read_bytes()
        c_name = "snippet_" + arch.replace("-", "_")
        out.append(f"/* {arch} ({len(data)} bytes) */\n")
        out.append(f"static const u8_t {c_name}[] = {{\n")
        out.extend(line + "\n" for line in format_array(data))
        out.append("};\n\n")

    out.append("#endif\n")
    output.write_text("".join(out), encoding="utf-8")
    print(f"[+] wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
