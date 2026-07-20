# Generated architecture-identification fixtures

This directory contains the source, Docker image, and generation scripts for
architecture-identification regression fixtures.

## What gets generated

Running the generator produces, for each target architecture:

- `<arch>.o`: the compiled object file
- `<arch>.bin`: the raw `.text` section used by the tests
- `<arch>.objdump.txt`: a disassembly dump for inspection/debugging
- `manifest.json`: metadata and hashes for the generated fixtures

The generated files are written into `tests/data/identify/generated/`.
After that, `tests/data/identify/generate_asm_snippets.py` refreshes
`tests/data/asm_snippets.h`, which is what the ISA-identification tests compile
against.

## How to generate the fixtures

From the repository root:

```sh
tests/data/identify/gen_identify_testcases.sh
```

That script:

1. builds `tests/data/identify/docker/Dockerfile`
2. starts the container with the repository mounted in `/work`
3. runs `tests/data/identify/generate.py` inside the container
4. runs `tests/data/identify/generate_asm_snippets.py` on the host

So a single command regenerates both the raw fixture binaries and the checked-in
`tests/data/asm_snippets.h` header.

## Directory layout

- `identify_sample.c` -- source program compiled for each target ISA
- `docker/Dockerfile` -- container image used for fixture generation
- `generate.py` -- compiles the sample and extracts `.text` into raw binaries
- `generate_asm_snippets.py` -- converts generated `.bin` files into
  `tests/data/asm_snippets.h`
- `gen_identify_testcases.sh` -- one-shot wrapper that runs the full pipeline
- `generated/` -- output directory for fixture artifacts and `manifest.json`

## Why Docker

The fixture set needs a large collection of cross-compilers. Keeping that
inside a container makes the host setup reproducible and avoids polluting the
local machine with many toolchains.

## Notes

- The fixture compiler is currently Clang with explicit `--target=...` flags.
  We originally aimed for GCC cross-compilers, but Clang targets proved more
  portable in the Docker environment while still producing representative code.
- The generator intentionally emits raw `.text` bytes, because ISA detection
  operates on byte streams and should not depend on ELF parsing details.
- `i8086` currently uses `clang -m16`, which generates 16-bit real-mode x86.
  That is the closest compiler-generated fixture to the `i8086` bucket used by
  `ds`.
- The current fixture set covers all general-purpose architectures used by the
  ISA-identification tests, including `m68k`. `bpf`/`ebpf` fixtures can be
  added later with a dedicated toolchain if needed.
- You can override the output directory by setting `OUT_DIR=/path/to/dir` when
  invoking `gen_identify_testcases.sh`.
