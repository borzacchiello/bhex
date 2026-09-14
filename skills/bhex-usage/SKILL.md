---
name: bhex-usage
description: Drive the bhex hex editor from the shell — inspect, search, hash, diff, disassemble and patch a binary file, interactively or from a script. Use when answering "what is in this file", carving or extracting bytes, applying a binary patch, or automating any of that with `bhex -c` / `bhex -s`. Covers the command grammar, the current-offset model, backtick expressions and the write/commit workflow.
---

# Using bhex

`bhex <file>` opens a shell on a file; every command acts at a **current offset** you move with
`s`. Nothing is written back to disk until you `c` (commit).

For writing `.bhe` templates (the `t` command's input language) see the sibling
`bhengine-template` skill — this one is about driving the editor.

`reference.md` in this skill folder has the full command/modifier/argument table and the expression
grammar. Live, always-correct help is one keystroke away: `?` after any command
name (`p?`, `w?`, `src?`), and `h` lists the commands.

## Three ways to run it

```sh
bhex file                       # interactive shell
bhex -2nc "s 0x40; p 64" file   # run commands, print, exit   <- default for automation
printf 's 0x40\np 64\n' | bhex -2ns file   # one command per line from stdin
```

`-w` opens for writing (and **creates the file if it does not exist** — that is how you build one
from scratch), `-b` first copies it to `file.bk`, `-2` silences warnings, `-n` skips the history
file. `reference.md` has the rest; colors need no flag when scripting, since they are emitted only
when the standard output is a terminal.

For scripting always pass `-2 -n`: without them every run emits the read-only warning and appends
to `~/.bhex_history`.

Short flags cluster, so that pair is usually written `-2n`, and the whole invocation `-2nc "..."`
or `-2nwbc "..."`. Two rules make clustering safe:

- **`-c` (or `-s`) has to be last in the cluster**, since `-c` swallows the next word: `-2cn "p 4"`
  runs the command string `n` and then chokes on the two leftover arguments.
- **Every option has to come before the filename.** `bhex file -2n` fails with
  `missing input file` — the argument loop stops looking for a path once getopt has permuted the
  command line. This bites when you edit a previous shell line to add a flag at the end.

## Command grammar

```
name/mod1/mod2 arg1 "arg with spaces" `expression`
```

- **Aliases are the normal form**: `p`, `s`, `src`, `str`, `hh`, `cr`, `cs`, `t`, `w`, `tr`, `c`,
  `u`, `df`, `ex`, `im`, `ds`, `e`, `i`, `sb`, `ec`, `ii`, `fba`.
- **Modifiers must come before the first space.** After it, `/` is an ordinary character — which is
  why `t ./myfmt.bhe` and `df ../other.bin` parse fine.
- Quote any argument containing spaces: `w/x "00 01 02 03"`. Inside quotes only `\"` and `\\` are
  unescaped by the parser; `\xNN` survives and is decoded by the commands that take binary data
  (`src "\x00\x01"`).
- `;` separates commands in `-c`, and **the batch stops at the first failing command**.
- `?` prints a command's help, but only bare: `p?` works, `p/x?` and `p? 4` are parse errors.

## Everything happens at the current offset

| | |
| --- | --- |
| `s 0x40` / `s/+ 16` / `s/- 16` | seek absolute / forward / backward |
| `s -` | back to the offset before the last seek |
| `s` | print the current offset |
| `sb 0x400000` | set a base address: displayed addresses and `s` arguments become base-relative |

`p`, `str`, `hh`, `cr`, `cs`, `e`, `ds`, `ii`, `t`, `w`, `d`, `ex`, `im` all start from there.
The size/offset pairs taken by `hh`/`cr`/`cs` are *relative to it*: `hh md5 0x20 4` hashes 0x20
bytes starting 4 bytes ahead.

## Backtick expressions

Any argument in backticks is evaluated against the file before the command runs, and substituted
as a decimal number:

```sh
bhex -2nc 's `$size - 8`; p 8' file            # last 8 bytes
bhex -2nc 's `[32le 0x18]`; p 64' file         # follow a 32-bit LE pointer stored at 0x18
bhex -2nc 'ec `[8 $off] * 4`' file             # byte at the cursor, times 4
```

`$off`/`$o`, `$base`/`$b`, `$size`/`$s`; `[expr]` reads 32-bit LE at that address, `[8 a]`,
`[16be a]`, `[64le a]` pick width and endianness. Operators: `+ - * << >> & | ~ ()` on u64 — there
is **no division and no modulo**.

**`[...]` addresses are raw file offsets while `$off`/`$base` are base-relative.** With a base set,
`[8 $off]` reads at the wrong place (or fails as out-of-bounds); write `[8 $off - $base]`.

## Inspecting a file

```sh
bhex -2nc "i"                    file   # size, entropy, md5
bhex -2nc "p 64"                 file   # hex+ascii; p/d/be 8 = 8 big-endian dwords
bhex -2nc "p/a -"                file   # /- = whole file (default: 256 bytes)
bhex -2nc "str/n VERSION 4"      file   # NUL-terminated strings containing VERSION, len >= 4
bhex -2nc "src/x/p 89504e47"     file   # find hex bytes, print context around each match
bhex -2nc "e 16"                 file   # entropy graph, 16 rows
bhex -2nc "hi 4096"              file   # byte histogram of the first 4096 bytes
bhex -2nc 'hh sha256; cr "*"'    file   # a hash, then every known CRC
bhex -2nc "hh xxh64"             file   # the checksum a Zstandard frame carries
bhex -2nc "t png"                file   # decode with a shipped template (t/l lists them)
bhex -2nc "id"                   file   # scan for every format the templates know
bhex -2nc "ds x64 20"            file   # disassemble 20 instructions at the cursor
bhex -2nc "ds x64"               file   # ... or the whole function, up to its "ret"
```

`src` scans the **whole file** regardless of the current offset unless a `<len>` is given, which
makes it a window starting at the cursor. It is multithreaded, so match order is not guaranteed and
`src/sk` leaves you on the last match it reported — `src/1` stops at the first one and is ordered.
A hex needle may carry `?` in place of a digit, matching any value for that nibble
(`src/x "e8 ?? ?? ?? ??"`). `hh`, `cs`, `cr` accept a partial name or `*` (`cr crc32` matches
nothing — the names are `CRC-32/ISO-HDLC` and friends, list them with `cr/l`).

`t` also runs one struct or one named proc of a template: `t elf.Elf_Ehdr`, `t zip.list_files`
(`t/l <filter>` lists both). `t/x` emits XML for machine consumption, `t/i "stmts"` runs inline
bhengine code — the fastest way to compute something the commands do not cover.

## Editing: nothing is saved until `c`

```sh
bhex -2nwbc 's 0x10; w/x "90 90"; c' file   # patch two bytes, keeping file.bk
```

- **`c` is not optional.** Writes live in an in-memory overlay; exiting without `c` silently
  discards them. `c/l` shows what is pending, `u` undoes the last write, `u/a` all of them. In the
  interactive shell a `*` before the `$` of the prompt marks an overlay that is not empty.
- Without `-w` writes still *appear* to work in the buffer — you only get a warning and a refusal
  at commit time. If a patch seems to have done nothing, check for `-w`.
- **`w` does not advance the offset.** Writing several fields means seeking between them, or the
  second write lands on top of the first.
- `w` overwrites and **fails past the end of the file** ("not enough space to write the data"); to
  grow a file use `w/i` (insert) or `im` (import, insert by default, `im/ovw` to overwrite).
  Building a file from nothing is a sequence of `w/i` at explicit offsets.
- `d <n>` deletes n bytes at the cursor (all the remaining ones if omitted), `ex out.bin <n>`
  carves n bytes out to another file.
- `tr` rewrites a range instead of replacing it with a literal: `tr/xor "de ad be ef"`,
  `tr/not 0x40`, `tr/swap 4`, `tr/rev`, `tr/add "10"`, `tr/rol 3`. It is a single pending
  overwrite, so `u` takes the whole thing back.

## Gotchas

- Exit status is 1 for a startup problem (unusable command line, missing/unopenable file) and 2
  when a command of the batch failed — `no such command`, a bad argument, a failed expression, a
  template exception. So `bhex -2nc "..." f && next-step` is safe.
- A failing backtick expression (`expr error: ...`) aborts the rest of a `-c` batch too, and is
  reported the same way.
- `e <rows> <len>` takes the **row count first** — `e 8` is an 8-row graph of the whole file,
  `e - 8` is a one-row graph of 8 bytes.
- `p <n>` counts *elements*, not bytes: `p/q 4` prints 32 bytes.
- `ds`/`as`/`ii`/`fba` are build-time optional. `no such command` for `as` means this build has no
  Keystone, not that you mistyped.
- Some output (the `df` byte diff) contains ANSI colour even when piped; use `df/p/n` to get plain
  text instead of stripping the escapes (differing bytes are then not marked in any way).
- `df/c` turns a diff into a patch: it prints the commands that make the current file into the
  other one, one per line, which `-s` replays —
  `bhex -2nc "df/c new.bin" old.bin > patch.bhx` then `bhex -2nwbs old.bin < patch.bhx`. The
  script is commands only (no comments, and `-s` rejects a blank line), it ends with its own `c`,
  and its offsets are raw, so do not replay it under a `sb`.
- The `t` search path for template *names* is `/usr/local/share/bhex/templates`, `../templates`,
  `.` — the first match wins. Use an explicit `t ./x.bhe` when it matters.
