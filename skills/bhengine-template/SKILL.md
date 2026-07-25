---
name: bhengine-template
description: Write, debug and ship a .bhe template for the bhex hex editor, in any directory. Use when writing a template that decodes a file format, editing or fixing an existing .bhe file, or debugging a template runtime error ("Exception @ line N"). Covers the bhengine language, its builtins, and the measure-then-read idiom that variable-length and text-oriented formats need.
---

# Writing bhengine (.bhe) templates

A template is a `.bhe` file describing a file format, which bhex's `t` command runs to decode a
file. It can live anywhere: `t ./myfmt.bhe <file>` runs a template by path. Templates are also
looked up **by name** (`t myfmt`) in `/usr/local/share/bhex/templates`, `../templates` and `.`,
in that order — dropping a file in the first of those makes it available everywhere, and note that
a name found there **shadows** a same-named file later in the list.

See `reference.md` in this skill folder for the complete builtin/type/operator tables. If you have
a bhex source checkout, `bhengine/` is the final authority (`parser.y`, `builtin.c`,
`interpreter.c`, `formatter_term.c` — they are small, read them when in doubt).

## Workflow

1. **Look at the bytes first.** `xxd`, `head -c`, or a Python snippet on 3-5 real samples of the
   format, including at least one large or unusual one. Formats differ from the spec in practice
   (e.g. PDF xref entries are specced at 20 bytes, but some producers emit 19).
2. **Read a shipped template** to match style — `t/l` lists what is installed, and the files are
   in the search paths above (usually `/usr/local/share/bhex/templates`): `png.bhe` (chunked
   binary, dispatch on a peeked tag, CRC validation), `gzip.bhe` (flags/enums, conditional
   fields), `tar.bhe` (ASCII fields, `to_int(..., 8)`), `pdf.bhe` (fully text-oriented,
   variable-length tokens).
3. **Iterate against real files** — the fastest loop, since the template is read from disk on
   every run and nothing needs rebuilding:
   ```sh
   bhex -2 -n -c "t ./myfmt.bhe" /path/to/sample
   ```
   `-2` silences warnings, `-n` skips history. For a quick language experiment use inline mode —
   note it takes **statements** (they get wrapped in `proc { ... }` for you) as a single
   double-quoted argument:
   ```sh
   bhex -2 -n -c 't/i "local x = 1 << 3; print(x, off());"' file
   ```
4. **Validate, do not eyeball.** Cross-check the parse against an independent implementation —
   e.g. extract the offsets your template printed and compare them with what Python computes from
   the format's own index/table. A template that prints plausible-looking output can still be
   silently misaligned.
5. **Test the edges**: truncated file, wrong magic, empty file, zero-length arrays, and the largest
   sample you have (watch the runtime). Every one of them must produce a clean template exception
   or a clean parse — never a crash. If a sanitizer build of bhex is around, re-run them through
   it.
6. **Ship it** (see the checklist at the bottom).

## Language essentials

Two kinds of variables, and the distinction drives everything:

- **File variables** — `u32 length;` — read bytes at the current offset, advance it, and get
  printed. Declared with a type, no `local`.
- **Locals** — `local n = off();` — pure computation, never touch the file, never printed.
  Re-assignment drops the keyword: `n = n + 1;`.

```
struct chunk_t
{
    u32  length;              // file var: reads 4 bytes, advances 4
    char type[4];             // char[] prints as a quoted string: 'IHDR'
    if (length > 0) {
        u8 data[length];      // array size is any expression
    }
    u32 crc;
}
```

Top-level constructs: `struct NAME { ... }`, `enum name_t : u8 { A = 1, B = 2 }` (`orenum` for
bit-flags, prints as `A | B`), `fn name(args) { ... }`, `proc { ... }` (the entry point, at most
one), and `proc name { ... }` (named alternative entry points, invoked as `t myfmt.name`).

Statements: file/local var decls, assignment, `if`/`elif`/`else`, `while`, `break`, `continue`,
`return`, and bare calls like `skip_while(" ");`. Structs and procs share the same statement grammar, so
control flow and locals are allowed anywhere.

Functions return by assigning the implicit `result` variable:

```
fn chunk_crc(length)
{
    disable_print();          // suppress output of this function's file vars
    result = crc("CRC-32/ISO-HDLC", length + 4, -(length + 8));
}
```

`disable_print()` and the endianness setting are automatically restored when the function returns,
so a helper cannot corrupt the caller's formatting state.

## Parsing variable-length / text-oriented formats

Binary formats map onto structs directly. Text formats (PDF, and any format with whitespace-
separated or delimited tokens) do not — you cannot write `char id[?]`. The idiom is **measure
first, then declare the field**, which is what the `scan_*` builtins are for: they return the
length of a run of bytes without moving the offset.

```
struct obj_t
{
    local id_len = scan_while("0123456789");     // how many digits are here
    assert(id_len > 0, "malformed object: missing id");
    char id[id_len];                             // now the length is known
    skip_while(" \t\r\n");                       // consume the separator
}
```

`scan_while(set)` / `skip_while(set)` measure or consume the bytes **in** the set,
`scan_until(set)` / `skip_until(set)` the bytes **not** in it (`scan_until("\r\n")` is "distance to
the end of the line").

`peek(n [, off])`, `peek_u8/u16/u32/u64([off])` and `read(n)` cover the rest: they read without
declaring a file variable, so nothing is printed and no helper function is needed. This is the
one-liner that replaces the four-line "read it, then seek back" dance:

```
    local cmd_type = peek_u32();      // dispatch on a header field
    local type     = peek(4, 4);      // 4 bytes, 4 bytes ahead
```

A NUL-terminated name in a header is a `string` field — never a loop reading one byte at a time,
which prints one line per character.

For "everything up to a marker", `find_next()` returns the offset of the match (or -1) without
moving the cursor:

```
    local body_end = find_next("endobj");
    assert(body_end >= 0, "malformed object: 'endobj' not found");
    u8 body[body_end - off()];
```

Use `find()` instead when you actually want to *go* to the match: it seeks there and returns 1, or
returns 0 and leaves the offset alone.

**Dispatch on a peeked keyword** instead of hardcoding a section order — it is what makes a
template survive files with repeated/interleaved sections (incremental updates, appended data):

```
fn parse_section()
{
    local kw = peek(4);
    if (kw == "xref") {
        xref_t xref;
    } elif (kw == "trai") {
        trailer_t trailer;
    } else {
        object_t object;
    }
}
```

Note this must be a `fn`, not a `proc name` — named procs are only reachable from the command
line, a bare `parse_section();` call resolves against builtins and `fn`s only.

## Validate what you parse

A template that only *describes* a format leaves the interesting question unanswered. The
integrity engines behind the `cr`, `cs` and `hh` commands are available as builtins, all taking
`(name [, size [, off]])` with `off` relative to the current offset:

```
    u32 length;
    char type[4];
    u8   data[length];
    u32  crc;
    // the PNG chunk CRC covers the type and the data, i.e. length + 4 bytes
    // ending just before the field we have read
    assert(crc == crc("CRC-32/ISO-HDLC", length + 4, -(length + 8)),
           "chunk CRC mismatch");
```

`hash(name, ...)` returns a hex string, `entropy([size [, off]])` returns the Shannon entropy
x1000 — useful to tell a compressed stream from a plain one without floating point.

## Gotchas

- **`char x[n]` is a string, `u8 x[n]` is a buffer.** Strings print fully, quoted, with
  non-printables escaped (`'<</Size 6\x0a>>'`) and **stop at the first NUL byte**. Buffers print as
  hex truncated to 16 bytes with `...`. Use `char` for text fields, `u8` for binary payloads — a
  large `char[]` will dump its entire content into the output.
- **Numeric arrays print at most 16 elements** (then `, ...`), but arrays of structs print in full.
  For a big table (a symbol table, an MP4 sample table) declare the array anyway and cap the
  *printing* with `max_array_print(n)`: every element is still parsed and still ends up in the
  `t/x` output, the terminal listing just stops at `n` and says how many were left out. Put the
  call inside the struct or `fn` that owns the table — like `disable_print()`, it is restored on
  exit, so it will not truncate unrelated arrays (see `mp4.bhe`, `squashfs.bhe`).
- **Guard every computed array size** before declaring it, or a corrupt file makes the template
  read absurd lengths: `assert(n * 18 <= remaining_size(), "...")`.
- Zero-length arrays (`u8 body[0]`) are legal and print as empty — no need to special-case them.
- **`error()`/`assert()` abort the whole template** with a source-annotated exception. That is the
  right reaction to a file that cannot be parsed further; the partial output is still shown. For
  something merely suspicious (a bad CRC, an unknown version) use `warning()`, which lets the
  parse continue.
- `find(s)` searches forward from the current offset and *moves* there; `find_next(s)` returns the
  offset without moving. Pass a second argument to search backward. Both are raw byte searches — a
  needle that can occur inside a compressed payload may match early.
- **There is no preprocessor**: `#` is the cross-file type operator, so character sets have to be
  written out at each use. String escapes are only `\0 \r \t \n \\ \xNN` — no `\f`.
- **Numbers print in hex by default** (`nums_in(10)` switches globally). `printable()` drops
  everything outside printable ASCII, so `to_int(printable(field))` is the safe ASCII-number
  idiom — and pass the base explicitly when the format is not decimal (tar's fields are octal).
- `&&`/`||` are the boolean operators; `&`/`|` are bitwise. Both exist and both parse. The
  boolean ones **short-circuit**, so a bound check can guard a call that would otherwise raise:
  `if (off() + 4 <= size() && peek_u32(4) == 0)` never evaluates the `peek_u32` when the file is
  too short.
- **A `peek`/`crc`/`hash` offset that lands outside the file is an exception**, not a short read.
  Reading *fewer bytes than asked* at a valid offset is fine (`peek()` returns a shorter string,
  `peek_u32()` returns -1), but `peek(4, 100)` with 10 bytes left aborts the template. Guard the
  offset, not just the size.
- `break`/`continue` are rejected outside a `while`, including at the top of a `fn` body.
- Check your template in both formatters: `t myfmt` and `t/x myfmt`. The XML output should parse
  (`python3 -c "import xml.etree.ElementTree as ET; ET.parse('out.xml')"`) — anything appearing
  outside a tag is a formatter bug worth chasing.

## Shipping checklist

- [ ] Keep the 4-space style of the shipped templates, and a comment above each struct saying what
      part of the format it covers.
- [ ] Name the entry point `proc { ... }`. Add `proc <name> { ... }` for alternative views (a
      listing, a summary) — they are reachable as `t myfmt.<name>`.
- [ ] Install it where you want it found by name: copy the `.bhe` into
      `/usr/local/share/bhex/templates` (or keep it next to your data and use `t ./myfmt.bhe`).
      Check `t/l myfmt` lists it, and that the name does not collide with a shipped template —
      the first match in the search path wins and the later file is silently skipped.
- [ ] Re-run the sample files one last time in both formatters, `t myfmt` and `t/x myfmt`.

### If you are working inside the bhex repository

The template itself needs no build step — `CMakeLists.txt` copies the whole `templates/`
directory — but a template that ships with bhex is expected to come with a test:

- [ ] `tests/data/sample_myfmt.myfmt` — the smallest real sample, dropped in as-is with its own
      extension. At build time `tests/gen_tests.py` turns every sample file in `tests/data` into a
      `tests/data/<name>.h` exposing it as `static u8_t <name>[]`; the generated headers are
      gitignored, so only the sample is committed.
- [ ] `tests/test_cmd_templates.c` — add the `#include` in alphabetical position and a
      `int TEST(template_myfmt_1)(void)` following the existing pattern (`dummyfilebuffer_create`,
      `exec_commands_on("t ./templates/myfmt.bhe", tfb)`, `compare_strings_ignoring_X`). Wrap the
      expected string in `// clang-format off/on`. Produce the expected literal from real output
      rather than by hand:
      ```sh
      cd build && ./bhex -2 -n -c "t ../templates/myfmt.bhe" sample | \
        python3 -c 'import sys
for l in sys.stdin.read().split("\n"):
    if l: print("        \"%s\\n\"" % l.replace("\\","\\\\").replace("\"","\\\""))'
      ```
      (`X` characters in the expected string act as wildcards.)
- [ ] `python3 tests/gen_tests.py` to regenerate `tests/main.c` (it is generated, not tracked).
- [ ] `cd build_tests && cmake --build . -j8 && ./bhex_tests` — the whole suite, then confirm the
      new test by name: `./bhex_tests cmd_templates.template_myfmt_1`.
- [ ] Repeat under `build_asan` and re-run the real samples through `build_asan/bhex`.
- [ ] Add the format to the `t/l` list in `README.md`.

To make this skill discoverable by Claude Code, put it (or a symlink to it) in `.claude/skills/`
of the project you are working in, or in `~/.claude/skills/` to have it everywhere.
