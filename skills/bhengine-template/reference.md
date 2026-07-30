# bhengine language reference

Extracted from the bhex sources — `bhengine/parser.y`, `bhengine/lexer.l`, `bhengine/builtin.c`,
`bhengine/interpreter.c`, `bhengine/formatter_term.c` and `cmd/cmd_template.c`. If you have a
checkout and something here disagrees with it, the code wins; those files are small, go read them.
Without a checkout, `t/l` and `t?` are the quickest way to confirm what a given build supports.

## Builtin types (file variables)

| Type | Size | Notes |
| --- | --- | --- |
| `u8` `u16` `u32` `u64` | 1/2/4/8 | unsigned, endianness-aware |
| `i8` `i16` `i32` `i64` | 1/2/4/8 | signed |
| `uint8_t` … `int64_t` | | aliases of the above |
| `char` | 1 | prints as a character, `'\xNN'` if not printable |
| `char name[n]` | n | prints as a **quoted string**, stops at the first NUL |
| `wchar` | 2 | endianness-aware |
| `string` | var | NUL-terminated, consumes the terminator |
| `wstring` | var | UTF-16, NUL-terminated |
| `u8 name[n]` | n | prints as hex, truncated to 16 bytes with `...` |

Any struct or enum name is also usable as a field type. `othertemplate#StructName v;` pulls a
struct from another `.bhe` file (the file is loaded on demand; nothing in `templates/` uses this
today).

## Builtin functions

The arity of every builtin is declared in one table and checked by the interpreter before the
call, so a wrong number of arguments always fails the same way.

### Cursor

| Call | Effect |
| --- | --- |
| `off()` / `size()` / `remaining_size()` | current offset, file size, bytes left |
| `seek(o)` | absolute seek |
| `fwd(n)` / `bwd(n)` | relative seek; both reject a move that leaves the file |

### Reading without declaring a file variable

| Call | Effect |
| --- | --- |
| `peek(n [, off])` | `n` bytes as a string, offset untouched; shorter at the end of the file |
| `peek_u8/u16/u32/u64([off])` | a number, honoring the endianness, or **-1** if there are not that many bytes left |
| `read(n)` | like `peek(n)`, but consumes the bytes |

`off` is relative to the current offset and may be **negative**, so `peek(4, 4)` is "the four bytes
after the next four" and `peek_u32(-4)` re-reads the field just consumed. A `u64` with its top bit
set is indistinguishable from the -1 sentinel: read those into a file variable instead. An `off`
landing outside the file raises `peek: offset N is outside of the file` (see the gotcha in
`SKILL.md`).

### Scanning runs of bytes

Each takes a string used as a *byte set*. `scan_*` measure without moving, `skip_*` consume.

| Call | Effect |
| --- | --- |
| `scan_while(set)` / `skip_while(set)` | length of the run of bytes that are in `set` |
| `scan_until(set)` / `skip_until(set)` | length of the run of bytes that are **not** in `set` |

### Searching

| Call | Effect |
| --- | --- |
| `find(s)` / `find(s, 1)` | forward / backward search from the current offset; on a match seeks to it and returns 1, otherwise leaves the offset alone and returns 0 |
| `find_next(s)` / `find_next(s, 1)` | same search, but returns the **offset** (or -1) and never moves |

Both take the needle exactly as the lexer decoded it, NUL bytes included. A backward search finds
the last match that *ends* at or before the current offset.

### Strings

| Call | Effect |
| --- | --- |
| `to_int(s)` / `to_int(s, base)` | ASCII to number, **base 10 by default** (2-36, or 0 to let the string decide) |
| `strlen(s)` | length up to the first NUL |
| `trim(s)` | drops leading and trailing whitespace |
| `printable(s)` | drops every non-printable-ASCII byte, wherever it is |
| `substr(s, start)` / `substr(s, start, len)` | slice |
| `starts_with(s, prefix)` | 1 or 0 |
| `index_of(s, needle)` | offset within the string, or -1 |
| `tostring(v)` / `tostring(v, base)` | value to string; base 10 or 16, defaults to the current number format |

`substr`, `starts_with`, `index_of`, `trim` and `printable` work on the raw bytes, NUL included, so
they can slice what `peek()` returns. `strlen` is the exception: it stops at the first NUL, which
is what a fixed-size `char[]` field needs.

### Math

| Call | Effect |
| --- | --- |
| `min(a, b, ...)` / `max(a, b, ...)` | variadic |
| `abs(v)` | absolute value |
| `align_up(v, alignment)` | rounds up to the next multiple: the padding math archives need |

### Integrity checks

The engines behind the `cr`, `cs` and `hh` commands, so a template can *validate* what it parses.
All take `(name [, size [, off]])`, where `size` 0 or missing means "to the end of the file" and
`off` is relative to the current offset.

| Call | Effect |
| --- | --- |
| `crc(name, ...)` | CRC value; `name` as listed by `cr/l` (e.g. `"CRC-32/ISO-HDLC"`) |
| `checksum(name, ...)` | checksum value; `name` as listed by `cs/l` (e.g. `"ADLER-32"`) |
| `hash(name, ...)` | digest as a lowercase hex string; `name` as listed by `hh/l` |
| `entropy([size [, off]])` | Shannon entropy x1000 (0 - 8000), so it compares without floats |

### Output and control flow

| Call | Effect |
| --- | --- |
| `print(a, b, ...)` | variadic, space separated, newline terminated; **ignores** `disable_print()` |
| `warning(a, b, ...)` | non-fatal diagnostic |
| `error(a, b, ...)` | raises a template exception and aborts the run |
| `assert(cond, msg...)` | raises unless `cond` holds |
| `exit()` | stops the template cleanly |
| `disable_print()` / `enable_print()` | suppress/restore printing of file variables |
| `max_array_print(n)` | print at most `n` elements of an array, `0` meaning all of them |
| `magic(pattern [, off])` | only in `_identify_magic`: declares a pattern without which `_identify` cannot succeed, sitting `off` bytes into the format |
| `nums_in(base)` | number format, 10 or 16 (16 is the default) |
| `little_endian()` / `big_endian()` | endianness for subsequent reads |
| `u8(v)` … `u64(v)`, `i8(v)` … `i64(v)` | cast to a sized integer |
| `wstring(v)` | ASCII string to wide string, for comparing against a `wstring` field |

`print`, `warning` and `error` are **not** printf-like: they space-join their arguments, exactly
like `print()` does, so a `"%d"` in the message is printed verbatim. Write
`warning("bad size at", off())`, not `warning("bad size at %d", off())`.

`disable_print()`, `max_array_print()` and the endianness are saved on entry to a `fn` **and to a
struct** and restored on exit, so a helper cannot leak its formatting state into the caller — which
is what makes `max_array_print()` usable as a per-struct setting:

```
struct table_box_t
{
    max_array_print(8);       // only this struct's arrays are truncated
    u32   entry_count;
    entry_t entries[entry_count];
}
```

The elements past the limit are still **parsed** — the offset advances over all of them, and the
values are still in the XML output — they are only left out of the terminal listing, which ends
with `... N more elements (M in total)`.

## Grammar

```
struct NAME { stmts }
enum   NAME : TYPE { A = 1, B = 2 }        // exact match printing
orenum NAME : TYPE { A = 1, B = 2 }        // bit-flags, prints "A | B"
fn NAME() { stmts }                        // callable; returns via `result`
fn NAME(a, b) { stmts }
proc { stmts }                             // entry point, at most one per file
proc NAME { stmts }                        // alternative entry point: t myfmt.NAME
proc _identify { stmts }                   // the id scan's probe; answers via `result`
proc _identify_magic { stmts }             // declares its magics via magic()
```

A named proc has a `result` local like a `fn` does, and may `return` early; `t myfmt.NAME` prints
it when it ends up non-zero. Only `_identify` is required to set it — see the `id` command below.

Statements: `TYPE name;`, `TYPE name[expr];`, `local x = expr;`, `x = expr;`, `f(args);`,
`if (e) { } elif (e) { } else { }`, `while (e) { }`, `break;`, `continue;`, `return;`.
Comments are `//`. Enum constants are referenced as `name_t::CONST`.

Operators, loosest to tightest binding:

```
&& ||                       boolean, short-circuiting
== != < <= > >=             comparison
& | ^                       bitwise
+ -
* / % << >>
!                           boolean not (unary)
[ ]  .                      indexing, field access
```

Literals: decimal and `0x` hex, with optional size/sign suffixes (`42s8`, `16u8`, `300u16`,
`0xffffu32`, `1099511627537u64`); strings with `\0 \r \t \n \\ \xNN` escapes. Strings compare with
`==`, and a `char[n]` field compares directly against a string literal.

## Output formatting (term mode)

- Each file var prints as `b+<offset>  <indent><name>: <value>`; nesting adds 4 spaces.
- Numbers: hex by default, width matching the type's size; `nums_in(10)` switches globally.
- Arrays of structs print every element, each preceded by `[i]`; builtin-typed arrays stop at 16.
- `max_array_print(n)` overrides both of those limits, for builtin and struct arrays alike. It is
  a **term-only** setting: `t/x` always emits every element, so the XML stays complete.
- `print()` output bypasses `disable_print()`.
- `t/x` emits XML instead (`formatter_xml.c`).

## The `t` command

```
t[/l/i/x] <name or file>
  l: list templates, structs and named procs (optionally filtered: t/l pdf)
  i: interpret inline bhex code
  x: XML output
```

Accepts a path (`t ./templates/pdf.bhe`), a template name (`t pdf`), a single struct
(`t pdf.pdf_header_t` — parses just that struct at the current offset), or a named proc
(`t tar.list_files`).

`t/i` takes exactly one argument, so the inline code must be wrapped in double quotes, and it is
**statements only** — `bhengine_vm_process_string()` wraps them in `proc { ... }`, so an explicit
`proc` in the argument is a syntax error. Statements need their trailing `;`:
`bhex -c 't/i "local x = 5; print(x);"' file`. The `-c` command splitter
(`cmdline_next_command()`) skips over quoted sections and `` `backtick` `` expressions, so a `;`
inside them does not end the command.

Templates are searched by name, in order, in `$BHEX_TEMPLATES_PATH` (when set),
`/usr/local/share/bhex/templates`, `../templates` and `.` — the first match wins, and a later file
with the same template name is skipped with a warning. A path argument (`t ./myfmt.bhe`) bypasses
the lookup entirely. Parsing always starts at the **current offset**, not at 0, so
`s <off> ; t myfmt` parses an embedded instance.

## The `id` command

```
id[/l/v/n/e] [<len>]
  l: list the templates that take part in the scan, with their magics
  v: per template timing
  n: do not skip over what was identified
  e: exhaustive; ignore the declared magics
```

Runs every template's `_identify` at every offset from the current one (see `SKILL.md` for the
`result` contract and what makes a probe cheap and strict). The scan reports a hit and resumes past
the largest region claimed at that offset, unless `/n`.

Cost is one pass over the bytes to find the declared magics, plus one interpreted run per
candidate.

## Debugging

A failing template prints the offending source lines with a caret and
`Exception @ line N, col M > <message>`, followed by whatever was decoded before the failure.
Common messages:

- `invalid array size: N, it is bigger than the remaining file size` — a computed length was not
  guarded against `remaining_size()`, or the offset drifted.
- `RUNTIME ERROR: <text>` — your own `error()` call.
- `unexpected break` — `break` outside a `while`.

Instrument with `print(off(), value)`; it prints even inside `disable_print()` sections.
