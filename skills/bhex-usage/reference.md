# bhex command reference

Extracted from the bhex sources (`main.c`, `common/cmdline_parser.c`, `common/expr_eval.c`,
`cmd/*.c`) and checked against a running binary. `?` after a command name prints the same help from
the build you actually have — prefer it when something here disagrees, and note that `ds`, `as`,
`ii` and `fba` only exist if the build enabled them.

## Invocation

```
bhex [ options ] inputfile
  -h  --help        print help
  -w  --write       open in write mode (creates the file if it does not exist)
  -b  --backup      copy the original to "inputfile.bk" before anything else
  -2  --no_warning  disable warnings
  -n  --no_history  do not save command history
  -C  --no_color    do not use colors (--no-color is accepted too)
  -U  --no_unicode  draw with ASCII only (the branch arrows of "ds/a")
  -c  "c1; c2; ..." run the commands and exit (mutually exclusive with -s)
  -s  --script      read one command per line from stdin
```

Parsing is plain `getopt_long`, so short options cluster (`-2n`, `-2nwb`) and `-c` takes its
argument attached or separated (`-2nc"p 4"`, `-2nc "p 4"`). Beyond the two clustering rules in
`SKILL.md`: long options never cluster (`--no_warning --no_history -c "p 4" file`), `-c` together
with `-s` is rejected outright, and both mistakes exit 1 with the usage message.

The output is colored (dumps, addresses, command names, log tags, template fields, the algorithm
names of `hh`/`cs`/`cr`, disassembly -- where jumps, calls and returns are painted apart from the
other mnemonics -- and the entropy graph, by band) only when the
standard output is a terminal and `NO_COLOR` is unset: a pipe or a redirect already yields plain
text, `-C` covers the remaining case. `df/n` and `tui/n` remain as per-command overrides.

The box drawing characters of the `ds/a` arrows are used only when `LC_ALL`/`LC_CTYPE`/`LANG`
name a UTF-8 locale and `TERM` is not `dumb`; `-U` forces the ASCII drawings. Unlike the colors,
this does not depend on the output being a terminal: a redirected listing keeps its arrows.

Exit code is 1 only for those startup failures (bad command line, missing/unopenable input file);
once the file is open, every command error still exits 0.

History goes to `$HOME/.bhex_history`, or `$BHEX_HISTORY_FILE` if set; it is neither loaded nor
saved when `-c` is used. In the interactive shell, Tab completes the command name in the first
word and file paths in the following ones, and a hint of the expected arguments is shown as you
type; `exit` (or EOF) quits.

## Command table

Modifiers are alternatives within `{}`, independent otherwise. All offsets/sizes accept decimal or
`0x`-prefixed hex, and any argument may be a backtick expression.

| Command | Alias | Form | Notes |
| --- | --- | --- | --- |
| help | `h` | `h` | list commands |
| info | `i` | `i` | path, size, entropy, md5 |
| setbase | `sb` | `sb [<base>]` | no arg prints the current base |
| echo | `ec` | `ec[/{x,d}] <arg>...` | `/x` hex (default), `/d` decimal; backticks evaluated |
| seek | `s` | `s[/{+,-}] [<off>]` | no arg prints the offset; `s -` returns to the previous one; `/+` `/-` are relative and wrap |
| print | `p` | `p[/{x,w,d,q,a,C}/{le,be}/r/W/{+,-}] [<nelements>]` | default 256 bytes, `-` = whole file; `r` raw, `W` 32 bytes/line, `/+` `/-` seek after printing |
| entropy | `e` | `e [<rows> <len>]` | **rows first**; `-` or omitted = auto rows; rows are colored by band (>= 7 red, >= 5 yellow) |
| search | `src` | `src[/{s,x}/sk/p] <what>` | `s` string (default, `\xNN` accepted), `x` hex string, `sk` seek to a match, `p` print context |
| strings | `str` | `str[/n/{a,w}] [<pattern> <num>]` | `n` NUL-terminated only, `a` 8-bit, `w` 16-bit; `pattern` may use `*`; `num` = min length (3) |
| hash | `hh` | `hh[/l] <algo> [<size> <off>]` | `off` relative to the cursor; `size` 0/omitted = to EOF; `*` = all; `/l` lists |
| checksum | `cs` | `cs[/l] <name> [<size> <off>]` | partial names and `*` accepted |
| crc | `cr` | `cr[/l] <name> [<size> <off>]` | names look like `CRC-32/ISO-HDLC` |
| template | `t` | `t[/l/i/x] <name\|path\|filter\|code>` | `l` list, `x` XML output, `i` inline bhengine statements |
| diff | `df` | `df[/p/w/n] <file>` | `p` print differing bytes, `w` 16-byte rows, `n` no colors even on a terminal |
| export | `ex` | `ex <ofile> [<size>]` | writes from the cursor |
| import | `im` | `im[/{i,ovw}] <file> [<size> <offset>]` | `i` insert (default), `ovw` overwrite; `offset` is into the *imported* file |
| write | `w` | `w[/{s,x,b,w,d,q}/{le,be}/u/i] <data>` | `s` string (default), `x` hex string, `b/w/d/q` sized number, `i` insert instead of overwrite |
| delete | `d` | `d [<nbytes>]` | omitted = to EOF |
| undo | `u` | `u[/a]` | `a` undo everything |
| commit | `c` | `c[/l]` | `l` lists pending changes without writing; the bytes are colored like a diff (green added, red removed) |
| disas | `ds` | `ds[/l\|/a] <arch> [<n>]` | Capstone; `n` = instruction count (8); control flow instructions are highlighted; `a` draws the branches as arrows left of the mnemonics (`◂` jump, `▸` target, `▾`/`▴` target outside the listing), up to 5 nested ones; ASCII (`<`, `>`, `v`, `^`) without a UTF-8 locale or with `-U` |
| assemble | `as` | `as[/l/i/s] <arch> '<code>'` | Keystone; writes at the cursor, `i` insert, `s` seek to the end |
| isa_identify | `ii` | `ii[/g] [<size>]` | bundled models; `g` = per-1024-byte-chunk code ranges; the confidence is colored by band |
| findbase | `fba` | `fba[/{32,64}/{le,be}]` | binbloom base-address guess for raw firmware; the certainty of the guess is colored |

`help` also lists `interactive` (`tui`), a full-screen editor driven by keystrokes. It is for humans
at a terminal only: do not use it — every inspection and edit it offers is available through the
commands above, which is what you want when driving bhex.

## Parsing rules

`SKILL.md` has the grammar; the details it leaves out:

- `;` separates commands in the interactive line as well as in `-c`, and is ignored inside quotes
  and backticks.
- Errors: a bad command, a bad modifier, a bad argument or a failed expression stops a `-c` batch
  and the `-s` loop. The process still exits 0 — only the startup failures listed above set 1.

## Expression grammar (backticks)

```
expr    := or
or      := and   ( '|'  and )*
and     := shift ( '&'  shift )*
shift   := add   ( '<<' | '>>' add )*
add     := mul   ( '+' | '-' mul )*
mul     := unary ( '*' unary )*
unary   := '~' unary | primary
primary := '$' name | '(' expr ')' | '[' deref ']' | number
deref   := [ bitlen ('be'|'le')? ] expr        # bitlen in { 8, 16, 32, 64 }, default 32 LE
number  := decimal | 0xHEX
```

`$off`/`$o` is the current offset **plus base**. All arithmetic is u64 and wraps; nesting is capped
at 128. A dereference whose address+width exceeds the file size fails with
`memory read out of bounds`.

Dereference addresses are **absolute file offsets**, unaffected by `sb`. The result of the whole
expression is substituted into the command line as a decimal string, so it can also be used where
a name is expected.
