# BHE language support for VS Code

Editor support for the `.bhe` template language that [bhex](https://github.com/borzacchiello/bhex)
runs with its `t` command. The templates in `templates/` are what it is written against.

## Features

- **Syntax highlighting** for everything `bhengine/lexer.l` accepts: the size and sign suffixes on
  integer literals (`42s8`, `0xffffu32`), the `::` enum access, the `#` cross-file type operator,
  the escapes `unescape_ascii_string` understands — and a warning colour on the ones it does not.
- **Formatting** (`Format Document`, or format on save) in the style of the shipped templates.
- **Outline and breadcrumbs**: structs with their fields, enums with their members, functions with
  their parameters, and the entry point.
- **Hover documentation** for every builtin, type and keyword, with the signature the interpreter
  actually checks the arity against.
- **Completion** for the builtins, the types, the keywords, and whatever the file itself declares.
- **Snippets** for the shapes that are easy to get wrong: `_identify`, `_identify_magic`, the
  measure-then-read idiom, a guarded array.

## The formatting style

Four spaces per block, and `{` on a line of its own after `struct`, `enum`, `orenum`, `fn` and
`proc` but on the same line after `if`, `elif`, `else` and `while`:

```bhe
struct chunk_t
{
    u32  length;
    char type[4];
    if (length > 0) {
        u8 data[length];
    }
}
```

A declaration whose body closes on the same line is left as it is, so the one-line accessors in
`mp3.bhe` survive.

A wrapped line lines up under the innermost bracket still open above it, or, when none is, under
the right-hand side of the assignment it continues:

```bhe
    assert(box_size >= 16 && start + box_size <= size(),
           "malformed 'ftyp' box: bad size");

    result = checksum("SUM-32", 148, 0) + 8 * 0x20 +
             checksum("SUM-32", 0x200 - 156, 156);
```

Consecutive field declarations line their names up, and so do the `=` of consecutive enum members.
A `local` is not a type, so it lines up with other locals rather than widening a field's type
column. Both can be turned off in the settings (`bhe.format.alignDeclarations`,
`bhe.format.alignEnumMembers`).

Missing spaces around operators are **added**, and existing spacing is never collapsed — the
hand-aligned comment columns in `mp3.bhe` come out of a format unchanged. A block comment that
spans lines is left exactly as it was found, since there is no safe way to re-indent one.

## Layout

| Path | What it is |
| --- | --- |
| `src/language.js` | the only place keywords, types and builtins are listed |
| `src/lexer.js` | tokenizer, mirroring `bhengine/lexer.l` |
| `src/format.js` | the formatter, working on tokens so it can never rewrite a string |
| `src/symbols.js` | declarations, for the outline |
| `src/intellisense.js` | hover and completion content |
| `src/extension.js` | the only file that touches the `vscode` API |
| `scripts/gen-grammar.js` | generates `syntaxes/bhe.tmLanguage.json` from `language.js` |

Everything but `extension.js` is plain Node, which is what lets the test suite cover it without
launching an editor.

## Working on it

```sh
npm install          # only needed for the grammar tests
npm test             # 97 tests, ~150ms
npm run gen-grammar  # after editing src/language.js
make package         # regenerates the grammar, then builds the .vsix
```

The grammar is **generated**: edit `src/language.js` and re-run `npm run gen-grammar` rather than
editing `syntaxes/bhe.tmLanguage.json`, which a test will otherwise flag as stale.

When bhex is checked out alongside (it is, in this repository), the test suite reads
`bhengine/builtin.c` and `bhengine/lexer.l` and fails if a builtin, type or keyword has been added
there but not here. It also formats every file in `templates/`, and asserts the result is
idempotent and has exactly the same tokens as the input — a formatter that drops or rewrites code
cannot pass.
