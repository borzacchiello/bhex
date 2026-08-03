# Changelog

## 2.0.0

Rewrite. The extension used to be one file of line-oriented regexes; it is now a tokenizer and a
set of providers built on it, with a test suite.

### Fixed

- **The formatter corrupted string literals.** Operator spacing was applied to the whole line
  including the inside of strings, so `crc("CRC-32/ISO-HDLC", ...)` came back as
  `crc("CRC - 32 / ISO - HDLC", ...)` and the template no longer ran. Formatting now works on
  tokens and never touches the inside of a string or a comment.
- A comment written in the middle of a line was moved to the end of it.
- A wrapped line lost its indentation, ending up at the indentation of the statement it continued.
- A `local` in a run of field declarations widened the type column of every field around it.
- The alignment meant for enum members was applied to any consecutive lines that looked like
  `name = value`, which padded the operands of a wrapped boolean expression.
- A one-line `fn f(h) { result = ...; }` was split across three lines.
- The grammar listed builtins that do not exist (`nums_in_hex`, `nums_in_dec`, `atoi`, `strip`) and
  was missing about forty that do.
- The grammar highlighted binary and octal literals, which the lexer does not accept, and missed
  the size and sign suffixes it does (`42s8`, `0xffffu32`).
- The grammar treated `\"` as an escape inside a string. The lexer's rule is `"[^"]*"`, so a `"`
  always ends the string.
- The grammar highlighted single-quoted strings, which do not exist in the language.
- An identifier beginning with `proc` (`processLoadCommands`) had its first four characters
  highlighted as the keyword.
- Every identifier in the file was coloured as a parameter, which left nothing distinguishable.
- `language-configuration.json` auto-closed `'`, which is not a delimiter in this language.

### Added

- Outline, breadcrumbs and "go to symbol": structs with their fields, enums with their members,
  functions with their parameters, and the entry point.
- Hover documentation for every builtin, type and keyword.
- Completion for the builtins, types, keywords and the declarations in the open file, with
  argument snippets taken from each builtin's real arity.
- Snippets for `struct`, `enum`, `orenum`, `fn`, `proc`, `_identify`, `_identify_magic`, the
  measure-then-read idiom and a guarded array declaration.
- Highlighting for `::` enum access, the `#` cross-file type operator, declaration names, enum
  members, `result`, and an invalid-escape colour for the escapes the lexer rejects.
- Settings: `bhe.format.alignDeclarations`, `bhe.format.alignEnumMembers`.
- A test suite (`npm test`): 97 tests covering the lexer, the formatter, the symbols and the
  grammar. The grammar tests run the real TextMate engine; the formatter tests assert that
  formatting every shipped template is idempotent and preserves every token. Further tests read
  `bhengine/builtin.c` and `bhengine/lexer.l` and fail when the language has grown but the
  extension has not.

### Changed

- The grammar is generated from `src/language.js` by `npm run gen-grammar`, so the keyword, type
  and builtin lists exist in one place. A test fails when the checked-in grammar is stale.
- `}` and a following `else`/`elif` are joined onto one line, matching the shipped templates.
- Sources moved to `src/`; `main` is now `./src/extension.js`.

## 1.0.0

Syntax highlighting and a formatter.
