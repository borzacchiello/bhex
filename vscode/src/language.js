// Copyright (c) 2022-2026, bageyelet

/*  language.js
 *  Single source of truth for the "bhe" language surface.
 *
 *  Everything here is transcribed from the bhex sources; keep it in sync with
 *  them when the language grows:
 *      keywords      <- bhengine/lexer.l
 *      builtin types <- bhengine/builtin.c    (builtin_types[])
 *      builtins      <- bhengine/builtin.c    (builtin_funcs[])
 *
 *  The TextMate grammar is generated from this file, so a name added here
 *  lights up in the editor after `npm run gen-grammar`, and the hover and
 *  completion providers pick it up with no further work.
 */

'use strict';

/* Every keyword the lexer knows, split by the role it plays. */
const KEYWORDS_CONTROL = ['if', 'elif', 'else', 'while', 'break', 'continue', 'return'];
const KEYWORDS_DECL = ['struct', 'enum', 'orenum', 'fn', 'proc'];
const KEYWORDS_MODIFIER = ['local'];

const KEYWORDS = [...KEYWORDS_CONTROL, ...KEYWORDS_DECL, ...KEYWORDS_MODIFIER];

/* Types usable in a file-variable declaration. */
const BUILTIN_TYPES = [
    'u8', 'u16', 'u32', 'u64',
    'i8', 'i16', 'i32', 'i64',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'char', 'string', 'wchar', 'wstring'
];

/* The implicit local a `fn`, a named `proc` and `_identify` return through. */
const SPECIAL_VARIABLES = ['result'];

/* Procs the `id` command looks for by name. */
const SPECIAL_PROCS = ['_identify', '_identify_magic'];

/*  Builtin functions, in the order and grouping of builtin_funcs[].
 *  `signature` is what the hover and the completion detail show, `doc` is one
 *  or two sentences of markdown.
 */
const BUILTINS = [
    /* --- casts ---------------------------------------------------------- */
    ...['u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64'].map((t) => ({
        name: t,
        group: 'cast',
        signature: `${t}(v)`,
        doc: `Cast \`v\` to a ${t.startsWith('u') ? 'unsigned' : 'signed'} ${t.slice(1)}-bit integer.`
    })),
    {
        name: 'wstring',
        group: 'cast',
        signature: 'wstring(v)',
        doc: 'Convert an ASCII string to a wide string, so it can be compared against a `wstring` field.'
    },

    /* --- cursor --------------------------------------------------------- */
    { name: 'off', group: 'cursor', signature: 'off()', doc: 'The current offset in the file.' },
    { name: 'size', group: 'cursor', signature: 'size()', doc: 'The size of the file.' },
    {
        name: 'remaining_size',
        group: 'cursor',
        signature: 'remaining_size()',
        doc: 'The number of bytes between the current offset and the end of the file.\n\nGuard every computed array size against it.'
    },
    { name: 'seek', group: 'cursor', signature: 'seek(o)', doc: 'Move the cursor to the absolute offset `o`.' },
    {
        name: 'fwd',
        group: 'cursor',
        signature: 'fwd(n)',
        doc: 'Move the cursor `n` bytes forward. Rejects a move that would leave the file.'
    },
    {
        name: 'bwd',
        group: 'cursor',
        signature: 'bwd(n)',
        doc: 'Move the cursor `n` bytes backward. Rejects a move that would leave the file.'
    },

    /* --- reading without declaring a file variable ----------------------- */
    {
        name: 'peek',
        group: 'read',
        signature: 'peek(n [, off])',
        doc: 'Read `n` bytes as a string without moving the cursor. `off` is relative to the current offset and may be negative.\n\nReturns fewer bytes at the end of the file, but an `off` landing outside the file raises an exception.'
    },
    ...['u8', 'u16', 'u32', 'u64'].map((t) => ({
        name: `peek_${t}`,
        group: 'read',
        signature: `peek_${t}([off])`,
        doc: `Read a \`${t}\` without moving the cursor, honoring the current endianness. Returns \`-1\` when fewer than ${
            { u8: 1, u16: 2, u32: 4, u64: 8 }[t]
        } bytes are left.`
    })),
    { name: 'read', group: 'read', signature: 'read(n)', doc: 'Like `peek(n)`, but consumes the bytes.' },

    /* --- scanning runs of bytes ------------------------------------------ */
    {
        name: 'scan_while',
        group: 'scan',
        signature: 'scan_while(set)',
        doc: 'Length of the run of bytes that are in `set`, without moving the cursor.\n\nThe measure-then-declare idiom for variable-length fields.'
    },
    {
        name: 'scan_until',
        group: 'scan',
        signature: 'scan_until(set)',
        doc: 'Length of the run of bytes that are **not** in `set`, without moving the cursor.'
    },
    {
        name: 'skip_while',
        group: 'scan',
        signature: 'skip_while(set)',
        doc: 'Consume the run of bytes that are in `set` and return its length.'
    },
    {
        name: 'skip_until',
        group: 'scan',
        signature: 'skip_until(set)',
        doc: 'Consume the run of bytes that are **not** in `set` and return its length.'
    },

    /* --- searching -------------------------------------------------------- */
    {
        name: 'find',
        group: 'search',
        signature: 'find(s [, backward])',
        doc: 'Raw byte search from the current offset. On a match seeks to it and returns `1`, otherwise leaves the offset alone and returns `0`.'
    },
    {
        name: 'find_next',
        group: 'search',
        signature: 'find_next(s [, backward])',
        doc: 'The same search as `find`, but returns the **offset** of the match (or `-1`) and never moves the cursor.'
    },

    /* --- strings ---------------------------------------------------------- */
    {
        name: 'to_int',
        group: 'string',
        signature: 'to_int(s [, base])',
        doc: 'ASCII to number, **base 10 by default** (2-36, or `0` to let the string decide).\n\nPass the base explicitly when the format is not decimal, and wrap the field in `printable()` first.'
    },
    { name: 'strlen', group: 'string', signature: 'strlen(s)', doc: 'Length of `s` up to the first NUL byte.' },
    {
        name: 'printable',
        group: 'string',
        signature: 'printable(s)',
        doc: 'Drop every non-printable-ASCII byte of `s`, wherever it is.'
    },
    { name: 'trim', group: 'string', signature: 'trim(s)', doc: 'Drop leading and trailing whitespace.' },
    { name: 'substr', group: 'string', signature: 'substr(s, start [, len])', doc: 'Slice of `s`, NUL bytes included.' },
    { name: 'starts_with', group: 'string', signature: 'starts_with(s, prefix)', doc: '`1` or `0`.' },
    { name: 'index_of', group: 'string', signature: 'index_of(s, needle)', doc: 'Offset of `needle` within `s`, or `-1`.' },
    {
        name: 'tostring',
        group: 'string',
        signature: 'tostring(v [, base])',
        doc: 'Value to string, in base 10 or 16. Defaults to the current number format.'
    },

    /* --- math ------------------------------------------------------------- */
    { name: 'min', group: 'math', signature: 'min(a, b, ...)', doc: 'Smallest of the arguments; variadic.' },
    { name: 'max', group: 'math', signature: 'max(a, b, ...)', doc: 'Largest of the arguments; variadic.' },
    { name: 'abs', group: 'math', signature: 'abs(v)', doc: 'Absolute value.' },
    {
        name: 'align_up',
        group: 'math',
        signature: 'align_up(v, alignment)',
        doc: 'Round `v` up to the next multiple of `alignment` — the padding math archives need.'
    },

    /* --- output and control flow ------------------------------------------ */
    { name: 'little_endian', group: 'output', signature: 'little_endian()', doc: 'Little endian for subsequent reads.' },
    { name: 'big_endian', group: 'output', signature: 'big_endian()', doc: 'Big endian for subsequent reads.' },
    {
        name: 'nums_in',
        group: 'output',
        signature: 'nums_in(base)',
        doc: 'Number format for the output: `10` or `16`. Hex is the default.'
    },
    {
        name: 'max_array_print',
        group: 'output',
        signature: 'max_array_print(n)',
        doc: 'Print at most `n` elements of an array, `0` meaning all of them.\n\nSaved and restored per `struct` and per `fn`, so it works as a per-struct setting. Term output only: the elements past the limit are still parsed and still appear in `t/x`.'
    },
    {
        name: 'magic',
        group: 'output',
        signature: 'magic(pattern [, off])',
        doc: 'Only in `_identify_magic`: declare a pattern without which `_identify` cannot succeed, sitting `off` bytes into the format.\n\nThe pattern **must** be a necessary condition, or files are silently never found.'
    },
    {
        name: 'disable_print',
        group: 'output',
        signature: 'disable_print()',
        doc: 'Suppress the printing of file variables. Restored automatically when the enclosing `fn` or `struct` returns.'
    },
    { name: 'enable_print', group: 'output', signature: 'enable_print()', doc: 'Restore the printing of file variables.' },
    {
        name: 'print',
        group: 'output',
        signature: 'print(a, b, ...)',
        doc: 'Print the arguments space-separated, newline-terminated. Bypasses `disable_print()`.\n\nNot printf-like: a `"%d"` is printed verbatim.'
    },
    {
        name: 'warning',
        group: 'output',
        signature: 'warning(a, b, ...)',
        doc: 'Non-fatal diagnostic; the parse continues. The right reaction to something merely suspicious, like a bad CRC.'
    },
    {
        name: 'error',
        group: 'output',
        signature: 'error(a, b, ...)',
        doc: 'Raise a template exception and abort the run. Whatever was decoded before the failure is still shown.'
    },
    {
        name: 'assert',
        group: 'output',
        signature: 'assert(cond, msg, ...)',
        doc: 'Raise a template exception unless `cond` holds.'
    },
    { name: 'exit', group: 'output', signature: 'exit()', doc: 'Stop the template cleanly.' },

    /* --- integrity checks -------------------------------------------------- */
    {
        name: 'crc',
        group: 'integrity',
        signature: 'crc(name [, size [, off]])',
        doc: 'CRC over `size` bytes at `off` (relative to the current offset). `name` as listed by `cr/l`, e.g. `"CRC-32/ISO-HDLC"`.\n\nA `size` of 0 or missing means "to the end of the file".'
    },
    {
        name: 'checksum',
        group: 'integrity',
        signature: 'checksum(name [, size [, off]])',
        doc: 'Checksum over `size` bytes at `off`. `name` as listed by `cs/l`, e.g. `"ADLER-32"`.'
    },
    {
        name: 'hash',
        group: 'integrity',
        signature: 'hash(name [, size [, off]])',
        doc: 'Digest over `size` bytes at `off`, as a lowercase hex string. `name` as listed by `hh/l`.'
    },
    {
        name: 'entropy',
        group: 'integrity',
        signature: 'entropy([size [, off]])',
        doc: 'Shannon entropy x1000 (0 - 8000), so it compares without floats. Tells a compressed stream from a plain one.'
    }
];

/* Names that are both a builtin type and a cast builtin, e.g. `u8`. */
const BUILTIN_FUNCTION_NAMES = [...new Set(BUILTINS.map((b) => b.name))];

const BUILTIN_BY_NAME = new Map(BUILTINS.map((b) => [b.name, b]));

module.exports = {
    KEYWORDS,
    KEYWORDS_CONTROL,
    KEYWORDS_DECL,
    KEYWORDS_MODIFIER,
    BUILTIN_TYPES,
    BUILTINS,
    BUILTIN_BY_NAME,
    BUILTIN_FUNCTION_NAMES,
    SPECIAL_VARIABLES,
    SPECIAL_PROCS
};
