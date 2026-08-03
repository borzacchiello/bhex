// Copyright (c) 2022-2026, bageyelet

/*  intellisense.js
 *  What the hover and the completion list show. Pure data, so it can be tested
 *  without the editor; extension.js turns it into vscode objects.
 */

'use strict';

const { BUILTIN_BY_NAME, BUILTINS, BUILTIN_TYPES, KEYWORDS, SPECIAL_VARIABLES, SPECIAL_PROCS } = require('./language');
const { documentSymbols } = require('./symbols');

const TYPE_DOCS = {
    u8: 'Unsigned 8 bit integer.',
    u16: 'Unsigned 16 bit integer, endianness-aware.',
    u32: 'Unsigned 32 bit integer, endianness-aware.',
    u64: 'Unsigned 64 bit integer, endianness-aware.',
    i8: 'Signed 8 bit integer.',
    i16: 'Signed 16 bit integer, endianness-aware.',
    i32: 'Signed 32 bit integer, endianness-aware.',
    i64: 'Signed 64 bit integer, endianness-aware.',
    char: 'One byte, printed as a character. `char name[n]` is printed as a **quoted string** and stops at the first NUL.',
    wchar: 'Two bytes, endianness-aware.',
    string: 'NUL-terminated string; the terminator is consumed.',
    wstring: 'NUL-terminated UTF-16 string.'
};

const KEYWORD_DOCS = {
    struct: 'A named group of fields, usable afterwards as a field type.',
    enum: 'A named set of values, printed by exact match: `enum name_t : u8 { A = 1 }`.',
    orenum: 'Like `enum`, but for bit flags: the value prints as `A | B`.',
    fn: 'A function. It returns by assigning the implicit `result` local, and its `disable_print()`, `max_array_print()` and endianness are restored when it returns.',
    proc: 'The entry point. `proc { }` is the one the `t` command runs; `proc NAME { }` is reachable as `t myfmt.NAME`.',
    local: 'Declares a local: pure computation, never reads the file, never printed. Re-assignment drops the keyword.',
    if: 'Conditional. `elif` and `else` continue it.',
    elif: 'A further condition of an `if`.',
    else: 'The fallback branch of an `if`.',
    while: 'Loop. `break` and `continue` are only valid inside one.',
    break: 'Leaves the innermost `while`.',
    continue: 'Skips to the next iteration of the innermost `while`.',
    return: 'Returns from the enclosing `fn` or `proc`. Also allowed at the top level of `_identify`.'
};

const SPECIAL_DOCS = {
    result: 'The implicit local a `fn` or a named `proc` returns through.\n\nIn `_identify` it is **the number of bytes the scan may skip**: `0` means "not my format", anything else means "identified, and this long".',
    _identify: 'Run by the `id` command at every candidate offset. Nothing is printed and exceptions are swallowed, so it has to be strict and cheap.',
    _identify_magic: 'Runs once, before the scan, and declares through `magic(pattern [, off])` the byte patterns without which `_identify` cannot succeed.'
};

/**
 * Markdown for the word under the cursor, or null when there is nothing to say.
 *
 * @param {string} word
 * @param {string} [src]  the document, so its own declarations are covered too
 * @returns {string|null}
 */
function hover(word, src) {
    const builtin = BUILTIN_BY_NAME.get(word);
    const isType = BUILTIN_TYPES.includes(word);

    if (builtin && isType) {
        /* `u8` is both a field type and a cast */
        return [
            '```bhe', `${word} name;`, '```', TYPE_DOCS[word] || '',
            '', '---', '',
            '```bhe', builtin.signature, '```', builtin.doc
        ].join('\n');
    }
    if (builtin) return ['```bhe', builtin.signature, '```', builtin.doc].join('\n');
    if (isType) return ['```bhe', `${word} name;`, '```', TYPE_DOCS[word] || ''].join('\n');
    if (SPECIAL_DOCS[word]) return SPECIAL_DOCS[word];
    if (KEYWORD_DOCS[word]) return ['```bhe', word, '```', KEYWORD_DOCS[word]].join('\n');

    if (src) {
        const declared = findDeclaration(documentSymbols(src), word);
        if (declared) {
            const head =
                declared.kind === 'function'
                    ? `fn ${declared.name}${declared.detail}`
                    : declared.kind === 'enumMember'
                      ? `${declared.name} = ${declared.detail}`
                      : `${declared.kind} ${declared.name}${declared.detail ? ' : ' + declared.detail : ''}`;
            return ['```bhe', head, '```'].join('\n');
        }
    }

    return null;
}

function findDeclaration(symbols, name) {
    for (const s of symbols) {
        if (s.name === name) return s;
        const child = findDeclaration(s.children, name);
        if (child) return child;
    }
    return null;
}

/**
 * @typedef {object} Completion
 * @property {string} label
 * @property {'function'|'type'|'keyword'|'struct'|'enum'|'enumMember'|'variable'} kind
 * @property {string} detail
 * @property {string} documentation
 * @property {string} [insertText]  a snippet, when the item takes arguments
 * @property {string} [sortText]
 */

/**
 * The full completion list for a document.
 *
 * @param {string} [src]  the document, so its own declarations are offered too
 * @returns {Completion[]}
 */
function completions(src) {
    /** @type {Completion[]} */
    const out = [];

    for (const b of BUILTINS) {
        if (out.some((o) => o.label === b.name && o.kind === 'function')) continue;
        out.push({
            label: b.name,
            kind: 'function',
            detail: b.signature,
            documentation: b.doc,
            insertText: snippetFor(b),
            sortText: `1${b.name}`
        });
    }

    for (const t of BUILTIN_TYPES) {
        out.push({ label: t, kind: 'type', detail: 'builtin type', documentation: TYPE_DOCS[t] || '', sortText: `0${t}` });
    }

    for (const k of KEYWORDS) {
        out.push({ label: k, kind: 'keyword', detail: 'keyword', documentation: KEYWORD_DOCS[k] || '', sortText: `2${k}` });
    }

    for (const v of SPECIAL_VARIABLES) {
        out.push({ label: v, kind: 'variable', detail: 'implicit local', documentation: SPECIAL_DOCS[v] || '', sortText: `0${v}` });
    }

    for (const p of SPECIAL_PROCS) {
        out.push({
            label: `proc ${p}`,
            kind: 'keyword',
            detail: 'id scan',
            documentation: SPECIAL_DOCS[p] || '',
            insertText: `proc ${p}\n{\n\t$0\n}`,
            sortText: `2proc ${p}`
        });
    }

    if (src) {
        for (const s of documentSymbols(src)) {
            out.push({
                label: s.name,
                kind: s.kind === 'function' ? 'function' : s.kind === 'enum' ? 'enum' : s.kind === 'proc' ? 'function' : 'struct',
                detail: s.kind === 'function' ? `fn ${s.name}${s.detail}` : `${s.kind} ${s.name}`,
                documentation: '',
                insertText: s.kind === 'function' ? `${s.name}($0)` : undefined,
                sortText: `0${s.name}`
            });
            for (const c of s.children) {
                if (c.kind !== 'enumMember') continue;
                out.push({
                    label: `${s.name}::${c.name}`,
                    kind: 'enumMember',
                    detail: `${c.name} = ${c.detail}`,
                    documentation: '',
                    sortText: `0${s.name}::${c.name}`
                });
            }
        }
    }

    return out;
}

/** Turns `peek(n [, off])` into a tab-stop snippet. */
function snippetFor(builtin) {
    const args = builtin.signature.slice(builtin.name.length).replace(/^\(|\)$/g, '');
    const required = args.split('[')[0].trim().replace(/,\s*$/, '');
    if (required === '') return `${builtin.name}()$0`;

    const placeholders = required
        .split(',')
        .map((a, k) => `\${${k + 1}:${a.trim()}}`)
        .join(', ');
    return `${builtin.name}(${placeholders})$0`;
}

module.exports = { hover, completions, TYPE_DOCS, KEYWORD_DOCS, SPECIAL_DOCS };
