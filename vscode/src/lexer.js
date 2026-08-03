// Copyright (c) 2022-2026, bageyelet

/*  lexer.js
 *  Tokenizer for the "bhe" language, mirroring bhengine/lexer.l.
 *
 *  The formatter and the symbol provider both work on this token stream rather
 *  than on raw lines, which is what keeps them from ever rewriting the inside
 *  of a string or a comment.
 *
 *  Two details are taken verbatim from the flex rules and matter here:
 *    - a string is `"[^"]*"`. There is no escape for the delimiter, so a `"`
 *      always ends the string, and a string may span lines.
 *    - integer literals may carry a size/sign suffix: 42s8, 0xffffu32, ...
 */

'use strict';

const { KEYWORDS, BUILTIN_TYPES } = require('./language');

const KEYWORD_SET = new Set(KEYWORDS);
const TYPE_SET = new Set(BUILTIN_TYPES);

/* Longest first, so `<<` wins over `<` and `::` over `:`. */
const PUNCTUATORS = [
    '::', '!=', '==', '>>', '<<', '>=', '<=', '&&', '||',
    '+', '-', '*', '/', '%', '&', '|', '^', '!', '=',
    '(', ')', '{', '}', '[', ']', ',', '.', ':', ';', '#'
];

const NUMBER_RE = /^(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:[us](?:8|16|32|64))?/;
const IDENT_RE = /^[a-zA-Z_][a-zA-Z0-9_]*/;

/**
 * @typedef {object} Token
 * @property {'ws'|'newline'|'comment'|'string'|'number'|'ident'|'keyword'|'type'|'punct'|'unknown'} kind
 * @property {string} text   the source text, verbatim
 * @property {number} start  index into the source
 * @property {number} end    index into the source, exclusive
 * @property {number} line   0-based line of `start`
 * @property {boolean} [block]  comment only: true for a block comment
 */

/**
 * Tokenize a bhe source. Every byte of the input ends up in exactly one token,
 * so `tokens.map(t => t.text).join('')` reproduces the source.
 *
 * @param {string} src
 * @returns {Token[]}
 */
function tokenize(src) {
    /** @type {Token[]} */
    const tokens = [];
    let i = 0;
    let line = 0;

    const push = (kind, start, end, extra) => {
        const text = src.slice(start, end);
        tokens.push({ kind, text, start, end, line, ...extra });
        /* A token may span lines: strings and block comments do. */
        for (let k = 0; k < text.length; k++) {
            if (text.charCodeAt(k) === 10 /* \n */) line++;
        }
    };

    while (i < src.length) {
        const c = src[i];

        if (c === '\n') {
            push('newline', i, i + 1);
            i += 1;
            continue;
        }
        if (c === ' ' || c === '\t' || c === '\r') {
            let j = i;
            while (j < src.length && (src[j] === ' ' || src[j] === '\t' || src[j] === '\r')) j++;
            push('ws', i, j);
            i = j;
            continue;
        }
        if (c === '/' && src[i + 1] === '/') {
            let j = i;
            while (j < src.length && src[j] !== '\n') j++;
            push('comment', i, j, { block: false });
            i = j;
            continue;
        }
        if (c === '/' && src[i + 1] === '*') {
            const close = src.indexOf('*/', i + 2);
            const j = close === -1 ? src.length : close + 2;
            push('comment', i, j, { block: true });
            i = j;
            continue;
        }
        if (c === '"') {
            /* No escape for the delimiter: the next `"` ends the string. */
            const close = src.indexOf('"', i + 1);
            const j = close === -1 ? src.length : close + 1;
            push('string', i, j);
            i = j;
            continue;
        }
        if (c >= '0' && c <= '9') {
            const m = NUMBER_RE.exec(src.slice(i));
            push('number', i, i + m[0].length);
            i += m[0].length;
            continue;
        }
        if (/[a-zA-Z_]/.test(c)) {
            const m = IDENT_RE.exec(src.slice(i));
            const word = m[0];
            const kind = KEYWORD_SET.has(word) ? 'keyword' : TYPE_SET.has(word) ? 'type' : 'ident';
            push(kind, i, i + word.length);
            i += word.length;
            continue;
        }

        const punct = PUNCTUATORS.find((p) => src.startsWith(p, i));
        if (punct) {
            push('punct', i, i + punct.length);
            i += punct.length;
            continue;
        }

        push('unknown', i, i + 1);
        i += 1;
    }

    return tokens;
}

/** True for tokens that carry no meaning for the grammar. */
function isTrivia(tok) {
    return tok.kind === 'ws' || tok.kind === 'newline' || tok.kind === 'comment';
}

module.exports = { tokenize, isTrivia };
