// Copyright (c) 2022-2026, bageyelet

/*  symbols.js
 *  Extracts the declarations of a bhe source: what feeds the outline, the
 *  breadcrumbs and the "go to symbol" list.
 *
 *  Returns plain objects with 0-based positions, so it can be unit tested
 *  without the editor; extension.js maps them onto vscode.DocumentSymbol.
 */

'use strict';

const { tokenize, isTrivia } = require('./lexer');
const { SPECIAL_PROCS } = require('./language');

/**
 * @typedef {object} Symbol
 * @property {string} name
 * @property {'struct'|'enum'|'function'|'proc'|'field'|'enumMember'} kind
 * @property {string} detail       short annotation shown next to the name
 * @property {{line: number, character: number}} start   of the whole declaration
 * @property {{line: number, character: number}} end
 * @property {{line: number, character: number}} selectionStart  of the name alone
 * @property {{line: number, character: number}} selectionEnd
 * @property {Symbol[]} children
 */

/**
 * @param {string} src
 * @returns {Symbol[]}
 */
function documentSymbols(src) {
    const lineStarts = computeLineStarts(src);
    const toks = tokenize(src).filter((t) => !isTrivia(t));
    const pos = (offset) => {
        const line = lineOf(lineStarts, offset);
        return { line, character: offset - lineStarts[line] };
    };

    /** @type {Symbol[]} */
    const out = [];
    let i = 0;

    while (i < toks.length) {
        const tok = toks[i];

        if (tok.kind === 'keyword' && ['struct', 'enum', 'orenum', 'fn', 'proc'].includes(tok.text)) {
            const decl = readDeclaration(toks, i, tok.text);
            if (decl) {
                const bodyEnd = matchingBrace(toks, decl.braceIndex);
                const endTok = bodyEnd === -1 ? toks[toks.length - 1] : toks[bodyEnd];

                out.push({
                    name: decl.name,
                    kind: decl.kind,
                    detail: decl.detail,
                    start: pos(tok.start),
                    end: pos(endTok.end),
                    selectionStart: pos(decl.nameTok ? decl.nameTok.start : tok.start),
                    selectionEnd: pos(decl.nameTok ? decl.nameTok.end : tok.end),
                    children:
                        decl.kind === 'enum'
                            ? enumMembers(toks, decl.braceIndex, bodyEnd, pos)
                            : decl.kind === 'struct'
                              ? structFields(toks, decl.braceIndex, bodyEnd, pos)
                              : []
                });

                i = bodyEnd === -1 ? toks.length : bodyEnd + 1;
                continue;
            }
        }

        i++;
    }

    return out;
}

/** Reads a declaration header, returning where its `{` is. */
function readDeclaration(toks, i, keyword) {
    const nameTok = toks[i + 1] && toks[i + 1].kind === 'ident' ? toks[i + 1] : null;

    if (keyword === 'fn') {
        if (!nameTok) return null;
        const params = readParams(toks, i + 2);
        const braceIndex = indexOfBrace(toks, i);
        if (braceIndex === -1) return null;
        return { name: nameTok.text, nameTok, kind: 'function', detail: `(${params.join(', ')})`, braceIndex };
    }

    if (keyword === 'proc') {
        const braceIndex = indexOfBrace(toks, i);
        if (braceIndex === -1) return null;
        const name = nameTok ? nameTok.text : 'proc';
        const detail = !nameTok
            ? 'entry point'
            : SPECIAL_PROCS.includes(name)
              ? 'id scan'
              : 'named proc';
        return { name, nameTok, kind: 'proc', detail, braceIndex };
    }

    if (!nameTok) return null;

    if (keyword === 'struct') {
        const braceIndex = indexOfBrace(toks, i);
        if (braceIndex === -1) return null;
        return { name: nameTok.text, nameTok, kind: 'struct', detail: '', braceIndex };
    }

    /* enum / orenum: `NAME : TYPE {` */
    const backing = toks[i + 2] && toks[i + 2].text === ':' && toks[i + 3] ? toks[i + 3].text : '';
    const braceIndex = indexOfBrace(toks, i);
    if (braceIndex === -1) return null;
    return {
        name: nameTok.text,
        nameTok,
        kind: 'enum',
        detail: [keyword === 'orenum' ? 'flags' : '', backing].filter(Boolean).join(' '),
        braceIndex
    };
}

function readParams(toks, i) {
    if (!toks[i] || toks[i].text !== '(') return [];
    const params = [];
    for (let k = i + 1; k < toks.length && toks[k].text !== ')'; k++) {
        if (toks[k].kind === 'ident') params.push(toks[k].text);
    }
    return params;
}

/** The `{` that opens the body of the declaration starting at `i`. */
function indexOfBrace(toks, i) {
    for (let k = i + 1; k < toks.length; k++) {
        if (toks[k].text === '{') return k;
        /* another declaration started: this one has no body */
        if (toks[k].kind === 'keyword' && ['struct', 'enum', 'orenum', 'fn', 'proc'].includes(toks[k].text)) return -1;
    }
    return -1;
}

function matchingBrace(toks, braceIndex) {
    let depth = 0;
    for (let k = braceIndex; k < toks.length; k++) {
        if (toks[k].text === '{') depth++;
        else if (toks[k].text === '}' && --depth === 0) return k;
    }
    return -1;
}

/** `NAME = NUMBER` members of an enum body. */
function enumMembers(toks, braceIndex, endIndex, pos) {
    const out = [];
    const last = endIndex === -1 ? toks.length : endIndex;
    for (let k = braceIndex + 1; k < last; k++) {
        if (toks[k].kind === 'ident' && toks[k + 1] && toks[k + 1].text === '=' && toks[k + 2]) {
            out.push({
                name: toks[k].text,
                kind: 'enumMember',
                detail: toks[k + 2].text,
                start: pos(toks[k].start),
                end: pos(toks[k + 2].end),
                selectionStart: pos(toks[k].start),
                selectionEnd: pos(toks[k].end),
                children: []
            });
        }
    }
    return out;
}

/**
 * File-variable declarations directly inside a struct body: `u32 length;`,
 * `char type[4];`. Locals are left out, and so is anything nested in an `if` or
 * a `while` — the outline is meant to show the fixed shape of the format, not
 * every statement that may or may not run.
 */
function structFields(toks, braceIndex, endIndex, pos) {
    const out = [];
    const last = endIndex === -1 ? toks.length : endIndex;
    let nesting = 0;

    for (let k = braceIndex + 1; k < last; k++) {
        const type = toks[k];
        if (type.text === '{') {
            nesting++;
            continue;
        }
        if (type.text === '}') {
            nesting = Math.max(0, nesting - 1);
            continue;
        }
        if (nesting > 0) continue;
        if (type.kind !== 'type' && type.kind !== 'ident') continue;

        /* `other#Struct name` counts too */
        let n = k + 1;
        let typeText = type.text;
        if (toks[n] && toks[n].text === '#' && toks[n + 1]) {
            typeText += '#' + toks[n + 1].text;
            n += 2;
        }

        const name = toks[n];
        if (!name || name.kind !== 'ident') continue;

        const after = toks[n + 1];
        if (!after) continue;

        if (after.text === ';') {
            out.push(field(typeText, name, name, pos));
            k = n + 1;
        } else if (after.text === '[') {
            const close = matchingBracket(toks, n + 1);
            if (close === -1 || !toks[close + 1] || toks[close + 1].text !== ';') continue;
            const size = toks
                .slice(n + 2, close)
                .map((t) => t.text)
                .join('');
            out.push(field(`${typeText}[${size}]`, name, toks[close + 1], pos));
            k = close + 1;
        }
    }

    return out;
}

function field(detail, nameTok, endTok, pos) {
    return {
        name: nameTok.text,
        kind: 'field',
        detail,
        start: pos(nameTok.start),
        end: pos(endTok.end),
        selectionStart: pos(nameTok.start),
        selectionEnd: pos(nameTok.end),
        children: []
    };
}

function matchingBracket(toks, openIndex) {
    let depth = 0;
    for (let k = openIndex; k < toks.length; k++) {
        if (toks[k].text === '[') depth++;
        else if (toks[k].text === ']' && --depth === 0) return k;
    }
    return -1;
}

function computeLineStarts(src) {
    const starts = [0];
    for (let i = 0; i < src.length; i++) if (src[i] === '\n') starts.push(i + 1);
    return starts;
}

function lineOf(starts, offset) {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid] <= offset) lo = mid;
        else hi = mid - 1;
    }
    return lo;
}

module.exports = { documentSymbols };
