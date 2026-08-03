// Copyright (c) 2022-2026, bageyelet

/*  format.js
 *  Formatter for the "bhe" language.
 *
 *  It works on the token stream rather than on raw lines, which is what keeps
 *  it from ever rewriting the inside of a string or a comment — the previous
 *  line-and-regex implementation turned `crc("CRC-32/ISO-HDLC")` into
 *  `crc("CRC - 32 / ISO - HDLC")` and silently broke the template.
 *
 *  The style it produces is the one the templates shipped with bhex are
 *  written in:
 *
 *    - four spaces per block, `{` on its own line after a declaration and on
 *      the same line after `if`/`elif`/`else`/`while`;
 *    - a wrapped line lines up under the first bracket still open above it,
 *      or under the right-hand side of the assignment it continues;
 *    - runs of consecutive declarations line their names up in a column, and
 *      so do the `=` of consecutive enum members.
 *
 *  Spacing inside a line is only ever *added*, never collapsed, so hand-made
 *  alignment (the comment columns in mp3.bhe, say) survives a format.
 */

'use strict';

const { tokenize } = require('./lexer');

const DEFAULT_OPTIONS = {
    tabSize: 4,
    alignDeclarations: true,
    alignEnumMembers: true
};

const DECL_KEYWORDS = new Set(['struct', 'enum', 'orenum', 'fn', 'proc']);
const CONTROL_KEYWORDS = new Set(['if', 'elif', 'else', 'while']);
const ENUM_KEYWORDS = new Set(['enum', 'orenum']);

/* Operators that bind their operand tightly: no space is ever added after. */
const UNARY_OPERATORS = new Set(['-', '+', '!']);

/* Never spaced, on either side. */
const TIGHT_PUNCT = new Set(['.', '::', '#']);

/**
 * @param {string} src
 * @param {Partial<typeof DEFAULT_OPTIONS>} [options]
 * @returns {string} the formatted source, LF terminated, always ending in a
 *                   single newline
 */
function formatBhe(src, options) {
    const opts = { ...DEFAULT_OPTIONS, ...options };
    const lines = layout(reflowBraces(toLines(src.replace(/\r\n/g, '\n'))), opts);
    align(lines, opts);

    const out = lines
        .map((l) => l.text.replace(/[ \t]+$/, ''))
        .join('\n')
        .replace(/\n+$/, '');
    return out === '' ? '' : out + '\n';
}

/* -------------------------------------------------------------------------
 *  Step 1 - group the token stream into lines
 * ---------------------------------------------------------------------- */

/**
 * A line holds its tokens — comments included, so one written in the middle of
 * a line stays where it was — each with the whitespace that preceded it.
 *
 * `verbatim` lines are the ones a multi-line token (a block comment, a string
 * with a newline in it) reaches into: they are copied out untouched, because
 * there is no safe way to re-indent them.
 *
 * @typedef {object} Line
 * @property {{tok: import('./lexer').Token, gap: string}[]} items
 * @property {string} lead   the original indentation
 * @property {boolean} verbatim
 * @property {string} raw    original text, without the line terminator
 */

/** @returns {Line[]} */
function toLines(src) {
    /** @type {Line[]} */
    const lines = src.split('\n').map((raw) => ({ items: [], lead: '', verbatim: false, raw }));

    let gap = '';
    for (const tok of tokenize(src)) {
        if (tok.kind === 'newline') {
            gap = '';
            continue;
        }
        if (tok.kind === 'ws') {
            gap += tok.text;
            continue;
        }

        if (tok.text.includes('\n')) {
            /* Mark every line the token touches; they are emitted as they are. */
            const span = (tok.text.match(/\n/g) || []).length;
            for (let l = tok.line; l <= tok.line + span && l < lines.length; l++) lines[l].verbatim = true;
            gap = '';
            continue;
        }

        const line = lines[tok.line];
        if (line.items.length === 0) {
            line.lead = gap;
            line.items.push({ tok, gap: '' });
        } else {
            line.items.push({ tok, gap });
        }
        gap = '';
    }

    return lines;
}

const isComment = (it) => it.tok.kind === 'comment';
const codeItems = (line) => line.items.filter((it) => !isComment(it));
const codeTokens = (line) => codeItems(line).map((it) => it.tok);
const isBlank = (line) => line.items.length === 0 && !line.verbatim;

/* -------------------------------------------------------------------------
 *  Step 2 - brace placement
 * ---------------------------------------------------------------------- */

/**
 * `struct`/`enum`/`fn`/`proc` want their `{` on the next line, control flow
 * wants it on the same one. A declaration whose body closes on the same line
 * (mp3.bhe's one-line accessors) is left alone.
 *
 * @param {Line[]} lines
 * @returns {Line[]}
 */
function reflowBraces(lines) {
    /** @type {Line[]} */
    const out = [];

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const toks = codeTokens(line);
        if (line.verbatim || toks.length === 0) {
            out.push(line);
            continue;
        }

        /* A lone `{` joins the control-flow line above it. */
        if (toks.length === 1 && toks[0].text === '{') {
            const prev = lastCodeLine(out);
            if (prev && startsControlFlow(codeTokens(prev)) && !codeTokens(prev).some((t) => t.text === '{')) {
                for (const it of line.items) prev.items.push({ ...it, gap: it.gap || ' ' });
                continue;
            }
        }

        /* A lone `}` takes the `else`/`elif` that follows it. */
        if (line.items.length === 1 && toks[0].text === '}') {
            const next = nextCodeLine(lines, i + 1);
            if (next && ['else', 'elif'].includes(codeTokens(next)[0].text)) {
                next.items.unshift({ tok: toks[0], gap: '' });
                next.items[1].gap = ' ';
                continue;
            }
        }

        /* A declaration's `{` moves to a line of its own, unless the body
         * closes on this same line. */
        if (DECL_KEYWORDS.has(toks[0].text)) {
            const braceAt = line.items.findIndex((it) => it.tok.text === '{');
            if (braceAt > 0 && !toks.some((t) => t.text === '}')) {
                const tail = line.items.slice(braceAt);
                /* whatever trails the `{` on the original line goes with it */
                out.push({ ...line, items: line.items.slice(0, braceAt) });
                out.push({
                    items: tail.map((it, k) => (k === 0 ? { ...it, gap: '' } : it)),
                    lead: '',
                    verbatim: false,
                    raw: ''
                });
                continue;
            }
        }

        out.push(line);
    }

    return out;
}

function lastCodeLine(lines) {
    for (let i = lines.length - 1; i >= 0; i--) {
        if (lines[i].verbatim) return null;
        if (codeTokens(lines[i]).length > 0) return lines[i];
    }
    return null;
}

function nextCodeLine(lines, from) {
    for (let i = from; i < lines.length; i++) {
        if (lines[i].verbatim) return null;
        if (codeTokens(lines[i]).length > 0) return lines[i];
    }
    return null;
}

function startsControlFlow(toks) {
    if (CONTROL_KEYWORDS.has(toks[0].text)) return true;
    /* `} else`, `} elif (...)` */
    return toks[0].text === '}' && toks.length > 1 && CONTROL_KEYWORDS.has(toks[1].text);
}

/* -------------------------------------------------------------------------
 *  Step 3 - indentation and intra-line spacing
 * ---------------------------------------------------------------------- */

/**
 * Renders every line, taking its indent from the block depth, from the
 * brackets still open above it, and from the assignment it continues. Each
 * line also records the output column of each of its code tokens, which is
 * what the alignment step works on.
 *
 * @param {Line[]} lines
 * @returns {(Line & {text: string, indent: number, codeCols: number[], blockKind: string, endComment: number|null})[]}
 */
function layout(lines, opts) {
    const unit = opts.tabSize;

    let depth = 0;
    /** brackets left open above: content column, and the indent of their line */
    const open = [];
    /** the kind of every block we are inside, so enum bodies can be told apart */
    const blocks = [];
    let pendingBlock = 'block';
    /** the column a wrapped line lines up under when no bracket is open */
    let continuationCol = null;
    let inStatement = false;
    /** column of the trailing comment of the line above, for comment blocks */
    let prevEndComment = null;

    const out = [];
    const blockKind = () => blocks[blocks.length - 1] || 'top';
    const emit = (line, text, indent, codeCols, endComment) => {
        out.push({ ...line, text, indent, codeCols, blockKind: blockKind(), endComment });
        prevEndComment = endComment;
    };

    for (const line of lines) {
        if (line.verbatim) {
            /* Still count the braces, so what follows stays aligned. */
            for (const t of codeTokens(line)) {
                if (t.text === '{') depth++;
                else if (t.text === '}') depth = Math.max(0, depth - 1);
            }
            emit(line, line.raw, 0, [], null);
            continue;
        }
        if (isBlank(line)) {
            emit(line, '', 0, [], null);
            continue;
        }

        const toks = codeTokens(line);

        /* --- pick the indent ------------------------------------------- */
        let indent;
        if (open.length > 0) {
            /* Line up under the innermost bracket that is still open; a line
             * that starts by closing it goes back to that bracket's indent. */
            const inner = open[open.length - 1];
            const closesInner = toks[0] && (toks[0].text === ')' || toks[0].text === ']');
            indent = closesInner ? inner.indent : inner.col;
        } else if (inStatement && continuationCol !== null) {
            indent = continuationCol;
        } else {
            let leadingCloses = 0;
            while (leadingCloses < toks.length && toks[leadingCloses].text === '}') leadingCloses++;
            indent = Math.max(0, depth - leadingCloses) * unit;
        }

        /* A comment on a line of its own is placed, but changes nothing. It
         * stays where it was when it continues the comment column of the line
         * above, which is how a wrapped remark is written. */
        if (toks.length === 0) {
            const col = expandTabs(line.lead, unit).length;
            emit(line, ' '.repeat(prevEndComment === col ? col : indent) + line.items[0].tok.text, indent, [], prevEndComment === col ? col : null);
            continue;
        }

        /* --- render ------------------------------------------------------ */
        const startsStatement = !inStatement && open.length === 0;
        let text = ' '.repeat(indent);
        let bracketDepth = 0;
        let assignRhsCol = null;
        let endComment = null;
        const codeCols = [];

        for (let k = 0; k < line.items.length; k++) {
            const { tok, gap } = line.items[k];
            if (k > 0) {
                const prev = line.items[k - 1].tok;
                text += gap !== '' ? expandTabs(gap, unit) : needsSpace(prev, tok, line.items, k) ? ' ' : '';
            }

            if (tok.kind === 'comment') {
                /* only the last token on the line anchors a comment column */
                endComment = k === line.items.length - 1 ? text.length : null;
                text += tok.text;
                continue;
            }

            codeCols.push(text.length);
            text += tok.text;

            switch (tok.text) {
                case '(':
                case '[':
                    open.push({ col: text.length, indent });
                    bracketDepth++;
                    break;
                case ')':
                case ']':
                    open.pop();
                    bracketDepth--;
                    break;
                case '{':
                    blocks.push(pendingBlock);
                    pendingBlock = 'block';
                    depth++;
                    break;
                case '}':
                    blocks.pop();
                    depth = Math.max(0, depth - 1);
                    break;
                case '=':
                    if (bracketDepth === 0 && assignRhsCol === null && startsStatement) assignRhsCol = text.length + 1;
                    break;
                default:
                    break;
            }
        }

        /* --- remember what this line leaves open ------------------------- */
        if (ENUM_KEYWORDS.has(toks[0].text)) pendingBlock = 'enum';
        else if (DECL_KEYWORDS.has(toks[0].text)) pendingBlock = 'block';

        /* A declaration header is complete on its own: the `{` that opens its
         * body lives on the next line and belongs to the enclosing block, not
         * to a wrapped expression. An enum body holds nothing but members, and
         * its last one carries no separator at all. */
        const last = toks[toks.length - 1].text;
        const terminated =
            open.length === 0 &&
            (last === ';' ||
                last === '{' ||
                last === '}' ||
                last === ',' ||
                blockKind() === 'enum' ||
                DECL_KEYWORDS.has(toks[0].text));

        if (startsStatement) continuationCol = assignRhsCol !== null ? assignRhsCol : indent + unit;
        inStatement = !terminated;

        emit(line, text, indent, codeCols, endComment);
    }

    return out;
}

const expandTabs = (ws, unit) => ws.replace(/\t/g, ' '.repeat(unit));

/**
 * Whether a space has to be inserted between two adjacent tokens that were
 * written without one. This only ever adds; existing whitespace is kept as is.
 */
function needsSpace(prev, cur, items, index) {
    if (prev.text === '(' || prev.text === '[') return false;
    if (cur.text === ')' || cur.text === ']' || cur.text === ',' || cur.text === ';') return false;
    if (TIGHT_PUNCT.has(prev.text) || TIGHT_PUNCT.has(cur.text)) return false;
    if (prev.kind === 'comment' || cur.kind === 'comment') return true;
    if (isUnary(items, index - 1)) return false;

    if (cur.text === '(' || cur.text === '[') {
        if (prev.kind === 'keyword') return true;
        if (prev.kind === 'punct') return prev.text !== ')' && prev.text !== ']';
        return false; /* a call, or an index */
    }
    return true;
}

/** Is the operator at `items[i]` a unary one? */
function isUnary(items, i) {
    const tok = items[i] && items[i].tok;
    if (!tok || tok.kind !== 'punct' || !UNARY_OPERATORS.has(tok.text)) return false;
    if (tok.text === '!') return true;

    /* Look past a comment: `a /* c *\/ - b` is still a subtraction. */
    let j = i - 1;
    while (j >= 0 && items[j].tok.kind === 'comment') j--;
    const before = items[j] && items[j].tok;
    if (!before) return true;
    if (['ident', 'type', 'number', 'string'].includes(before.kind)) return false;
    return before.text !== ')' && before.text !== ']';
}

/* -------------------------------------------------------------------------
 *  Step 4 - column alignment
 * ---------------------------------------------------------------------- */

/**
 * Lines up consecutive declarations and enum members. Only whole single-line
 * statements take part, so alignment can never move a bracket that a wrapped
 * line below has already been aligned under.
 */
function align(lines, opts) {
    const infos = lines.map((l) => classify(l));

    for (let i = 0; i < lines.length; ) {
        const info = infos[i];
        if (!info) {
            i++;
            continue;
        }

        let j = i + 1;
        while (j < lines.length && infos[j] && infos[j].family === info.family && infos[j].indent === info.indent) j++;

        const run = [];
        for (let k = i; k < j; k++) run.push({ line: lines[k], info: infos[k] });
        alignOn(run, info.family === 'enum' ? opts.alignEnumMembers : opts.alignDeclarations);

        i = j;
    }
}

/** Pads every line of `run` so its recorded token starts in the same column. */
function alignOn(run, enabled) {
    if (!enabled || run.length < 2) return;

    const target = Math.max(...run.map((r) => r.info.pos));
    for (const { line, info } of run) {
        const pad = target - info.pos;
        if (pad <= 0) continue;
        line.text = line.text.slice(0, info.pos) + ' '.repeat(pad) + line.text.slice(info.pos);
        info.pos = target;
    }
}

/**
 * Recognises the statement shapes that take part in alignment, and records the
 * output column of the token that has to line up.
 *
 * File-variable declarations line their names up, so `u32` and `char` share a
 * type column. `local` declarations line up among themselves: padding a
 * keyword out to a type column reads wrong, and would make one added local
 * reflow a whole struct. A run is a maximal group of lines of the same family
 * at the same indent, so anything else between them starts a new column.
 *
 * @returns {{family: string, indent: number, pos: number}|null}
 */
function classify(line) {
    if (line.verbatim) return null;

    const toks = codeTokens(line);
    if (toks.length === 0) return null;
    const last = toks[toks.length - 1];

    /* --- enum member: NAME = NUMBER [,] ---------------------------------- */
    if (line.blockKind === 'enum') {
        const body = last.text === ',' ? toks.slice(0, -1) : toks;
        if (body.length === 3 && body[0].kind === 'ident' && body[1].text === '=' && body[2].kind === 'number') {
            return { family: 'enum', indent: line.indent, pos: line.codeCols[1] };
        }
        return null;
    }

    /* --- statements: everything else has to end in `;` ------------------- */
    if (last.text !== ';') return null;
    const body = toks.slice(0, -1);
    if (body.length === 0 || body.some((t) => t.text === '{' || t.text === '}')) return null;

    /* `local NAME = expr;` */
    if (body[0].text === 'local') {
        if (body[1] === undefined || body[1].kind !== 'ident') return null;
        return { family: 'local', indent: line.indent, pos: line.codeCols[1] };
    }

    /* `TYPE NAME;`, `TYPE NAME[expr];`, `other#TYPE NAME;` — a file variable */
    const nameIndex = fileVarNameIndex(body);
    if (nameIndex !== -1) return { family: 'filevar', indent: line.indent, pos: line.codeCols[nameIndex] };

    return null;
}

/**
 * For a file-variable declaration, the index of the variable name; -1 when the
 * statement is not one.
 */
function fileVarNameIndex(body) {
    let i = 0;
    if (!body[i] || (body[i].kind !== 'type' && body[i].kind !== 'ident')) return -1;
    i++;
    if (body[i] && body[i].text === '#') {
        i++;
        if (!body[i] || (body[i].kind !== 'ident' && body[i].kind !== 'type')) return -1;
        i++;
    }

    const nameIndex = i;
    if (!body[nameIndex] || body[nameIndex].kind !== 'ident') return -1;
    i++;
    if (i === body.length) return nameIndex;
    if (body[i].text === '[' && body[body.length - 1].text === ']') return nameIndex;
    return -1;
}

module.exports = { formatBhe, DEFAULT_OPTIONS };
