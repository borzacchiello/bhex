// Copyright (c) 2022-2026, bageyelet

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { formatBhe } = require('../src/format');

const TEMPLATES = path.join(__dirname, '..', '..', 'templates');

const fmt = (src) => formatBhe(src);

test('leaves the inside of a string alone', () => {
    const src = 'proc\n{\n    local x = crc("CRC-32/ISO-HDLC", 4);\n}\n';
    assert.match(fmt(src), /"CRC-32\/ISO-HDLC"/);
});

test('does not treat a // inside a string as a comment', () => {
    const src = 'proc\n{\n    print("http://example.com/a-b");\n}\n';
    assert.match(fmt(src), /"http:\/\/example\.com\/a-b"/);
});

test('leaves the inside of a comment alone', () => {
    const src = 'proc\n{\n    seek(0);   // rebase->bind, 1+2\n}\n';
    assert.match(fmt(src), /\/\/ rebase->bind, 1\+2/);
});

test('keeps a comment written in the middle of a line where it was', () => {
    const src = 'proc\n{\n    if (find(magic, 1 /* backward */)) {\n        seek(0);\n    }\n}\n';
    assert.match(fmt(src), /find\(magic, 1 \/\* backward \*\/\)/);
});

test('adds the missing spaces around operators', () => {
    const src = 'proc\n{\n    local a = 1+2*3;\n}\n';
    assert.match(fmt(src), /local a = 1 \+ 2 \* 3;/);
});

test('does not space a unary minus away from its operand', () => {
    const src = 'proc\n{\n    local a = crc("X", 4, -(len + 8));\n    local b = peek_u32(-4);\n    local c = 1 - 2;\n}\n';
    const out = fmt(src);
    assert.match(out, /-\(len \+ 8\)/);
    assert.match(out, /peek_u32\(-4\)/);
    assert.match(out, /1 - 2/);
});

test('never collapses existing spacing', () => {
    const src = 'struct s_t\n{\n    u32   a;\n    u32   b;   // kept\n}\n';
    assert.strictEqual(fmt(src), src);
});

test('puts a declaration brace on its own line', () => {
    assert.strictEqual(fmt('struct s_t {\n    u8 a;\n}\n'), 'struct s_t\n{\n    u8 a;\n}\n');
});

test('keeps a one-line declaration on one line', () => {
    const src = 'fn version_bits(h)   { result = (h >> 19) & 3; }\n';
    assert.strictEqual(fmt(src), src);
});

test('pulls a lone brace up onto the control-flow line', () => {
    const src = 'proc\n{\n    if (a)\n    {\n        seek(0);\n    }\n}\n';
    assert.match(fmt(src), /^ {4}if \(a\) \{$/m);
});

test('joins a closing brace with the else that follows it', () => {
    const src = 'proc\n{\n    if (a) {\n        seek(0);\n    }\n    else {\n        seek(1);\n    }\n}\n';
    assert.match(fmt(src), /^ {4}\} else \{$/m);
});

test('indents by four spaces per block', () => {
    const src = 'struct s_t\n{\nif (a) {\nwhile (b) {\nu8 x;\n}\n}\n}\n';
    assert.strictEqual(fmt(src), 'struct s_t\n{\n    if (a) {\n        while (b) {\n            u8 x;\n        }\n    }\n}\n');
});

test('lines a wrapped expression up under the open bracket', () => {
    const src = 'proc\n{\n    assert(box_size >= 16 && start <= size(),\n"malformed");\n}\n';
    assert.match(fmt(src), /^ {11}"malformed"\);$/m);
});

test('lines a wrapped assignment up under its right-hand side', () => {
    const src = 'fn f()\n{\n    result = checksum("SUM-32", 148, 0) +\nchecksum("SUM-32", 4, 156);\n}\n';
    assert.match(fmt(src), /^ {13}checksum\("SUM-32", 4, 156\);$/m);
});

test('lines the names of consecutive field declarations up', () => {
    const src = 'struct s_t\n{\nchar id[4];\nu16 version;\nu8 flags;\n}\n';
    assert.strictEqual(fmt(src), 'struct s_t\n{\n    char id[4];\n    u16  version;\n    u8   flags;\n}\n');
});

test('does not pad a file-variable column out to a local', () => {
    const src = 'struct s_t\n{\nu16 a;\nu8 b;\nlocal c = 1;\n}\n';
    assert.strictEqual(fmt(src), 'struct s_t\n{\n    u16 a;\n    u8  b;\n    local c = 1;\n}\n');
});

test('lines the = of consecutive enum members up', () => {
    const src = 'enum e_t : u8\n{\nA = 0x01,\nBCD = 0x02\n}\n';
    assert.strictEqual(fmt(src), 'enum e_t : u8\n{\n    A   = 0x01,\n    BCD = 0x02\n}\n');
});

test('does not align an expression that merely looks like an enum body', () => {
    const src = 'fn f(type)\n{\n    result = (type == "moov" ||\n              type == "trak");\n}\n';
    assert.strictEqual(fmt(src), src);
});

test('strips trailing whitespace and normalises the final newline', () => {
    assert.strictEqual(fmt('proc\n{\n    seek(0);   \n}\n\n\n'), 'proc\n{\n    seek(0);\n}\n');
});

test('leaves a block comment that spans lines untouched', () => {
    const src = 'proc\n{\n    /* one\n       two */\n    seek(0);\n}\n';
    assert.match(fmt(src), /\/\* one\n {7}two \*\//);
});

test('handles an empty document', () => {
    assert.strictEqual(fmt(''), '');
    assert.strictEqual(fmt('\n\n'), '');
});

test('converts CRLF to LF', () => {
    assert.strictEqual(fmt('proc\r\n{\r\n    seek(0);\r\n}\r\n'), 'proc\n{\n    seek(0);\n}\n');
});

/* ---------------------------------------------------------------------
 *  Against the templates shipped with bhex: the formatter must be stable
 *  and must never lose a byte of code.
 * ------------------------------------------------------------------ */

const templates = fs.existsSync(TEMPLATES) ? fs.readdirSync(TEMPLATES).filter((f) => f.endsWith('.bhe')) : [];

test('the shipped templates are available to test against', () => {
    assert.ok(templates.length > 0, `no .bhe templates found in ${TEMPLATES}`);
});

for (const name of templates) {
    const src = fs.readFileSync(path.join(TEMPLATES, name), 'utf8');

    test(`${name}: formatting is idempotent`, () => {
        const once = fmt(src);
        assert.strictEqual(fmt(once), once);
    });

    test(`${name}: formatting preserves every token`, () => {
        const { tokenize } = require('../src/lexer');
        const significant = (text) =>
            tokenize(text)
                .filter((t) => !['ws', 'newline'].includes(t.kind))
                .map((t) => t.text);
        assert.deepStrictEqual(significant(fmt(src)), significant(src));
    });
}
