// Copyright (c) 2022-2026, bageyelet

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { tokenize } = require('../src/lexer');

const kinds = (src) => tokenize(src).filter((t) => t.kind !== 'ws').map((t) => `${t.kind}:${t.text}`);

test('round-trips the source exactly', () => {
    const src = 'struct s_t\n{\n    u32 a;   // note\n    char b[4];\n}\n';
    assert.strictEqual(tokenize(src).map((t) => t.text).join(''), src);
});

test('tells keywords, builtin types and identifiers apart', () => {
    assert.deepStrictEqual(kinds('local u32 name'), ['keyword:local', 'type:u32', 'ident:name']);
});

test('reads the size and sign suffixes of integer literals', () => {
    assert.deepStrictEqual(kinds('42s8 16u8 0xffffu32 1099511627537u64 0x10'), [
        'number:42s8',
        'number:16u8',
        'number:0xffffu32',
        'number:1099511627537u64',
        'number:0x10'
    ]);
});

test('a string ends at the next quote: there is no escape for the delimiter', () => {
    /* mirrors the flex rule `"[^"]*"` */
    assert.deepStrictEqual(kinds('"a\\"b"'), ['string:"a\\"', 'ident:b', 'string:"']);
});

test('keeps a // inside a string out of the comment', () => {
    assert.deepStrictEqual(kinds('print("a//b");'), [
        'ident:print',
        'punct:(',
        'string:"a//b"',
        'punct:)',
        'punct:;'
    ]);
});

test('reads both comment forms', () => {
    assert.deepStrictEqual(kinds('// one\n/* two */'), ['comment:// one', 'newline:\n', 'comment:/* two */']);
});

test('an unterminated string or comment runs to the end of the input', () => {
    assert.deepStrictEqual(kinds('"abc'), ['string:"abc']);
    assert.deepStrictEqual(kinds('/* abc'), ['comment:/* abc']);
});

test('reads the longest punctuator', () => {
    assert.deepStrictEqual(kinds('a::b << c >= d != e && f'), [
        'ident:a',
        'punct:::',
        'ident:b',
        'punct:<<',
        'ident:c',
        'punct:>=',
        'ident:d',
        'punct:!=',
        'ident:e',
        'punct:&&',
        'ident:f'
    ]);
});

test('reads the cross-file type operator', () => {
    assert.deepStrictEqual(kinds('other#Struct v;'), [
        'ident:other',
        'punct:#',
        'ident:Struct',
        'ident:v',
        'punct:;'
    ]);
});

test('tracks the line of a token across a multi-line one', () => {
    const toks = tokenize('a\n/* x\ny */\nb');
    assert.strictEqual(toks[toks.length - 1].text, 'b');
    assert.strictEqual(toks[toks.length - 1].line, 3);
});
