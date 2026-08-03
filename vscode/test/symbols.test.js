// Copyright (c) 2022-2026, bageyelet

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { documentSymbols } = require('../src/symbols');

test('finds a struct and its fields', () => {
    const src = 'struct chunk_t\n{\n    u32  length;\n    char type[4];\n    u8   data[length];\n}\n';
    const [s] = documentSymbols(src);

    assert.strictEqual(s.name, 'chunk_t');
    assert.strictEqual(s.kind, 'struct');
    assert.deepStrictEqual(
        s.children.map((c) => [c.name, c.detail]),
        [
            ['length', 'u32'],
            ['type', 'char[4]'],
            ['data', 'u8[length]']
        ]
    );
});

test('leaves locals and control flow out of a struct outline', () => {
    const src = 'struct s_t\n{\n    local n = off();\n    if (n > 0) {\n        u8 a;\n    }\n    u32 b;\n}\n';
    const [s] = documentSymbols(src);
    assert.deepStrictEqual(s.children.map((c) => c.name), ['b']);
});

test('finds an enum, its backing type and its members', () => {
    const src = 'orenum flags_t : u8\n{\n    FTEXT = 0x01,\n    FHCRC = 0x02\n}\n';
    const [s] = documentSymbols(src);

    assert.strictEqual(s.kind, 'enum');
    assert.strictEqual(s.detail, 'flags u8');
    assert.deepStrictEqual(
        s.children.map((c) => [c.name, c.detail]),
        [
            ['FTEXT', '0x01'],
            ['FHCRC', '0x02']
        ]
    );
});

test('finds functions with their parameters', () => {
    const [s] = documentSymbols('fn check_crc(length, off)\n{\n    result = 0;\n}\n');
    assert.strictEqual(s.kind, 'function');
    assert.strictEqual(s.detail, '(length, off)');
});

test('tells the entry point, a named proc and the id probe apart', () => {
    const src = 'proc\n{\n    seek(0);\n}\n\nproc list\n{\n    seek(0);\n}\n\nproc _identify\n{\n    result = 1;\n}\n';
    assert.deepStrictEqual(
        documentSymbols(src).map((s) => [s.name, s.detail]),
        [
            ['proc', 'entry point'],
            ['list', 'named proc'],
            ['_identify', 'id scan']
        ]
    );
});

test('reports a range that covers the whole declaration', () => {
    const [s] = documentSymbols('struct s_t\n{\n    u8 a;\n}\n');
    assert.strictEqual(s.start.line, 0);
    assert.strictEqual(s.end.line, 3);
    assert.deepStrictEqual([s.selectionStart.line, s.selectionStart.character], [0, 7]);
});

test('recovers from a declaration with no body', () => {
    const src = 'struct broken\n\nstruct ok_t\n{\n    u8 a;\n}\n';
    assert.deepStrictEqual(documentSymbols(src).map((s) => s.name), ['ok_t']);
});

test('handles a one-line function', () => {
    const [s] = documentSymbols('fn f(h) { result = h; }\n');
    assert.strictEqual(s.name, 'f');
    assert.strictEqual(s.start.line, 0);
    assert.strictEqual(s.end.line, 0);
});
