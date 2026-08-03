// Copyright (c) 2022-2026, bageyelet

/*  Checks the language data against the bhex sources it was transcribed from,
 *  when a checkout is around, and checks the generated grammar is up to date.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { BUILTIN_TYPES, BUILTIN_FUNCTION_NAMES, KEYWORDS, BUILTINS } = require('../src/language');
const { hover, completions } = require('../src/intellisense');
const { render, GRAMMAR_PATH } = require('../scripts/gen-grammar');

const ENGINE = path.join(__dirname, '..', '..', 'bhengine');
const read = (f) => fs.readFileSync(path.join(ENGINE, f), 'utf8');
const haveEngine = fs.existsSync(ENGINE);

test('the checked-in grammar matches what the generator produces', () => {
    assert.strictEqual(
        fs.readFileSync(GRAMMAR_PATH, 'utf8'),
        render(),
        'syntaxes/bhe.tmLanguage.json is stale — run `npm run gen-grammar`'
    );
});

test('every builtin has a signature and a doc', () => {
    for (const b of BUILTINS) {
        assert.ok(b.signature.startsWith(`${b.name}(`), `${b.name}: signature does not start with its name`);
        assert.ok(b.doc && b.doc.length > 10, `${b.name}: missing doc`);
    }
});

test('every builtin, type and keyword hovers', () => {
    for (const name of [...BUILTIN_FUNCTION_NAMES, ...BUILTIN_TYPES, ...KEYWORDS, 'result']) {
        assert.ok(hover(name), `no hover for ${name}`);
    }
});

test('an unknown word does not hover', () => {
    assert.strictEqual(hover('not_a_thing'), null);
});

test('a declaration in the document hovers', () => {
    assert.match(hover('chunk_t', 'struct chunk_t\n{\n    u8 a;\n}\n'), /struct chunk_t/);
});

test('completions cover the builtins and the document declarations', () => {
    const items = completions('struct chunk_t\n{\n    u8 a;\n}\n\nfn helper(x)\n{\n    result = x;\n}\n');
    const labels = items.map((i) => i.label);

    for (const name of BUILTIN_FUNCTION_NAMES) assert.ok(labels.includes(name), `missing completion for ${name}`);
    assert.ok(labels.includes('chunk_t'));
    assert.ok(labels.includes('helper'));
});

test('a builtin completion inserts a snippet with its required arguments', () => {
    const items = completions();
    assert.strictEqual(items.find((i) => i.label === 'off' && i.kind === 'function').insertText, 'off()$0');
    assert.strictEqual(items.find((i) => i.label === 'peek').insertText, 'peek(${1:n})$0');
    assert.strictEqual(items.find((i) => i.label === 'substr').insertText, 'substr(${1:s}, ${2:start})$0');
});

/* ---------------------------------------------------------------------
 *  Against bhengine, so a builtin added there is noticed here
 * ------------------------------------------------------------------ */

test('the builtin types match bhengine/builtin.c', { skip: !haveEngine }, () => {
    const table = read('builtin.c').match(/builtin_types\[\]\s*=\s*\{([\s\S]*?)\n\};/);
    assert.ok(table, 'could not find builtin_types[] in builtin.c');

    const names = [...table[1].matchAll(/\{"([a-z0-9_]+)"/g)].map((m) => m[1]);
    assert.deepStrictEqual([...new Set(names)].sort(), [...BUILTIN_TYPES].sort());
});

test('the builtin functions match bhengine/builtin.c', { skip: !haveEngine }, () => {
    const table = read('builtin.c').match(/builtin_funcs\[\]\s*=\s*\{([\s\S]*?)\n\};/);
    assert.ok(table, 'could not find builtin_funcs[] in builtin.c');

    const names = [...table[1].matchAll(/\{"([a-z0-9_]+)"/g)].map((m) => m[1]);
    assert.deepStrictEqual([...new Set(names)].sort(), [...BUILTIN_FUNCTION_NAMES].sort());
});

test('the keywords match bhengine/lexer.l', { skip: !haveEngine }, () => {
    const names = [...read('lexer.l').matchAll(/^"([a-z]+)"\s+\{ handle_token; return T[A-Z]+; \}/gm)].map((m) => m[1]);
    assert.deepStrictEqual([...new Set(names)].sort(), [...KEYWORDS].sort());
});
