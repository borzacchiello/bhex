// Copyright (c) 2022-2026, bageyelet

/*  Runs the generated TextMate grammar through the same engine VS Code uses,
 *  and asserts the scope a given piece of source ends up with.
 *
 *  Skipped when the devDependencies are not installed, so `npm test` still
 *  works in a bare checkout.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const GRAMMAR_PATH = path.join(__dirname, '..', 'syntaxes', 'bhe.tmLanguage.json');
const TEMPLATES = path.join(__dirname, '..', '..', 'templates');

let textmate;
let oniguruma;
try {
    textmate = require('vscode-textmate');
    oniguruma = require('vscode-oniguruma');
} catch {
    /* devDependencies not installed */
}

const suite = textmate ? test : test.skip;

let grammar;

async function loadGrammar() {
    if (grammar) return grammar;

    await oniguruma.loadWASM(fs.readFileSync(require.resolve('vscode-oniguruma/release/onig.wasm')).buffer);
    const registry = new textmate.Registry({
        onigLib: Promise.resolve({
            createOnigScanner: (s) => new oniguruma.OnigScanner(s),
            createOnigString: (s) => new oniguruma.OnigString(s)
        }),
        loadGrammar: async () =>
            textmate.parseRawGrammar(fs.readFileSync(GRAMMAR_PATH, 'utf8'), path.basename(GRAMMAR_PATH))
    });

    grammar = await registry.loadGrammar('source.bhe');
    assert.ok(grammar, 'the grammar failed to load');
    return grammar;
}

/** The scopes of the first token whose text is exactly `needle`. */
async function scopeOf(line, needle) {
    const g = await loadGrammar();
    const { tokens } = g.tokenizeLine(line, textmate.INITIAL);
    const token = tokens.find((t) => line.slice(t.startIndex, t.endIndex) === needle);
    assert.ok(token, `no token "${needle}" in ${JSON.stringify(line)}`);
    return token.scopes.join(' ');
}

suite('scopes a builtin call as a builtin', async () => {
    assert.match(await scopeOf('    local x = peek_u32(4);', 'peek_u32'), /support\.function\.builtin/);
});

suite('scopes a user call as a call, not a builtin', async () => {
    const scopes = await scopeOf('    local x = check_crc(4);', 'check_crc');
    assert.match(scopes, /entity\.name\.function\.call/);
    assert.doesNotMatch(scopes, /builtin/);
});

suite('does not treat a builtin name as a call without parentheses', async () => {
    assert.doesNotMatch(await scopeOf('    u8 size;', 'size'), /support\.function/);
});

suite('scopes a declaration name as a definition', async () => {
    assert.match(await scopeOf('struct chunk_t', 'chunk_t'), /entity\.name\.type\.struct/);
    assert.match(await scopeOf('fn check_crc(length)', 'check_crc'), /entity\.name\.function/);
    assert.match(await scopeOf('fn check_crc(length)', 'length'), /variable\.parameter/);
});

suite('scopes the two procs the id command looks for', async () => {
    assert.match(await scopeOf('proc _identify', '_identify'), /support\.function\.identify/);
    assert.match(await scopeOf('proc _identify_magic', '_identify_magic'), /support\.function\.identify/);
    assert.match(await scopeOf('proc list_files', 'list_files'), /entity\.name\.function\.proc/);
});

suite('does not mistake an identifier starting with proc for the keyword', async () => {
    assert.doesNotMatch(await scopeOf('    processLoadCommands();', 'processLoadCommands'), /keyword/);
});

suite('scopes a file variable declaration', async () => {
    assert.match(await scopeOf('    u32 length;', 'u32'), /storage\.type\.primitive/);
    assert.match(await scopeOf('    u32 length;', 'length'), /variable\.other\.member/);
    assert.match(await scopeOf('    RGB entries[n];', 'RGB'), /entity\.name\.type/);
    assert.match(await scopeOf('    RGB entries[n];', 'entries'), /variable\.other\.member/);
});

suite('does not read two identifiers as a declaration without a ; or [', async () => {
    assert.doesNotMatch(await scopeOf('    result = a;', 'result'), /storage\.type/);
});

suite('scopes enum access', async () => {
    assert.match(await scopeOf('    if (t == flags_t::FNAME) {', 'flags_t'), /entity\.name\.type/);
    assert.match(await scopeOf('    if (t == flags_t::FNAME) {', 'FNAME'), /variable\.other\.enummember/);
});

suite('scopes the cross-file type operator', async () => {
    assert.match(await scopeOf('    other#Struct v;', 'other'), /entity\.name\.namespace/);
    assert.match(await scopeOf('    other#Struct v;', 'Struct'), /entity\.name\.type/);
});

suite('scopes every literal form the lexer accepts', async () => {
    assert.match(await scopeOf('    local a = 0xffffu32;', '0xffffu32'), /constant\.numeric\.hex/);
    assert.match(await scopeOf('    local a = 42s8;', '42s8'), /constant\.numeric\.decimal/);
    assert.match(await scopeOf('    local a = 1099511627537u64;', '1099511627537u64'), /constant\.numeric\.decimal/);
});

suite('scopes string escapes, and flags the ones the lexer rejects', async () => {
    assert.match(await scopeOf('    print("\\x41");', '\\x41'), /constant\.character\.escape/);
    assert.match(await scopeOf('    print("\\f");', '\\f'), /invalid\.illegal/);
});

suite('does not let a // inside a string start a comment', async () => {
    assert.doesNotMatch(await scopeOf('    print("a//b");', 'a//b'), /comment/);
});

suite('scopes result as a language variable', async () => {
    assert.match(await scopeOf('    result = 33;', 'result'), /variable\.language/);
});

suite('scopes enum members inside an enum body', async () => {
    const g = await loadGrammar();
    let rules = textmate.INITIAL;
    let scopes = null;

    for (const line of ['orenum flags_t : u8', '{', '    FTEXT = 0x01,', '    FHCRC = 0x02', '}']) {
        const r = g.tokenizeLine(line, rules);
        rules = r.ruleStack;
        const t = r.tokens.find((t) => line.slice(t.startIndex, t.endIndex) === 'FTEXT');
        if (t) scopes = t.scopes.join(' ');
    }

    assert.match(scopes, /variable\.other\.enummember/);
});

suite('tokenizes every shipped template without leaking a scope past the end', async () => {
    const g = await loadGrammar();
    const templates = fs.existsSync(TEMPLATES) ? fs.readdirSync(TEMPLATES).filter((f) => f.endsWith('.bhe')) : [];
    assert.ok(templates.length > 0, `no .bhe templates found in ${TEMPLATES}`);

    for (const name of templates) {
        let rules = textmate.INITIAL;
        for (const line of fs.readFileSync(path.join(TEMPLATES, name), 'utf8').split('\n')) {
            rules = g.tokenizeLine(line, rules).ruleStack;
        }
        /* back to the grammar's base rule: no unterminated string, comment or
         * enum body has swallowed the rest of the file */
        assert.strictEqual(rules.depth, 1, `${name}: a scope is still open at the end of the file`);
    }
});
