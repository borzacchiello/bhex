/*  extension.js
 *  Formatter for the “bhe” language ─ VS Code DocumentFormattingEditProvider
 */

const vscode = require('vscode');

/*──────────────────────────  VS Code glue  ─────────────────────────────────*/
function activate (ctx) {
    ctx.subscriptions.push(
        vscode.languages.registerDocumentFormattingEditProvider(
            { language: 'bhe', scheme: 'file' },
            {
                provideDocumentFormattingEdits (doc) {
                    const whole = new vscode.Range(
                        doc.positionAt(0),
                        doc.positionAt(doc.getText().length)
                    );
                    return [vscode.TextEdit.replace(whole, formatBhe(doc.getText()))];
                }
            }
        )
    );
}
function deactivate () {}

/*──────────────────────────  core pipeline  ───────────────────────────────*/
function formatBhe (src) {
    const lines   = src.split(/\r?\n/);
    const stage1  = fixBracePlacement(lines);
    const stage2  = indent(stage1);
    const stage3  = alignVarsAndEnums(stage2);
    const stage4  = addSpacesAroundOperators(stage3);
    const stage5  = fixSplitAssignments(stage4);
    return stage5.join('\n');                     // no comment-alignment stage
}

/*──────────────────────────  step 1  ───── brace placement ────────────────*/
function fixBracePlacement (rows) {
    const out = [];

    for (let i = 0; i < rows.length; i++) {
        let raw   = rows[i].replace(/\t/g, '    ').trimEnd();
        const ind = raw.match(/^(\s*)/)[1];
        const txt = raw.trim();

        if (!txt) { out.push(raw); continue; }

        /* control-flow lines: merge lone “{” below them */
        if (/^(while|if|elif|else)\b/.test(txt) && !txt.includes('{')) {
            let j = i + 1;
            while (j < rows.length && rows[j].trim() === '') j++;
            if (j < rows.length && rows[j].trim() === '{') {
                raw = ind + txt + ' {';
                i   = j;                    // skip the isolated “{”
            }
            out.push(raw);
            continue;
        }

        /* declarations: split off inline “{” to its own line */
        if (/^(fn\s+\w+|struct\s+\w+|enum\s+\w+|orenum\s+\w+|proc)\b/.test(txt) &&
            txt.includes('{')) {
            const brace = raw.indexOf('{');
            const head  = raw.slice(0, brace).trimEnd();
            const rest  = raw.slice(brace + 1).trim();
            out.push(head);
            out.push(ind + '{' + (rest ? ' ' + rest : ''));
            continue;
        }

        out.push(raw);
    }
    return out;
}

/*──────────────────────────  step 2  ───── indentation ────────────────────*/
function indent (rows) {
    const out = [];
    let depth = 0;

    for (const original of rows) {
        const line = original.trim();
        if (line === '') { out.push(''); continue; }

        const leadingClose = line.startsWith('}')
            ? line.match(/^}+/)[0].length
            : 0;

        const indentLevel = Math.max(depth - leadingClose, 0);
        out.push(' '.repeat(indentLevel * 4) + line);

        const opens  = (line.match(/{/g) || []).length;
        const closes = (line.match(/}/g) || []).length;
        depth += opens - closes;
        if (depth < 0) depth = 0;           // safety against malformed code
    }
    return out;
}

/*──────────────────────────  step 3  ───── align vars & enums ─────────────*/
function alignVarsAndEnums (rows) {
    const result = [];
    let i = 0;

    /* helper: render a block (no comment alignment) */
    function renderBlock (blk, padTo, makeLine) {
        for (const e of blk) result.push(makeLine(e, padTo));
    }

    while (i < rows.length) {

        /* ───── variable declarations ─────────────────────────────────────*/
        let m = rows[i].match(
            /^(\s*)([A-Za-z_][\w\s\*<>]*\w)\s+([A-Za-z_]\w*(?:\[[^\]]*\])?(?:\s*=\s*[^;]+)?)(;?)(\s*\/\/.*)?$/
        );
        if (m) {
            const indent = m[1];
            const blk = [];
            let j = i;
            while (j < rows.length) {
                const n = rows[j].match(
                    /^(\s*)([A-Za-z_][\w\s\*<>]*\w)\s+([A-Za-z_]\w*(?:\[[^\]]*\])?(?:\s*=\s*[^;]+)?)(;?)(\s*\/\/.*)?$/
                );
                if (!n || n[1] !== indent) break;
                blk.push({
                    indent: n[1],
                    type:   n[2].trim(),
                    rest:   n[3].trim() + n[4] + (n[5] ?? '')  // keep comment
                });
                j++;
            }
            const widthType = Math.max(...blk.map(b => b.type.length));
            renderBlock(
                blk,
                widthType,
                (b,w) => b.indent + b.type.padEnd(w,' ') + ' ' + b.rest.trimStart()
            );
            i = j;
            continue;
        }

        /* ───── enum / orenum members ────────────────────────────────────*/
        m = rows[i].match(
            /^(\s*)([A-Za-z_]\w*)(\s*)(=\s*[^,}]+)?(\s*,?)(\s*\/\/.*)?$/
        );
        if (m) {
            const indent = m[1];
            const blk = [];
            let j = i;
            while (j < rows.length) {
                const n = rows[j].match(
                    /^(\s*)([A-Za-z_]\w*)(\s*)(=\s*[^,}]+)?(\s*,?)(\s*\/\/.*)?$/
                );
                if (!n || n[1] !== indent) break;
                blk.push({
                    indent:  n[1],
                    id:      n[2],
                    assign: (n[4] || '').trim(),
                    comma:   n[5]?.includes(',') || false,
                    comment:(n[6] || '').trim()
                });
                j++;
            }
            const widthId = Math.max(...blk.map(b => b.id.length));
            renderBlock(
                blk,
                widthId,
                (b,w)=>{
                    let ln = b.indent + b.id.padEnd(w,' ');
                    if (b.assign) ln += ' ' + b.assign;
                    if (b.comma)  ln += ',';
                    if (b.comment) ln += ' ' + b.comment;
                    return ln;
                }
            );
            i = j;
            continue;
        }

        /* ───── ordinary line ────────────────────────────────────────────*/
        result.push(rows[i]);
        i++;
    }
    return result;
}

/*──────────────────────────  step 4  ───── spaces around operators ─────────*/
function addSpacesAroundOperators (rows) {
    const opRE1 = /(\S)([+\-*\/%&|^]=?|==|!=|<=|>=|<<|>>|&&|\|\|)(?=\S)/g;
    const opRE2 = /(\S)([=<>])(?=\S)/g;       // simple = < >
    const strRE = /(["'`]).*?\1/g;            // naive string-literal matcher

    return rows.map(row => {
        const parts = row.split('//');        // keep comment tail intact
        let code = parts.shift();

        /* protect spaces inside string literals */
        code = code.replace(strRE, m => m.replace(/ /g, '\x01'));

        code = code
            .replace(opRE1, '$1 $2 ')
            .replace(opRE2, '$1 $2 ');

        code = code.replace(/\x01/g, ' ');    // restore

        return [code, ...parts].join('//');
    });
}

/*──────────────────────────  step 5  ───── indent split assignments ────────*/
function fixSplitAssignments (rows) {
    const out = [...rows];
    for (let i = 0; i < out.length; i++) {
        const m = out[i].match(/^(\s*[^=]+=\s*)$/);   // line ends with “=”
        if (!m) continue;

        const baseIndent = m[1].match(/^(\s*)/)[1];
        let j = i + 1;
        while (j < out.length) {
            const txt = out[j].trim();
            if (txt === '') break;                   // blank  → stop
            out[j] = ' '.repeat(baseIndent.length + 4) + txt.replace(/^\s+/, '');
            if (txt.endsWith(';')) break;            // statement finished
            j++;
        }
        i = j;
    }
    return out;
}

/*──────────────────────────  exports  ──────────────────────────────────────*/
module.exports = { activate, deactivate };
