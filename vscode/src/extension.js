// Copyright (c) 2022-2026, bageyelet

/*  extension.js
 *  VS Code glue: registers the providers and maps the editor-independent
 *  modules in this folder onto the vscode API. All the logic lives in
 *  format.js, symbols.js and intellisense.js, which know nothing about the
 *  editor and are unit tested on their own.
 */

'use strict';

const vscode = require('vscode');

const { formatBhe, DEFAULT_OPTIONS } = require('./format');
const { documentSymbols } = require('./symbols');
const intellisense = require('./intellisense');

const SELECTOR = { language: 'bhe' };

const SYMBOL_KINDS = {
    struct: vscode.SymbolKind.Struct,
    enum: vscode.SymbolKind.Enum,
    enumMember: vscode.SymbolKind.EnumMember,
    function: vscode.SymbolKind.Function,
    proc: vscode.SymbolKind.Module,
    field: vscode.SymbolKind.Field
};

const COMPLETION_KINDS = {
    function: vscode.CompletionItemKind.Function,
    type: vscode.CompletionItemKind.TypeParameter,
    keyword: vscode.CompletionItemKind.Keyword,
    struct: vscode.CompletionItemKind.Struct,
    enum: vscode.CompletionItemKind.Enum,
    enumMember: vscode.CompletionItemKind.EnumMember,
    variable: vscode.CompletionItemKind.Variable
};

function activate(context) {
    context.subscriptions.push(
        vscode.languages.registerDocumentFormattingEditProvider(SELECTOR, {
            provideDocumentFormattingEdits(document, options) {
                const formatted = formatBhe(document.getText(), formatOptions(options));
                return [vscode.TextEdit.replace(wholeDocument(document), formatted)];
            }
        }),

        vscode.languages.registerDocumentSymbolProvider(SELECTOR, {
            provideDocumentSymbols(document) {
                return documentSymbols(document.getText()).map(toDocumentSymbol);
            }
        }),

        vscode.languages.registerHoverProvider(SELECTOR, {
            provideHover(document, position) {
                const range = document.getWordRangeAtPosition(position, /[A-Za-z_][A-Za-z0-9_]*/);
                if (!range) return undefined;

                const markdown = intellisense.hover(document.getText(range), document.getText());
                return markdown ? new vscode.Hover(new vscode.MarkdownString(markdown), range) : undefined;
            }
        }),

        vscode.languages.registerCompletionItemProvider(SELECTOR, {
            provideCompletionItems(document) {
                return intellisense.completions(document.getText()).map(toCompletionItem);
            }
        })
    );
}

function deactivate() {}

/* -------------------------------------------------------------------------
 *  mapping onto the vscode API
 * ---------------------------------------------------------------------- */

function formatOptions(options) {
    const settings = vscode.workspace.getConfiguration('bhe.format');
    return {
        tabSize: (options && options.tabSize) || DEFAULT_OPTIONS.tabSize,
        alignDeclarations: settings.get('alignDeclarations', DEFAULT_OPTIONS.alignDeclarations),
        alignEnumMembers: settings.get('alignEnumMembers', DEFAULT_OPTIONS.alignEnumMembers)
    };
}

function wholeDocument(document) {
    return new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length));
}

const toRange = (start, end) =>
    new vscode.Range(new vscode.Position(start.line, start.character), new vscode.Position(end.line, end.character));

function toDocumentSymbol(symbol) {
    const item = new vscode.DocumentSymbol(
        symbol.name,
        symbol.detail,
        SYMBOL_KINDS[symbol.kind] || vscode.SymbolKind.Variable,
        toRange(symbol.start, symbol.end),
        toRange(symbol.selectionStart, symbol.selectionEnd)
    );
    item.children = symbol.children.map(toDocumentSymbol);
    return item;
}

function toCompletionItem(completion) {
    const item = new vscode.CompletionItem(
        completion.label,
        COMPLETION_KINDS[completion.kind] || vscode.CompletionItemKind.Text
    );
    item.detail = completion.detail;
    if (completion.documentation) item.documentation = new vscode.MarkdownString(completion.documentation);
    if (completion.insertText) item.insertText = new vscode.SnippetString(completion.insertText);
    if (completion.sortText) item.sortText = completion.sortText;
    return item;
}

module.exports = { activate, deactivate };
