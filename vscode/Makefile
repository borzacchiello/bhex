all: package install

package:
	vsce package

install:
	code --install-extension bhe-syntax-highlight-*.vsix

requirements:
	npm -g install @vscode/vsce
