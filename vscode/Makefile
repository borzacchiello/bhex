all: test package install

test:
	npm test

grammar:
	npm run gen-grammar

package: grammar
	vsce package

install:
	code --install-extension bhe-syntax-highlight-*.vsix

clean:
	rm -f *.vsix

requirements:
	npm -g install @vscode/vsce
	npm install

.PHONY: all test grammar package install clean requirements
