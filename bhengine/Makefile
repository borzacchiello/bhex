all: parser lexer

parser:
	bison -d -v -o parser.c parser.y

lexer:
	flex -o lexer.c lexer.l

clean:
	rm -f parser.c parser.h lexer.c
	rm -rf parser.dSYM lexer.dSYM
