all: parser lexer

parser:
	bison -d -v -o parser.c parser.y

lexer:
	flex -o lexer.c lexer.l

test: parser lexer # test binary
	gcc -g -fno-omit-frame-pointer -fsanitize=address,undefined parser.c lexer.c main.c ast.c map.c dlist.c tengine.c ../cmd/util/*.c ../log.c ../ll.c ../alloc.c ../filebuffer.c -o test

clean:
	rm -f test parser.c parser.h lexer.c
	rm -rf test.dSYM
