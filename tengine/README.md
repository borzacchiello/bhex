# TEngine

Work in progress template engine

[X] p/r 100 prints 112 chars
[ ] calls to non-existent non-void function leads to segfault
[ ] make sure operator precedence is respected
[ ] implement remaining expression operators
[ ] implement a 'remaining size' API
[ ] implement literals
	[ ] string
	[ ] u8, u16, u32, i8, i16, i32
	[ ] raw_buffer
[ ] implement print API
	* needs string literal
[ ] implement a 'find_next' API (which returns the offset, or -1)
	* needs string literal
[ ] allow usage of structs from other files (using like an "import NAME" statement)
[ ] make 'proc' not mandatory
