TEngine
-------

Work in progress template engine

[X] implement cast function (e.g., u8(42))
[X] implement type aliases (e.g., uint8_t)
[X] implement custom functions
[X] fix that p/r 100 prints 112 chars
[X] fix mem leak when syntax error occurs
[X] find a way to test tengine through in-memory file buffers
[X] make sure operator precedence is respected
[X] implement remaining expression operators
[X] implement a 'remaining size' API
[X] implement literals
	[X] string
	[X] u8, u16, u32, i8, i16, i32
	[X] raw_buffer
[X] implement print API
[X] allow usage of structs from other files (using like an "import NAME" statement)
[X] make 'proc' not mandatory
[X] refactor tengine interpreter
	- parsing helpers should be moved to ast.c
	- the TEngineInterpreter struct should be merged with ProcessContext and made private
[X] implement a 'find_next' API (which returns the offset, or -1)
[X] improve error print
[ ] print source code context while printing exceptions
[X] implement the output in a generic way, so that we can choose different backends (e.g., JSON)
