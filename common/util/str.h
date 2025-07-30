#ifndef STR_H
#define STR_H

#include <defs.h>
#include <stdlib.h>

int    escape_char_to_byte(char c, u8_t* o_byte);
int    hex_nibble_to_num(char c, u8_t* b);
int    unescape_ascii_string(char* string, u8_t** o_buf, size_t* o_size);
int    hex_to_bytes(char* hex_string, u8_t** o_buf, size_t* o_size);
size_t count_chars_in_str(char* s, char c);
char*  str_indent(char* s, u32_t spaces);
void   strip_chars(char* s, const char* chars);

#endif
