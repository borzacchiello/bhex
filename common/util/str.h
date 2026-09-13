// Copyright (c) 2022-2026, bageyelet

#ifndef STR_H
#define STR_H

#include <defs.h>
#include <stdlib.h>

int escape_char_to_byte(char c, u8_t* o_byte);
int hex_nibble_to_num(char c, u8_t* b);
int unescape_ascii_string(char* string, u8_t** o_buf, size_t* o_size);
int hex_to_bytes(char* hex_string, u8_t** o_buf, size_t* o_size);
// Like hex_to_bytes(), but '?' is accepted in place of a hex digit and stands
// for "any nibble". *o_mask gets one byte per output byte, holding 0xf0 for a
// fixed high nibble and 0x0f for a fixed low one, so that a comparison is
// (candidate & mask) == (buf & mask). Both buffers are owned by the caller.
int         hex_to_bytes_masked(char* hex_string, u8_t** o_buf, u8_t** o_mask,
                                size_t* o_size);
size_t      count_chars_in_str(char* s, char c);
char*       str_indent(char* s, u32_t spaces);
void        strip_chars(char* s, const char* chars);
const char* stristr(const char* haystack, const char* needle);
char*       _strsep(char** stringp, const char* delim);

#endif
