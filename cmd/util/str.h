#ifndef STR_H
#define STR_H

#include <stdint.h>
#include <stdlib.h>

int escape_char_to_byte(char c, uint8_t* o_byte);
int hex_nibble_to_num(char c, uint8_t* b);
int unescape_ascii_string(char* string, uint8_t** o_buf, size_t* o_size);
int hex_to_bytes(char* hex_string, uint8_t** o_buf, size_t* o_size);

#endif
