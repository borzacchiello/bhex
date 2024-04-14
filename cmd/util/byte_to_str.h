#ifndef BYTE_TO_STR_H
#define BYTE_TO_STR_H

#include "../../defs.h"
#include <stdlib.h>

char  nibble_to_hex_char(u8_t b);
int   hex_to_nibble(char c);
char* bytes_to_hex(const u8_t* bytes, size_t size);
int   is_printable_ascii(char c);
char  get_printable_ascii_or_dot(char c);

#endif
