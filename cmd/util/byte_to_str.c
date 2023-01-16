#include "byte_to_str.h"
#include "../../alloc.h"

char nibble_to_hex_char(uint8_t b)
{
    if ((b & 0xf) < 10)
        return '0' + (b & 0xf);
    return 'A' + ((b & 0xf) - 10);
}

char* bytes_to_hex(uint8_t* bytes, size_t size)
{
    char* res     = bhex_malloc(size * 2 + 1);
    res[size * 2] = 0;

    size_t i;
    for (i = 0; i < size * 2; i += 2) {
        res[i + 1] = nibble_to_hex_char(bytes[i >> 1] & 0xF);
        res[i]     = nibble_to_hex_char((bytes[i >> 1] >> 4) & 0xF);
    }
    return res;
}

int  is_printable_ascii(char c) { return c >= 32 && c <= 126; }
char get_printable_ascii_or_dot(char c)
{
    if (is_printable_ascii(c))
        return c;
    return '.';
}