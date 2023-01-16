#include "str.h"
#include "../../alloc.h"

#include <string.h>

#define ESCAPE_OK           0
#define ESCAPE_NEXT_IS_BYTE 1
#define ESCAPE_ERR          2

int escape_char_to_byte(char c, u8_t* o_byte)
{
    switch (c) {
        case 't':
            *o_byte = '\t';
            return ESCAPE_OK;
        case 'n':
            *o_byte = '\n';
            return ESCAPE_OK;
        case '\\':
            *o_byte = '\\';
            return ESCAPE_OK;
        case 'x':
            return ESCAPE_NEXT_IS_BYTE;
        default:
            break;
    }
    return ESCAPE_ERR;
}

int hex_nibble_to_num(char c, u8_t* b)
{
    if (c >= '0' && c <= '9') {
        *b = c - '0';
        return 1;
    }
    if (c >= 'a' && c <= 'f') {
        *b = c - 'a' + 10;
        return 1;
    }
    if (c >= 'A' && c <= 'F') {
        *b = c - 'A' + 10;
        return 1;
    }
    return 0;
}

int unescape_ascii_string(char* str, u8_t** o_buf, size_t* o_size)
{
    size_t str_len = strlen(str);

    // Result is AT LEAST long as much as the stirng, but can be less
    u8_t* res = bhex_malloc(str_len);

    size_t i, j = 0;
    for (i = 0; i < str_len; ++i) {
        char c = str[i];
        if (c == '\\') {
            if (i + 1 >= str_len)
                goto ERR_OUT;
            c = str[++i];

            u8_t b;
            int     r = escape_char_to_byte(c, &b);
            if (r == ESCAPE_ERR) {
                goto ERR_OUT;
            } else if (r == ESCAPE_NEXT_IS_BYTE) {
                if (i + 2 >= str_len)
                    goto ERR_OUT;

                u8_t hi, lo;
                if (!hex_nibble_to_num(str[i + 1], &hi))
                    goto ERR_OUT;
                if (!hex_nibble_to_num(str[i + 2], &lo))
                    goto ERR_OUT;
                res[j++] = (hi << 4) | lo;
                i += 2;
            } else {
                res[j++] = b;
            }
        } else {
            res[j++] = (u8_t)c;
        }
    }

    if (j != str_len)
        res = bhex_realloc(res, j);

    *o_size = j;
    *o_buf  = res;
    return 1;

ERR_OUT:
    bhex_free(res);
    return 0;
}

int hex_to_bytes(char* hex_string, u8_t** o_buf, size_t* o_size)
{
    size_t str_len = strlen(hex_string);

    // Result is AT LEAST long as much as the stirng, but can be less
    u8_t* res = bhex_malloc(str_len);

    int    high = 1;
    size_t i, j = 0;
    for (i = 0; i < str_len; ++i) {
        char c = hex_string[i];
        if (c == ' ' || c == '\t')
            continue;

        u8_t v;
        if (!hex_nibble_to_num(c, &v))
            goto ERR_OUT;
        if (high) {
            res[j] = v << 4;
        } else {
            res[j++] |= v;
        }
        high = !high;
    }
    if (!high)
        goto ERR_OUT;

    *o_size = j;
    *o_buf  = res;
    return 1;

ERR_OUT:
    bhex_free(res);
    return 0;
}
