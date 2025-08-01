#include "str.h"
#include "defs.h"

#include <string.h>
#include <alloc.h>
#include <log.h>

#define ESCAPE_OK           0
#define ESCAPE_NEXT_IS_BYTE 1
#define ESCAPE_ERR          2

int escape_char_to_byte(char c, u8_t* o_byte)
{
    switch (c) {
        case '0':
            *o_byte = 0;
            return ESCAPE_OK;
        case 'r':
            *o_byte = '\r';
            return ESCAPE_OK;
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
            int  r = escape_char_to_byte(c, &b);
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

size_t count_chars_in_str(char* s, char c)
{
    if (!s)
        return 0;

    size_t n = 0;
    while (*s)
        if (*s++ == c)
            n += 1;
    return n;
}

void strip_chars(char* s, const char* chars)
{
    size_t i    = 0;
    size_t size = strlen(s);
    while (i < size) {
        const char* curr = chars;
        while (*curr) {
            if (*curr == s[i]) {
                memmove(&s[i], &s[i + 1], size - i);
                size -= 1;
                break;
            }
            curr++;
        }
        i += 1;
    }
}

char* str_indent(char* s, u32_t spaces)
{
    if (spaces == 0)
        return s;

    size_t len    = strlen(s);
    size_t newlen = len + (count_chars_in_str(s, '\n') + 1) * spaces;
    if (newlen < len)
        panic("overflow");

    s = bhex_realloc(s, newlen + 1);

    memmove(s + spaces, s, len);
    memset(s, ' ', spaces);
    u32_t i = spaces;
    while (i < newlen) {
        if (s[i] == '\n') {
            i += 1;
            memmove(s + i + spaces, s + i, newlen - i - spaces);
            memset(s + i, ' ', spaces);
            i += spaces;
            continue;
        }
        i += 1;
    }
    s[newlen] = 0;
    return s;
}
