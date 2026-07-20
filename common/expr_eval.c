// Copyright (c) 2022-2026, bageyelet

#include "expr_eval.h"

#include <string.h>
#include <alloc.h>
#include <util/endian.h>
#include <util/math.h>

#define EXPR_SENTINEL '\x01'

const char* expr_eval_err_to_string(int err)
{
    switch (err) {
        case EXPR_EVAL_OK:
            return "no error";
        case EXPR_EVAL_ERR_SYNTAX:
            return "syntax error in expression";
        case EXPR_EVAL_ERR_UNEXPECTED_END:
            return "unexpected end of expression";
        case EXPR_EVAL_ERR_INVALID_NUMBER:
            return "invalid number in expression";
        case EXPR_EVAL_ERR_INVALID_BITLEN:
            return "invalid bitlen (must be 8, 16, 32, or 64)";
        case EXPR_EVAL_ERR_UNCLOSED_BRACKET:
            return "unclosed bracket in expression";
        case EXPR_EVAL_ERR_READ_OOB:
            return "memory read out of bounds";
        case EXPR_EVAL_ERR_INVALID_ENDIAN:
            return "invalid endian (must be 'be' or 'le')";
        case EXPR_EVAL_ERR_UNKNOWN_GLOBAL_VAR:
            return "unknown global variable";
        default:
            return "unknown expression error";
    }
}

// --- forward declarations for recursive descent ---

static int parse_expr(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_bitwise_or(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_bitwise_and(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_shift(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_add(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_mul(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_unary(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_primary(const char** p, FileBuffer* fb, u64_t* o_result);
static int parse_number(const char** p, u64_t* o_result);
static int parse_mem_deref(const char** p, FileBuffer* fb, u64_t* o_result);

static void skip_spaces(const char** p)
{
    while (**p == ' ' || **p == '\t')
        (*p)++;
}

// --- recursive descent parser ---

static int parse_number(const char** p, u64_t* o_result)
{
    skip_spaces(p);
    const char* start = *p;

    if (start[0] == '0' && (start[1] == 'x' || start[1] == 'X')) {
        // hex number
        *p += 2;
        u64_t val    = 0;
        int   digits = 0;
        while (**p) {
            char c = **p;
            if (c >= '0' && c <= '9')
                val = (val << 4) | (u64_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                val = (val << 4) | (u64_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                val = (val << 4) | (u64_t)(c - 'A' + 10);
            else
                break;
            digits++;
            (*p)++;
        }
        if (digits == 0)
            return EXPR_EVAL_ERR_INVALID_NUMBER;
        *o_result = val;
        return EXPR_EVAL_OK;
    }

    // decimal number
    if (*start < '0' || *start > '9')
        return EXPR_EVAL_ERR_INVALID_NUMBER;

    u64_t val = 0;
    while (**p >= '0' && **p <= '9') {
        val = val * 10 + (u64_t)(**p - '0');
        (*p)++;
    }
    *o_result = val;
    return EXPR_EVAL_OK;
}

static int parse_mem_deref(const char** p, FileBuffer* fb, u64_t* o_result)
{
    // we're past the '[' already
    skip_spaces(p);

    if (**p == '\0')
        return EXPR_EVAL_ERR_UNCLOSED_BRACKET;

    // Parse optional bitlen + endian: [bitlen[be|le] expr]
    // A number is a bitlen only if followed by 'be'/'le' or by a space
    // and more content before ']'. Otherwise it's the address expression.
    u64_t bitlen     = 32; // default
    int   big_endian = 0;  // default LE

    if (**p >= '0' && **p <= '9') {
        const char* before_num = *p;
        u64_t       candidate;
        int         r = parse_number(p, &candidate);
        if (r != EXPR_EVAL_OK) {
            *p = before_num;
        } else if (candidate == 8 || candidate == 16 || candidate == 32 ||
                   candidate == 64) {
            // Valid bitlen candidate, check what follows
            if ((*p)[0] == 'b' && (*p)[1] == 'e') {
                bitlen     = candidate;
                big_endian = 1;
                *p += 2;
            } else if ((*p)[0] == 'l' && (*p)[1] == 'e') {
                bitlen     = candidate;
                big_endian = 0;
                *p += 2;
            } else {
                // No endian, check if there's an expression after
                skip_spaces(p);
                if (**p != ']' && **p != '\0') {
                    // Something follows: this number is the bitlen
                    bitlen = candidate;
                } else {
                    // Nothing follows: this number is the address
                    *p = before_num;
                }
            }
        } else {
            // Not a valid bitlen, check if user intended it as one
            skip_spaces(p);
            if (**p != ']' && **p != '\0') {
                // Something follows: user intended this as a bitlen
                return EXPR_EVAL_ERR_INVALID_BITLEN;
            }
            // Just a lone number in brackets, treat as address
            *p = before_num;
        }
    }

    // Now parse the address expression
    skip_spaces(p);
    u64_t addr;
    int   r = parse_expr(p, fb, &addr);
    if (r != EXPR_EVAL_OK)
        return r;

    skip_spaces(p);
    if (**p != ']')
        return EXPR_EVAL_ERR_UNCLOSED_BRACKET;
    (*p)++; // consume ']'

    // Read memory
    size_t byte_len = (size_t)(bitlen / 8);
    if (addr + byte_len > fb->size || addr + byte_len < addr)
        return EXPR_EVAL_ERR_READ_OOB;

    u8_t* data = fb_read_alloc(fb, addr, byte_len);
    if (!data)
        return EXPR_EVAL_ERR_READ_OOB;

    switch (bitlen) {
        case 8:
            *o_result = read8(data);
            break;
        case 16:
            *o_result = big_endian ? read_be16(data) : read_le16(data);
            break;
        case 32:
            *o_result = big_endian ? read_be32(data) : read_le32(data);
            break;
        case 64:
            *o_result = big_endian ? read_be64(data) : read_le64(data);
            break;
    }

    bhex_free(data);
    return EXPR_EVAL_OK;
}

typedef void (*ExprGlobalVarCallback)(FileBuffer* fb, u64_t* o_result);

typedef struct {
    const char*           name;
    ExprGlobalVarCallback get_value;
} ExprGlobalVar;

static void gvar_offset(FileBuffer* fb, u64_t* o_result)
{
    *o_result = fb->off + fb->base_addr;
}

static void gvar_base(FileBuffer* fb, u64_t* o_result)
{
    *o_result = fb->base_addr;
}

static void gvar_size(FileBuffer* fb, u64_t* o_result) { *o_result = fb->size; }

static const ExprGlobalVar global_vars[] = {
    {"off", gvar_offset}, {"o", gvar_offset},  {"base", gvar_base},
    {"b", gvar_base},     {"size", gvar_size}, {"s", gvar_size},
};

static int parse_primary(const char** p, FileBuffer* fb, u64_t* o_result)
{
    skip_spaces(p);

    if (**p == '$') {
        (*p)++; // consume '$'

        for (size_t i = 0; i < sizeof(global_vars) / sizeof(global_vars[0]);
             i++) {
            size_t len = strlen(global_vars[i].name);
            if (strncmp(*p, global_vars[i].name, len) == 0) {
                *p += len;
                global_vars[i].get_value(fb, o_result);
                return EXPR_EVAL_OK;
            }
        }
        return EXPR_EVAL_ERR_UNKNOWN_GLOBAL_VAR;
    }

    if (**p == '(') {
        (*p)++; // consume '('
        int r = parse_expr(p, fb, o_result);
        if (r != EXPR_EVAL_OK)
            return r;
        skip_spaces(p);
        if (**p != ')')
            return EXPR_EVAL_ERR_SYNTAX;
        (*p)++; // consume ')'
        return EXPR_EVAL_OK;
    }

    if (**p == '[') {
        (*p)++; // consume '['
        return parse_mem_deref(p, fb, o_result);
    }

    return parse_number(p, o_result);
}

static int parse_unary(const char** p, FileBuffer* fb, u64_t* o_result)
{
    skip_spaces(p);

    if (**p == '~') {
        (*p)++; // consume '~'
        int r = parse_unary(p, fb, o_result);
        if (r != EXPR_EVAL_OK)
            return r;
        *o_result = ~(*o_result);
        return EXPR_EVAL_OK;
    }

    return parse_primary(p, fb, o_result);
}

static int parse_mul(const char** p, FileBuffer* fb, u64_t* o_result)
{
    int r = parse_unary(p, fb, o_result);
    if (r != EXPR_EVAL_OK)
        return r;

    while (1) {
        skip_spaces(p);
        if (**p == '*') {
            (*p)++;
            u64_t rhs;
            r = parse_unary(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) * rhs;
        } else {
            break;
        }
    }
    return EXPR_EVAL_OK;
}

static int parse_add(const char** p, FileBuffer* fb, u64_t* o_result)
{
    int r = parse_mul(p, fb, o_result);
    if (r != EXPR_EVAL_OK)
        return r;

    while (1) {
        skip_spaces(p);
        if (**p == '+') {
            (*p)++;
            u64_t rhs;
            r = parse_mul(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) + rhs;
        } else if (**p == '-') {
            (*p)++;
            u64_t rhs;
            r = parse_mul(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) - rhs;
        } else {
            break;
        }
    }
    return EXPR_EVAL_OK;
}

static int parse_shift(const char** p, FileBuffer* fb, u64_t* o_result)
{
    int r = parse_add(p, fb, o_result);
    if (r != EXPR_EVAL_OK)
        return r;

    while (1) {
        skip_spaces(p);
        if ((*p)[0] == '<' && (*p)[1] == '<') {
            *p += 2;
            u64_t rhs;
            r = parse_add(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) << rhs;
        } else if ((*p)[0] == '>' && (*p)[1] == '>') {
            *p += 2;
            u64_t rhs;
            r = parse_add(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) >> rhs;
        } else {
            break;
        }
    }
    return EXPR_EVAL_OK;
}

static int parse_bitwise_and(const char** p, FileBuffer* fb, u64_t* o_result)
{
    int r = parse_shift(p, fb, o_result);
    if (r != EXPR_EVAL_OK)
        return r;

    while (1) {
        skip_spaces(p);
        if (**p == '&') {
            (*p)++;
            u64_t rhs;
            r = parse_shift(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) & rhs;
        } else {
            break;
        }
    }
    return EXPR_EVAL_OK;
}

static int parse_bitwise_or(const char** p, FileBuffer* fb, u64_t* o_result)
{
    int r = parse_bitwise_and(p, fb, o_result);
    if (r != EXPR_EVAL_OK)
        return r;

    while (1) {
        skip_spaces(p);
        if (**p == '|') {
            (*p)++;
            u64_t rhs;
            r = parse_bitwise_and(p, fb, &rhs);
            if (r != EXPR_EVAL_OK)
                return r;
            *o_result = (*o_result) | rhs;
        } else {
            break;
        }
    }
    return EXPR_EVAL_OK;
}

static int parse_expr(const char** p, FileBuffer* fb, u64_t* o_result)
{
    return parse_bitwise_or(p, fb, o_result);
}

// --- public API ---

int expr_eval(const char* expr, FileBuffer* fb, u64_t* o_result)
{
    if (!expr || !fb || !o_result)
        return EXPR_EVAL_ERR_SYNTAX;

    const char* p = expr;
    int         r = parse_expr(&p, fb, o_result);
    if (r != EXPR_EVAL_OK)
        return r;

    skip_spaces(&p);
    if (*p != '\0')
        return EXPR_EVAL_ERR_SYNTAX; // trailing garbage

    return EXPR_EVAL_OK;
}

// --- helper for cmdline_parser integration ---

int expr_is_sentinel_token(const char* token)
{
    return token && token[0] == EXPR_SENTINEL;
}

const char* expr_strip_sentinel(const char* token)
{
    if (!token || token[0] != EXPR_SENTINEL)
        return token;
    return token + 1;
}
