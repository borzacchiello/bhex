// Copyright (c) 2022-2026, bageyelet

#ifndef EXPR_EVAL_H
#define EXPR_EVAL_H

#include <defs.h>
#include <filebuffer.h>

#define EXPR_EVAL_OK                   0
#define EXPR_EVAL_ERR_SYNTAX           1
#define EXPR_EVAL_ERR_UNEXPECTED_END   2
#define EXPR_EVAL_ERR_INVALID_NUMBER   3
#define EXPR_EVAL_ERR_INVALID_BITLEN   4
#define EXPR_EVAL_ERR_UNCLOSED_BRACKET 5
#define EXPR_EVAL_ERR_READ_OOB           6
#define EXPR_EVAL_ERR_INVALID_ENDIAN     7
#define EXPR_EVAL_ERR_UNKNOWN_GLOBAL_VAR 8

const char* expr_eval_err_to_string(int err);

// Evaluate an expression string (e.g. "10+20", "[32be 0x1000 + 4]").
// Returns 0 on success, storing the result in *o_result.
// Requires a FileBuffer* for memory read operations.
int expr_eval(const char* expr, FileBuffer* fb, u64_t* o_result);

// Check if a token is an expression token (starts with the sentinel).
int expr_is_sentinel_token(const char* token);
// Strip the sentinel prefix from an expression token.
const char* expr_strip_sentinel(const char* token);

#endif
