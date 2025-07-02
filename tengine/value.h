#ifndef TENGINE_VALUE_H
#define TENGINE_VALUE_H

#include "dlist.h"
#include <defs.h>
#include <map.h>

struct TEngine;
struct InterpreterContext;

typedef enum TEngineValueType {
    TENGINE_UNUM = 500,
    TENGINE_SNUM,
    TENGINE_CHAR,
    TENGINE_STRING,
    TENGINE_ENUM_VALUE,
    TENGINE_BUF,
    TENGINE_ARRAY,
    TENGINE_OBJ,
} TEngineValueType;

typedef struct TEngineValue {
    TEngineValueType t;
    union {
        struct {
            // TENGINE_UNUM
            u64_t unum;
            u32_t unum_size;
        };
        struct {
            // TENGINE_SNUM
            s64_t snum;
            u32_t snum_size;
        };
        struct {
            // TENGINE_CHAR
            char c;
        };
        struct {
            // TENGINE_STRING
            u8_t* str;
            u32_t str_size;
        };
        struct {
            // TENGINE_ENUM_VALUE
            char* enum_value;
            u64_t enum_const;
        };
        struct {
            // TENGINE_BUF
            u64_t buf_off;
            u64_t buf_size;
        };
        struct {
            // TENGINE_ARRAY
            DList* array_data;
        };
        struct {
            // TENGINE_OBJ
            map* subvals;
        };
    };
} TEngineValue;

TEngineValue* TEngineValue_UNUM_new(u64_t v, u32_t size);
TEngineValue* TEngineValue_SNUM_new(s64_t v, u32_t size);
TEngineValue* TEngineValue_CHAR_new(char c);
TEngineValue* TEngineValue_STRING_new(const u8_t* str, u32_t size);
TEngineValue* TEngineValue_ENUM_VALUE_new(const char* ename, u64_t econst);
TEngineValue* TEngineValue_BUF_new(u64_t off, u64_t size);
TEngineValue* TEngineValue_ARRAY_new();
TEngineValue* TEngineValue_OBJ_new(map* subvals);
TEngineValue* TEngineValue_dup(TEngineValue* v);
void          TEngineValue_free(TEngineValue* v);

void TEngineValue_ARRAY_append(TEngineValue* arr, TEngineValue* v);

TEngineValue* TEngineValue_array_sub(struct InterpreterContext* ctx,
                                     const TEngineValue*        e,
                                     const TEngineValue*        n);
TEngineValue* TEngineValue_add(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_sub(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_mul(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_div(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_mod(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_and(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_or(struct InterpreterContext* ctx,
                              const TEngineValue* lhs, const TEngineValue* rhs);
TEngineValue* TEngineValue_xor(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_shl(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_shr(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_bgt(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_bge(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_blt(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_ble(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_beq(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_band(struct InterpreterContext* ctx,
                                const TEngineValue*        lhs,
                                const TEngineValue*        rhs);
TEngineValue* TEngineValue_bor(struct InterpreterContext* ctx,
                               const TEngineValue*        lhs,
                               const TEngineValue*        rhs);
TEngineValue* TEngineValue_bnot(struct InterpreterContext* ctx,
                                const TEngineValue*        child);

int TEngineValue_as_u64(struct InterpreterContext* ctx, const TEngineValue* v,
                        u64_t* o);
int TEngineValue_as_s64(struct InterpreterContext* ctx, const TEngineValue* v,
                        s64_t* o);
int TEngineValue_as_string(struct InterpreterContext* ctx,
                           const TEngineValue* v, const char** o);

void  TEngineValue_pp(const TEngineValue* v, int hex);
char* TEngineValue_tostring(const TEngineValue* v, int hex);

#endif
