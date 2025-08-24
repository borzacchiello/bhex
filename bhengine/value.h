#ifndef TENGINE_VALUE_H
#define TENGINE_VALUE_H

#include "dlist.h"
#include <defs.h>
#include <map.h>

struct BHEngine;
struct InterpreterContext;

typedef enum BHEngineValueType {
    TENGINE_UNUM = 500,
    TENGINE_SNUM,
    TENGINE_CHAR,
    TENGINE_WCHAR,
    TENGINE_STRING,
    TENGINE_WSTRING,
    TENGINE_ENUM_VALUE,
    TENGINE_BUF,
    TENGINE_ARRAY,
    TENGINE_OBJ,
} BHEngineValueType;

typedef struct BHEngineValue {
    BHEngineValueType t;
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
            // TENGINE_WCHAR
            u16_t wc;
        };
        struct {
            // TENGINE_STRING
            u8_t* str;
            u32_t str_size;
        };
        struct {
            // TENGINE_WSTRING
            u16_t* wstr;
            u32_t  wstr_size;
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
} BHEngineValue;

BHEngineValue* BHEngineValue_UNUM_new(u64_t v, u32_t size);
BHEngineValue* BHEngineValue_SNUM_new(s64_t v, u32_t size);
BHEngineValue* BHEngineValue_CHAR_new(char c);
BHEngineValue* BHEngineValue_WCHAR_new(u16_t c);
BHEngineValue* BHEngineValue_STRING_new(const u8_t* str, u32_t size);
BHEngineValue* BHEngineValue_WSTRING_new(const u16_t* str, u32_t size);
BHEngineValue* BHEngineValue_ENUM_VALUE_new(const char* ename, u64_t econst);
BHEngineValue* BHEngineValue_BUF_new(u64_t off, u64_t size);
BHEngineValue* BHEngineValue_ARRAY_new();
BHEngineValue* BHEngineValue_OBJ_new(map* subvals);
BHEngineValue* BHEngineValue_dup(BHEngineValue* v);
void           BHEngineValue_free(BHEngineValue* v);

void BHEngineValue_ARRAY_append(BHEngineValue* arr, BHEngineValue* v);

BHEngineValue* BHEngineValue_array_sub(struct InterpreterContext* ctx,
                                       const BHEngineValue*       e,
                                       const BHEngineValue*       n);
BHEngineValue* BHEngineValue_add(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_sub(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_mul(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_div(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_mod(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_and(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_or(struct InterpreterContext* ctx,
                                const BHEngineValue*       lhs,
                                const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_xor(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_shl(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_shr(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_bgt(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_bge(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_blt(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_ble(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_beq(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_band(struct InterpreterContext* ctx,
                                  const BHEngineValue*       lhs,
                                  const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_bor(struct InterpreterContext* ctx,
                                 const BHEngineValue*       lhs,
                                 const BHEngineValue*       rhs);
BHEngineValue* BHEngineValue_bnot(struct InterpreterContext* ctx,
                                  const BHEngineValue*       child);

int BHEngineValue_as_u64(struct InterpreterContext* ctx, const BHEngineValue* v,
                         u64_t* o);
int BHEngineValue_as_s64(struct InterpreterContext* ctx, const BHEngineValue* v,
                         s64_t* o);
int BHEngineValue_as_string(struct InterpreterContext* ctx,
                            const BHEngineValue* v, const char** o);

void  BHEngineValue_pp(const BHEngineValue* v, int hex);
char* BHEngineValue_tostring(const BHEngineValue* v, int hex);

#endif
