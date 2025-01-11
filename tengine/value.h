#ifndef TENGINE_VALUE_H
#define TENGINE_VALUE_H

#include <defs.h>
#include <map.h>

struct TEngine;

typedef enum TEngineValueType {
    UNUM = 500,
    SNUM,
    CHAR,
    STRING,
    CUSTOM_TYPE,
    ENUM_VALUE,
} TEngineValueType;

typedef struct TEngineValue {
    TEngineValueType t;
    union {
        struct {
            // UNUM
            u64_t unum;
            u32_t unum_size;
        };
        struct {
            // SNUM
            s64_t snum;
            u32_t snum_size;
        };
        struct {
            // CHAR
            char c;
        };
        struct {
            // STRING
            char* str;
        };
        struct {
            // CUSTOM_TYPE
            map* subvals;
        };
        struct {
            // ENUM_VALUE
            char* enum_value;
            u64_t enum_const;
        };
    };
} TEngineValue;

TEngineValue* TEngineValue_UNUM_new(u64_t v, u32_t size);
TEngineValue* TEngineValue_CHAR_new(char c);
TEngineValue* TEngineValue_STRING_new(const char* str);
TEngineValue* TEngineValue_SNUM_new(s64_t v, u32_t size);
TEngineValue* TEngineValue_CUSTOM_TYPE_new(map* subvals);
TEngineValue* TEngineValue_ENUM_VALUE_new(const char* ename, u64_t econst);
TEngineValue* TEngineValue_dup(TEngineValue* v);
void          TEngineValue_free(TEngineValue* v);

TEngineValue* TEngineValue_add(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_sub(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_mul(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_bgt(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_bge(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_blt(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_ble(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_beq(const TEngineValue* lhs,
                               const TEngineValue* rhs);

int TEngineValue_as_u64(TEngineValue* v, u64_t* o);
int TEngineValue_as_s64(TEngineValue* v, s64_t* o);
int TEngineValue_as_string(TEngineValue* v, const char** o);

void TEngineValue_pp(struct TEngine* e, TEngineValue* v, int print_off);

#endif
