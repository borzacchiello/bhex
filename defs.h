#ifndef DEF_H
#define DEF_H

typedef unsigned long uptr_t;

typedef unsigned long long u64_t;
typedef unsigned int       u32_t;
typedef unsigned short     u16_t;
typedef unsigned char      u8_t;

typedef long long s64_t;
typedef int       s32_t;
typedef short     s16_t;
typedef char      s8_t;

#define INT8_MIN  (s8_t)(-0x7fl - 1)
#define INT16_MIN (s16_t)(-0x7fffl - 1)
#define INT32_MIN (s32_t)(-0x7fffffffl - 1)
#define INT64_MIN (s64_t)(-0x7fffffffffffffffl - 1)

#define INT8_MAX  (s8_t)0x7fl
#define INT16_MAX (s16_t)0x7fffl
#define INT32_MAX (s32_t)0x7fffffffl
#define INT64_MAX (s64_t)0x7fffffffffffffffl

#define UINT8_MAX  (u8_t)0xfful
#define UINT16_MAX (u16_t)0xfffful
#define UINT32_MAX (u32_t)0xfffffffful
#define UINT64_MAX (u64_t)0xfffffffffffffffful

#endif
