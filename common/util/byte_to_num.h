// Copyright (c) 2022-2026, bageyelet

#ifndef BYTE_TO_NUM_H
#define BYTE_TO_NUM_H

#include <defs.h>

int str_to_uint64(const char* str, u64_t* o_num);
int str_to_uint32(const char* str, u32_t* o_num);
int str_to_uint16(const char* str, u16_t* o_num);
int str_to_uint8(const char* str, u8_t* o_num);

// Parses a signed number, letting the string pick its own base (a "0x" prefix
// means hexadecimal, a leading zero means octal)
int str_to_int64(const char* str, s64_t* o_num);

// Parses a signed number in the given base (2 - 36, or 0 to let the string
// pick its own). Unlike str_to_int64 this never surprises the caller with
// octal: "0000000063" in base 10 is sixty-three.
int str_to_int64_base(const char* str, int base, s64_t* o_num);
int str_to_int32(const char* str, s32_t* o_num);
int str_to_int16(const char* str, s16_t* o_num);
int str_to_int8(const char* str, s8_t* o_num);

#endif
