/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef BLAKE2_IMPL_H
#define BLAKE2_IMPL_H

#include <string.h>
#include <defs.h>

#if !defined(__cplusplus) &&                                                   \
    (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#if defined(_MSC_VER)
#define BLAKE2_INLINE __inline
#elif defined(__GNUC__)
#define BLAKE2_INLINE __inline__
#else
#define BLAKE2_INLINE
#endif
#else
#define BLAKE2_INLINE inline
#endif

static BLAKE2_INLINE u32_t load32(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    u32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const u8_t* p = (const u8_t*)src;
    return ((u32_t)(p[0]) << 0) | ((u32_t)(p[1]) << 8) | ((u32_t)(p[2]) << 16) |
           ((u32_t)(p[3]) << 24);
#endif
}

static BLAKE2_INLINE u64_t load64(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    u64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const u8_t* p = (const u8_t*)src;
    return ((u64_t)(p[0]) << 0) | ((u64_t)(p[1]) << 8) | ((u64_t)(p[2]) << 16) |
           ((u64_t)(p[3]) << 24) | ((u64_t)(p[4]) << 32) |
           ((u64_t)(p[5]) << 40) | ((u64_t)(p[6]) << 48) |
           ((u64_t)(p[7]) << 56);
#endif
}

static BLAKE2_INLINE u16_t load16(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    u16_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const u8_t* p = (const u8_t*)src;
    return (u16_t)(((u32_t)(p[0]) << 0) | ((u32_t)(p[1]) << 8));
#endif
}

static BLAKE2_INLINE void store16(void* dst, u16_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    u8_t* p = (u8_t*)dst;
    *p++    = (u8_t)w;
    w >>= 8;
    *p++ = (u8_t)w;
#endif
}

static BLAKE2_INLINE void store32(void* dst, u32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    u8_t* p = (u8_t*)dst;
    p[0]    = (u8_t)(w >> 0);
    p[1]    = (u8_t)(w >> 8);
    p[2]    = (u8_t)(w >> 16);
    p[3]    = (u8_t)(w >> 24);
#endif
}

static BLAKE2_INLINE void store64(void* dst, u64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    u8_t* p = (u8_t*)dst;
    p[0]    = (u8_t)(w >> 0);
    p[1]    = (u8_t)(w >> 8);
    p[2]    = (u8_t)(w >> 16);
    p[3]    = (u8_t)(w >> 24);
    p[4]    = (u8_t)(w >> 32);
    p[5]    = (u8_t)(w >> 40);
    p[6]    = (u8_t)(w >> 48);
    p[7]    = (u8_t)(w >> 56);
#endif
}

static BLAKE2_INLINE u64_t load48(const void* src)
{
    const u8_t* p = (const u8_t*)src;
    return ((u64_t)(p[0]) << 0) | ((u64_t)(p[1]) << 8) | ((u64_t)(p[2]) << 16) |
           ((u64_t)(p[3]) << 24) | ((u64_t)(p[4]) << 32) |
           ((u64_t)(p[5]) << 40);
}

static BLAKE2_INLINE void store48(void* dst, u64_t w)
{
    u8_t* p = (u8_t*)dst;
    p[0]    = (u8_t)(w >> 0);
    p[1]    = (u8_t)(w >> 8);
    p[2]    = (u8_t)(w >> 16);
    p[3]    = (u8_t)(w >> 24);
    p[4]    = (u8_t)(w >> 32);
    p[5]    = (u8_t)(w >> 40);
}

static BLAKE2_INLINE u32_t rotr32(const u32_t w, const unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

static BLAKE2_INLINE u64_t rotr64(const u64_t w, const unsigned c)
{
    return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static BLAKE2_INLINE void secure_zero_memory(void* v, size_t n)
{
    static void* (*const volatile memset_v)(void*, int, size_t) = &memset;
    memset_v(v, 0, n);
}

#endif
