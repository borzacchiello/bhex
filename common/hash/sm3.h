// clang-format off
/*
    Based on: https://github.com/AyrA/sm3/tree/master

    MIT License

    Copyright (c) 2019 Kevin Gut

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
*/
// clang-format on

#ifndef LIBSM3_SM3_H
#define LIBSM3_SM3_H

#define SM3_DIGEST_LENGTH 32
#define SM3_BLOCK_SIZE    64

#include <sys/types.h>
#include <defs.h>

typedef struct {
    u32_t         digest[8];
    u32_t         nblocks;
    unsigned char block[64];
    u32_t         num;
} sm3_ctx_t;

void SM3Init(sm3_ctx_t* ctx);
void SM3Update(sm3_ctx_t* ctx, const unsigned char* data, u32_t data_len);
void SM3Finalize(unsigned char digest[SM3_DIGEST_LENGTH], sm3_ctx_t* ctx);

void SM3Hash(const unsigned char* data, u32_t datalen,
             unsigned char digest[SM3_DIGEST_LENGTH]);

#endif
