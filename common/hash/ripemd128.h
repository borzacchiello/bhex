/**
 * @file ripemd128.h
 * @brief RIPEMD-128 hash function
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.4
 **/

#ifndef _RIPEMD128_H
#define _RIPEMD128_H

#include <defs.h>

// RIPEMD-128 block size
#define RIPEMD128_BLOCK_SIZE 64
// RIPEMD-128 digest size
#define RIPEMD128_DIGEST_SIZE 16
// Minimum length of the padding string
#define RIPEMD128_MIN_PAD_SIZE 9

/**
 * @brief RIPEMD-128 algorithm context
 **/

typedef struct {
    u32_t h[4];
    union {
        u32_t x[16];
        u8_t  buffer[64];
    };
    u32_t size;
    u64_t totalSize;
} Ripemd128Context;

// RIPEMD-128 related constants
extern const u8_t RIPEMD128_OID[5];

// RIPEMD-128 related functions
void ripemd128Init(Ripemd128Context* context);
void ripemd128Update(Ripemd128Context* context, const u8_t* data, u32_t length);
void ripemd128Final(u8_t* digest, Ripemd128Context* context);
void ripemd128ProcessBlock(Ripemd128Context* context);

#endif
