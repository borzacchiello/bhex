/**
 * @file ripemd160.h
 * @brief RIPEMD-160 hash function
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

#ifndef _RIPEMD160_H
#define _RIPEMD160_H

// Dependencies
#include <defs.h>

// RIPEMD-160 block size
#define RIPEMD160_BLOCK_SIZE 64
// RIPEMD-160 digest size
#define RIPEMD160_DIGEST_SIZE 20
// Minimum length of the padding string
#define RIPEMD160_MIN_PAD_SIZE 9

/**
 * @brief RIPEMD-160 algorithm context
 **/

typedef struct {
    u32_t h[5];
    union {
        u32_t x[16];
        u8_t  buffer[64];
    };
    u32_t size;
    u64_t totalSize;
} Ripemd160Context;

// RIPEMD-160 related constants
extern const u8_t RIPEMD160_OID[5];

// RIPEMD-160 related functions
void ripemd160Init(Ripemd160Context* context);
void ripemd160Update(Ripemd160Context* context, const u8_t* data, u32_t length);
void ripemd160Final(u8_t* digest, Ripemd160Context* context);
void ripemd160ProcessBlock(Ripemd160Context* context);

#endif
