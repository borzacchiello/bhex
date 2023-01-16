// Taken From Rizin https://github.com/rizinorg/rizin

// SPDX-FileCopyrightText: 1999 Alan DeKok <aland@ox.org>
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef HASH_MD5_H
#define HASH_MD5_H

#define HASH_MD5_DIGEST_SIZE  0x10
#define HASH_MD5_BLOCK_LENGTH 0x40

#include <string.h>
#include "../../defs.h"

/*  The below was retrieved from
 *  http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/crypto/md5.h?rev=1.1
 *  With the following changes: u64_t => u32_t[2]
 *  Commented out #include <sys/cdefs.h>
 *  Commented out the __BEGIN and __END _DECLS, and the __attributes.
 */

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#define MD5_BLOCK_LENGTH  64
#define MD5_DIGEST_LENGTH 16

typedef struct MD5Context {
    u32_t state[4];                 /* state */
    u32_t count[2];                 /* number of bits, mod 2^64 */
    u8_t  buffer[MD5_BLOCK_LENGTH]; /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX*);
void MD5Update(MD5_CTX*, const u8_t*, size_t);
void MD5Final(u8_t[MD5_DIGEST_LENGTH], MD5_CTX*);

#endif /* HASH_MD5_H */
