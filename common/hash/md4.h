/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See md4.c for more information.
 */

#ifndef MD4_H
#define MD4_H

#include <defs.h>

#define MD4_DIGEST_LENGTH 16

typedef struct {
    u32_t         lo, hi;
    u32_t         a, b, c, d;
    unsigned char buffer[64];
    u32_t         block[16];
} MD4_CTX;

extern void MD4Init(MD4_CTX* ctx);
extern void MD4Update(MD4_CTX* ctx, const void* data, unsigned long size);
extern void MD4Final(u8_t result[MD4_DIGEST_LENGTH], MD4_CTX* ctx);

#endif
