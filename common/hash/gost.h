/*
 *  gost.h
 *  21 Apr 1998  Markku-Juhani Saarinen <mjos@ssh.fi>
 *
 *  GOST R 34.11-94, Russian Standard Hash Function
 *  header with function prototypes.
 *
 *  Copyright (c) 1998 SSH Communications Security, Finland
 *  All rights reserved.
 */

// Updated 12 Jan 2016  by Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef _GOSTHASH_H_
#define _GOSTHASH_H_

#include <defs.h>

#define GOST_DIGEST_LENGTH 32

/* State structure */

typedef struct {
    uint32_t sum[8];
    uint32_t hash[8];
    uint32_t len[8];
    uint8_t  partial[32];
    u32_t    partial_bytes;
} GostHashCtx;

/* Compute some lookup-tables that are needed by all other functions. */

void GOSTInit(GostHashCtx* ctx);

/* Mix in len bytes of data for the given buffer. */

void GOSTUpdate(GostHashCtx* ctx, const uint8_t* buf, u32_t len);

/* Compute and save the 32-byte digest. */

void GOSTFinal(uint8_t digest[GOST_DIGEST_LENGTH], GostHashCtx* ctx);

#endif /* GOSTHASH_H */
