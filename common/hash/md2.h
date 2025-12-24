/*********************************************************************
 * Filename:   md2.h
 * Author:     Brad Conte (brad AT bradconte.com)
 * Copyright:
 * Disclaimer: This code is presented "as is" without any guarantees.
 * Details:    Defines the API for the corresponding MD2 implementation.
 *********************************************************************/

#ifndef MD2_H
#define MD2_H

/*************************** HEADER FILES ***************************/
#include <defs.h>

/****************************** MACROS ******************************/
#define MD2_BLOCK_SIZE 16

/**************************** DATA TYPES ****************************/

typedef struct {
    u8_t data[16];
    u8_t state[48];
    u8_t checksum[16];
    int  len;
} MD2_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void MD2Init(MD2_CTX* ctx);
void MD2Update(MD2_CTX* ctx, const u8_t data[], u64_t len);
void MD2Final(u8_t hash[MD2_BLOCK_SIZE], MD2_CTX* ctx);

#endif // MD2_H
