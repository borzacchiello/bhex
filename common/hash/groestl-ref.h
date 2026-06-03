/* Groestl-ref.c     January 2011
 * Reference ANSI C code
 * Authors: Soeren S. Thomsen
 *          Krystian Matusiewicz
 *
 * This code is placed in the public domain
 */

#ifndef GROESTL_REF_H
#define GROESTL_REF_H

/* Opaque handle: the real state struct (and all of its dimension macros) is
 * defined in groestl-ref.c. groestl_*_init allocates it, groestl_final frees
 * it, so a caller only ever holds the pointer. */
typedef struct GroestlState* GroestlCtx;

#define GROESTL_224_DIGEST_LENGTH 28
#define GROESTL_256_DIGEST_LENGTH 32
#define GROESTL_384_DIGEST_LENGTH 48
#define GROESTL_512_DIGEST_LENGTH 64

void groestl_224_init(GroestlCtx* ctx);
void groestl_256_init(GroestlCtx* ctx);
void groestl_384_init(GroestlCtx* ctx);
void groestl_512_init(GroestlCtx* ctx);
void groestl_update(GroestlCtx* ctx, const unsigned char* data,
                    unsigned long long len);
void groestl_final(unsigned char* digest, GroestlCtx* ctx);

#endif /* GROESTL_REF_H */
