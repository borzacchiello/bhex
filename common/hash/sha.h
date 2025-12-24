/**************************** sha.h ****************************/
/***************** See RFC 6234 for details. *******************/
/*
   Copyright (c) 2011 IETF Trust and the persons identified as
   authors of the code.  All rights reserved.

   Redistribution and use in source and binary forms, with or
   without modification, are permitted provided that the following
   conditions are met:

   - Redistributions of source code must retain the above
     copyright notice, this list of conditions and
     the following disclaimer.

   - Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

   - Neither the name of Internet Society, IETF or IETF Trust, nor
     the names of specific contributors, may be used to endorse or
     promote products derived from this software without specific
     prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
   CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
   EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef _SHA_H_
#define _SHA_H_

/*
 *  Description:
 *      This file implements the Secure Hash Algorithms
 *      as defined in the U.S. National Institute of Standards
 *      and Technology Federal Information Processing Standards
 *      Publication (FIPS PUB) 180-3 published in October 2008
 *      and formerly defined in its predecessors, FIPS PUB 180-1
 *      and FIP PUB 180-2.
 *
 *      A combined document showing all algorithms is available at
 *              http://csrc.nist.gov/publications/fips/
 *                     fips180-3/fips180-3_final.pdf
 *
 *      The five hashes are defined in these sizes:
 *              SHA-1           20 byte / 160 bit
 *              SHA-224         28 byte / 224 bit
 *              SHA-256         32 byte / 256 bit
 *              SHA-384         48 byte / 384 bit
 *              SHA-512         64 byte / 512 bit
 *
 *  Compilation Note:
 *    These files may be compiled with two options:
 *        USE_32BIT_ONLY - use 32-bit arithmetic only, for systems
 *                         without 64-bit integers
 *
 *        USE_MODIFIED_MACROS - use alternate form of the SHA_Ch()
 *                         and SHA_Maj() macros that are equivalent
 *                         and potentially faster on many systems
 *
 */

#include <defs.h>

#ifndef _SHA_enum_
#define _SHA_enum_
/*
 *  All SHA functions return one of these values.
 */
enum {
    shaSuccess = 0,
    shaNull,         /* Null pointer parameter */
    shaInputTooLong, /* input data too long */
    shaStateError,   /* called Input after FinalBits or Result */
    shaBadParam      /* passed a bad parameter */
};
#endif /* _SHA_enum_ */

/*
 *  These constants hold size information for each of the SHA
 *  hashing operations
 */
enum {
    SHA1_Message_Block_Size     = 64,
    SHA224_Message_Block_Size   = 64,
    SHA256_Message_Block_Size   = 64,
    SHA384_Message_Block_Size   = 128,
    SHA512_Message_Block_Size   = 128,
    USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

    SHA1HashSize    = 20,
    SHA224HashSize  = 28,
    SHA256HashSize  = 32,
    SHA384HashSize  = 48,
    SHA512HashSize  = 64,
    USHAMaxHashSize = SHA512HashSize,

    SHA1HashSizeBits    = 160,
    SHA224HashSizeBits  = 224,
    SHA256HashSizeBits  = 256,
    SHA384HashSizeBits  = 384,
    SHA512HashSizeBits  = 512,
    USHAMaxHashSizeBits = SHA512HashSizeBits
};

/*
 *  These constants are used in the USHA (Unified SHA) functions.
 */
typedef enum SHAversion { SHA1, SHA224, SHA256, SHA384, SHA512 } SHAversion;

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation.
 */
typedef struct SHA1Context {
    u32_t Intermediate_Hash[SHA1HashSize / 4]; /* Message Digest */

    u32_t Length_High; /* Message length in bits */
    u32_t Length_Low;  /* Message length in bits */

    u16_t Message_Block_Index; /* Message_Block array index */
                               /* 512-bit message blocks */
    u8_t Message_Block[SHA1_Message_Block_Size];

    int Computed;  /* Is the hash computed? */
    int Corrupted; /* Cumulative corruption code */
} SHA1Context;

/*
 *  This structure will hold context information for the SHA-256
 *  hashing operation.
 */
typedef struct SHA256Context {
    u32_t Intermediate_Hash[SHA256HashSize / 4]; /* Message Digest */

    u32_t Length_High; /* Message length in bits */
    u32_t Length_Low;  /* Message length in bits */

    u16_t Message_Block_Index; /* Message_Block array index */
                               /* 512-bit message blocks */
    u8_t Message_Block[SHA256_Message_Block_Size];

    int Computed;  /* Is the hash computed? */
    int Corrupted; /* Cumulative corruption code */
} SHA256Context;

/*
 *  This structure will hold context information for the SHA-512
 *  hashing operation.
 */
typedef struct SHA512Context {
#ifdef USE_32BIT_ONLY
    u32_t Intermediate_Hash[SHA512HashSize / 4]; /* Message Digest  */
    u32_t Length[4];                             /* Message length in bits */
#else                                            /* !USE_32BIT_ONLY */
    u64_t Intermediate_Hash[SHA512HashSize / 8]; /* Message Digest */
    u64_t Length_High, Length_Low;               /* Message length in bits */
#endif                                           /* USE_32BIT_ONLY */

    u16_t Message_Block_Index; /* Message_Block array index */
                               /* 1024-bit message blocks */
    u8_t Message_Block[SHA512_Message_Block_Size];

    int Computed;  /* Is the hash computed?*/
    int Corrupted; /* Cumulative corruption code */
} SHA512Context;

/*
 *  This structure will hold context information for the SHA-224
 *  hashing operation.  It uses the SHA-256 structure for computation.
 */
typedef struct SHA256Context SHA224Context;

/*
 *  This structure will hold context information for the SHA-384
 *  hashing operation.  It uses the SHA-512 structure for computation.
 */
typedef struct SHA512Context SHA384Context;

/*
 *  This structure holds context information for all SHA
 *  hashing operations.
 */
typedef struct USHAContext {
    int whichSha; /* which SHA is being used */
    union {
        SHA1Context   sha1Context;
        SHA224Context sha224Context;
        SHA256Context sha256Context;
        SHA384Context sha384Context;
        SHA512Context sha512Context;
    } ctx;

} USHAContext;

/*
 *  This structure will hold context information for the HMAC
 *  keyed-hashing operation.
 */
typedef struct HMACContext {
    int           whichSha;   /* which SHA is being used */
    int           hashSize;   /* hash size of SHA being used */
    int           blockSize;  /* block size of SHA being used */
    USHAContext   shaContext; /* SHA context */
    unsigned char k_opad[USHA_Max_Message_Block_Size];
    /* outer padding - key XORd with opad */
    int Computed;  /* Is the MAC computed? */
    int Corrupted; /* Cumulative corruption code */

} HMACContext;

/*
 *  This structure will hold context information for the HKDF
 *  extract-and-expand Key Derivation Functions.
 */
typedef struct HKDFContext {
    int           whichSha; /* which SHA is being used */
    HMACContext   hmacContext;
    int           hashSize; /* hash size of SHA being used */
    unsigned char prk[USHAMaxHashSize];
    /* pseudo-random key - output of hkdfInput */
    int Computed;  /* Is the key material computed? */
    int Corrupted; /* Cumulative corruption code */
} HKDFContext;

/*
 *  Function Prototypes
 */

/* SHA-1 */
extern int SHA1Reset(SHA1Context*);
extern int SHA1Input(SHA1Context*, const u8_t* bytes, unsigned int bytecount);
extern int SHA1FinalBits(SHA1Context*, u8_t bits, unsigned int bit_count);
extern int SHA1Result(u8_t Message_Digest[SHA1HashSize], SHA1Context*);

/* SHA-224 */
extern int SHA224Reset(SHA224Context*);
extern int SHA224Input(SHA224Context*, const u8_t* bytes,
                       unsigned int bytecount);
extern int SHA224FinalBits(SHA224Context*, u8_t bits, unsigned int bit_count);
extern int SHA224Result(u8_t Message_Digest[SHA224HashSize], SHA224Context*);

/* SHA-256 */
extern int SHA256Reset(SHA256Context*);
extern int SHA256Input(SHA256Context*, const u8_t* bytes,
                       unsigned int bytecount);
extern int SHA256FinalBits(SHA256Context*, u8_t bits, unsigned int bit_count);
extern int SHA256Result(u8_t Message_Digest[SHA256HashSize], SHA256Context*);

/* SHA-384 */
extern int SHA384Reset(SHA384Context*);
extern int SHA384Input(SHA384Context*, const u8_t* bytes,
                       unsigned int bytecount);
extern int SHA384FinalBits(SHA384Context*, u8_t bits, unsigned int bit_count);
extern int SHA384Result(u8_t Message_Digest[SHA384HashSize], SHA384Context*);

/* SHA-512 */
extern int SHA512Reset(SHA512Context*);
extern int SHA512Input(SHA512Context*, const u8_t* bytes,
                       unsigned int bytecount);
extern int SHA512FinalBits(SHA512Context*, u8_t bits, unsigned int bit_count);
extern int SHA512Result(u8_t Message_Digest[SHA512HashSize], SHA512Context*);

#endif /* _SHA_H_ */
