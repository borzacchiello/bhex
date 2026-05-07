// Copyright (c) 2022-2026, bageyelet

/*
 * A small freestanding program compiled into per-architecture .text blobs for
 * ds/i regression tests.
 *
 * The goal is not to be fast, but to force a representative mix of call,
 * branch, stack, arithmetic, load/store and switch instructions so the
 * architecture-identification heuristics see realistic code.
 */

typedef unsigned char u8;
typedef unsigned int  u32;

volatile int bhex_identify_sink;

#define NOINLINE __attribute__((noinline, used))

NOINLINE static int rotmix(int x, int y)
{
    u32 a = (u32)x;
    u32 b = (u32)y;
    a ^= (b << 5) | (b >> 3);
    a += 0x13579BDFu;
    a ^= (a >> 7);
    a += b * 9u;
    return (int)a;
}

NOINLINE static int fib(int n)
{
    if (n < 2)
        return n + 1;
    return fib(n - 1) + fib(n - 2);
}

NOINLINE static int sum_words(const int* p, int n)
{
    int acc = 0;
    int i;
    for (i = 0; i < n; ++i)
        acc += p[i] ^ (i * 17 + 3);
    return acc;
}

NOINLINE static int sum_bytes(const u8* p, int n)
{
    int acc = 0;
    int i;
    for (i = 0; i < n; ++i)
        acc += (int)p[i] * (i + 1);
    return acc;
}

NOINLINE static int dispatch(int x)
{
    switch (x & 7) {
        case 0:
            return x + 3;
        case 1:
            return x - 7;
        case 2:
            return x ^ 0x55AA;
        case 3:
            return x * 5;
        case 4:
            return x / 3 + 11;
        case 5:
            return x | 0x1234;
        case 6:
            return x & 0x0FFF;
        default:
            return x ^ 0x13579BDFu;
    }
}

NOINLINE static void stir(int* p, int n)
{
    int i;
    for (i = 0; i < n; ++i)
        p[i] = rotmix(p[i], i + 3) ^ dispatch(i + p[i]);
}

int bhex_identify_entry(int seed)
{
    int words[12] = {
        3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610,
    };
    u8 bytes[16] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
    };

    int v = rotmix(seed, dispatch(seed));
    stir(words, (int)(sizeof(words) / sizeof(words[0])));
    v += sum_words(words, (int)(sizeof(words) / sizeof(words[0])));
    v ^= sum_bytes(bytes, (int)sizeof(bytes));
    v += fib((seed & 7) + 2);
    bhex_identify_sink = v;
    return v;
}
