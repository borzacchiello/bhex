// Copyright (c) 2022-2026, bageyelet

#include "checksums.h"

#include <string.h>

// --- BSD checksum (16-bit, circular rotate right + add) ---

static checksum_state_t bsd_init(void) { return (checksum_state_t){0, 0, 0}; }

static checksum_state_t bsd_step(checksum_state_t s, const u8_t* buf, u32_t sz)
{
    u16_t cksum = (u16_t)s.s1;
    for (u32_t i = 0; i < sz; i++) {
        cksum = (cksum >> 1) + ((cksum & 1) << 15);
        cksum += buf[i];
    }
    s.s1 = cksum;
    return s;
}

static u32_t bsd_finalize(checksum_state_t s) { return (u32_t)(s.s1 & 0xFFFF); }

// --- SYSV checksum (32-bit sum folded to 16-bit) ---

static checksum_state_t sysv_init(void) { return (checksum_state_t){0, 0, 0}; }

static checksum_state_t sum_step(checksum_state_t s, const u8_t* buf, u32_t sz)
{
    for (u32_t i = 0; i < sz; i++)
        s.s1 += buf[i];
    return s;
}

static u32_t sysv_finalize(checksum_state_t s)
{
    u32_t r = (u32_t)s.s1;
    r       = (r & 0xFFFF) + (r >> 16);
    r       = (r & 0xFFFF) + (r >> 16);
    return r & 0xFFFF;
}

// --- sum8 (8-bit sum) ---

static u32_t sum8_finalize(checksum_state_t s) { return (u32_t)(s.s1 & 0xFF); }

// --- Internet Checksum (RFC 1071, 16-bit ones' complement) ---

static checksum_state_t inet_init(void) { return (checksum_state_t){0, 0, 0}; }

static checksum_state_t inet_step(checksum_state_t s, const u8_t* buf, u32_t sz)
{
    u32_t sum = (u32_t)s.s1;
    u32_t i   = 0;

    if (s.s2) {
        if (sz > 0) {
            sum += ((u32_t)(s.s2 & 0xFF) << 8) | buf[0];
            i    = 1;
            s.s2 = 0;
        }
    }

    for (; i + 1 < sz; i += 2)
        sum += ((u32_t)buf[i] << 8) | buf[i + 1];

    if (i < sz)
        s.s2 = 0x100 | buf[i];

    s.s1 = sum;
    return s;
}

static u32_t inet_finalize(checksum_state_t s)
{
    u32_t sum = (u32_t)s.s1;
    if (s.s2)
        sum += (u32_t)(s.s2 & 0xFF) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum) & 0xFFFF;
}

// --- sum24 (24-bit sum) ---

static u32_t sum24_finalize(checksum_state_t s)
{
    return (u32_t)(s.s1 & 0xFFFFFF);
}

// --- sum32 (32-bit sum) ---

static u32_t sum32_finalize(checksum_state_t s)
{
    return (u32_t)(s.s1 & 0xFFFFFFFF);
}

// --- Fletcher-4 (2-bit data words, mod 3, 4-bit result) ---

static checksum_state_t fletcher4_init(void)
{
    return (checksum_state_t){0, 0, 0};
}

static checksum_state_t fletcher4_step(checksum_state_t s, const u8_t* buf,
                                       u32_t sz)
{
    u32_t a = (u32_t)s.s1;
    u32_t b = (u32_t)s.s2;
    for (u32_t i = 0; i < sz; i++) {
        u8_t byte = buf[i];
        for (int shift = 6; shift >= 0; shift -= 2) {
            u8_t word = (byte >> shift) & 0x03;
            a         = (a + word) % 3;
            b         = (b + a) % 3;
        }
    }
    s.s1 = a;
    s.s2 = b;
    return s;
}

static u32_t fletcher4_finalize(checksum_state_t s)
{
    return (u32_t)(((s.s2 & 0x3) << 2) | (s.s1 & 0x3));
}

// --- Fletcher-8 (4-bit nibbles, mod 15, 8-bit result) ---

static checksum_state_t fletcher8_init(void)
{
    return (checksum_state_t){0, 0, 0};
}

static checksum_state_t fletcher8_step(checksum_state_t s, const u8_t* buf,
                                       u32_t sz)
{
    u32_t a = (u32_t)s.s1;
    u32_t b = (u32_t)s.s2;
    for (u32_t i = 0; i < sz; i++) {
        a = (a + (buf[i] >> 4)) % 15;
        b = (b + a) % 15;
        a = (a + (buf[i] & 0x0F)) % 15;
        b = (b + a) % 15;
    }
    s.s1 = a;
    s.s2 = b;
    return s;
}

static u32_t fletcher8_finalize(checksum_state_t s)
{
    return (u32_t)(((s.s2 & 0xF) << 4) | (s.s1 & 0xF));
}

// --- Fletcher-16 (bytes, mod 255, 16-bit result) ---

static checksum_state_t fletcher16_init(void)
{
    return (checksum_state_t){0, 0, 0};
}

static checksum_state_t fletcher16_step(checksum_state_t s, const u8_t* buf,
                                        u32_t sz)
{
    u32_t a = (u32_t)s.s1;
    u32_t b = (u32_t)s.s2;
    for (u32_t i = 0; i < sz; i++) {
        a = (a + buf[i]) % 255;
        b = (b + a) % 255;
    }
    s.s1 = a;
    s.s2 = b;
    return s;
}

static u32_t fletcher16_finalize(checksum_state_t s)
{
    return (u32_t)(((s.s2 & 0xFF) << 8) | (s.s1 & 0xFF));
}

// --- Fletcher-32 (16-bit words big-endian, mod 65535, 32-bit result) ---

static checksum_state_t fletcher32_init(void)
{
    return (checksum_state_t){0, 0, 0};
}

static checksum_state_t fletcher32_step(checksum_state_t s, const u8_t* buf,
                                        u32_t sz)
{
    u32_t a = (u32_t)s.s1;
    u32_t b = (u32_t)s.s2;
    u32_t i = 0;

    if (s.count && sz > 0) {
        u16_t word = (u16_t)((s.count & 0xFF) << 8) | buf[0];
        a          = (a + word) % 65535;
        b          = (b + a) % 65535;
        i          = 1;
        s.count    = 0;
    }

    for (; i + 1 < sz; i += 2) {
        u16_t word = ((u16_t)buf[i] << 8) | buf[i + 1];
        a          = (a + word) % 65535;
        b          = (b + a) % 65535;
    }

    if (i < sz)
        s.count = 0x100 | buf[i];

    s.s1 = a;
    s.s2 = b;
    return s;
}

static u32_t fletcher32_finalize(checksum_state_t s)
{
    u32_t a = (u32_t)s.s1;
    u32_t b = (u32_t)s.s2;
    if (s.count) {
        u16_t word = (u16_t)((s.count & 0xFF) << 8);
        a          = (a + word) % 65535;
        b          = (b + a) % 65535;
    }
    return (b << 16) | a;
}

// --- Adler-32 (mod 65521) ---

static checksum_state_t adler32_init(void)
{
    return (checksum_state_t){1, 0, 0};
}

static checksum_state_t adler32_step(checksum_state_t s, const u8_t* buf,
                                     u32_t sz)
{
    u32_t a = (u32_t)s.s1;
    u32_t b = (u32_t)s.s2;
    for (u32_t i = 0; i < sz; i++) {
        a = (a + buf[i]) % 65521;
        b = (b + a) % 65521;
    }
    s.s1 = a;
    s.s2 = b;
    return s;
}

static u32_t adler32_finalize(checksum_state_t s)
{
    return (u32_t)((s.s2 << 16) | s.s1);
}

// --- xor8 (8-bit XOR) ---

static checksum_state_t xor8_init(void) { return (checksum_state_t){0, 0, 0}; }

static checksum_state_t xor8_step(checksum_state_t s, const u8_t* buf, u32_t sz)
{
    for (u32_t i = 0; i < sz; i++)
        s.s1 ^= buf[i];
    return s;
}

static u32_t xor8_finalize(checksum_state_t s) { return (u32_t)(s.s1 & 0xFF); }

// --- Luhn algorithm (decimal check digit) ---
// Each byte is treated as byte % 10 to produce a digit.
// Tracks sums for both even/odd positions, raw and doubled,
// then selects based on total count in finalize.

static u8_t luhn_double(u8_t d)
{
    u8_t dd = d * 2;
    return dd > 9 ? dd - 9 : dd;
}

static checksum_state_t luhn_init(void) { return (checksum_state_t){0, 0, 0}; }

static checksum_state_t luhn_step(checksum_state_t s, const u8_t* buf, u32_t sz)
{
    u32_t even_raw = (u32_t)(s.s1 & 0xFFFFu);
    u32_t even_dbl = (u32_t)((s.s1 >> 16) & 0xFFFFu);
    u32_t odd_raw  = (u32_t)(s.s2 & 0xFFFFu);
    u32_t odd_dbl  = (u32_t)((s.s2 >> 16) & 0xFFFFu);

    for (u32_t i = 0; i < sz; i++) {
        u8_t d  = buf[i] % 10;
        u8_t dd = luhn_double(d);
        if ((s.count + i) % 2 == 0) {
            even_raw += d;
            even_dbl += dd;
        } else {
            odd_raw += d;
            odd_dbl += dd;
        }
    }

    s.s1 = (u64_t)even_raw | ((u64_t)even_dbl << 16);
    s.s2 = (u64_t)odd_raw | ((u64_t)odd_dbl << 16);
    s.count += sz;
    return s;
}

static u32_t luhn_finalize(checksum_state_t s)
{
    u32_t even_raw = (u32_t)(s.s1 & 0xFFFFu);
    u32_t even_dbl = (u32_t)((s.s1 >> 16) & 0xFFFFu);
    u32_t odd_raw  = (u32_t)(s.s2 & 0xFFFFu);
    u32_t odd_dbl  = (u32_t)((s.s2 >> 16) & 0xFFFFu);

    u32_t sum;
    if (s.count % 2 == 0)
        sum = even_dbl + odd_raw;
    else
        sum = even_raw + odd_dbl;

    return (10 - (sum % 10)) % 10;
}

// --- Verhoeff algorithm (decimal check digit) ---
// Each byte is treated as byte % 10.
// Tracks 8 parallel states for each possible (total_count % 8),
// picks the correct one in finalize.

// clang-format off
static const u8_t verhoeff_d[10][10] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
    {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
    {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
    {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
    {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
    {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
    {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
    {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
    {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
    {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
};

static const u8_t verhoeff_p[8][10] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
    {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
    {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
    {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
    {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
    {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
    {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
    {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
};

static const u8_t verhoeff_inv[10] = {0, 4, 3, 2, 1, 5, 6, 7, 8, 9};
// clang-format on

static checksum_state_t verhoeff_init(void)
{
    return (checksum_state_t){0, 0, 0};
}

static checksum_state_t verhoeff_step(checksum_state_t s, const u8_t* buf,
                                      u32_t sz)
{
    u8_t c[8];
    for (int k = 0; k < 8; k++)
        c[k] = (s.s1 >> (k * 8)) & 0xFF;

    for (u32_t i = 0; i < sz; i++) {
        u8_t  digit = buf[i] % 10;
        u64_t idx   = s.count + i;
        for (int k = 0; k < 8; k++) {
            int perm_idx = (int)((k + 8 - (idx % 8)) % 8);
            c[k]         = verhoeff_d[c[k]][verhoeff_p[perm_idx][digit]];
        }
    }

    s.s1 = 0;
    for (int k = 0; k < 8; k++)
        s.s1 |= ((u64_t)c[k] << (k * 8));
    s.count += sz;
    return s;
}

static u32_t verhoeff_finalize(checksum_state_t s)
{
    int  k = (int)(s.count % 8);
    u8_t c = (s.s1 >> (k * 8)) & 0xFF;
    return verhoeff_inv[c];
}

// --- Damm algorithm (decimal check digit, quasigroup) ---
// Each byte is treated as byte % 10.

// clang-format off
static const u8_t damm_table[10][10] = {
    {0, 3, 1, 7, 5, 9, 8, 6, 4, 2},
    {7, 0, 9, 2, 1, 5, 4, 8, 6, 3},
    {4, 2, 0, 6, 8, 7, 1, 3, 5, 9},
    {1, 7, 5, 0, 9, 8, 3, 4, 2, 6},
    {6, 1, 2, 3, 0, 4, 5, 9, 7, 8},
    {3, 6, 7, 4, 2, 0, 9, 5, 8, 1},
    {5, 8, 6, 9, 7, 2, 0, 1, 3, 4},
    {8, 9, 4, 5, 3, 6, 2, 0, 1, 7},
    {9, 4, 3, 8, 6, 1, 7, 2, 0, 5},
    {2, 5, 8, 1, 4, 3, 6, 7, 9, 0}
};
// clang-format on

static checksum_state_t damm_init(void) { return (checksum_state_t){0, 0, 0}; }

static checksum_state_t damm_step(checksum_state_t s, const u8_t* buf, u32_t sz)
{
    u8_t state = (u8_t)s.s1;
    for (u32_t i = 0; i < sz; i++)
        state = damm_table[state][buf[i] % 10];
    s.s1 = state;
    return s;
}

static u32_t damm_finalize(checksum_state_t s) { return (u32_t)(s.s1 & 0xF); }

// --- Algorithm table ---

// clang-format off
static const checksum_algo_t checksum_algos[] = {
    {"BSD",          16, 0, bsd_init,       bsd_step,       bsd_finalize},
    {"SYSV",         16, 0, sysv_init,      sum_step,       sysv_finalize},
    {"SUM-8",         8, 0, sysv_init,      sum_step,       sum8_finalize},
    {"INTERNET",     16, 0, inet_init,      inet_step,      inet_finalize},
    {"SUM-24",       24, 0, sysv_init,      sum_step,       sum24_finalize},
    {"SUM-32",       32, 0, sysv_init,      sum_step,       sum32_finalize},
    {"FLETCHER-4",    4, 0, fletcher4_init,  fletcher4_step,  fletcher4_finalize},
    {"FLETCHER-8",    8, 0, fletcher8_init,  fletcher8_step,  fletcher8_finalize},
    {"FLETCHER-16",  16, 0, fletcher16_init, fletcher16_step, fletcher16_finalize},
    {"FLETCHER-32",  32, 0, fletcher32_init, fletcher32_step, fletcher32_finalize},
    {"ADLER-32",     32, 0, adler32_init,   adler32_step,   adler32_finalize},
    {"XOR-8",         8, 0, xor8_init,      xor8_step,      xor8_finalize},
    {"LUHN",          4, 1, luhn_init,      luhn_step,      luhn_finalize},
    {"VERHOEFF",      4, 1, verhoeff_init,  verhoeff_step,  verhoeff_finalize},
    {"DAMM",          4, 1, damm_init,      damm_step,      damm_finalize},
};
// clang-format on

static const u32_t checksum_algos_size =
    sizeof(checksum_algos) / sizeof(checksum_algos[0]);

u32_t calculate_checksum(const u8_t* buffer, u32_t size,
                         const checksum_algo_t* algo)
{
    if (!buffer || !algo || size == 0)
        return 0;

    checksum_state_t state = algo->init();
    state                  = algo->step(state, buffer, size);
    return algo->finalize(state);
}

const checksum_algo_t* get_checksum_by_name(const char* name)
{
    if (name == NULL)
        return NULL;

    for (u32_t i = 0; i < checksum_algos_size; i++) {
        if (strcmp(name, checksum_algos[i].name) == 0)
            return &checksum_algos[i];
    }

    return NULL;
}

const char* const* get_all_checksum_names(void)
{
    static const char*
               names[sizeof(checksum_algos) / sizeof(checksum_algos[0]) + 1];
    static int initialized = 0;

    if (!initialized) {
        for (u32_t i = 0; i < checksum_algos_size; i++)
            names[i] = checksum_algos[i].name;
        names[checksum_algos_size] = NULL;
        initialized                = 1;
    }

    return names;
}
