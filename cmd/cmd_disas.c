// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include "cmd_disas.h"

#include <util/byte_to_num.h>
#include <util/byte_to_str.h>
#include <display.h>
#include <string.h>
#include <stdlib.h>
#include <alloc.h>
#include <log.h>

#include <capstone/capstone.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DEFAULT_DISAS_OPCODES 8
#define MAX_UNIQUE_MNEMONICS  64

#define X86_64_ARCH      0
#define X86_ARCH         1
#define X86_16_ARCH      2
#define ARM32_ARCH       3
#define AARCH64_ARCH     4
#define ARM32_THUMB_ARCH 5
#define MIPS32_ARCH      6
#define MIPS64_ARCH      7
#define MIPSEL32_ARCH    8
#define MIPSEL64_ARCH    9
#define PPC32_ARCH       10
#define PPC64_ARCH       11
#define PPCLE32_ARCH     12
#define PPCLE64_ARCH     13
#define BPF_ARCH         14
#define eBPF_ARCH        15

#define MAX_DEFAULT_SIZE 1024 * 1024 * 2

#define HINT_STR "[/l/i] [<arch>] [<nbytes>]"

typedef struct {
    cs_arch arch;
    cs_mode mode;
} CapstoneArchInfo;

static CapstoneArchInfo map_arch[] = {
    {CS_ARCH_X86, CS_MODE_64},                              // X86_64_ARCH
    {CS_ARCH_X86, CS_MODE_32},                              // X86_ARCH
    {CS_ARCH_X86, CS_MODE_16},                              // X86_16_ARCH
    {CS_ARCH_ARM, CS_MODE_ARM},                             // ARM32_ARCH
    {CS_ARCH_AARCH64, CS_MODE_ARM},                         // AARCH64_ARCH
    {CS_ARCH_ARM, CS_MODE_THUMB},                           // ARM32_THUMB_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN},    // MIPS32_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN},    // MIPS64_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN}, // MIPSEL32_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN}, // MIPSEL64_ARCH
    {CS_ARCH_PPC, CS_MODE_BIG_ENDIAN},                      // PPC32_ARCH
    {CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN},         // PPC64_ARCH
    {CS_ARCH_PPC, CS_MODE_LITTLE_ENDIAN},                   // PPCLE32_ARCH
    {CS_ARCH_PPC, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN},      // PPCLE64_ARCH
    {CS_ARCH_BPF, CS_MODE_BPF_CLASSIC},                     // BPF_ARCH
    {CS_ARCH_BPF, CS_MODE_BPF_EXTENDED},                    // eBPF_ARCH
};

static const char* map_arch_names[] = {
    "x64",         // X86_64_ARCH
    "x86",         // X86_ARCH
    "i8086",       // X86_16_ARCH
    "arm32",       // ARM32_ARCH
    "aarch64",     // AARCH64_ARCH
    "arm32-thumb", // ARM32_THUMB_ARCH
    "mips32",      // MIPS32_ARCH
    "mips64",      // MIPS64_ARCH
    "mipsel32",    // MIPSEL32_ARCH
    "mipsel64",    // MIPSEL64_ARCH
    "ppc32",       // PPC32_ARCH
    "ppc64",       // PPC64_ARCH
    "ppcle32",     // PPCLE32_ARCH
    "ppcle64",     // PPCLE64_ARCH
    "bpf",         // BPF_ARCH
    "ebpf",        // eBPF_ARCH
};

/* ── architecture identification ─────────────────────────────────────────── */

typedef struct {
    int    arch_idx;
    double score;
    double valid_ratio;
    int    unique_mnemonics;
    size_t valid_bytes;
    size_t insn_count;
    int    prologue_hits;
} ArchScore;

/* Minimum expected average instruction size (bytes) for genuine code.
 * 0 = no penalty applied (fixed-width ISAs are already constrained).     */
static const double min_avg_insn_size[] = {
    3.5, /* X86_64_ARCH      real x64: 4-7 bytes avg   */
    3.0, /* X86_ARCH         real x86: 3-6 bytes avg   */
    2.5, /* X86_16_ARCH      real 8086: 2-5 bytes avg  */
    0.0, /* ARM32_ARCH       fixed 4 bytes             */
    0.0, /* AARCH64_ARCH     fixed 4 bytes             */
    2.5, /* ARM32_THUMB_ARCH mix 2/4 bytes             */
    0.0, /* MIPS32_ARCH      fixed 4 bytes             */
    0.0, /* MIPS64_ARCH      fixed 4 bytes             */
    0.0, /* MIPSEL32_ARCH    fixed 4 bytes             */
    0.0, /* MIPSEL64_ARCH    fixed 4 bytes             */
    0.0, /* PPC32_ARCH       fixed 4 bytes             */
    0.0, /* PPC64_ARCH       fixed 4 bytes             */
    0.0, /* PPCLE32_ARCH     fixed 4 bytes             */
    0.0, /* PPCLE64_ARCH     fixed 4 bytes             */
};

/*
 * Two characteristic mnemonics for each ISA.  If neither appears after
 * CHAR_THRESHOLD valid instructions the decode is likely a false positive.
 *   both found → factor 1.00   one found → 0.75   none found → 0.50
 */
#define CHAR_THRESHOLD 100

#define N_ARCHS (sizeof(map_arch) / sizeof(map_arch[0]))
/* BPF/eBPF are available for manual disassembly (ds bpf / ds ebpf) but are
 * excluded from automatic identification because they are not general-purpose
 * machine code ISAs and would create noise in the scoring.               */
#define N_IDENTIFY_ARCHS (N_ARCHS - 2)

static const char* arch_char[N_IDENTIFY_ARCHS][2] = {
    {"call", "push"}, /* X86_64      */
    {"call", "push"}, /* X86         */
    {"call", "push"}, /* X86_16      */
    {"bx", "push"},   /* ARM32       bx lr = return; push = prologue */
    {"ret", "cbz"},   /* AARCH64       ret/cbz exclusive to AArch64    */
    {"bx", "push"},   /* ARM32_THUMB */
    {"jal", "jr"},    /* MIPS32      */
    {"jal", "jr"},    /* MIPS64      */
    {"jal", "jr"},    /* MIPSEL32    */
    {"jal", "jr"},    /* MIPSEL64    */
    {"blr", "mflr"},  /* PPC32       blr = return; mflr = prologue */
    {"blr", "mflr"},  /* PPC64       */
    {"blr", "mflr"},  /* PPCLE32     */
    {"blr", "mflr"},  /* PPCLE64     */
};

/*
 * Prologue/epilogue byte patterns for architecture fingerprinting.
 *
 * Each entry is {mask[4], val[4], aligned4}: a 4-byte sliding window matches
 * when (buf[i+k] & mask[k]) == val[k] for all k.  If aligned4=1 only
 * 4-byte-aligned offsets are checked (correct for RISC ISAs with fixed-width
 * instructions; avoids false positives from data sections).
 *
 * Patterns are highly ISA-specific and appear in virtually every compiled
 * binary:
 *   x86-64  : push rbp/mov rbp,rsp (55 48 89 E5); endbr64 (F3 0F 1E FA);
 *             pop rbp/ret (5D C3)
 *   x86-32  : push ebp/mov ebp,esp (55 89 E5); pop ebp/ret (5D C3)
 *   i8086   : same encoding as x86-32
 *   ARM32 LE: push{regs,lr}  = [XX][0x40|XX] 0x2D 0xE9
 *             pop {regs,pc}  = [XX][0x80|XX] 0xBD 0xE8
 *             (LR=r14→bit14 of reg-list→bit6 of byte[1];
 *              PC=r15→bit15→bit7 of byte[1])
 *   AARCH64 LE: stp x29,x30,[sp,#-N]! = FD 7B [BC-BF] A9
 *               ldp x29,x30,[sp],#N   = FD 7B [C0-FF] A8
 *               ret                   = C0 03 5F D6
 *   Thumb-2 : push.w {regs,lr} = 2D E9 XX [0x40|XX]
 *             pop.w  {regs,pc} = BD E8 XX [0x80|XX]
 *   MIPS BE : addiu sp,sp,-N = 27 BD FF XX; sw ra,N(sp) = AF BF XX XX
 *   MIPS LE : same words, byte-swapped
 */
#define MAX_PRO_PATTERNS 4

typedef struct {
    u8_t mask[4];
    u8_t val[4];
    int  aligned4;
} ProPattern;

static const ProPattern pro_patterns[N_IDENTIFY_ARCHS][MAX_PRO_PATTERNS] = {
    /* X86_64 */
    [X86_64_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0xFF},
             {0x55, 0x48, 0x89, 0xE5},
             0}, /* push rbp; mov rbp,rsp */
            {{0xFF, 0xFF, 0xFF, 0xFF},
             {0xF3, 0x0F, 0x1E, 0xFA},
             0}, /* endbr64              */
            {{0xFF, 0xFF, 0x00, 0x00},
             {0x5D, 0xC3, 0x00, 0x00},
             0}, /* pop rbp; ret         */
        },
    /* X86 */
    [X86_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0x00},
             {0x55, 0x89, 0xE5, 0x00},
             0}, /* push ebp; mov ebp,esp */
            {{0xFF, 0xFF, 0x00, 0x00},
             {0x5D, 0xC3, 0x00, 0x00},
             0}, /* pop ebp; ret          */
        },
    /* i8086 — same encoding as x86-32 */
    [X86_16_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0x00}, {0x55, 0x89, 0xE5, 0x00}, 0},
            {{0xFF, 0xFF, 0x00, 0x00}, {0x5D, 0xC3, 0x00, 0x00}, 0},
        },
    /* ARM32 LE */
    [ARM32_ARCH] =
        {
            {{0x00, 0x40, 0xFF, 0xFF},
             {0x00, 0x40, 0x2D, 0xE9},
             1}, /* push {regs,lr} */
            {{0x00, 0x80, 0xFF, 0xFF},
             {0x00, 0x80, 0xBD, 0xE8},
             1}, /* pop  {regs,pc} */
        },
    /* AARCH64 LE */
    [AARCH64_ARCH] =
        {
            {{0xFF, 0xFF, 0xFC, 0xFF},
             {0xFD, 0x7B, 0xBC, 0xA9},
             1}, /* stp x29,x30,[sp,#-N]! */
            {{0xFF, 0xFF, 0xC0, 0xFF},
             {0xFD, 0x7B, 0xC0, 0xA8},
             1}, /* ldp x29,x30,[sp],#N   */
            {{0xFF, 0xFF, 0xFF, 0xFF}, {0xC0, 0x03, 0x5F, 0xD6}, 1}, /* ret */
        },
    /* ARM32-Thumb (Thumb-2 wide encodings) */
    [ARM32_THUMB_ARCH] =
        {
            {{0xFF, 0xFF, 0x00, 0x40},
             {0x2D, 0xE9, 0x00, 0x40},
             0}, /* push.w {regs,lr} */
            {{0xFF, 0xFF, 0x00, 0x80},
             {0xBD, 0xE8, 0x00, 0x80},
             0}, /* pop.w  {regs,pc} */
        },
    /* MIPS32 BE */
    [MIPS32_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0x00},
             {0x27, 0xBD, 0xFF, 0x00},
             1}, /* addiu sp,sp,-N    */
            {{0xFF, 0xFF, 0x00, 0x00},
             {0xAF, 0xBF, 0x00, 0x00},
             1}, /* sw ra,N(sp)       */
        },
    /* MIPS64 BE */
    [MIPS64_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0x00},
             {0x67, 0xBD, 0xFF, 0x00},
             1}, /* daddiu sp,sp,-N   */
            {{0xFF, 0xFF, 0x00, 0x00},
             {0xFF, 0xBF, 0x00, 0x00},
             1}, /* sd ra,N(sp)       */
        },
    /* MIPSEL32 LE */
    [MIPSEL32_ARCH] =
        {
            {{0x00, 0xFF, 0xFF, 0xFF},
             {0x00, 0xFF, 0xBD, 0x27},
             1}, /* addiu sp,sp,-N LE */
            {{0x00, 0x00, 0xFF, 0xFF},
             {0x00, 0x00, 0xBF, 0xAF},
             1}, /* sw ra,N(sp) LE    */
        },
    /* MIPSEL64 LE */
    [MIPSEL64_ARCH] =
        {
            {{0x00, 0xFF, 0xFF, 0xFF},
             {0x00, 0xFF, 0xBD, 0x67},
             1}, /* daddiu sp,sp,-N LE */
            {{0x00, 0x00, 0xFF, 0xFF},
             {0x00, 0x00, 0xBF, 0xFF},
             1}, /* sd ra,N(sp) LE     */
        },
    /* PPC32 BE: stwu r1,-N(r1) = 94 21 FF XX; mflr r0 = 7C 08 02 A6 */
    [PPC32_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0x00},
             {0x94, 0x21, 0xFF, 0x00},
             1}, /* stwu r1,-N(r1) BE  */
            {{0xFF, 0xFF, 0xFF, 0xFF},
             {0x7C, 0x08, 0x02, 0xA6},
             1}, /* mflr r0 BE         */
        },
    /* PPC64 BE: stdu r1,-N(r1) = F8 21 FF X1; mflr r0 same */
    [PPC64_ARCH] =
        {
            {{0xFF, 0xFF, 0xFF, 0x01},
             {0xF8, 0x21, 0xFF, 0x01},
             1}, /* stdu r1,-N(r1) BE  */
            {{0xFF, 0xFF, 0xFF, 0xFF},
             {0x7C, 0x08, 0x02, 0xA6},
             1}, /* mflr r0 BE         */
        },
    /* PPCLE32 LE: stwu r1,-N(r1) byte-swapped = XX FF 21 94 */
    [PPCLE32_ARCH] =
        {
            {{0x00, 0xFF, 0xFF, 0xFF},
             {0x00, 0xFF, 0x21, 0x94},
             1}, /* stwu r1,-N(r1) LE  */
            {{0xFF, 0xFF, 0xFF, 0xFF},
             {0xA6, 0x02, 0x08, 0x7C},
             1}, /* mflr r0 LE         */
        },
    /* PPCLE64 LE: stdu r1,-N(r1) byte-swapped = X1 FF 21 F8 */
    [PPCLE64_ARCH] =
        {
            {{0x01, 0xFF, 0xFF, 0xFF},
             {0x01, 0xFF, 0x21, 0xF8},
             1}, /* stdu r1,-N(r1) LE  */
            {{0xFF, 0xFF, 0xFF, 0xFF},
             {0xA6, 0x02, 0x08, 0x7C},
             1}, /* mflr r0 LE         */
        },
};

static const int pro_npatterns[N_IDENTIFY_ARCHS] = {
    3, /* X86_64      */
    2, /* X86         */
    2, /* X86_16      */
    2, /* ARM32       */
    3, /* AARCH64       */
    2, /* ARM32_THUMB */
    2, /* MIPS32      */
    2, /* MIPS64      */
    2, /* MIPSEL32    */
    2, /* MIPSEL64    */
    2, /* PPC32       */
    2, /* PPC64       */
    2, /* PPCLE32     */
    2, /* PPCLE64     */
};

/* Count prologue/epilogue pattern hits in one buffer chunk. */
static int scan_prologue(int arch_idx, const u8_t* buf, size_t sz)
{
    const ProPattern* pats = pro_patterns[arch_idx];
    int               np   = pro_npatterns[arch_idx];
    int               hits = 0;
    int               p;

    for (p = 0; p < np; p++) {
        size_t step = (size_t)(pats[p].aligned4 ? 4 : 1);
        size_t i;
        if (sz < 4)
            continue;
        for (i = 0; i + 4 <= sz; i += step) {
            if (((buf[i] & pats[p].mask[0]) == pats[p].val[0]) &&
                ((buf[i + 1] & pats[p].mask[1]) == pats[p].val[1]) &&
                ((buf[i + 2] & pats[p].mask[2]) == pats[p].val[2]) &&
                ((buf[i + 3] & pats[p].mask[3]) == pats[p].val[3]))
                hits++;
        }
    }
    return hits;
}

/*
 * Per-architecture accumulator for chunked file processing.
 * The file is read one fb_block_size chunk at a time (fb_read enforces this
 * limit); each chunk is fed to both the Capstone disassembler and the
 * prologue pattern scanner. Stats are accumulated across all chunks, then
 * finalised into an ArchScore.
 */

typedef struct {
    csh    handle;
    int    handle_ok;
    size_t valid_bytes;
    size_t insn_count;
    int    nunique;
    int    char_found[2];
    char   seen[MAX_UNIQUE_MNEMONICS][CS_MNEMONIC_SIZE + 1];
    int    prologue_hits;
} ArchAccum;

static void arch_accum_init(ArchAccum* a, int arch_idx)
{
    memset(a, 0, sizeof(*a));
    a->handle_ok = (cs_open(map_arch[arch_idx].arch, map_arch[arch_idx].mode,
                            &a->handle) == CS_ERR_OK);
    if (a->handle_ok)
        cs_option(a->handle, CS_OPT_SKIPDATA, CS_OPT_ON);
}

static void arch_accum_chunk(ArchAccum* a, int arch_idx, const u8_t* chunk,
                             size_t chunk_size)
{
    cs_insn* insn;
    size_t   count;
    size_t   j;

    if (!a->handle_ok)
        return;

    count = cs_disasm(a->handle, chunk, chunk_size, 0, 0, &insn);
    if (count > 0) {
        for (j = 0; j < count; j++) {
            size_t k;
            if (insn[j].id == 0) /* SKIPDATA pseudo-op: invalid bytes */
                continue;
            a->valid_bytes += insn[j].size;
            a->insn_count++;
            if (!a->char_found[0] &&
                strcmp(insn[j].mnemonic, arch_char[arch_idx][0]) == 0)
                a->char_found[0] = 1;
            if (!a->char_found[1] &&
                strcmp(insn[j].mnemonic, arch_char[arch_idx][1]) == 0)
                a->char_found[1] = 1;
            if (a->nunique < MAX_UNIQUE_MNEMONICS) {
                int found = 0;
                for (k = 0; (int)k < a->nunique; k++) {
                    if (strcmp(a->seen[k], insn[j].mnemonic) == 0) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    strncpy(a->seen[a->nunique], insn[j].mnemonic,
                            CS_MNEMONIC_SIZE);
                    a->seen[a->nunique][CS_MNEMONIC_SIZE] = '\0';
                    a->nunique++;
                }
            }
        }
        cs_free(insn, count);
    }

    a->prologue_hits += scan_prologue(arch_idx, chunk, chunk_size);
}

static void arch_accum_close(ArchAccum* a)
{
    if (a->handle_ok)
        cs_close(&a->handle);
}

/*
 * Compute the final ArchScore from accumulated stats.
 *
 * Scoring components (sum to 1.0 before char_factor):
 *
 *   55% — penalised valid-byte ratio
 *     Fraction of file bytes that decode as valid instructions.  For
 *     variable-width ISAs (x86) a quadratic penalty is applied when the
 *     average instruction size falls below the ISA's expected minimum,
 *     since decoding foreign data produces suspiciously short instructions.
 *
 *   15% — mnemonic diversity
 *     How many distinct opcodes appear, capped at MAX_UNIQUE_MNEMONICS.
 *     Genuine code is diverse; random data decoded as the wrong ISA tends
 *     to produce repetitive mnemonics.
 *
 *   30% — prologue/epilogue bonus
 *     Counts ISA-specific byte patterns (frame setup/teardown, ret).
 *     These patterns are virtually impossible to fake: an AARCH64 binary
 *     contains many `stp x29,x30,[sp,#-N]!` sequences (FD 7B [BC-BF] A9)
 *     that will never appear at 4-byte-aligned positions in x86 code.
 *     Normalised against expected prologues (~1 per 600 bytes of binary).
 *
 * The whole score is then multiplied by char_factor (1.0 / 0.75 / 0.50)
 * depending on how many ISA-signature mnemonics were found.
 */
static ArchScore arch_finalize(const ArchAccum* a, int arch_idx,
                               size_t total_bytes)
{
    ArchScore s;
    double    penalised_ratio;
    double    min_avg;
    double    diversity;
    double    char_factor;
    double    prologue_bonus;
    double    expected_prologues;

    s.arch_idx         = arch_idx;
    s.valid_bytes      = a->valid_bytes;
    s.insn_count       = a->insn_count;
    s.unique_mnemonics = a->nunique;
    s.prologue_hits    = a->prologue_hits;
    s.valid_ratio =
        total_bytes > 0 ? (double)a->valid_bytes / (double)total_bytes : 0.0;

    /* Plausibility penalty for variable-width ISAs */
    penalised_ratio = s.valid_ratio;
    min_avg         = min_avg_insn_size[arch_idx];
    if (min_avg > 0.0 && a->insn_count > 0) {
        double avg_size = (double)a->valid_bytes / (double)a->insn_count;
        if (avg_size < min_avg) {
            double r = avg_size / min_avg;
            penalised_ratio *= r * r; /* quadratic penalty */
        }
    }

    diversity = (double)a->nunique / (double)MAX_UNIQUE_MNEMONICS;
    if (diversity > 1.0)
        diversity = 1.0;

    char_factor = 1.0;
    if (a->insn_count >= CHAR_THRESHOLD) {
        int nfound = a->char_found[0] + a->char_found[1];
        if (nfound == 0)
            char_factor = 0.50;
        else if (nfound == 1)
            char_factor = 0.75;
    }

    /* Prologue bonus: normalise against ~1 prologue per 600 bytes of binary */
    expected_prologues = (double)total_bytes / 600.0;
    if (expected_prologues < 1.0)
        expected_prologues = 1.0;
    prologue_bonus = (double)a->prologue_hits / expected_prologues;
    if (prologue_bonus > 1.0)
        prologue_bonus = 1.0;

    s.score =
        (penalised_ratio * 0.55 + diversity * 0.15 + prologue_bonus * 0.30) *
        char_factor;

    return s;
}
static int cmp_arch_score(const void* a, const void* b)
{
    const ArchScore* sa = (const ArchScore*)a;
    const ArchScore* sb = (const ArchScore*)b;
    if (sb->score > sa->score + 1e-9)
        return 1;
    if (sa->score > sb->score + 1e-9)
        return -1;
    return sb->unique_mnemonics - sa->unique_mnemonics;
}

static void do_identify(FileBuffer* fb, u64_t limit)
{
    u64_t      orig_off    = fb->off;
    u64_t      start       = fb->off;
    u64_t      end         = fb->size;
    size_t     total_bytes = 0;
    size_t     i;
    ArchAccum* acc;
    u64_t      off;

    if (limit > 0 && start + limit < end)
        end = start + limit;
    if (limit == 0 && end - start > MAX_DEFAULT_SIZE) {
        warning("limiting the scan size to %d bytes for performance; use "
                "`ds/i %llu` to scan the whole file",
                MAX_DEFAULT_SIZE, (unsigned long long)(end - start));
        end = start + MAX_DEFAULT_SIZE;
    }

    acc = bhex_malloc(N_IDENTIFY_ARCHS * sizeof(ArchAccum));
    off = start;

    for (i = 0; i < N_IDENTIFY_ARCHS; i++)
        arch_accum_init(&acc[i], (int)i);

    while (off < end) {
        u64_t  remaining = end - off;
        size_t chunk =
            (size_t)(remaining < fb_block_size ? remaining : fb_block_size);
        const u8_t* data;
        fb_seek(fb, off);
        data = fb_read(fb, chunk);
        if (!data)
            break;
        for (i = 0; i < N_IDENTIFY_ARCHS; i++)
            arch_accum_chunk(&acc[i], (int)i, data, chunk);
        off += chunk;
        total_bytes += chunk;
    }

    fb_seek(fb, orig_off);

    ArchScore scores[N_IDENTIFY_ARCHS];
    for (i = 0; i < N_IDENTIFY_ARCHS; i++) {
        arch_accum_close(&acc[i]);
        scores[i] = arch_finalize(&acc[i], (int)i, total_bytes);
    }
    bhex_free(acc);

    qsort(scores, N_IDENTIFY_ARCHS, sizeof(ArchScore), cmp_arch_score);

    display_printf("Architecture identification (%zu bytes analyzed):\n",
                   total_bytes);
    for (i = 0; i < N_IDENTIFY_ARCHS; i++) {
        display_printf("  %-14s  score=%4.2f  valid=%5.1f%%  insns=%-5zu"
                       "  unique=%-3d  prologues=%-4d\n",
                       map_arch_names[scores[i].arch_idx], scores[i].score,
                       scores[i].valid_ratio * 100.0, scores[i].insn_count,
                       scores[i].unique_mnemonics, scores[i].prologue_hits);
    }
}

/* ── help / exec ─────────────────────────────────────────────────────────── */

static void disascmd_help(void* obj)
{
    display_printf(
        "disas: disassemble code at current offset\n"
        "\n"
        "  ds" HINT_STR "\n"
        "     l:  list supported architectures\n"
        "     i:  identify architecture; optional nbytes limits the scan to\n"
        "         that many bytes from the current offset (default: whole "
        "file)\n"
        "\n"
        "  arch:   the architecture to use\n"
        "  nbytes: number of opcodes to disassemble (default: %d)\n",
        DEFAULT_DISAS_OPCODES);
}

static void disascmd_dispose(void* obj) {}

static int parse_arch(const char* a, int* out_arch)
{
    size_t i;
    for (i = 0; i < sizeof(map_arch_names) / sizeof(void*); ++i) {
        if (strcmp(map_arch_names[i], a) == 0) {
            *out_arch = i;
            return 1;
        }
    }
    return 0;
}

static const char* bytes_str(const cs_insn* insn, size_t max_size)
{
    static char disas[16 * 3 + 1];

    if (max_size >= sizeof(disas) || max_size < 3)
        panic("invalid max_size");

    size_t i = 0, off = 0;
    while (off < insn->size) {
        if (i + 3 >= max_size - 2 && off != insn->size - 1) {
            disas[i]     = '.';
            disas[i + 1] = '.';
            disas[i + 2] = '.';
            i += 3;
            break;
        }
        disas[i + 2] = ' ';
        disas[i + 1] = nibble_to_hex_char(insn->bytes[off] & 0xF);
        disas[i]     = nibble_to_hex_char((insn->bytes[off] >> 4) & 0xF);

        off += 1;
        i += 3;
    }
    for (; i < max_size; ++i)
        disas[i] = ' ';
    disas[max_size] = 0;

    return disas;
}

static void do_disas(int arch, u64_t addr, const u8_t* code, size_t code_size,
                     u64_t nopcodes)
{
    csh      handle;
    cs_insn* insn;
    size_t   count;

    if (cs_open(map_arch[arch].arch, map_arch[arch].mode, &handle) !=
        CS_ERR_OK) {
        error("unable to disassemble with given arch, maybe it is not "
              "included in your capstone version");
        return;
    }

    count = cs_disasm(handle, code, code_size - 1, addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < min(count, nopcodes); j++) {
            display_printf("0x%08llx: %s %s\t\t%s\n", (u64_t)insn[j].address,
                           bytes_str(&insn[j], 21), insn[j].mnemonic,
                           insn[j].op_str);
        }
        cs_free(insn, count);
    } else
        display_printf("invalid\n");

    cs_close(&handle);
}

static int disascmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "l") == 0) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_ARG;

        // list the supported architectures
        display_printf("Supported architectures:\n");
        size_t i;
        for (i = 0; i < sizeof(map_arch_names) / sizeof(void*); ++i) {
            display_printf("    %s\n", map_arch_names[i]);
        }
        return COMMAND_OK;
    }

    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "i") == 0) {
        if (pc->args.size > 1)
            return COMMAND_INVALID_ARG;

        u64_t limit = 0;
        if (pc->args.size == 1) {
            const char* lim_str = (const char*)pc->args.head->data;
            if (!str_to_uint64(lim_str, &limit))
                return COMMAND_INVALID_ARG;
        }

        do_identify(fb, limit);
        return COMMAND_OK;
    }

    if (pc->args.size != 1 && pc->args.size != 2)
        return COMMAND_INVALID_ARG;

    int         arch     = 0;
    u64_t       nopcodes = 0;
    const u8_t* bytes    = NULL;

    const char* arch_str = (const char*)pc->args.head->data;
    if (!parse_arch(arch_str, &arch)) {
        return COMMAND_INVALID_ARG;
    }

    if (pc->args.size == 2) {
        const char* size_str = (const char*)pc->args.head->next->data;
        if (!str_to_uint64(size_str, &nopcodes))
            return COMMAND_INVALID_ARG;
    } else {
        nopcodes = DEFAULT_DISAS_OPCODES;
    }

    // we are assuming that no opcodes has more than 10 bytes
    u64_t size = min(nopcodes * 10, fb->size - fb->off);
    bytes      = fb_read(fb, size);
    if (!bytes)
        return COMMAND_INVALID_ARG;
    do_disas(arch, fb->off, bytes, size, nopcodes);
    return COMMAND_OK;
}

Cmd* disascmd_create(void)
{
    Cmd* cmd   = bhex_malloc(sizeof(Cmd));
    cmd->obj   = NULL;
    cmd->name  = "disas";
    cmd->alias = "ds";
    cmd->hint  = HINT_STR;

    cmd->dispose = disascmd_dispose;
    cmd->help    = disascmd_help;
    cmd->exec    = disascmd_exec;

    return cmd;
}

#endif
