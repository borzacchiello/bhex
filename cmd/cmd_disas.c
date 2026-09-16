// Copyright (c) 2022-2026, bageyelet

#ifndef DISABLE_CAPSTONE

#include "cmd_arg_handler.h"
#include "cmd_disas.h"

#include <disassemble/disassemble.h>
#include <util/byte_to_num.h>
#include <util/byte_to_str.h>
#include <util/str.h>
#include <display.h>
#include <unicode.h>
#include <color.h>
#include <stdlib.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#include <capstone/capstone.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

// with no count given the listing runs to the end of the function: to the
// first instruction that returns, or to the end of the file (or of what can
// be decoded) when there is none
#define DISAS_UNTIL_RETURN ((u64_t) - 1)

// the longest instruction of the supported architectures (x86 tops out at 15
// bytes), used to size the window read for a given number of opcodes
#define MAX_INSN_SIZE 16

// Branch arrows ("/a"): the gutter drawn between the opcode bytes and the
// mnemonic, where every branch whose target is printed too becomes a line
// going from the jump to the instruction it lands on.
//
// A lane is one column of the gutter, lane 0 being the one closest to the
// mnemonics. Nested branches need one lane each: past the last one, and for
// the branches whose target is not printed, only the marker of the direction
// is drawn
#define MAX_ARROW_LANES 5
// the lanes, the column of the direction markers, the column of the heads
#define MAX_GUTTER (MAX_ARROW_LANES + 2)
// how many branches can be given a lane: assigning them costs
// O(branches * MAX_ARROWS), and the cap sizes the scratch array. The arrows
// are drawn one block at a time (see do_disas), and a block holds at most
// fb_block_size bytes of code, so this is only reached by a block made of
// very short branches
#define MAX_ARROWS 1024

// The lines of the gutter are drawn cell by cell, a cell being one column of
// one row. What is kept of a cell is the set of directions the line leaves it
// towards: the glyph follows from them, and two lines meeting in the same cell
// merge into the one glyph that joins them -- which is what makes several
// branches landing on the same instruction read as a single line
#define DIR_UP    (1u << 0)
#define DIR_DOWN  (1u << 1)
#define DIR_LEFT  (1u << 2)
#define DIR_RIGHT (1u << 3)
#define DIR_COUNT (1u << 4)

static const char* const box_unicode[DIR_COUNT] = {
    [0]                                        = " ",
    [DIR_UP]                                   = "╵",
    [DIR_DOWN]                                 = "╷",
    [DIR_LEFT]                                 = "╴",
    [DIR_RIGHT]                                = "╶",
    [DIR_UP | DIR_DOWN]                        = "│",
    [DIR_LEFT | DIR_RIGHT]                     = "─",
    [DIR_DOWN | DIR_RIGHT]                     = "╭",
    [DIR_UP | DIR_RIGHT]                       = "╰",
    [DIR_DOWN | DIR_LEFT]                      = "╮",
    [DIR_UP | DIR_LEFT]                        = "╯",
    [DIR_UP | DIR_DOWN | DIR_RIGHT]            = "├",
    [DIR_UP | DIR_DOWN | DIR_LEFT]             = "┤",
    [DIR_UP | DIR_LEFT | DIR_RIGHT]            = "┴",
    [DIR_DOWN | DIR_LEFT | DIR_RIGHT]          = "┬",
    [DIR_UP | DIR_DOWN | DIR_LEFT | DIR_RIGHT] = "┼",
};

// ASCII has no glyph for a line joining a third one, so the junctions all
// become a '+'
static const char* const box_ascii[DIR_COUNT] = {
    [0]                                        = " ",
    [DIR_UP]                                   = "|",
    [DIR_DOWN]                                 = "|",
    [DIR_LEFT]                                 = "-",
    [DIR_RIGHT]                                = "-",
    [DIR_UP | DIR_DOWN]                        = "|",
    [DIR_LEFT | DIR_RIGHT]                     = "-",
    [DIR_DOWN | DIR_RIGHT]                     = "/",
    [DIR_UP | DIR_RIGHT]                       = "\\",
    [DIR_DOWN | DIR_LEFT]                      = "\\",
    [DIR_UP | DIR_LEFT]                        = "/",
    [DIR_UP | DIR_DOWN | DIR_RIGHT]            = "+",
    [DIR_UP | DIR_DOWN | DIR_LEFT]             = "+",
    [DIR_UP | DIR_LEFT | DIR_RIGHT]            = "+",
    [DIR_DOWN | DIR_LEFT | DIR_RIGHT]          = "+",
    [DIR_UP | DIR_DOWN | DIR_LEFT | DIR_RIGHT] = "+",
};

// The two rightmost columns of the gutter say what the lines are about, and
// are not lines themselves
typedef enum {
    MARK_NONE = 0,
    MARK_FROM, // the branch
    MARK_TO,   // the instruction it lands on
    MARK_DOWN, // a target further down, outside the listing
    MARK_UP,   // a target further up, outside the listing
    MARK_COUNT
} ArrowMark;

static const char* const marks_unicode[MARK_COUNT] = {" ", "◂", "▸", "▾", "▴"};
static const char* const marks_ascii[MARK_COUNT]   = {" ", "<", ">", "v", "^"};

// the longest glyph of the tables above takes three bytes
#define MAX_GUTTER_BYTES (MAX_GUTTER * 3 + 1)

// The operands are printed at a fixed column, so that they line up no matter
// how long the mnemonics of the architecture are. The column is computed on
// the listing being printed: architectures with short mnemonics (x86) do not
// pay for the ones with long mnemonics (m68k, and its size suffixes). The
// bounds keep the listing stable when a single instruction is printed, and
// stop an outlier (e.g. an AVX-512 mnemonic) from pushing everything right:
// the few instructions longer than the max simply overflow the column
#define MNEMONIC_MIN_WIDTH 7
#define MNEMONIC_MAX_WIDTH 16

#define HINT_STR "[/l [<filter>]|/a/o] <arch> [<nbytes>]"

typedef struct {
    const char* name;
    const char* descr;
    cs_arch     arch;
    cs_mode     mode;
} CapstoneArchInfo;

/*
   Every architecture capstone can decode, mirrored from its own cstool table
   so that a submodule bump cannot leave bhex naming an instruction set that
   capstone has renamed or re-tuned. Regenerate with:

       scripts/gen_disas_archs.py

   The names bhex has always had come first and keep their meaning even where
   capstone now uses the same string for something else; see the generated
   file for which those are.
*/
static const CapstoneArchInfo map_arch[] = {
#include "disas_archs.inc"
};

#define N_ARCHS (sizeof(map_arch) / sizeof(map_arch[0]))

static void disascmd_help(void* obj)
{
    (void)obj;

    // the drawings are the ones the output can carry, so that the help shows
    // what will really be printed
    const char* const* marks = unicode_enabled() ? marks_unicode : marks_ascii;

    display_printf(
        "disas: disassemble code at current offset\n"
        "\n"
        "  ds" HINT_STR "\n"
        "     l:  list the supported architectures, or those <filter>\n"
        "         names: the one called that, else the ones starting\n"
        "         with it, else the ones mentioning it anywhere\n"
        "     a:  draw the branches as arrows on the left of the mnemonics.\n"
        "         '%s' marks a jump, '%s' where it lands, '%s' and '%s' a\n"
        "         target that is not part of the listing\n"
        "     o:  print the bytes of every instruction\n"
        "\n"
        "  arch:   the architecture to use\n"
        "  nbytes: number of opcodes to disassemble (default: up to the\n"
        "          instruction that returns)\n",
        marks[MARK_FROM], marks[MARK_TO], marks[MARK_DOWN], marks[MARK_UP]);
}

static void disascmd_dispose(void* obj) { (void)obj; }

// The table read by name, on str_pick_tier()'s terms: "sh" is the one SuperH
// SH1 entry rather than the eighteen names it appears in, and "arm" is ARM
// rather than every name with "arm" in it
static const char* arch_name_at(size_t i, void* ctx)
{
    (void)ctx;
    return map_arch[i].name;
}

// Whether `a` belongs in a "ds/l <query>" listing read at `tier`. A NULL
// query lists everything.
//
// The description is searched only at the widest tier, where the question
// being asked is already a vague one ("ds/l endian", "ds/l thumb"): matching
// it any earlier would let a word in someone else's description outrank a
// name that is spelled exactly right.
static int arch_matches(const CapstoneArchInfo* a, const char* query,
                        MatchTier tier)
{
    if (query == NULL)
        return 1;
    if (str_matches_at(a->name, query, tier))
        return 1;
    return tier == MATCH_ANYWHERE && stristr(a->descr, query) != NULL;
}

static int parse_arch(const char* a, int* out_arch)
{
    size_t i;
    for (i = 0; i < N_ARCHS; ++i) {
        if (strcmp(map_arch[i].name, a) == 0) {
            *out_arch = (int)i;
            return 1;
        }
    }
    return 0;
}

static const char* bytes_str(const cs_insn* insn, size_t max_size)
{
    static char disas[16 * 3 + 1];
    size_t      i   = 0;
    size_t      off = 0;

    if (max_size >= sizeof(disas) || max_size < 3)
        panic("invalid max_size");

    while (off < insn->size) {
        if (i + 3 >= max_size - 2 && off != (size_t)insn->size - 1) {
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

// The instructions that alter the control flow are painted differently, so
// that the shape of the code (where it branches, calls and returns) can be
// seen without reading every mnemonic. Capstone tells them apart only in
// detail mode, which is why it is requested -- and only when it is of use
static Color mnemonic_color(csh handle, const cs_insn* insn, int detail)
{
    static const int flow_groups[] = {CS_GRP_JUMP, CS_GRP_CALL,
                                      CS_GRP_RET,  CS_GRP_INT,
                                      CS_GRP_IRET, CS_GRP_BRANCH_RELATIVE};

    // the details are always asked for now, so this is where the group
    // lookups are skipped when nothing would be painted with them
    if (!detail || insn->detail == NULL || !colors_enabled())
        return COLOR_MNEMONIC;

    for (size_t i = 0; i < sizeof(flow_groups) / sizeof(flow_groups[0]); ++i)
        if (cs_insn_group(handle, insn, (unsigned int)flow_groups[i]))
            return COLOR_MNEMONIC_FLOW;
    return COLOR_MNEMONIC;
}

static size_t mnemonic_width(const cs_insn* insn, size_t count)
{
    size_t width = MNEMONIC_MIN_WIDTH;
    for (size_t i = 0; i < count; ++i) {
        size_t len = strlen(insn[i].mnemonic);
        if (len > width)
            width = len;
    }
    return min(width, (size_t)MNEMONIC_MAX_WIDTH);
}

// Whether the instruction can send the execution somewhere else than the next
// instruction. The returns are left out on purpose: they do have a target,
// but not one that is known while disassembling
static int is_branch(csh handle, const cs_insn* insn)
{
    return cs_insn_group(handle, insn, CS_GRP_JUMP) ||
           cs_insn_group(handle, insn, CS_GRP_CALL) ||
           cs_insn_group(handle, insn, CS_GRP_BRANCH_RELATIVE);
}

// The address a branch jumps to, when it is a fixed one (an indirect jump
// through a register has no target here, and gets no arrow).
//
// Capstone has no architecture independent way of reading the value of an
// operand -- cs_op_count() and cs_op_index() only count them, the values live
// in the per architecture union -- hence the switch. Every architecture but
// m68k resolves the target to an absolute address in its last immediate
// operand; m68k keeps it as a displacement from the word that follows the
// opcode. The type of the immediate operands is CS_OP_IMM for all of them
static int branch_target(cs_arch arch, const cs_insn* insn, u64_t* out)
{
    const cs_detail* d = insn->detail;
    if (d == NULL)
        return 0;

    // the target is the *last* immediate: the conditional branches of several
    // architectures name the register or the condition they test first
#define LAST_IMM(arch_field)                                                   \
    do {                                                                       \
        for (int i = (int)d->arch_field.op_count - 1; i >= 0; --i)             \
            if ((int)d->arch_field.operands[i].type == (int)CS_OP_IMM) {       \
                *out = (u64_t)d->arch_field.operands[i].imm;                   \
                return 1;                                                      \
            }                                                                  \
    } while (0)

    switch (arch) {
        case CS_ARCH_X86:
            LAST_IMM(x86);
            break;
        case CS_ARCH_ARM:
            LAST_IMM(arm);
            break;
        case CS_ARCH_AARCH64:
            LAST_IMM(aarch64);
            break;
        case CS_ARCH_MIPS:
            LAST_IMM(mips);
            break;
        case CS_ARCH_PPC:
            LAST_IMM(ppc);
            break;
        case CS_ARCH_RISCV:
            LAST_IMM(riscv);
            break;
        case CS_ARCH_SPARC:
            LAST_IMM(sparc);
            break;
        case CS_ARCH_SYSTEMZ:
            LAST_IMM(systemz);
            break;
        case CS_ARCH_ALPHA:
            LAST_IMM(alpha);
            break;
        case CS_ARCH_LOONGARCH:
            LAST_IMM(loongarch);
            break;
        case CS_ARCH_ARC:
            LAST_IMM(arc);
            break;
        case CS_ARCH_M68K:
            for (int i = (int)d->m68k.op_count - 1; i >= 0; --i)
                if (d->m68k.operands[i].type == M68K_OP_BR_DISP) {
                    // the program counter of a m68k branch is the address of
                    // the instruction plus the size of its opcode word
                    *out = insn->address + 2 +
                           (u64_t)(s64_t)d->m68k.operands[i].br_disp.disp;
                    return 1;
                }
            break;
        default:
            /*
               No arrow, for one of three reasons.

               bpf/ebpf, tricore, tms320c64x and xcore never get here at all:
               capstone reports no group for their jumps, so is_branch() does
               not let them through.

               evm and wasm have no branch with an address in it to begin
               with -- they jump to a value on the stack, or to the end of a
               structured block.

               The rest are reached but say where they go in a way this
               cannot read: xtensa's immediate is a displacement rather than
               the address capstone prints ("j . +5"), sh keeps a
               displacement too, and mos65xx, m680x and hppa put the target
               somewhere other than an operand of type CS_OP_IMM. Drawing
               those would mean resolving each one, and an arrow to the wrong
               instruction is worse than no arrow
            */
            break;
    }

#undef LAST_IMM
    return 0;
}

// One branch to draw. The rows are indexes in the printed listing
typedef struct {
    size_t src_row; // the branch itself
    size_t dst_row; // the instruction it lands on, when it is printed
    int    lane;    // -1 when only the direction marker is drawn
    int    off;     // the target is not printed (or no lane was left for it)
    int    down;    // the target is at a higher address
} Arrow;

static size_t arrow_top(const Arrow* a) { return min(a->src_row, a->dst_row); }

static size_t arrow_bottom(const Arrow* a)
{
    return a->src_row > a->dst_row ? a->src_row : a->dst_row;
}

static int arrows_overlap(const Arrow* a, const Arrow* b)
{
    return arrow_top(a) <= arrow_bottom(b) && arrow_top(b) <= arrow_bottom(a);
}

// The short branches are given the lanes closest to the code, so that the
// nesting of the listing can be seen: the ordering is what does it, the
// assignment below just takes the first lane that is free
static int arrow_cmp(const void* pa, const void* pb)
{
    const Arrow* a     = (const Arrow*)pa;
    const Arrow* b     = (const Arrow*)pb;
    size_t       spana = arrow_bottom(a) - arrow_top(a);
    size_t       spanb = arrow_bottom(b) - arrow_top(b);

    if (spana != spanb)
        return spana < spanb ? -1 : 1;
    if (a->src_row != b->src_row)
        return a->src_row < b->src_row ? -1 : 1;
    return 0;
}

// The row of the instruction starting at `addr`, or `nrows` when none does:
// either the address is not part of the listing, or it lands inside an
// instruction rather than on one. The listing is ordered by address
static size_t row_of(const cs_insn* insn, size_t nrows, u64_t addr)
{
    size_t lo = 0;
    size_t hi = nrows;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (insn[mid].address == addr)
            return mid;
        if (insn[mid].address < addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    return nrows;
}

// Every printed instruction branches at most once, so there can be no more
// arrows than rows
static size_t collect_arrows(csh handle, cs_arch arch, const cs_insn* insn,
                             size_t nrows, Arrow* out)
{
    size_t n = 0;
    for (size_t row = 0; row < nrows; ++row) {
        u64_t target;
        if (!is_branch(handle, &insn[row]) ||
            !branch_target(arch, &insn[row], &target))
            continue;

        size_t dst = row_of(insn, nrows, target);
        Arrow  a   = {.src_row = row,
                      .dst_row = dst == nrows ? row : dst,
                      .lane    = -1,
                      .off     = dst == nrows,
                      .down    = target > insn[row].address};
        out[n++]   = a;
    }
    return n;
}

// Spread the arrows over the lanes, so that two of them that span a common row
// never share one. What does not fit keeps its direction marker only
static void assign_lanes(Arrow* arrows, size_t narrows, size_t* out_nlanes,
                         int* out_markers)
{
    size_t placed[MAX_ARROWS];
    size_t nplaced = 0;
    size_t nlanes  = 0;

    *out_markers = 0;
    qsort(arrows, narrows, sizeof(Arrow), arrow_cmp);

    for (size_t i = 0; i < narrows; ++i) {
        if (arrows[i].off || nplaced == MAX_ARROWS) {
            arrows[i].off = 1;
            *out_markers  = 1;
            continue;
        }

        unsigned taken = 0;
        for (size_t k = 0; k < nplaced; ++k) {
            const Arrow* other = &arrows[placed[k]];
            if (arrows_overlap(&arrows[i], other))
                taken |= 1u << other->lane;
        }

        for (int lane = 0; lane < MAX_ARROW_LANES; ++lane)
            if (!(taken & (1u << lane))) {
                arrows[i].lane = lane;
                if ((size_t)lane + 1 > nlanes)
                    nlanes = (size_t)lane + 1;
                placed[nplaced++] = i;
                break;
            }

        if (arrows[i].lane < 0) {
            arrows[i].off = 1;
            *out_markers  = 1;
        }
    }

    *out_nlanes = nlanes;
}

// The gutter of one row, `width` columns into `buf`, which must hold
// MAX_GUTTER_BYTES. `lane[]` holds the arrow crossing this row in every lane
// (NULL where none does), `marker` says where an off-listing branch starting
// here is going
static const char* render_gutter(char* buf, size_t width, size_t nlanes,
                                 size_t row, const Arrow* const* lane,
                                 ArrowMark marker)
{
    const char* const* box   = unicode_enabled() ? box_unicode : box_ascii;
    const char* const* marks = unicode_enabled() ? marks_unicode : marks_ascii;

    unsigned lines[MAX_GUTTER]    = {0};
    int      crossing[MAX_GUTTER] = {0};

    // the arrows that turn towards the code in this row: their corner, and the
    // line running from it to the mnemonics. The directions are merged rather
    // than written over each other, so that the arrows meeting here join
    for (size_t l = 0; l < nlanes; ++l) {
        const Arrow* a = lane[l];
        if (a == NULL)
            continue;

        size_t col = nlanes - 1 - l;
        if (row != arrow_top(a) && row != arrow_bottom(a)) {
            // this one is only passing through, and gives way to the lines
            // that are turning: an arrow crossing them would break them
            crossing[col] = 1;
            continue;
        }
        lines[col] |= DIR_RIGHT | (row == arrow_top(a) ? DIR_DOWN : DIR_UP);
        for (size_t c = col + 1; c + 1 < width; ++c)
            lines[c] |= DIR_LEFT | DIR_RIGHT;
    }

    // an instruction that is both jumped to and jumping is marked as a target:
    // that it branches is already written in its mnemonic, that the execution
    // can land on it would be nowhere to be seen
    ArrowMark head = marker != MARK_NONE ? MARK_FROM : MARK_NONE;
    for (size_t l = 0; l < nlanes; ++l) {
        if (lane[l] == NULL)
            continue;
        if (lane[l]->dst_row == row) {
            head = MARK_TO;
            break;
        }
        if (lane[l]->src_row == row)
            head = MARK_FROM;
    }

    size_t off = 0;
    for (size_t c = 0; c < width; ++c) {
        const char* glyph;
        if (c + 1 == width)
            glyph = marks[head];
        else if (c + 2 == width && marker != MARK_NONE)
            // the marker column only exists when some arrow needs it, and then
            // it is the one right before the heads
            glyph = marks[marker];
        else if (lines[c] != 0)
            glyph = box[lines[c]];
        else
            glyph = crossing[c] ? box[DIR_UP | DIR_DOWN] : box[0];

        size_t n = strlen(glyph);
        memcpy(buf + off, glyph, n);
        off += n;
    }
    buf[off] = 0;

    return buf;
}

#define NO_ARROW ((size_t)-1)

// The arrows of one listing, indexed so that it can be printed in a single
// pass: an arrow is looked up by the row it starts at, its lane is taken when
// that row is reached and given back once its last row is printed
typedef struct {
    Arrow*     arrows;
    size_t     narrows;
    size_t*    row_first;  // per row: first arrow starting there, or NO_ARROW
    size_t*    next;       // per arrow: next one starting at the same row
    ArrowMark* row_marker; // per row: where an off-listing branch goes, if any
    size_t     nlanes;
    size_t     width; // columns of the gutter, 0 when there is nothing to draw
    const Arrow* lane[MAX_ARROW_LANES];
} Gutter;

static void gutter_dispose(Gutter* g)
{
    bhex_free(g->arrows);
    bhex_free(g->row_first);
    bhex_free(g->next);
    bhex_free(g->row_marker);
    memset(g, 0, sizeof(*g));
}

// Returns the width of the gutter, zero when the listing holds no branch: a
// listing of straight line code is then printed exactly as it is without "/a".
//
// `fixed` asks for the whole gutter (every lane, plus the column of the
// markers) whatever this block happens to hold: a listing printed block by
// block would otherwise have its mnemonics move sideways from one block to
// the next, as the number of lanes in use changes
static size_t gutter_init(Gutter* g, csh handle, cs_arch arch,
                          const cs_insn* insn, size_t nrows, int fixed)
{
    memset(g, 0, sizeof(*g));
    if (nrows == 0)
        return 0;

    g->arrows  = bhex_malloc(nrows * sizeof(Arrow));
    g->narrows = collect_arrows(handle, arch, insn, nrows, g->arrows);
    if (g->narrows == 0 && !fixed) {
        gutter_dispose(g);
        return 0;
    }

    int markers = 0;
    assign_lanes(g->arrows, g->narrows, &g->nlanes, &markers);
    if (fixed) {
        g->nlanes = MAX_ARROW_LANES;
        g->width  = MAX_GUTTER;
    } else {
        g->width = g->nlanes + (markers ? 1 : 0) + 1;
    }

    g->row_first  = bhex_malloc(nrows * sizeof(size_t));
    g->next       = bhex_malloc((g->narrows ? g->narrows : 1) * sizeof(size_t));
    g->row_marker = bhex_calloc(nrows * sizeof(ArrowMark));
    for (size_t r = 0; r < nrows; ++r)
        g->row_first[r] = NO_ARROW;

    for (size_t i = 0; i < g->narrows; ++i) {
        const Arrow* a = &g->arrows[i];
        g->next[i]     = NO_ARROW;
        if (a->off) {
            g->row_marker[a->src_row] = a->down ? MARK_DOWN : MARK_UP;
            continue;
        }
        size_t top        = arrow_top(a);
        g->next[i]        = g->row_first[top];
        g->row_first[top] = i;
    }

    return g->width;
}

// The gutter of `row`, into a buffer of at least MAX_GUTTER_BYTES. The rows
// must be asked for in order, as the lanes are tracked along the way
static const char* gutter_row(Gutter* g, size_t row, char* buf)
{
    for (size_t i = g->row_first[row]; i != NO_ARROW; i = g->next[i])
        g->lane[g->arrows[i].lane] = &g->arrows[i];

    const char* r = render_gutter(buf, g->width, g->nlanes, row, g->lane,
                                  g->row_marker[row]);

    for (size_t l = 0; l < g->nlanes; ++l)
        if (g->lane[l] != NULL && arrow_bottom(g->lane[l]) == row)
            g->lane[l] = NULL;

    return r;
}

// What has to stay the same from the first row of a listing to the last, and
// is therefore decided once rather than per block (see do_disas)
typedef struct {
    csh     handle;
    cs_arch arch;
    cs_mode mode;
    int     detail;
    int     arrows;
    int     opcodes;
    size_t  mnemonic_width;
    int     fixed_gutter;
} DisasCtx;

// The row a listing that runs to the end of the function stops at: the index
// of the first instruction that returns, or `nrows` when this block holds
// none
static size_t first_return(const DisasCtx* ctx, const cs_insn* insn,
                           size_t nrows)
{
    for (size_t i = 0; i < nrows; ++i)
        if (disas_is_return(ctx->arch, ctx->handle, &insn[i]))
            return i;
    return nrows;
}

static void print_block(const DisasCtx* ctx, const cs_insn* insn, size_t nrows)
{
    Gutter gutter;
    char   gutter_buf[MAX_GUTTER_BYTES];
    size_t gutter_width = 0;

    if (ctx->arrows && ctx->detail)
        gutter_width = gutter_init(&gutter, ctx->handle, ctx->arch, insn, nrows,
                                   ctx->fixed_gutter);

    size_t width = ctx->mnemonic_width;
    for (size_t j = 0; j < nrows; j++) {
        Color  mnemonic = mnemonic_color(ctx->handle, &insn[j], ctx->detail);
        size_t len      = strlen(insn[j].mnemonic);

        display_printf("%s0x%08llx:%s ", color_str(COLOR_ADDR),
                       (u64_t)insn[j].address, color_str(COLOR_RESET));
        if (ctx->opcodes)
            display_printf("%s%s%s ", color_str(COLOR_HEADER),
                           bytes_str(&insn[j], 21), color_str(COLOR_RESET));
        if (gutter_width > 0)
            display_printf("%s%s%s ", color_str(COLOR_MNEMONIC_FLOW),
                           gutter_row(&gutter, j, gutter_buf),
                           color_str(COLOR_RESET));

        // the color escapes have no width on screen: the mnemonic is
        // padded by hand, a format width would count them in
        display_printf("%s%s%s", color_str(mnemonic), insn[j].mnemonic,
                       color_str(COLOR_RESET));
        if (insn[j].op_str[0] != '\0')
            display_printf("%*s%s", (int)(len < width ? width - len : 0) + 1,
                           "", insn[j].op_str);

        // an operand counted from the program counter says nothing about
        // where it lands: the address it resolves to is printed as a comment
        u64_t target;
        if (disas_pc_relative(ctx->arch, ctx->mode, ctx->handle, &insn[j],
                              &target))
            display_printf(" %s; 0x%08llx%s", color_str(COLOR_HEADER), target,
                           color_str(COLOR_RESET));
        display_printf("\n");
    }

    if (gutter_width > 0)
        gutter_dispose(&gutter);
}

// A listing is read, disassembled and printed one block at a time, a block
// being as much code as a single fb_read() can serve: asking for a million
// instructions costs the same memory as asking for eight, and the rows start
// appearing without waiting for the last block to be read.
//
// A block ends at an arbitrary byte, so its last instruction may be one that
// the cut has truncated into something that still decodes: unless the block
// ends with the file, that instruction is left out and decoded again as the
// first one of the next block.
//
// What a block does not see is the rest of the listing, which is what "/a"
// costs here: a branch is drawn as a line only when its target is part of the
// same block, and gets the marker of its direction when it is not.
//
// `nopcodes` of DISAS_UNTIL_RETURN asks for the function rather than for a
// number of rows: the listing then ends with the first instruction that gives
// control back to the caller, which is one thing per architecture (see
// common/disassemble)
static int do_disas(int arch, FileBuffer* fb, u64_t nopcodes, int arrows,
                    int opcodes)
{
    csh handle;
    if (cs_open(map_arch[arch].arch, map_arch[arch].mode, &handle) !=
        CS_ERR_OK) {
        error("unable to disassemble with given arch, maybe it is not "
              "included in your capstone version");
        return COMMAND_INTERNAL_ERROR;
    }

    // the details are what the pc-relative operands are resolved from, what
    // says where a branch goes and what tells a return from the rest, so
    // every listing needs them
    int until_ret = nopcodes == DISAS_UNTIL_RETURN;
    int detail    = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;

    DisasCtx ctx = {.handle         = handle,
                    .arch           = map_arch[arch].arch,
                    .mode           = map_arch[arch].mode,
                    .detail         = detail,
                    .arrows         = arrows,
                    .opcodes        = opcodes,
                    .mnemonic_width = MNEMONIC_MIN_WIDTH,
                    .fixed_gutter   = 0};

    int   r       = COMMAND_OK;
    u64_t off     = fb->off;
    u64_t printed = 0;
    // rows left to print once the return was found, zero while it was not
    size_t tail = 0;

    while (printed < nopcodes && off < fb->size) {
        u64_t remaining = nopcodes - printed;
        // assume max instruction size <= MAX_INSN_SIZE bytes for sizing the
        // input window: reading more than the remaining opcodes can possibly
        // need would only be thrown away. An instruction longer than that
        // simply makes the block yield fewer rows, and the loop reads again
        u64_t size = min((u64_t)fb_block_size, fb->size - off);
        if (remaining < (u64_t)fb_block_size)
            size = min(size, remaining * MAX_INSN_SIZE);

        const u8_t* code = fb_read_at(fb, off, size);
        if (code == NULL) {
            // the file shrank under us, and fb_read_at() said so
            r = COMMAND_INTERNAL_ERROR;
            break;
        }

        cs_insn* insn;
        size_t   count =
            cs_disasm(handle, code, size, off + fb->base_addr, 0, &insn);
        if (count == 0) {
            // nothing decodes at this address, so the listing stops here,
            // short of what was asked for: say it, rather than leaving the
            // rows that were printed looking like the whole answer
            display_printf("%sinvalid%s\n", color_str(COLOR_HIGHLIGHT),
                           color_str(COLOR_RESET));
            break;
        }

        int    is_last = off + size >= fb->size;
        size_t usable  = (!is_last && count > 1) ? count - 1 : count;
        size_t nrows   = min(usable, remaining);
        int    done    = 0;

        if (until_ret) {
            if (tail == 0) {
                size_t i = first_return(&ctx, insn, nrows);
                if (i < nrows)
                    // the return, and what its delay slot still owes it: the
                    // slot can fall in the next block, hence the counter
                    tail = i + 1 +
                           disas_delay_slots(ctx.arch, ctx.handle, &insn[i]);
            }
            if (tail != 0) {
                nrows = min(nrows, tail);
                tail -= nrows;
                done = tail == 0;
            }
        }

        if (printed == 0) {
            ctx.mnemonic_width = mnemonic_width(insn, nrows);
            // a listing that fits in one block is printed as it always was:
            // the gutter is the one the listing needs, no wider
            ctx.fixed_gutter = !done && !is_last && nrows < remaining;
        }

        print_block(&ctx, insn, nrows);

        printed += nrows;
        off = insn[nrows - 1].address + insn[nrows - 1].size - fb->base_addr;
        cs_free(insn, count);

        if (done)
            break;
    }

    cs_close(&handle);
    return r;
}

#define MOD_UNSET -1
#define MOD_SET   0

static int disascmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;

    int list_archs = MOD_UNSET;
    int arrows     = MOD_UNSET;
    int opcodes    = MOD_UNSET;
    if (handle_mods(pc, "l|a|o", &list_archs, &arrows, &opcodes) != 0)
        return COMMAND_INVALID_MOD;

    // listing the architectures and disassembling are two different things to
    // ask for: "ds/l/a" is a mistake, not a listing
    if (list_archs == MOD_SET && (arrows == MOD_SET || opcodes == MOD_SET))
        return COMMAND_INVALID_MOD;

    if (list_archs == MOD_SET) {
        // a couple of hundred names is more than anyone wants to read to find
        // "the arm ones", so the listing takes an optional filter
        char* query = NULL;
        if (handle_args(pc, 1, 0, &query) != 0)
            return COMMAND_INVALID_ARG;

        MatchTier tier = query
                             ? str_pick_tier(query, N_ARCHS, arch_name_at, NULL)
                             : MATCH_ANYWHERE;
        size_t    width  = 0;
        size_t    nmatch = 0;
        for (size_t i = 0; i < N_ARCHS; ++i) {
            if (!arch_matches(&map_arch[i], query, tier))
                continue;
            size_t l = strlen(map_arch[i].name);
            if (l > width)
                width = l;
            nmatch += 1;
        }

        if (nmatch == 0) {
            warning("no architecture matches '%s'", query);
            return COMMAND_OK;
        }

        // the name alone is not enough to pick one by: "tc161" and "hd6309"
        // say nothing on their own
        if (query == NULL)
            display_printf("Supported architectures (%zu):\n", N_ARCHS);
        else
            display_printf(
                "Supported architectures matching '%s' (%zu of %zu):\n", query,
                nmatch, N_ARCHS);
        for (size_t i = 0; i < N_ARCHS; ++i)
            if (arch_matches(&map_arch[i], query, tier))
                display_printf("    %s%-*s%s  %s\n", color_str(COLOR_CMD),
                               (int)width, map_arch[i].name,
                               color_str(COLOR_RESET), map_arch[i].descr);
        return COMMAND_OK;
    }

    if (pc->args.size != 1 && pc->args.size != 2)
        return COMMAND_INVALID_ARG;

    int         arch     = 0;
    u64_t       nopcodes = DISAS_UNTIL_RETURN;
    const char* arch_str = (const char*)pc->args.head->data;

    if (!parse_arch(arch_str, &arch))
        return COMMAND_INVALID_ARG;

    if (pc->args.size == 2) {
        const char* size_str = (const char*)pc->args.head->next->data;
        if (!str_to_uint64(size_str, &nopcodes) || nopcodes == 0)
            return COMMAND_INVALID_ARG;
    }

    if (fb->off >= fb->size)
        return COMMAND_INVALID_ARG;

    return do_disas(arch, fb, nopcodes, arrows == MOD_SET, opcodes == MOD_SET);
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
