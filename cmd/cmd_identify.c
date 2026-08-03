// Copyright (c) 2022-2026, bageyelet

#include "cmd_arg_handler.h"
#include "cmd_identify.h"
#include "../bhengine/vm.h"
#include "cmd.h"

#include <util/byte_to_num.h>

#include <stdlib.h>

#include <filebuffer.h>
#include <display.h>
#include <string.h>
#include <dlist.h>
#include <color.h>
#include <alloc.h>
#include <time.h>
#include <defs.h>
#include <log.h>

#define HINT_STR "[/l/v/n/e] [<len>]"

#define MODE_LIST      0
#define VERBOSE_SET    0
#define NOSKIP_SET     0
#define EXHAUSTIVE_SET 0

// How much of the file the prefilter reads at a time
#define PREFILTER_CHUNK (1u << 20)

// One template taking part in the scan
typedef struct IdentifyEntry {
    char*               name;
    BHEngineIdentifier* id;
    const DList*        magics; // of BHEngineMagic*, empty = no prefilter
    u64_t               nhits;
    u64_t               nanos; // only measured in verbose mode
} IdentifyEntry;

// A pattern, and the template that declared it
typedef struct PatternRef {
    const BHEngineMagic* magic;
    u64_t                entry;
} PatternRef;

// An offset worth running a template's "_identify" at
typedef struct Candidate {
    u64_t off;
    u64_t entry;
} Candidate;

// The prefilter: every declared pattern, bucketed by its first byte. One pass
// over the file then only has to memcmp the patterns sharing the byte it is
// looking at, which is almost never more than one. Aho-Corasick is the answer
// for hundreds of patterns; at a couple of dozen this is a table lookup per
// byte and no new dependency.
typedef struct Prefilter {
    DList* buckets[256]; // of PatternRef*
    u32_t  max_len;
    u64_t  max_off;
    u64_t  npatterns;
} Prefilter;

static void identifycmd_help(void* obj)
{
    display_printf(
        "identify: scan the file for known formats. One pass finds every magic\n"
        "          the templates declared ('" BHENGINE_IDENTIFY_MAGIC_PROC
        "'), and only where\n"
        "          one matched is a template asked ('" BHENGINE_IDENTIFY_PROC
        "')\n"
        "\n"
        "  id" HINT_STR "\n"
        "     l: list the templates that take part in the scan\n"
        "     v: report the time each template cost (measuring it is not "
        "free,\n"
        "        the scan itself gets slower)\n"
        "     n: do not skip over what was identified\n"
        "     e: exhaustive: ignore the declared magics and ask every "
        "template\n"
        "        at every offset. Comparing 'id/n' with 'id/n/e' is how a "
        "wrong\n"
        "        magic declaration gets caught\n"
        "\n"
        "  len: number of bytes to scan starting from the current offset\n"
        "       (if omitted, scan up to the end of the file)\n"
        "\n"
        "  A hit reports the size the template gave for what it recognised,\n"
        "  and the scan resumes past it -- so a format embedded in something\n"
        "  already identified is only found with '/n'\n");
}

static void IdentifyEntry_delete(void* o)
{
    IdentifyEntry* e = (IdentifyEntry*)o;
    bhengine_identifier_free(e->id);
    bhex_free(e->name);
    bhex_free(e);
}

static void collect_cb(const char* name, BHEngineIdentifier* id, void* user)
{
    IdentifyEntry* e = bhex_calloc(sizeof(IdentifyEntry));
    e->name          = bhex_strdup(name);
    e->id            = id;
    e->magics        = bhengine_identifier_magics(id);
    DList_add((DList*)user, e);
}

static void prefilter_init(Prefilter* pf, DList* entries)
{
    memset(pf, 0, sizeof(*pf));
    for (u64_t i = 0; i < entries->size; ++i) {
        const DList* magics = ((IdentifyEntry*)entries->data[i])->magics;
        for (u64_t j = 0; magics != NULL && j < magics->size; ++j) {
            const BHEngineMagic* m = (const BHEngineMagic*)magics->data[j];
            PatternRef*          p = bhex_calloc(sizeof(PatternRef));
            p->magic               = m;
            p->entry               = i;

            u8_t b = m->pattern[0];
            if (pf->buckets[b] == NULL)
                pf->buckets[b] = DList_new();
            DList_add(pf->buckets[b], p);

            if (m->size > pf->max_len)
                pf->max_len = m->size;
            if (m->offset > pf->max_off)
                pf->max_off = m->offset;
            pf->npatterns += 1;
        }
    }
}

static void prefilter_deinit(Prefilter* pf)
{
    for (int i = 0; i < 256; ++i)
        if (pf->buckets[i])
            DList_destroy(pf->buckets[i], bhex_free);
}

static int candidate_cmp(const void* a, const void* b)
{
    const Candidate* x = (const Candidate*)a;
    const Candidate* y = (const Candidate*)b;
    if (x->off != y->off)
        return x->off < y->off ? -1 : 1;
    if (x->entry != y->entry)
        return x->entry < y->entry ? -1 : 1;
    return 0;
}

// Walks [start, scan_end) once and returns the offsets at which some template
// is worth running, sorted and deduplicated. A pattern declared at offset N
// found at file offset X means that template's format may start at X - N.
static Candidate* prefilter_run(Prefilter* pf, FileBuffer* fb, u64_t start,
                                u64_t end_off, u64_t* o_ncands)
{
    *o_ncands = 0;
    if (pf->npatterns == 0)
        return NULL;

    // a match may point back by as much as the largest declared offset, so the
    // pass has to run past the end of the range the user asked for
    u64_t scan_end = end_off + pf->max_off + pf->max_len;
    if (scan_end > fb->size)
        scan_end = fb->size;

    DList*   cands = DList_new();
    FbReader reader;
    fb_reader_init(&reader, fb);

    u8_t* buf     = bhex_malloc(PREFILTER_CHUNK);
    u64_t overlap = pf->max_len > 1 ? pf->max_len - 1 : 0;
    u64_t pos     = start;

    while (pos < scan_end) {
        u64_t want = scan_end - pos;
        if (want > PREFILTER_CHUNK)
            want = PREFILTER_CHUNK;
        if (!fb_reader_read(&reader, pos, buf, want))
            break;

        for (u64_t i = 0; i < want; ++i) {
            DList* bucket = pf->buckets[buf[i]];
            if (bucket == NULL)
                continue;
            for (u64_t k = 0; k < bucket->size; ++k) {
                PatternRef*          p = (PatternRef*)bucket->data[k];
                const BHEngineMagic* m = p->magic;
                if (i + m->size > want)
                    continue; // re-examined from the next chunk
                if (memcmp(buf + i, m->pattern, m->size) != 0)
                    continue;

                u64_t hit = pos + i;
                if (hit < m->offset)
                    continue;
                u64_t cand = hit - m->offset;
                if (cand < start || cand >= end_off)
                    continue;

                Candidate* c = bhex_calloc(sizeof(Candidate));
                c->off       = cand;
                c->entry     = p->entry;
                DList_add(cands, c);
            }
        }

        if (want <= overlap)
            break;
        pos += want - overlap;
    }

    bhex_free(buf);
    fb_reader_deinit(&reader);

    // flatten into a sorted, deduplicated array: the scan walks it in order
    Candidate* out = NULL;
    u64_t      n   = 0;
    if (cands->size > 0) {
        out = bhex_malloc(sizeof(Candidate) * cands->size);
        for (u64_t i = 0; i < cands->size; ++i)
            out[i] = *(Candidate*)cands->data[i];
        qsort(out, cands->size, sizeof(Candidate), candidate_cmp);

        n = 1;
        for (u64_t i = 1; i < cands->size; ++i)
            if (candidate_cmp(&out[i], &out[n - 1]) != 0)
                out[n++] = out[i];
    }
    DList_destroy(cands, bhex_free);

    *o_ncands = n;
    return out;
}

static u64_t now_nanos(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64_t)ts.tv_sec * 1000000000ULL + (u64_t)ts.tv_nsec;
}

static int identifycmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;

    char* len_str = NULL;
    if (handle_args(pc, 1, 0, &len_str) != 0)
        return COMMAND_INVALID_ARG;

    int mode    = -1;
    int verbose = -1;
    int noskip  = -1;
    int exhaust = -1;
    if (handle_mods(pc, "l|v|n|e", &mode, &verbose, &noskip, &exhaust) != 0)
        return COMMAND_INVALID_MOD;

    // Two independent things, and keeping them apart is what makes either one
    // usable as a reference: '/e' drops the prefilter, '/n' drops the skip
    int exhaustive = exhaust == EXHAUSTIVE_SET;
    int no_skip    = noskip == NOSKIP_SET;

    // asked for here and not when the command was built: the VM scans the
    // template folders as it comes up, and a session that never identifies
    // anything should not pay for that
    BHEngineVM* vm = bhengine_vm_get();

    DList* entries = DList_new();
    bhengine_vm_iter_identifiers(vm, fb, collect_cb, entries);

    // declared up here so that the early exits below can share one cleanup
    Prefilter  pf      = {0};
    Candidate* cands   = NULL;
    u64_t      ncands  = 0;
    u64_t      prefilt = 0;
    DList*     brute   = DList_new();

    int r = COMMAND_OK;
    if (entries->size == 0) {
        warning("no template declares a '" BHENGINE_IDENTIFY_PROC "' proc");
        goto end;
    }

    if (mode == MODE_LIST) {
        display_printf("Templates taking part in the scan:\n");
        for (u64_t i = 0; i < entries->size; ++i) {
            IdentifyEntry* e = (IdentifyEntry*)entries->data[i];
            u64_t          n = e->magics ? e->magics->size : 0;
            if (n == 0) {
                // no magic to search for, so this one is tried everywhere and
                // sets the floor for the whole scan
                display_printf("  %-12s every offset\n", e->name);
                continue;
            }
            display_printf("  %-12s %llu magic pattern(s):", e->name, n);
            for (u64_t j = 0; j < n; ++j) {
                const BHEngineMagic* m =
                    (const BHEngineMagic*)e->magics->data[j];
                display_printf(" ");
                for (u32_t k = 0; k < m->size; ++k)
                    display_printf("%02x", m->pattern[k]);
                if (m->offset != 0)
                    display_printf("@+%llu", m->offset);
            }
            display_printf("\n");
        }
        goto end;
    }

    u64_t start = fb->off;
    u64_t len   = fb->size - start;
    if (len_str) {
        if (!str_to_uint64(len_str, &len)) {
            warning("not a number: '%s'", len_str);
            r = COMMAND_INVALID_ARG;
            goto end;
        }
        if (len > fb->size - start)
            len = fb->size - start;
    }
    u64_t end_off = start + len;

    // Templates with no declared magic have to be tried everywhere, which puts
    // a floor under the whole scan. Note nothing is lost by prefiltering the
    // others: an "_identify" re-checks its own magic, so the patterns only say
    // where it is worth asking
    for (u64_t i = 0; i < entries->size; ++i) {
        IdentifyEntry* e = (IdentifyEntry*)entries->data[i];
        if (exhaustive || e->magics == NULL || e->magics->size == 0)
            DList_add(brute, (void*)i);
    }

    // The identify procs are the ones reporting hits; nothing else they may
    // have to say is worth a million lines
    int saved_disable_warning = disable_warning;
    disable_warning           = 1;

    u64_t t0 = now_nanos();
    if (!exhaustive) {
        prefilter_init(&pf, entries);
        cands   = prefilter_run(&pf, fb, start, end_off, &ncands);
        prefilt = now_nanos() - t0;
    }

    u64_t nhits    = 0;
    u64_t noffsets = 0;
    u64_t nruns    = 0;
    u64_t off      = start;
    u64_t ci       = 0;

    // With nothing to ask at every offset, the walk starts at the first
    // candidate rather than at the beginning of the range -- and does not start
    // at all when there is none
    if (brute->size == 0)
        off = ncands > 0 ? cands[0].off : end_off;

    while (off < end_off) {
        // The largest region identified here: the scan resumes past it, so a
        // container hides the formats packed inside it. That is the deal the
        // skip buys, and '/n' is how to opt out of it
        u64_t skip = 0;

#define RUN_ENTRY(idx)                                                         \
    do {                                                                       \
        IdentifyEntry* e   = (IdentifyEntry*)entries->data[idx];               \
        u64_t          t   = verbose == VERBOSE_SET ? now_nanos() : 0;         \
        u64_t          hit = bhengine_identifier_run(e->id, off);              \
        if (verbose == VERBOSE_SET)                                            \
            e->nanos += now_nanos() - t;                                       \
        nruns += 1;                                                            \
        if (hit != 0) {                                                        \
            e->nhits += 1;                                                     \
            nhits += 1;                                                        \
            if (hit > skip)                                                    \
                skip = hit;                                                    \
            display_printf("  %s0x%08llx%s  %-12s %llu bytes\n",               \
                           color_str(COLOR_ADDR), off + fb->base_addr,         \
                           color_str(COLOR_RESET), e->name, hit);              \
        }                                                                      \
    } while (0)

        for (u64_t i = 0; i < brute->size; ++i)
            RUN_ENTRY((u64_t)(uptr_t)brute->data[i]);

        // the prefiltered templates, only where a pattern of theirs matched
        while (ci < ncands && cands[ci].off < off)
            ci += 1;
        while (ci < ncands && cands[ci].off == off) {
            RUN_ENTRY(cands[ci].entry);
            ci += 1;
        }
#undef RUN_ENTRY

        noffsets += 1;
        if (no_skip || skip == 0)
            skip = 1;
        // the skip comes from a template, so it is not to be trusted with the
        // arithmetic: clamp it instead of letting 'off' wrap around
        if (skip >= end_off - off)
            break;
        off += skip;

        if (brute->size == 0) {
            // nothing has to be asked at every offset, so walk candidate to
            // candidate instead of byte to byte
            while (ci < ncands && cands[ci].off < off)
                ci += 1;
            if (ci >= ncands)
                break;
            off = cands[ci].off;
        }
    }
    u64_t elapsed = now_nanos() - t0;

    disable_warning = saved_disable_warning;
    fb_seek(fb, start);

    display_printf("\n%llu hit%s in %llu byte%s, %llu template%s\n", nhits,
                   nhits == 1 ? "" : "s", len, len == 1 ? "" : "s",
                   entries->size, entries->size == 1 ? "" : "s");
    if (exhaustive) {
        display_printf("exhaustive: magics ignored, every template at every "
                       "offset\n");
    } else {
        display_printf("prefilter: %llu pattern%s -> %llu candidate%s in %.3fs",
                       pf.npatterns, pf.npatterns == 1 ? "" : "s", ncands,
                       ncands == 1 ? "" : "s", (double)prefilt / 1e9);
        if (brute->size > 0)
            display_printf(", %llu template%s with no magic (every offset)",
                           brute->size, brute->size == 1 ? "" : "s");
        display_printf("\n");
    }
    display_printf("%llu offsets, %llu runs in %.3fs", noffsets, nruns,
                   (double)elapsed / 1e9);
    if (nruns > 0 && elapsed > 0)
        display_printf(" (%.0f runs/s, %.0f ns/run)",
                       (double)nruns * 1e9 / (double)elapsed,
                       (double)elapsed / (double)nruns);
    display_printf("\n");

    if (verbose == VERBOSE_SET) {
        display_printf("\nPer template:\n");
        for (u64_t i = 0; i < entries->size; ++i) {
            IdentifyEntry* e = (IdentifyEntry*)entries->data[i];
            display_printf("  %-16s %8.3fs  %llu hits\n", e->name,
                           (double)e->nanos / 1e9, e->nhits);
        }
    }

end:
    prefilter_deinit(&pf);
    bhex_free(cands);
    DList_destroy(brute, NULL);
    DList_destroy(entries, IdentifyEntry_delete);
    return r;
}

static void identifycmd_dispose(void* obj) { (void)obj; }

Cmd* identifycmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "identify";
    cmd->alias = "id";
    cmd->hint  = HINT_STR;

    cmd->dispose = identifycmd_dispose;
    cmd->help    = identifycmd_help;
    cmd->exec    = identifycmd_exec;

    return cmd;
}
