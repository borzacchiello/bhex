// Copyright (c) 2022-2026, bageyelet

#include "cmd_isa_identify.h"
#include "cmd_arg_handler.h"

#include <alloc.h>
#include <display.h>
#include <log.h>
#include <ml/binexec.h>
#include <ml/isadetect.h>
#include <ml/model_locator.h>
#include <ml/rf_model.h>
#include <util/byte_to_num.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HINT_STR           "[/g] [<size>]"
#define ISA_MODEL_NAME     "isadetect_model.bin"
#define BINEXEC_MODEL_NAME "binexec_model_1024.bin"
#define ISA_TOPK           3
#define GRAPH_ARCH_WIDTH   8

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    isadetect_model_t* isa_model;
    binexec_model_t*   binexec_model;
    char               isa_model_path[PATH_MAX];
    char               binexec_model_path[PATH_MAX];
} IsaIdentifyCmdCtx;

typedef struct {
    int         label;
    double      probability;
    const char* architecture;
    const char* endianness;
    int         wordsize;
    const char* display_name;
} RankedPrediction;

static void isa_identifycmd_help(void* obj)
{
    (void)obj;
    display_printf(
        "isa_identify: identify the ISA of a block of bytes using bundled "
        "AI models\n"
        "\n"
        "  ii" HINT_STR "\n"
        "     g:  graph mode; scan the input in 1024-byte chunks, detect code "
        "ranges\n"
        "\n"
        "  size: number of bytes to analyze starting from the current "
        "offset\n"
        "        (if omitted, use the whole file)\n");
}

static void isa_identifycmd_dispose(IsaIdentifyCmdCtx* ctx)
{
    if (ctx->isa_model != NULL) {
        isadetect_model_free(ctx->isa_model);
    }
    if (ctx->binexec_model != NULL) {
        binexec_model_free(ctx->binexec_model);
    }
    bhex_free(ctx);
}

static int ensure_isa_model_loaded(IsaIdentifyCmdCtx* ctx)
{
    int rc;

    if (ctx->isa_model != NULL) {
        return 1;
    }

    if (!bhex_model_resolve_path(ctx->isa_model_path,
                                 sizeof(ctx->isa_model_path), ISA_MODEL_NAME)) {
        error("unable to find ISA model '%s'", ISA_MODEL_NAME);
        return 0;
    }

    rc = isadetect_model_load(&ctx->isa_model, ctx->isa_model_path);
    if (rc != ISADETECT_OK) {
        error("unable to load ISA model '%s': %s", ctx->isa_model_path,
              bhex_ml_err_to_string(rc));
        ctx->isa_model = NULL;
        return 0;
    }

    return 1;
}

static int ensure_binexec_model_loaded(IsaIdentifyCmdCtx* ctx)
{
    int rc;

    if (ctx->binexec_model != NULL) {
        return 1;
    }

    if (!bhex_model_resolve_path(ctx->binexec_model_path,
                                 sizeof(ctx->binexec_model_path),
                                 BINEXEC_MODEL_NAME)) {
        error("unable to find executable-content model '%s'",
              BINEXEC_MODEL_NAME);
        return 0;
    }

    rc = binexec_model_load(&ctx->binexec_model, ctx->binexec_model_path);
    if (rc != BINEXEC_OK) {
        error("unable to load executable-content model '%s': %s",
              ctx->binexec_model_path, bhex_ml_err_to_string(rc));
        ctx->binexec_model = NULL;
        return 0;
    }

    return 1;
}

static const char* map_to_bhex_arch(const char* architecture,
                                    const char* endianness, int wordsize)
{
    if (architecture == NULL || endianness == NULL)
        return NULL;

    if (strcmp(architecture, "amd64") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 64)
        return "x64";

    if (strcmp(architecture, "i386") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 32)
        return "x86";

    if (strcmp(architecture, "x32") == 0 && strcmp(endianness, "little") == 0 &&
        wordsize == 32)
        return "x86";

    if ((strcmp(architecture, "arm") == 0 ||
         strcmp(architecture, "armhf") == 0) &&
        strcmp(endianness, "little") == 0 && wordsize == 32)
        return "arm32";

    if (strcmp(architecture, "arm") == 0 && strcmp(endianness, "little") == 0 &&
        wordsize == 64)
        return "aarch64";

    if (strcmp(architecture, "m68k") == 0 && strcmp(endianness, "big") == 0 &&
        wordsize == 32)
        return "m68k";

    if (strcmp(architecture, "alpha") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 64)
        return "alpha";

    if (strcmp(architecture, "riscv") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 64)
        return "riscv64";

    if (strcmp(architecture, "mips") == 0 && strcmp(endianness, "big") == 0) {
        if (wordsize == 32)
            return "mips32";
        if (wordsize == 64)
            return "mips64";
    }

    if (strcmp(architecture, "mips") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 32)
        return "mipsel32";

    if (strcmp(architecture, "mips") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 64)
        return "mipsel64";

    if ((strcmp(architecture, "powerpc") == 0 ||
         strcmp(architecture, "powerpcspe") == 0) &&
        strcmp(endianness, "big") == 0) {
        if (wordsize == 32)
            return "ppc32";
        if (wordsize == 64)
            return "ppc64";
    }

    if (strcmp(architecture, "powerpc") == 0 &&
        strcmp(endianness, "little") == 0) {
        if (wordsize == 32)
            return "ppcle32";
        if (wordsize == 64)
            return "ppcle64";
    }

    if (strcmp(architecture, "s390x") == 0 && strcmp(endianness, "big") == 0 &&
        wordsize == 64)
        return "s390x";

    if (strcmp(architecture, "sparc") == 0 && strcmp(endianness, "big") == 0) {
        if (wordsize == 32)
            return "sparc";
        if (wordsize == 64)
            return "sparc64";
    }

    return NULL;
}

static int extract_features_from_fb(FileBuffer* fb, u64_t start, size_t size,
                                    double features[ISADETECT_NUM_FEATURES])
{
    isadetect_feature_extractor_t extractor;
    u64_t                         orig_off = fb->off;
    u64_t                         off      = start;
    u64_t                         end      = start + (u64_t)size;
    int                           rc       = ISADETECT_OK;

    isadetect_feature_extractor_init(&extractor);

    while (off < end) {
        size_t chunk =
            (size_t)((end - off) < (u64_t)fb_block_size ? (end - off)
                                                        : (u64_t)fb_block_size);
        const u8_t* data;

        if (fb_seek(fb, off) != 0) {
            rc = ISADETECT_ERR_IO;
            break;
        }

        data = fb_read(fb, chunk);
        if (data == NULL) {
            rc = ISADETECT_ERR_IO;
            break;
        }

        rc = isadetect_feature_extractor_update(&extractor, data, chunk);
        if (rc != ISADETECT_OK) {
            break;
        }

        off += chunk;
    }

    fb_seek(fb, orig_off);
    if (rc != ISADETECT_OK) {
        return rc;
    }

    return isadetect_feature_extractor_finalize(&extractor, features);
}

static int rank_predictions(const isadetect_model_t* model,
                            const double probabilities[ISADETECT_NUM_CLASSES],
                            RankedPrediction top[ISA_TOPK])
{
    int    used[ISADETECT_NUM_CLASSES] = {0};
    size_t rank;

    for (rank = 0; rank < ISA_TOPK; ++rank) {
        int         best_idx = -1;
        int         label;
        const char* architecture = NULL;
        const char* endianness   = NULL;
        int         wordsize     = 0;
        size_t      i;

        for (i = 0; i < ISADETECT_NUM_CLASSES; ++i) {
            if (used[i])
                continue;
            if (best_idx < 0 || probabilities[i] > probabilities[best_idx])
                best_idx = (int)i;
        }

        if (best_idx < 0)
            return ISADETECT_ERR_INVALID_INPUT;

        used[best_idx] = 1;

        if (isadetect_model_get_class_label(model, (size_t)best_idx, &label) !=
            ISADETECT_OK)
            return ISADETECT_ERR_INVALID_INPUT;

        if (isadetect_describe_label(label, &architecture, &endianness,
                                     &wordsize) != ISADETECT_OK) {
            architecture = "unknown";
            endianness   = "unknown";
            wordsize     = 0;
        }

        top[rank].label        = label;
        top[rank].probability  = probabilities[best_idx];
        top[rank].architecture = architecture;
        top[rank].endianness   = endianness;
        top[rank].wordsize     = wordsize;
        top[rank].display_name =
            map_to_bhex_arch(architecture, endianness, wordsize);
        if (top[rank].display_name == NULL)
            top[rank].display_name = architecture;
    }

    return ISADETECT_OK;
}

static int predict_topk_for_range(IsaIdentifyCmdCtx* ctx, FileBuffer* fb,
                                  u64_t start, size_t size,
                                  RankedPrediction top[ISA_TOPK])
{
    double features[ISADETECT_NUM_FEATURES];
    double probabilities[ISADETECT_NUM_CLASSES];
    int    rc;

    rc = extract_features_from_fb(fb, start, size, features);
    if (rc != ISADETECT_OK) {
        return rc;
    }

    rc = isadetect_model_predict_proba(ctx->isa_model, features, probabilities);
    if (rc != ISADETECT_OK) {
        return rc;
    }

    return rank_predictions(ctx->isa_model, probabilities, top);
}

static int classify_chunk_from_fb(IsaIdentifyCmdCtx* ctx, FileBuffer* fb,
                                  u64_t start, size_t size, int* contains_code)
{
    const u8_t* buffer;
    u64_t       orig_off = fb->off;
    int         rc;
    double      probability;

    if (fb_seek(fb, start) != 0) {
        return BINEXEC_ERR_IO;
    }

    buffer = fb_read(fb, size);
    if (buffer == NULL) {
        fb_seek(fb, orig_off);
        return BINEXEC_ERR_IO;
    }

    rc = binexec_chunk_contains_code(ctx->binexec_model, buffer, size,
                                     contains_code, &probability);
    fb_seek(fb, orig_off);
    return rc;
}

static const char* graph_endianness_name(const char* endianness)
{
    if (endianness == NULL)
        return "?";
    if (strcmp(endianness, "little") == 0)
        return "le";
    if (strcmp(endianness, "big") == 0)
        return "be";
    return endianness;
}

static int print_code_range(IsaIdentifyCmdCtx* ctx, FileBuffer* fb, u64_t start,
                            u64_t end)
{
    RankedPrediction top[ISA_TOPK];
    int              rc;

    rc = predict_topk_for_range(ctx, fb, start, (size_t)(end - start), top);
    if (rc != ISADETECT_OK) {
        error("ISA prediction failed for code range [0x%llx, 0x%llx): %s",
              (unsigned long long)start, (unsigned long long)end,
              bhex_ml_err_to_string(rc));
        return COMMAND_SILENT_ERROR;
    }

    display_printf(
        "  [0x%016llx, 0x%016llx): %*s, %s (confidence: %.2f%%)\n",
        (unsigned long long)start, (unsigned long long)end, GRAPH_ARCH_WIDTH,
        top[0].display_name != NULL ? top[0].display_name : "unknown",
        graph_endianness_name(top[0].endianness), top[0].probability * 100.0);

    return COMMAND_OK;
}

static int isa_identifycmd_exec_default(IsaIdentifyCmdCtx* ctx, FileBuffer* fb,
                                        u64_t start, size_t size)
{
    RankedPrediction top[ISA_TOPK];
    int              rc;
    size_t           i;

    rc = predict_topk_for_range(ctx, fb, start, size, top);
    if (rc != ISADETECT_OK) {
        error("ISA prediction failed: %s", bhex_ml_err_to_string(rc));
        return COMMAND_SILENT_ERROR;
    }

    display_printf("ISA identification (%zu bytes analyzed):\n", size);
    for (i = 0; i < ISA_TOPK; ++i) {
        display_printf(
            "  top %zu: %s, %s-endian (confidence: %.2f%%)\n", i + 1,
            top[i].display_name != NULL ? top[i].display_name : "unknown",
            top[i].endianness != NULL ? top[i].endianness : "unknown",
            top[i].probability * 100.0);
    }

    return COMMAND_OK;
}

typedef struct {
    int    contains_code;
    double probability;
} ChunkClassification;

#define SMOOTH_MAX_GAP_CHUNKS     1
#define SMOOTH_MIN_PROBABILITY    0.05

static int isa_identifycmd_exec_graph(IsaIdentifyCmdCtx* ctx, FileBuffer* fb,
                                      u64_t start, size_t size)
{
    u64_t off          = start;
    u64_t end          = start + (u64_t)size;
    u64_t num_chunks   = 0;
    u64_t chunk_idx;
    u64_t i;
    int   have_range   = 0;
    int   current_type = 0;
    u64_t range_start  = 0;
    u64_t range_end    = 0;
    int   printed      = 0;
    int   rc;
    ChunkClassification* chunks = NULL;

    display_printf("ISA graph (%zu bytes analyzed, %d-byte chunks):\n", size,
                   BINEXEC_CHUNK_SIZE);

    /* --- Pass 1: collect all chunk classifications --- */
    {
        u64_t _off = start;

        num_chunks = (end - start + (u64_t)BINEXEC_CHUNK_SIZE - 1) /
                     (u64_t)BINEXEC_CHUNK_SIZE;
        chunks =
            (ChunkClassification*)bhex_malloc((size_t)num_chunks *
                                               sizeof(ChunkClassification));
        if (chunks == NULL) {
            error("out of memory allocating chunk results");
            return COMMAND_SILENT_ERROR;
        }

        chunk_idx = 0;
        while (_off < end) {
            size_t chunk_size =
                (size_t)((end - _off) < (u64_t)BINEXEC_CHUNK_SIZE
                             ? (end - _off)
                             : (u64_t)BINEXEC_CHUNK_SIZE);
            double prob = 0.0;

            rc = classify_chunk_from_fb(ctx, fb, _off, chunk_size,
                                        &chunks[chunk_idx].contains_code);
            if (rc != BINEXEC_OK) {
                error("executable-content prediction failed at 0x%llx: %s",
                      (unsigned long long)_off, bhex_ml_err_to_string(rc));
                bhex_free(chunks);
                return COMMAND_SILENT_ERROR;
            }

            /* Also capture probability for smoothing decisions. */
            {
                const u8_t* buf;
                u64_t       saved_off = fb->off;

                if (fb_seek(fb, _off) == 0) {
                    buf = fb_read(fb, chunk_size);
                    if (buf != NULL) {
                        binexec_chunk_contains_code(
                            ctx->binexec_model, buf, chunk_size, NULL, &prob);
                    }
                }
                fb_seek(fb, saved_off);
            }
            chunks[chunk_idx].probability = prob;

            chunk_idx++;
            _off += (u64_t)chunk_size;
        }
    }

    /* --- Pass 2: boundary smoothing --- */
    for (i = 0; i < num_chunks; ++i) {
        /* Drop isolated low-confidence code chunks. */
        if (chunks[i].contains_code &&
            chunks[i].probability < SMOOTH_MIN_PROBABILITY) {
            int left_code =
                (i > 0) ? chunks[i - 1].contains_code : 0;
            int right_code =
                (i + 1 < num_chunks) ? chunks[i + 1].contains_code : 0;
            if (!left_code && !right_code) {
                chunks[i].contains_code = 0;
            }
        }
    }

    for (i = 1; i + 1 < num_chunks; ++i) {
        /* Fill isolated single-chunk gaps between code regions.
         * Example: code | ___gap___ | code  ->  code | code | code */
        if (!chunks[i].contains_code && chunks[i - 1].contains_code &&
            chunks[i + 1].contains_code) {
            /* Only fill short gaps (SMOOTH_MAX_GAP_CHUNKS chunks). */
            u64_t gap_start = i;
            u64_t gap_end   = i;

            while (gap_end < num_chunks && !chunks[gap_end].contains_code)
                gap_end++;
            gap_end--; /* last non-code chunk in this gap */

            if (gap_end - gap_start + 1 <= (u64_t)SMOOTH_MAX_GAP_CHUNKS &&
                gap_end + 1 < num_chunks && chunks[gap_end + 1].contains_code) {
                for (u64_t j = gap_start; j <= gap_end; ++j)
                    chunks[j].contains_code = 1;
                i = gap_end; /* skip ahead */
            }
        }
    }

    /* --- Pass 3: print contiguous ranges --- */
    for (i = 0; i < num_chunks; ++i) {
        off = start + i * (u64_t)BINEXEC_CHUNK_SIZE;

        if (!have_range) {
            have_range   = 1;
            current_type = chunks[i].contains_code;
            range_start  = off;
            range_end    = off + (u64_t)BINEXEC_CHUNK_SIZE;
        } else if (chunks[i].contains_code == current_type) {
            range_end += (u64_t)BINEXEC_CHUNK_SIZE;
        } else {
            if (current_type != 0) {
                rc = print_code_range(ctx, fb, range_start, range_end);
                if (rc != COMMAND_OK) {
                    bhex_free(chunks);
                    return rc;
                }
                printed = 1;
            }
            current_type = chunks[i].contains_code;
            range_start  = off;
            range_end    = off + (u64_t)BINEXEC_CHUNK_SIZE;
        }
    }

    if (have_range && current_type != 0) {
        rc = print_code_range(ctx, fb, range_start, range_end);
        if (rc != COMMAND_OK) {
            bhex_free(chunks);
            return rc;
        }
        printed = 1;
    }

    if (!printed) {
        display_printf("  no code ranges detected\n");
    }

    bhex_free(chunks);
    return COMMAND_OK;
}

static int isa_identifycmd_exec(IsaIdentifyCmdCtx* ctx, FileBuffer* fb,
                                ParsedCommand* pc)
{
    int    graph_mode = -1;
    char*  size_str   = NULL;
    u64_t  requested_size;
    u64_t  remaining;
    u64_t  analyzed_u64;
    size_t analyzed_size;

    if (handle_mods(pc, "g", &graph_mode) != 0)
        return COMMAND_INVALID_MOD;
    graph_mode = graph_mode == 0;

    if (handle_args(pc, 1, 0, &size_str) != 0)
        return COMMAND_INVALID_ARG;

    requested_size = 0;
    if (size_str != NULL &&
        (!str_to_uint64(size_str, &requested_size) || requested_size == 0))
        return COMMAND_INVALID_ARG;

    if (fb->off >= fb->size) {
        error("no data left to analyze at current offset");
        return COMMAND_SILENT_ERROR;
    }

    if (!ensure_isa_model_loaded(ctx))
        return COMMAND_SILENT_ERROR;
    if (graph_mode && !ensure_binexec_model_loaded(ctx))
        return COMMAND_SILENT_ERROR;

    remaining    = fb->size - fb->off;
    analyzed_u64 = size_str == NULL ? remaining : requested_size;
    if (size_str != NULL && analyzed_u64 > remaining) {
        warning("requested %llu bytes but only %llu are available, analyzing "
                "the remaining bytes",
                (unsigned long long)requested_size,
                (unsigned long long)remaining);
        analyzed_u64 = remaining;
    }

    if (analyzed_u64 > (u64_t)SIZE_MAX) {
        warning("requested size exceeds the platform limit, analyzing %zu "
                "bytes instead",
                (size_t)SIZE_MAX);
        analyzed_u64 = (u64_t)SIZE_MAX;
    }

    analyzed_size = (size_t)analyzed_u64;

    if (graph_mode) {
        return isa_identifycmd_exec_graph(ctx, fb, fb->off, analyzed_size);
    }

    return isa_identifycmd_exec_default(ctx, fb, fb->off, analyzed_size);
}

Cmd* isa_identifycmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    IsaIdentifyCmdCtx* ctx = bhex_calloc(sizeof(IsaIdentifyCmdCtx));
    cmd->obj               = ctx;
    cmd->name              = "isa_identify";
    cmd->alias             = "ii";
    cmd->hint              = HINT_STR;

    cmd->dispose = (void (*)(void*))isa_identifycmd_dispose;
    cmd->help    = isa_identifycmd_help;
    cmd->exec =
        (int (*)(void*, FileBuffer*, ParsedCommand*))isa_identifycmd_exec;

    return cmd;
}
