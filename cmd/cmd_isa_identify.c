// Copyright (c) 2022-2026, bageyelet

#include "cmd_isa_identify.h"
#include "cmd_arg_handler.h"

#include <isadetect.h>
#include <util/byte_to_num.h>
#include <display.h>
#include <alloc.h>
#include <log.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HINT_STR              " [<size>]"
#define ISA_MODEL_NAME        "isadetect_model.bin"
#define ISA_MODEL_SYSTEM_PATH "/usr/local/share/bhex/models/" ISA_MODEL_NAME
#define ISA_TOPK              3

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    isadetect_model_t* model;
    char               model_path[PATH_MAX];
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
        "isa_identify: identify the ISA of a block of bytes using the "
        "bundled AI model\n"
        "\n"
        "  ii" HINT_STR "\n"
        "\n"
        "  size: number of bytes to analyze starting from the current "
        "offset\n"
        "        (if omitted, use the whole file)\n");
}

static void isa_identifycmd_dispose(IsaIdentifyCmdCtx* ctx)
{
    if (ctx->model)
        isadetect_model_free(ctx->model);
    bhex_free(ctx);
}

static int file_exists(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int copy_path(char* dst, size_t dst_size, const char* src)
{
    int n = snprintf(dst, dst_size, "%s", src);
    return n >= 0 && (size_t)n < dst_size;
}

static int get_executable_dir(char* out, size_t out_size)
{
    char    exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    char*   slash;

    if (len <= 0 || (size_t)len >= sizeof(exe_path))
        return 0;

    exe_path[len] = '\0';
    slash         = strrchr(exe_path, '/');
    if (!slash)
        return 0;

    *slash = '\0';
    return copy_path(out, out_size, exe_path);
}

static int make_candidate(char* out, size_t out_size, const char* dir,
                          const char* suffix)
{
    int n = snprintf(out, out_size, "%s/%s", dir, suffix);
    return n >= 0 && (size_t)n < out_size;
}

static int resolve_model_path(char* out, size_t out_size)
{
    char               exe_dir[PATH_MAX];
    char               candidate[PATH_MAX];
    size_t             i;
    static const char* local_suffixes[] = {
        "models/" ISA_MODEL_NAME,
        ISA_MODEL_NAME,
        "../models/" ISA_MODEL_NAME,
        "../share/bhex/models/" ISA_MODEL_NAME,
    };

    if (file_exists(ISA_MODEL_SYSTEM_PATH))
        return copy_path(out, out_size, ISA_MODEL_SYSTEM_PATH);

    if (!get_executable_dir(exe_dir, sizeof(exe_dir)))
        return 0;

    for (i = 0; i < sizeof(local_suffixes) / sizeof(local_suffixes[0]); ++i) {
        if (!make_candidate(candidate, sizeof(candidate), exe_dir,
                            local_suffixes[i]))
            continue;
        if (file_exists(candidate))
            return copy_path(out, out_size, candidate);
    }

    return 0;
}

static const char* isadetect_err_to_string(int err)
{
    switch (err) {
        case ISADETECT_OK:
            return "no error";
        case ISADETECT_ERR_INVALID_INPUT:
            return "invalid input";
        case ISADETECT_ERR_IO:
            return "I/O error";
        case ISADETECT_ERR_FORMAT:
            return "invalid model format";
        case ISADETECT_ERR_UNSUPPORTED:
            return "unsupported model";
        case ISADETECT_ERR_NOMEM:
            return "out of memory";
        default:
            return "unknown error";
    }
}

static int ensure_model_loaded(IsaIdentifyCmdCtx* ctx)
{
    int rc;

    if (ctx->model)
        return 1;

    if (!resolve_model_path(ctx->model_path, sizeof(ctx->model_path))) {
        error("unable to find ISA model '%s'; searched %s and paths relative "
              "to the executable",
              ISA_MODEL_NAME, ISA_MODEL_SYSTEM_PATH);
        return 0;
    }

    rc = isadetect_model_load(&ctx->model, ctx->model_path);
    if (rc != ISADETECT_OK) {
        error("unable to load ISA model '%s': %s", ctx->model_path,
              isadetect_err_to_string(rc));
        ctx->model = NULL;
        return 0;
    }

    return 1;
}

static const char* map_to_bhex_arch(const char* architecture,
                                    const char* endianness, int wordsize)
{
    if (!architecture || !endianness)
        return NULL;

    if (strcmp(architecture, "amd64") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 64)
        return "x64";

    if (strcmp(architecture, "i386") == 0 &&
        strcmp(endianness, "little") == 0 && wordsize == 32)
        return "x86";

    if (strcmp(architecture, "x32") == 0 && strcmp(endianness, "little") == 0 &&
        wordsize == 32)
        return "x64";

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
        if (rc != ISADETECT_OK)
            break;

        off += chunk;
    }

    fb_seek(fb, orig_off);
    if (rc != ISADETECT_OK)
        return rc;

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

static int isa_identifycmd_exec(IsaIdentifyCmdCtx* ctx, FileBuffer* fb,
                                ParsedCommand* pc)
{
    char*            size_str = NULL;
    u64_t            requested_size;
    u64_t            remaining;
    u64_t            analyzed_u64;
    size_t           analyzed_size;
    double           features[ISADETECT_NUM_FEATURES];
    double           probabilities[ISADETECT_NUM_CLASSES];
    RankedPrediction top[ISA_TOPK];
    int              rc;
    size_t           i;

    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

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

    if (!ensure_model_loaded(ctx))
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

    rc = extract_features_from_fb(fb, fb->off, analyzed_size, features);
    if (rc != ISADETECT_OK) {
        error("ISA feature extraction failed: %s", isadetect_err_to_string(rc));
        return COMMAND_SILENT_ERROR;
    }

    rc = isadetect_model_predict_proba(ctx->model, features, probabilities);
    if (rc != ISADETECT_OK) {
        error("ISA prediction failed: %s", isadetect_err_to_string(rc));
        return COMMAND_SILENT_ERROR;
    }

    rc = rank_predictions(ctx->model, probabilities, top);
    if (rc != ISADETECT_OK) {
        error("unable to rank ISA predictions: %s",
              isadetect_err_to_string(rc));
        return COMMAND_SILENT_ERROR;
    }

    display_printf("ISA identification (%zu bytes analyzed):\n", analyzed_size);
    for (i = 0; i < ISA_TOPK; ++i) {
        display_printf(
            "  top %zu: %s, %s-endian, %d-bit (confidence: %.2f%%)\n", i + 1,
            top[i].display_name ? top[i].display_name : "unknown",
            top[i].endianness ? top[i].endianness : "unknown", top[i].wordsize,
            top[i].probability * 100.0);
    }

    return COMMAND_OK;
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
