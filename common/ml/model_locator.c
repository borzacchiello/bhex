// Copyright (c) 2022-2026, bageyelet

#include "model_locator.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BHEX_MODEL_SYSTEM_DIR "/usr/local/share/bhex/models"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

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
    ssize_t len;
    char*   slash;

    len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0 || (size_t)len >= sizeof(exe_path)) {
        return 0;
    }

    exe_path[len] = '\0';
    slash         = strrchr(exe_path, '/');
    if (slash == NULL) {
        return 0;
    }

    *slash = '\0';
    return copy_path(out, out_size, exe_path);
}

static int make_candidate(char* out, size_t out_size, const char* dir,
                          const char* suffix)
{
    int n = snprintf(out, out_size, "%s/%s", dir, suffix);

    return n >= 0 && (size_t)n < out_size;
}

int bhex_model_resolve_path(char* out, size_t out_size, const char* model_name)
{
    char               exe_dir[PATH_MAX];
    char               candidate[PATH_MAX];
    char               system_path[PATH_MAX];
    size_t             i;
    static const char* local_suffixes[] = {
        "models/%s",
        "%s",
        "../models/%s",
        "../share/bhex/models/%s",
    };

    if (out == NULL || out_size == 0 || model_name == NULL) {
        return 0;
    }

    /* Try local paths first (from executable directory), then system. */
    if (get_executable_dir(exe_dir, sizeof(exe_dir))) {
        for (i = 0; i < sizeof(local_suffixes) / sizeof(local_suffixes[0]); ++i) {
            char suffix[PATH_MAX];
            int n = snprintf(suffix, sizeof(suffix), local_suffixes[i], model_name);
            if (n < 0 || (size_t)n >= sizeof(suffix)) {
                continue;
            }
            if (!make_candidate(candidate, sizeof(candidate), exe_dir, suffix)) {
                continue;
            }
            if (file_exists(candidate)) {
                return copy_path(out, out_size, candidate);
            }
        }
    }

    /* Fall back to system path. */
    if (make_candidate(system_path, sizeof(system_path), BHEX_MODEL_SYSTEM_DIR,
                       model_name) &&
        file_exists(system_path)) {
        return copy_path(out, out_size, system_path);
    }

    return 0;
}
