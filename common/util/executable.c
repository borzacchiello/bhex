// Copyright (c) 2022-2026, bageyelet

#include "executable.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int bhex_executable_dir(char* out, size_t out_size)
{
    if (out == NULL || out_size == 0)
        return 0;

    char exe_path[PATH_MAX];
#ifdef __COSMOPOLITAN__
    // The APE loader can be /proc/self/exe; ask the runtime for the program.
    const char* program_path = GetProgramExecutableName();
    if (program_path == NULL || program_path[0] == '\0')
        return 0;
    int path_len = snprintf(exe_path, sizeof(exe_path), "%s", program_path);
    if (path_len < 0 || (size_t)path_len >= sizeof(exe_path))
        return 0;
#else
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path));
    if (len <= 0 || (size_t)len >= sizeof(exe_path))
        return 0;

    exe_path[len] = '\0';
#endif
    char* slash = strrchr(exe_path, '/');
    if (slash == NULL)
        return 0;
    // Preserve the root directory for an executable directly under /.
    slash[slash == exe_path ? 1 : 0] = '\0';
    int n = snprintf(out, out_size, "%s", exe_path);
    return n >= 0 && (size_t)n < out_size;
}
