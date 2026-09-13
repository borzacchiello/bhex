// Copyright (c) 2022-2026, bageyelet

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <color.h>

#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(disabled_by_default)(void)
{
    // whoever does not go through main() (the tests, the fuzzers) must get
    // plain text
    int r = TEST_FAILED;
    ASSERT(!colors_enabled());
    ASSERT(strcmp(color_str(COLOR_ERROR), "") == 0);
    ASSERT(strcmp(color_str(COLOR_RESET), "") == 0);
    r = TEST_SUCCEEDED;
fail:
    return r;
}

int TEST(enabled)(void)
{
    int r = TEST_FAILED;
    colors_set_enabled(1);
    ASSERT(colors_enabled());
    ASSERT(strcmp(color_str(COLOR_RESET), "\x1b[0m") == 0);
    ASSERT(strlen(color_str(COLOR_BYTE_FF)) > 0);
    // an out of range color is never an escape sequence
    ASSERT(strcmp(color_str(COLOR_COUNT), "") == 0);
    r = TEST_SUCCEEDED;
fail:
    colors_set_enabled(0);
    return r;
}

int TEST(init_disable)(void)
{
    int r = TEST_FAILED;
    colors_set_enabled(1);
    colors_init(1);
    ASSERT(!colors_enabled());
    ASSERT(strcmp(color_str(COLOR_ERROR), "") == 0);
    r = TEST_SUCCEEDED;
fail:
    colors_set_enabled(0);
    return r;
}

int TEST(init_no_color_env)(void)
{
    int   r        = TEST_FAILED;
    char* saved    = getenv("NO_COLOR");
    char* saved_cp = saved ? strdup(saved) : NULL;

    colors_set_enabled(1);
    setenv("NO_COLOR", "1", 1);
    colors_init(0);
    ASSERT(!colors_enabled());

    // an empty value does not disable them (https://no-color.org): what is
    // left to decide is whether the output is a terminal
    setenv("NO_COLOR", "", 1);
    colors_init(0);
    ASSERT(colors_enabled() == isatty(STDOUT_FILENO));

    r = TEST_SUCCEEDED;
fail:
    if (saved_cp) {
        setenv("NO_COLOR", saved_cp, 1);
        free(saved_cp);
    } else {
        unsetenv("NO_COLOR");
    }
    colors_set_enabled(0);
    return r;
}

int TEST(init_clicolor_force_env)(void)
{
    int   r           = TEST_FAILED;
    char* saved       = getenv("CLICOLOR_FORCE");
    char* saved_cp    = saved ? strdup(saved) : NULL;
    char* saved_nc    = getenv("NO_COLOR");
    char* saved_nc_cp = saved_nc ? strdup(saved_nc) : NULL;

    if (saved_nc_cp)
        unsetenv("NO_COLOR");

    // the colors survive a pipe when asked for explicitly (what "bdiff" does
    // to keep them through "less")
    colors_set_enabled(0);
    setenv("CLICOLOR_FORCE", "1", 1);
    colors_init(0);
    ASSERT(colors_enabled());

    // "0" and the empty value mean "decide as usual"
    setenv("CLICOLOR_FORCE", "0", 1);
    colors_init(0);
    ASSERT(colors_enabled() == isatty(STDOUT_FILENO));

    setenv("CLICOLOR_FORCE", "", 1);
    colors_init(0);
    ASSERT(colors_enabled() == isatty(STDOUT_FILENO));

    // NO_COLOR and "--no_color" still win over it
    setenv("CLICOLOR_FORCE", "1", 1);
    colors_init(1);
    ASSERT(!colors_enabled());

    setenv("NO_COLOR", "1", 1);
    colors_init(0);
    ASSERT(!colors_enabled());
    unsetenv("NO_COLOR");

    r = TEST_SUCCEEDED;
fail:
    if (saved_nc_cp) {
        setenv("NO_COLOR", saved_nc_cp, 1);
        free(saved_nc_cp);
    } else {
        unsetenv("NO_COLOR");
    }
    if (saved_cp) {
        setenv("CLICOLOR_FORCE", saved_cp, 1);
        free(saved_cp);
    } else {
        unsetenv("CLICOLOR_FORCE");
    }
    colors_set_enabled(0);
    return r;
}
