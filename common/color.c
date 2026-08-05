// Copyright (c) 2022-2026, bageyelet

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <color.h>

int g_colors_enabled = 0;

/* SGR sequences indexed by Color. Every entry resets the previous attributes,
 * so that a missing reset in a call site cannot make the colors bleed into the
 * rest of the output. */
static const char* const colors[COLOR_COUNT] = {
    [COLOR_RESET]           = "\x1b[0m",
    [COLOR_BANNER]          = "\x1b[0;1;36m",    /* bold cyan */
    [COLOR_PROMPT]          = "\x1b[0;1;32m",    /* bold green */
    [COLOR_PANIC]           = "\x1b[0;1;37;41m", /* bold white on red */
    [COLOR_ERROR]           = "\x1b[0;1;31m",    /* bold red */
    [COLOR_WARNING]         = "\x1b[0;1;33m",    /* bold yellow */
    [COLOR_INFO]            = "\x1b[0;1;36m",    /* bold cyan */
    [COLOR_CMD]             = "\x1b[0;36m",      /* cyan */
    [COLOR_ALIAS]           = "\x1b[0;90m",      /* gray */
    [COLOR_ADDR]            = "\x1b[0;1;37m",    /* bold white */
    [COLOR_HEADER]          = "\x1b[0;90m",      /* gray */
    [COLOR_BYTE_ZERO]       = "\x1b[0;90m",      /* gray: 0x00 */
    [COLOR_BYTE_FF]         = "\x1b[0;31m",      /* red: 0xff */
    [COLOR_BYTE_ASCII]      = "\x1b[0;32m",      /* green: printable ASCII */
    [COLOR_BYTE_OTHER]      = "\x1b[0;37m",      /* white: everything else */
    [COLOR_MNEMONIC]        = "\x1b[0;1;37m",    /* bold white */
    [COLOR_MNEMONIC_FLOW]   = "\x1b[0;1;33m",    /* bold yellow */
    [COLOR_ENTROPY_LOW]     = "\x1b[0;32m",      /* green */
    [COLOR_ENTROPY_MID]     = "\x1b[0;33m",      /* yellow */
    [COLOR_ENTROPY_HIGH]    = "\x1b[0;31m",      /* red */
    [COLOR_CONFIDENCE_LOW]  = "\x1b[0;31m",      /* red */
    [COLOR_CONFIDENCE_MID]  = "\x1b[0;33m",      /* yellow */
    [COLOR_CONFIDENCE_HIGH] = "\x1b[0;32m",      /* green */
    [COLOR_MOD_INSERT]      = "\x1b[0;32m",      /* green */
    [COLOR_MOD_DELETE]      = "\x1b[0;31m",      /* red */
    [COLOR_LABEL]           = "\x1b[0;36m",      /* cyan */
    [COLOR_HIGHLIGHT]       = "\x1b[31;49;1m",   /* bold red */
};

void colors_init(int disable)
{
    if (disable) {
        g_colors_enabled = 0;
        return;
    }

    // https://no-color.org: any non-empty value disables the colors
    const char* no_color = getenv("NO_COLOR");
    if (no_color != NULL && no_color[0] != '\0') {
        g_colors_enabled = 0;
        return;
    }

    const char* term = getenv("TERM");
    if (term != NULL && strcmp(term, "dumb") == 0) {
        g_colors_enabled = 0;
        return;
    }

    // a caller that knows where the output goes (a pager, for instance) can
    // ask for the colors anyway, since the isatty() check below would see the
    // pipe and turn them off
    const char* force = getenv("CLICOLOR_FORCE");
    if (force != NULL && force[0] != '\0' && strcmp(force, "0") != 0) {
        g_colors_enabled = 1;
        return;
    }

    // when the output is redirected the escapes would end up in the file of
    // the user, so they are emitted only for a terminal
    g_colors_enabled = isatty(STDOUT_FILENO);
}

void colors_set_enabled(int enabled) { g_colors_enabled = enabled; }

int colors_enabled(void) { return g_colors_enabled; }

const char* color_str(Color c)
{
    if (!g_colors_enabled || (unsigned)c >= COLOR_COUNT)
        return "";
    return colors[c];
}
