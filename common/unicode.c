// Copyright (c) 2022-2026, bageyelet

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <unicode.h>

int g_unicode_enabled = 0;

// Whether the name of a locale mentions utf, spelled any of the ways it is
// ("UTF-8", "utf8"). Written by hand as strcasestr is not standard
static int names_utf(const char* s)
{
    for (; *s != '\0'; ++s)
        if (tolower((unsigned char)s[0]) == 'u' &&
            tolower((unsigned char)s[1]) == 't' &&
            tolower((unsigned char)s[2]) == 'f')
            return 1;
    return 0;
}

// The locale is read from the environment rather than through setlocale(): the
// program never sets one, so nl_langinfo() would always answer ASCII
static int locale_is_utf8(void)
{
    static const char* const vars[] = {"LC_ALL", "LC_CTYPE", "LANG"};

    for (size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); ++i) {
        const char* v = getenv(vars[i]);
        if (v == NULL || v[0] == '\0')
            continue;
        // the first one that is set decides, as it does for the C library
        return names_utf(v);
    }
    return 0;
}

void unicode_init(int disable)
{
    if (disable) {
        g_unicode_enabled = 0;
        return;
    }

    const char* term = getenv("TERM");
    if (term != NULL && strcmp(term, "dumb") == 0) {
        g_unicode_enabled = 0;
        return;
    }

    g_unicode_enabled = locale_is_utf8();
}

void unicode_set_enabled(int enabled) { g_unicode_enabled = enabled; }

int unicode_enabled(void) { return g_unicode_enabled; }
