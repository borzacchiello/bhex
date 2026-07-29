// Copyright (c) 2022-2026, bageyelet

#ifndef COLOR_H
#define COLOR_H

// Logical roles of the colored elements printed by the shell. The call sites
// name a role instead of an escape sequence, so that "--no_color" (and the
// automatic detection done by colors_init) can turn everything off in one
// place.
typedef enum Color {
    COLOR_RESET = 0,
    COLOR_BANNER,
    COLOR_PROMPT,
    COLOR_PANIC,
    COLOR_ERROR,
    COLOR_WARNING,
    COLOR_INFO,
    // command names and aliases in the help listing
    COLOR_CMD,
    COLOR_ALIAS,
    // dumps: addresses on the left, column offsets on top, and the bytes
    // themselves, colored after their "kind" as in the TUI
    COLOR_ADDR,
    COLOR_HEADER,
    COLOR_BYTE_ZERO,
    COLOR_BYTE_FF,
    COLOR_BYTE_ASCII,
    COLOR_BYTE_OTHER,
    // disassembly: the mnemonic, and the variant marking the instructions
    // that alter the control flow (jumps, calls, returns)
    COLOR_MNEMONIC,
    COLOR_MNEMONIC_FLOW,
    // entropy graph, by band: the interesting rows (compressed or encrypted
    // data) are the high ones
    COLOR_ENTROPY_LOW,
    COLOR_ENTROPY_MID,
    COLOR_ENTROPY_HIGH,
    // how much a guess of the models can be trusted. The bands run the other
    // way around than the entropy ones: here it is the low end that is worth
    // a second look
    COLOR_CONFIDENCE_LOW,
    COLOR_CONFIDENCE_MID,
    COLOR_CONFIDENCE_HIGH,
    // the bytes of the pending changes listed by "c/l", painted the way a
    // diff would: what is added is green, what goes away is red
    COLOR_MOD_INSERT,
    COLOR_MOD_DELETE,
    // names of the fields printed by a template, keys of the info command
    COLOR_LABEL,
    // bytes that differ (diff) and matches (search, strings)
    COLOR_HIGHLIGHT,
    COLOR_COUNT
} Color;

// Colors are off until colors_init() says otherwise, so that whoever captures
// the output without going through main() (the tests, the fuzzers) gets plain
// text.
extern int g_colors_enabled;

// Enable the colors, unless `disable` is set, the standard output is not a
// terminal, or the environment asks not to use them (NO_COLOR, TERM=dumb).
void colors_init(int disable);
void colors_set_enabled(int enabled);
int  colors_enabled(void);

// The escape sequence of `c`, or an empty string when the colors are off: it
// can always be used as a "%s" argument.
const char* color_str(Color c);

#endif
