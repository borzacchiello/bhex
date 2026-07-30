// Copyright (c) 2022-2026, bageyelet

#ifndef UNICODE_H
#define UNICODE_H

// Whether the output can carry characters outside ASCII, for the places that
// have something nicer to draw with them (the branch arrows of "ds/a"). Kept
// apart from the colors: a terminal that cannot paint may well be able to
// print box drawing characters, and the other way around.
//
// Unicode is off until unicode_init() says otherwise, so that whoever captures
// the output without going through main() (the tests, the fuzzers) gets the
// ASCII drawings.
extern int g_unicode_enabled;

// Enable unicode, unless `disable` is set, the terminal is a dumb one, or the
// locale of the environment is not a UTF-8 one.
void unicode_init(int disable);
void unicode_set_enabled(int enabled);
int  unicode_enabled(void);

#endif
