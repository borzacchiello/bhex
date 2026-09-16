// Copyright (c) 2022-2026, bageyelet

#ifndef STR_H
#define STR_H

#include <defs.h>
#include <stdlib.h>

int escape_char_to_byte(char c, u8_t* o_byte);
int hex_nibble_to_num(char c, u8_t* b);
int unescape_ascii_string(char* string, u8_t** o_buf, size_t* o_size);
int hex_to_bytes(char* hex_string, u8_t** o_buf, size_t* o_size);
// Like hex_to_bytes(), but '?' is accepted in place of a hex digit and stands
// for "any nibble". *o_mask gets one byte per output byte, holding 0xf0 for a
// fixed high nibble and 0x0f for a fixed low one, so that a comparison is
// (candidate & mask) == (buf & mask). Both buffers are owned by the caller.
int         hex_to_bytes_masked(char* hex_string, u8_t** o_buf, u8_t** o_mask,
                                size_t* o_size);
size_t      count_chars_in_str(char* s, char c);
char*       str_indent(char* s, u32_t spaces);
void        strip_chars(char* s, const char* chars);
const char* stristr(const char* haystack, const char* needle);
// Case-insensitive equality, and the same over the first `n` characters:
// rolled here rather than taken from strings.h, like stristr above, so that
// every target builds the same code
int   striequal(const char* a, const char* b);
int   striprefix(const char* s, const char* prefix);
char* _strsep(char** stringp, const char* delim);

/*
   How a name typed on the command line is matched against a list of them,
   shared by every command that takes one ("hash", "disas/l", ...).

   The narrowest tier that matches anything is the one used, so that the
   obvious reading wins: "skein-512" names one algorithm even though it is
   also the start of "skein-512-256", and "sh" is SuperH SH1 rather than the
   eighteen names it appears in. Matching anywhere in the name is the
   fallback, for "hh 256" and the like.
*/
typedef enum MatchTier {
    MATCH_EXACT = 0,
    MATCH_PREFIX,
    MATCH_ANYWHERE,
    MATCH_TIER_COUNT
} MatchTier;

// Whether `name` answers to `query` when read at `tier`
int str_matches_at(const char* name, const char* query, MatchTier tier);

// The tier `query` ends up being read at against a list of `n` names, `get`
// returning the i-th one. A query that matches nothing at any tier gets
// MATCH_ANYWHERE, where it will match nothing too: the caller reports that
// as "no such name" rather than as an empty list
typedef const char* (*match_name_at_t)(size_t i, void* ctx);
MatchTier str_pick_tier(const char* query, size_t n, match_name_at_t get,
                        void* ctx);

#endif
