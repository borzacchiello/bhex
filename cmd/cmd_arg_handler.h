#ifndef CMD_ARG_HANDLER_H
#define CMD_ARG_HANDLER_H

#include <defs.h>
#include <cmdline_parser.h>

int handle_mods(ParsedCommand* pcmd, const char* modsfmt, ...);
int handle_args(ParsedCommand* pcmd, u32_t max, u32_t required, ...);

#endif
