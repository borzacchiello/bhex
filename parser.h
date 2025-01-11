#ifndef PARSER_H
#define PARSER_H

#include <ll.h>

#define PARSER_OK                           0
#define PARSER_ERR_UNCLOSED_QUOTATION       1
#define PARSER_ERR_UNEXPECTED_SPACE         2
#define PARSER_ERR_UNEXPECTED_EMPTY_STRING  3
#define PARSER_ERR_NO_TOKENS                4
#define PARSER_ERR_CMDMOD_BEFORE_CMD        5
#define PARSER_ERR_UNEXPECTED_TRAILING_DATA 6
#define PARSER_ERR_INVALID_HELP_SWITCH      7
#define PARSER_ERR_INVALID_CMDMOD           8

typedef struct ParsedCommand {
    char* cmd;
    int   print_help;
    LL    cmd_modifiers;
    LL    args;
} ParsedCommand;

int  parse(const char* str, ParsedCommand** o_cmd);
void parsed_command_destroy(ParsedCommand* cmd);

const char* parser_err_to_string(int err);

#endif
