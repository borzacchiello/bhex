#ifndef CMD_H
#define CMD_H

#include <ll.h>
#include <filebuffer.h>
#include <cmdline_parser.h>

#define COMMAND_OK                   0
#define COMMAND_ERR_NO_SUCH_COMMAND  1
#define COMMAND_INVALID_HELP_COMMAND 2
#define COMMAND_UNSUPPORTED_MOD      3
#define COMMAND_UNSUPPORTED_ARG      4
#define COMMAND_INVALID_MOD          5
#define COMMAND_INVALID_ARG          6
#define COMMAND_INTERNAL_ERROR       7
#define COMMAND_FILE_WRITE_ERROR     8
#define COMMAND_SILENT_ERROR         9

typedef void (*fptr_help_t)(void* obj);
typedef void (*fptr_dispose_t)(void* obj);
typedef int (*fptr_exec_t)(void* obj, FileBuffer* fb, ParsedCommand* pc);

typedef struct Cmd {
    void*       obj;
    const char* name;
    const char* alias;
    const char* hint;

    fptr_help_t    help;
    fptr_exec_t    exec;
    fptr_dispose_t dispose;
} Cmd;

typedef struct CmdContext {
    ll_t commands;
} CmdContext;

CmdContext* cmdctx_init();
void        cmdctx_destroy(CmdContext* cc);

int cmdctx_run(CmdContext* cc, ParsedCommand* pc, FileBuffer* fb);
int cmd_help(CmdContext* cc);

const char* cmdctx_err_to_string(int err);

#endif
