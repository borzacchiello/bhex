#ifndef TEST_CMD_COMMON_H
#define TEST_CMD_COMMON_H

#include <strbuilder.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#include "dummy_filebuffer.h"
#include "elf_not_kitty.h"
#include "elf_truncated.h"
#include "../cmd/cmd.h"
#include "filebuffer.h"

static CmdContext*      cc;
static DummyFilebuffer *dfb, *dfb_alt_1, *dfb_alt_2;
static StringBuilder*   sb;

static void print_on_strbuilder(const char* fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvs(sb, fmt, argp);
    va_end(argp);
}

__attribute__((constructor)) static void __init(void)
{
    disable_warning = 1;

    cc = cmdctx_init();
    if (!cc)
        panic("unable to create cmd ctx");
    dfb = dummyfilebuffer_create(elf_not_kitty, sizeof(elf_not_kitty));
    if (!dfb)
        panic("unable to create dummy fb");
    dfb_alt_1 =
        dummyfilebuffer_create(elf_truncated_1, sizeof(elf_truncated_1));
    if (!dfb_alt_1)
        panic("unable to create dummy fb alt 1");
    dfb_alt_2 =
        dummyfilebuffer_create(elf_truncated_2, sizeof(elf_truncated_2));
    if (!dfb_alt_2)
        panic("unable to create dummy fb alt 2");
    sb = strbuilder_new();
    if (!sb)
        panic("unable to create string builder");

    display_set_print_callback(print_on_strbuilder);
}

__attribute__((destructor)) static void __deinit(void)
{
    if (cc)
        cmdctx_destroy(cc);
    if (dfb)
        dummyfilebuffer_destroy(dfb);
    if (dfb_alt_1)
        dummyfilebuffer_destroy(dfb_alt_1);
    if (dfb_alt_2)
        dummyfilebuffer_destroy(dfb_alt_2);
    if (sb)
        bhex_free(strbuilder_finalize(sb));
}

__attribute__((unused)) static int exec_commands(const char* s)
{
    char tmp[512] = {0};
    if (strlen(s) > sizeof(tmp) - 1)
        panic("exec_commands: s is too long");
    strcpy(tmp, s);

    // reset the state, just in case
    fb_seek(dfb->fb, 0);
    fb_undo_all(dfb->fb);

    char* cmd = strtok(tmp, ";");
    while (cmd) {
        ParsedCommand* pc;
        if (parse(cmd, &pc) != 0)
            panic("parse failed");
        int r;
        if ((r = cmdctx_run(cc, pc, dfb->fb)) != 0) {
            parsed_command_destroy(pc);
            return 1;
        }
        parsed_command_destroy(pc);
        cmd = strtok(NULL, ";");
    }
    return 0;
}

__attribute__((unused)) static int compare_strings_ignoring_X(const char* s1,
                                                              const char* s2)
{
    const char *p1 = s1, *p2 = s2;
    while (*p1 && *p2) {
        if (*p1 == 'X' || *p2 == 'X') {
            p1++;
            p2++;
            continue;
        }
        if (*p1++ != *p2++)
            break;
    }
    return !(*p1) && !(*p2);
}

__attribute__((unused)) static void print_str(const char* s)
{
    printf("\"");

    const char* p = s;
    while (*p) {
        char c = *p;
        switch (c) {
            case '\n':
                printf("\\n\"\n\"");
                break;
            default:
                printf("%c", c);
        }
        p++;
    }

    printf("\"\n");
}

#endif
