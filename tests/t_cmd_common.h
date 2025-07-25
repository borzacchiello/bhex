#ifndef TEST_CMD_COMMON_H
#define TEST_CMD_COMMON_H

#include <strbuilder.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#include "data/elf_not_kitty.h"
#include "data/elf_truncated.h"
#include "data/pe_tiny.h"

#include "dummy_filebuffer.h"
#include "filebuffer.h"
#include "../cmd/cmd.h"

#define print_err_sb()                                                         \
    do {                                                                       \
        char* err = strbuilder_reset(err_sb);                                  \
        printf("%s", err);                                                     \
        bhex_free(err);                                                        \
    } while (0)

extern int template_skip_search;

static CmdContext*      cc;
static DummyFilebuffer *elf_fb, *pe_fb, *dfb_alt_1, *dfb_alt_2;
static StringBuilder *  sb, *err_sb;

static void print_on_strbuilder(const char* fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvs(sb, fmt, argp);
    va_end(argp);
}

static void log_on_err_strbuilder(const char* str)
{
    strbuilder_append(err_sb, str);
    strbuilder_append_char(err_sb, '\n');
}

__attribute__((constructor)) static void __init(void)
{
    disable_warning      = 1;
    template_skip_search = 1;

    cc = cmdctx_init();
    if (!cc)
        panic("unable to create cmd ctx");
    elf_fb = dummyfilebuffer_create(elf_not_kitty, sizeof(elf_not_kitty));
    if (!elf_fb)
        panic("unable to create elf dummy fb");
    pe_fb = dummyfilebuffer_create(pe_tiny, sizeof(pe_tiny));
    if (!pe_fb)
        panic("unable to create pe dummy fb");
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
    err_sb = strbuilder_new();
    if (!err_sb)
        panic("unable to create error string builder");

    display_set_print_callback(print_on_strbuilder);
    register_log_callback(log_on_err_strbuilder);
}

__attribute__((destructor)) static void __deinit(void)
{
    if (cc)
        cmdctx_destroy(cc);
    if (elf_fb)
        dummyfilebuffer_destroy(elf_fb);
    if (pe_fb)
        dummyfilebuffer_destroy(pe_fb);
    if (dfb_alt_1)
        dummyfilebuffer_destroy(dfb_alt_1);
    if (dfb_alt_2)
        dummyfilebuffer_destroy(dfb_alt_2);
    if (sb)
        bhex_free(strbuilder_finalize(sb));
    if (err_sb)
        bhex_free(strbuilder_finalize(err_sb));
}

__attribute__((unused)) static void reset_global_state()
{
    bhex_free(strbuilder_reset(sb));
    bhex_free(strbuilder_reset(err_sb));
}

__attribute__((unused)) static int
exec_commands_on_ex(const char* s, DummyFilebuffer* dummyfb, int split)
{
    char tmp[512] = {0};
    if (strlen(s) > sizeof(tmp) - 1)
        panic("exec_commands: s is too long");
    strcpy(tmp, s);

    fb_seek(dummyfb->fb, 0);
    fb_undo_all(dummyfb->fb);
    reset_global_state();

    char* cmd = tmp;
    if (split)
        cmd = strtok(tmp, ";");
    while (cmd) {
        ParsedCommand* pc;
        if (cmdline_parse(cmd, &pc) != 0)
            panic("parse failed");
        int r;
        if ((r = cmdctx_run(cc, pc, dummyfb->fb)) != 0) {
            parsed_command_destroy(pc);
            return 1;
        }
        parsed_command_destroy(pc);
        cmd = strtok(NULL, ";");
    }
    return 0;
}

__attribute__((unused)) static int exec_commands_on(const char*      s,
                                                    DummyFilebuffer* dummyfb)
{
    return exec_commands_on_ex(s, dummyfb, 1);
}

__attribute__((unused)) static int exec_commands(const char* s)
{
    return exec_commands_on(s, elf_fb);
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
