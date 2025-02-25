#include "dummy_filebuffer.h"
#include "elf_not_kitty.h"
#include "../cmd/cmd.h"
#include "t.h"

#include <strbuilder.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static CmdContext*      cc;
static DummyFilebuffer* dfb;
static StringBuilder*   sb;

static void print_on_strbuilder(const char* fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvsf(sb, fmt, argp);
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
    if (sb)
        bhex_free(strbuilder_finalize(sb));
}

static ParsedCommand* parse_or_die(const char* s)
{
    ParsedCommand* pc;
    if (parse(s, &pc) != 0)
        panic("parse failed");
    return pc;
}

int TEST(hex_1)()
{
    // clang-format off
    const char* expected =
    "\n"
    "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    "       -----------------------------------------------\n"
    " 0000: 7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 00   .ELF............\n"
    " 0010: 02 00 03 00 01 00 00 00 74 80 04 08 34 00 00 00   ........t...4...\n"
    " 0020: A4 00 00 00 00 00 00 00 34 00 20 00 02 00 28 00   ........4. ...(.\n"
    " 0030: 04 00 03 00 01 00 00 00 00 00 00 00 00 80 04 08   ................\n"
    " 0040: 00 80 04 08 80 00 00 00 80 00 00 00 05 00 00 00   ................\n"
    " 0050: 00 10 00 00 01 00 00 00 80 00 00 00 80 90 04 08   ................\n"
    " 0060: 80 90 04 08 0C 00 00 00 0C 00 00 00 06 00 00 00   ................\n"
    " 0070: 00 10 00 00 B8 01 00 00 00 BB 2A 00 00 00 CD 80   ..........*.....\n"
    " 0080: 68 65 6C 6C 6F 20 77 6F 72 6C 64 00 00 2E 73 68   hello world...sh\n"
    " 0090: 73 74 72 74 61 62 00 2E 74 65 78 74 00 2E 64 61   strtab..text..da\n"
    " 00a0: 74 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ta..............\n"
    " 00b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................\n"
    " 00c0: 00 00 00 00 00 00 00 00 00 00 00 00 0B 00 00 00   ................\n"
    " 00d0: 01 00 00 00 06 00 00 00 74 80 04 08 74 00 00 00   ........t...t...\n"
    " 00e0: 0C 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00   ................\n"
    " 00f0: 00 00 00 00 11 00 00 00 01 00 00 00 03 00 00 00   ................\n"
    "\n";
    // clang-format on

    int            r  = TEST_FAILED;
    ParsedCommand* pc = parse_or_die("print");

    if (cmdctx_run(cc, pc, dfb->fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    parsed_command_destroy(pc);
    return r;
}

int TEST(hex_2)()
{
    // clang-format off
    const char* expected =
    "\n"
    "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    "       -----------------------------------------------\n"
    " 0000: 7F                                                .\n"
    "\n";
    // clang-format on

    int            r  = TEST_FAILED;
    ParsedCommand* pc = parse_or_die("print 1");

    if (cmdctx_run(cc, pc, dfb->fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    parsed_command_destroy(pc);
    return r;
}
