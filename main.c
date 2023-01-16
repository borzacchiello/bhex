#include <stdio.h>

#include "parser.h"
#include "alloc.h"
#include "cmd/cmd.h"

static void print_banner()
{
    static const char* banner = "  ____  _    _\n"
                                " |  _ \\| |  | |\n"
                                " | |_) | |__| | _____  __\n"
                                " |  _ <|  __  |/ _ \\ \\/ /\n"
                                " | |_) | |  | |  __/>  < \n"
                                " |____/|_|  |_|\\___/_/\\_\\\n";
    puts(banner);
}

static void usage(const char* prog)
{
    printf("USAGE: %s <filepath>\n", prog);
    exit(1);
}

int main(int argc, char const* argv[])
{
    print_banner();

    if (argc < 2)
        usage(argv[0]);

    FileBuffer* fb = filebuffer_create(argv[1]);
    if (!fb)
        return 1;

    CmdContext* cc = cmdctx_init();

    while (1) {
        printf("[0x%07llX] $ ", fb->off);
        char* inp = bhex_getline();
        if (!inp)
            break;

        ParsedCommand* pc;
        int            r = parse(inp, &pc);
        if (r != PARSER_OK) {
            printf("  !Err: %s\n", parser_err_to_string(r));
            bhex_free(inp);
            continue;
        }

        r = cmdctx_run(cc, pc, fb);
        if (r != COMMAND_OK) {
            printf("  !Err: %s\n", cmdctx_err_to_string(r));
            bhex_free(inp);
            continue;
        }

        parsed_command_destroy(pc);
        bhex_free(inp);
    }

    cmdctx_destroy(cc);
    filebuffer_destroy(fb);
    return 0;
}
