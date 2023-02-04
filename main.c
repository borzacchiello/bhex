#include <stdio.h>
#include <getopt.h>

#include "linenoise/linenoise.h"
#include "parser.h"
#include "alloc.h"
#include "cmd/cmd.h"

const char* const   short_options  = "hw";
const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"write", 0, NULL, 'w'},
    {NULL, 0, NULL, 0},
};

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

static void usage(const char* prog, int exit_code)
{
    printf("Usage:  %s [ options ] inputfile\n", prog);
    printf("  -h  --help   Display this usage information.\n"
           "  -w  --write  Open the file in write mode.\n");
    exit(exit_code);
}

static void mainloop(FileBuffer* fb, CmdContext* cc)
{
    static char prompt[256];

    while (1) {
        snprintf(prompt, sizeof(prompt), "[0x%07llX] $ ", fb->off);
        char* inp = linenoise(prompt);
        if (!inp)
            break;
        linenoiseHistoryAdd(inp);

        ParsedCommand* pc;
        int            r = parse(inp, &pc);
        if (r != PARSER_OK) {
            printf("  !Err: %s\n", parser_err_to_string(r));
            bhex_free(inp);
            continue;
        }

        r = cmdctx_run(cc, pc, fb);
        if (r != COMMAND_OK)
            printf("  !Err: %s\n", cmdctx_err_to_string(r));

        parsed_command_destroy(pc);
        bhex_free(inp);
    }
}

int main(int argc, char* argv[])
{
    print_banner();

    const char* progname   = argv[0];
    const char* path       = NULL;
    int         write_mode = 0;
    int         c;
    while (optind < argc) {
        if ((c = getopt_long(argc, argv, short_options, long_options, NULL)) !=
            -1) {
            switch (c) {
                case 'w':
                    write_mode = 1;
                    break;
                case 'h':
                    usage(progname, 0);
                    break;
                default:
                    break;
            }
        } else {
            if (path != NULL)
                usage(progname, 1);
            path = argv[optind++];
        }
    }
    if (path == NULL) {
        printf("Missing input file\n\n");
        usage(progname, 1);
    }

    FileBuffer* fb = filebuffer_create(path, !write_mode);
    if (!fb)
        return 1;

    CmdContext* cc = cmdctx_init();

    linenoiseHistorySetMaxLen(32);
    mainloop(fb, cc);

    cmdctx_destroy(cc);
    filebuffer_destroy(fb);
    return 0;
}
