#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "linenoise/linenoise.h"
#include "cmd/cmd.h"
#include "parser.h"
#include "alloc.h"
#include "log.h"

const char* const   short_options  = "hw2bnc:";
const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"write", no_argument, NULL, 'w'},
    {"backup", no_argument, NULL, 'b'},
    {"no_warning", no_argument, NULL, 'n'},
    {"no_history", no_argument, NULL, 'n'},
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
    printf("  -h  --help        Give this help list\n"
           "  -w  --write       Open the file in write mode\n"
           "  -b  --backup      Backup original file in "
           "\"filename.bk\"\n"
           "  -2  --no_warning  Disable warnings\n"
           "  -n  --no_history  Do not save command history\n"
           "  -c  \"c1; c2; ...\" Execute the commands given as "
           "argument and exit\n"
           "\n"
           "command history is saved in \"$HOME/.bhex_history\", it can be "
           "changed setting BHEX_HISTORY_FILE environment variable\n");
    exit(exit_code);
}

static const char* get_home()
{
    // could be null!
    return getenv("HOME");
}

static const char* get_history_file()
{
    static char history_path[1024];
    static int  history_file_set = 0;

    if (history_file_set)
        return history_path;

    const char* history_file = getenv("BHEX_HISTORY_FILE");
    if (history_file) {
        if (strncpy(history_path, history_file, sizeof(history_path) - 1) <= 0)
            return NULL;

        history_path[sizeof(history_path) - 1] = 0;
        history_file_set                       = 1;
        return history_path;
    }

    const char* home = get_home();
    if (!home)
        return NULL;
    if (snprintf(history_path, sizeof(history_path) - 1, "%s/.bhex_history",
                 home) <= 0)
        return NULL;

    history_path[sizeof(history_path) - 1] = 0;
    history_file_set                       = 1;
    return history_path;
}

static int copy_file(const char* src, const char* dst)
{
    int result = 0;
    errno      = 0;

    FILE* src_f = fopen(src, "rb");
    if (src_f == NULL)
        goto ret;
    FILE* dst_f = fopen(dst, "wb");
    if (dst_f == NULL)
        goto ret_close_src;

    result = 1;
    while (1) {
        int ch = fgetc(src_f);
        if (ch == EOF)
            break;
        if (fputc(ch, dst_f) == EOF) {
            result = 0;
            goto ret_close_dst_src;
        }
    }

ret_close_dst_src:
    fclose(dst_f);
ret_close_src:
    fclose(src_f);
ret:
    return result;
}

static void mainloop(FileBuffer* fb, CmdContext* cc)
{
    static char prompt[256];

    print_banner();
    while (1) {
        snprintf(prompt, sizeof(prompt), "[0x%07llX] $ ", fb->off);
        char* inp = linenoise(prompt);
        if (!inp || strcmp(inp, "exit") == 0) {
            bhex_free(inp);
            break;
        }
        linenoiseHistoryAdd(inp);

        ParsedCommand* pc;
        int            r = parse(inp, &pc);
        if (r != PARSER_OK) {
            error("%s", parser_err_to_string(r));
            bhex_free(inp);
            continue;
        }

        r = cmdctx_run(cc, pc, fb);
        if (r != COMMAND_OK)
            error("%s", cmdctx_err_to_string(r));

        parsed_command_destroy(pc);
        bhex_free(inp);
    }
}

static void command_loop(FileBuffer* fb, CmdContext* cc, char* commands)
{
    int            r;
    ParsedCommand* pc;

    char* token = strtok(commands, ";");
    while (token) {
        if ((r = parse(token, &pc)) != PARSER_OK) {
            error("%s", parser_err_to_string(r));
            return;
        }
        if ((r = cmdctx_run(cc, pc, fb)) != COMMAND_OK) {
            error("%s", cmdctx_err_to_string(r));
            parsed_command_destroy(pc);
            return;
        }
        token = strtok(NULL, ";");
        parsed_command_destroy(pc);
    }
}

int main(int argc, char* argv[])
{
    const char* progname   = argv[0];
    const char* path       = NULL;
    char*       commands   = NULL;
    int         write_mode = 0, backup = 0, save_history = 1;
    int         c;
    while (optind < argc) {
        if ((c = getopt_long(argc, argv, short_options, long_options, NULL)) !=
            -1) {
            switch (c) {
                case 'w':
                    write_mode = 1;
                    break;
                case 'b':
                    backup = 1;
                    break;
                case '2':
                    disable_warning = 1;
                    break;
                case 'n':
                    save_history = 0;
                    break;
                case 'h':
                    print_banner();
                    usage(progname, 0);
                    break;
                case 'c':
                    commands = bhex_strdup(optarg);
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
        bhex_free(commands);

        error("missing input file");
        exit(1);
    }

    if (save_history && !commands) {
        const char* history_file = get_history_file();
        if (history_file)
            linenoiseHistoryLoad(history_file);
    }

    FileBuffer* fb = filebuffer_create(path, !write_mode);
    if (!fb) {
        bhex_free(commands);
        return 1;
    }

    if (backup) {
        size_t backupname_len = strlen(fb->path) + 3 + 1;
        char*  backupname     = bhex_malloc(backupname_len);
        if (snprintf(backupname, backupname_len, "%s.bk", fb->path) < 0)
            panic("snprintf failed");
        backupname[backupname_len - 1] = 0;

        if (!copy_file(fb->path, backupname))
            warning("unable to create the backup file: %s\n", strerror(errno));
        bhex_free(backupname);
    }

    if (!write_mode)
        warning("file opened in read-only mode (use the switch '-w' to open "
                "the file in write mode)");

    CmdContext* cc = cmdctx_init();
    if (commands)
        command_loop(fb, cc, commands);
    else
        mainloop(fb, cc);

    if (save_history && !commands) {
        const char* history_file = get_history_file();
        if (history_file) {
            if (linenoiseHistorySave(history_file) < 0)
                warning("unable to save the history");
        }
    }

    bhex_free(commands);
    cmdctx_destroy(cc);
    filebuffer_destroy(fb);
    return 0;
}
