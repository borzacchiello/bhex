#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <alloc.h>
#include <log.h>
#include <cmdline_parser.h>

#include "linenoise/linenoise.h"
#include "completion.h"
#include "cmd/cmd.h"

const char* const   short_options  = "hw2bnsc:";
const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"write", no_argument, NULL, 'w'},
    {"script", no_argument, NULL, 's'},
    {"backup", no_argument, NULL, 'b'},
    {"no_warning", no_argument, NULL, '2'},
    {"no_history", no_argument, NULL, 'n'},
    {NULL, 0, NULL, 0},
};

static void print_banner(void)
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
    printf("  -h  --help        Print help\n"
           "  -w  --write       Open the file in write mode\n"
           "  -b  --backup      Backup original file in "
           "\"filename.bk\"\n"
           "  -2  --no_warning  Disable warnings\n"
           "  -n  --no_history  Do not save command history\n"
           "  -c  \"c1; c2; ...\" Execute the commands given as "
           "argument and exit\n"
           "  -s  --script      Script mode (commands from raw stdin)\n"
           "\n"
           "command history is saved in \"$HOME/.bhex_history\", it can be "
           "changed setting BHEX_HISTORY_FILE environment variable\n");
    exit(exit_code);
}

static const char* get_home(void)
{
    // could be null!
    return getenv("HOME");
}

static const char* get_history_file(void)
{
    static char history_path[1024];
    static int  history_file_set = 0;

    if (history_file_set)
        return history_path;

    const char* history_file = getenv("BHEX_HISTORY_FILE");
    if (history_file) {
        if (strncpy(history_path, history_file, sizeof(history_path) - 1) ==
            NULL)
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

static void main_loop(FileBuffer* fb, CmdContext* cc)
{
    static char prompt[256];
    cmd_help(cc);
    printf("Write '?' after a command to read the relative help\n\n");

    while (1) {
        snprintf(prompt, sizeof(prompt), "[0x%07llX] $ ", fb->off);
        char* inp = linenoise(prompt);
        if (!inp || strcmp(inp, "exit") == 0) {
            bhex_free(inp);
            break;
        }
        linenoiseHistoryAdd(inp);

        ParsedCommand* pc;
        int            r = cmdline_parse(inp, &pc);
        if (r != PARSER_OK) {
            error("%s", parser_err_to_string(r));
            bhex_free(inp);
            continue;
        }

        r = cmdctx_run(cc, pc, fb);
        if (r != COMMAND_OK && r != COMMAND_SILENT_ERROR)
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
        if ((r = cmdline_parse(token, &pc)) != PARSER_OK) {
            error("%s", parser_err_to_string(r));
            return;
        }
        if ((r = cmdctx_run(cc, pc, fb)) != COMMAND_OK &&
            r != COMMAND_SILENT_ERROR) {
            error("%s", cmdctx_err_to_string(r));
            parsed_command_destroy(pc);
            return;
        }
        token = strtok(NULL, ";");
        parsed_command_destroy(pc);
    }
}

static void stdin_loop(FileBuffer* fb, CmdContext* cc)
{
    int            r;
    ParsedCommand* pc;

    size_t  len = 0;
    ssize_t nread;
    char*   lineptr = NULL;

    while ((nread = getline(&lineptr, &len, stdin)) != -1) {
        if ((r = cmdline_parse(lineptr, &pc)) != PARSER_OK) {
            error("%s", parser_err_to_string(r));
            return;
        }
        if ((r = cmdctx_run(cc, pc, fb)) != COMMAND_OK &&
            r != COMMAND_SILENT_ERROR) {
            error("%s", cmdctx_err_to_string(r));
            parsed_command_destroy(pc);
            return;
        }
        parsed_command_destroy(pc);
    }
    free(lineptr);
}

static int file_exists(const char* path) { return access(path, F_OK) == 0; }

static void create_file(const char* path)
{
    FILE* f = fopen(path, "w");
    if (f)
        fclose(f);
}

int main(int argc, char* argv[])
{
    const char* progname   = argv[0];
    const char* path       = NULL;
    char*       commands   = NULL;
    int         write_mode = 0, backup = 0, save_history = 1, script_mode = 0;
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
                case 's':
                    script_mode = 1;
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
        return 1;
    }

    if (commands && script_mode) {
        bhex_free(commands);

        error("cannot have both -c and -s");
        return 1;
    }

    if (save_history && !commands) {
        const char* history_file = get_history_file();
        if (history_file)
            linenoiseHistoryLoad(history_file);
    }

    if (write_mode && !file_exists(path))
        create_file(path);

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
            warning("unable to create the backup file: %s", strerror(errno));
        bhex_free(backupname);
    }

    if (!write_mode)
        warning("file opened in read-only mode (use the switch '-w' to open "
                "the file in write mode)");

    CmdContext* cc = cmdctx_init();
    set_commands_for_completion(cc);
    linenoiseSetCompletionCallback(bhex_shell_completion);
    linenoiseSetHintsCallback(bhex_shell_hint);
    linenoiseSetFreeHintsCallback(bhex_free);
    linenoiseSetMultiLine(1);

    if (commands)
        command_loop(fb, cc, commands);
    else if (script_mode)
        stdin_loop(fb, cc);
    else
        main_loop(fb, cc);
    cmdctx_destroy(cc);

    if (save_history && !commands) {
        const char* history_file = get_history_file();
        if (history_file) {
            if (linenoiseHistorySave(history_file) < 0)
                warning("unable to save the history");
        }
    }

    bhex_free(commands);
    filebuffer_destroy(fb);
    return 0;
}
