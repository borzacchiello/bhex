#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>

#include "linenoise/linenoise.h"
#include "parser.h"
#include "alloc.h"
#include "log.h"
#include "cmd/cmd.h"

const char* const   short_options  = "hwbn";
const struct option long_options[] = {
    {"help", 0, NULL, 'h'},   {"write", 0, NULL, 'w'},
    {"backup", 0, NULL, 'b'}, {"no_history", 0, NULL, 'n'},
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
    printf("  -h  --help        Display this usage information.\n"
           "  -w  --write       Open the file in write mode.\n"
           "  -b  --backup      Backup original file in \"filename.bk\".\n"
           "  -n  --no_history  Do not save command history\n"
           "\n"
           "command history is saved in \"$HOME/.bhex_history\", but it can be "
           "changed setting BHEX_HISTORY_FILE env\n");
    exit(exit_code);
}

static const char* get_home()
{
    const char* homedir = NULL;
    if ((homedir = getenv("HOME")) == NULL)
        homedir = getpwuid(getuid())->pw_dir;
    // could be null!
    return homedir;
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
                case 'n':
                    save_history = 0;
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
        printf("missing input file\n\n");
        usage(progname, 1);
    }

    if (save_history) {
        const char* history_file = get_history_file();
        if (history_file)
            linenoiseHistoryLoad(history_file);
    }

    FileBuffer* fb = filebuffer_create(path, !write_mode);
    if (!fb)
        return 1;

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
        warning("file opened in read-only mode (use the switch '-w' to open the file in write mode)");

    CmdContext* cc = cmdctx_init();
    mainloop(fb, cc);

    if (save_history) {
        const char* history_file = get_history_file();
        if (history_file) {
            if (linenoiseHistorySave(history_file) < 0)
                warning("unable to save the history");
        }
    }

    cmdctx_destroy(cc);
    filebuffer_destroy(fb);
    return 0;
}
