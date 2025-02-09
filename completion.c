#include "defs.h"
#include "linenoise/linenoise.h"
#include "completion.h"
#include "cmd/cmd.h"
#include "cmd/cmd.h"

#include <dirent.h>
#include <libgen.h>
#include <alloc.h>
#include <strbuilder.h>
#include <string.h>
#include <ll.h>

CmdContext* g_cc = NULL;

void set_commands_for_completion(CmdContext* cc) { g_cc = cc; }

static int split_last_word(char* inp, char** prefix, char** last_word)
{
    if (!inp)
        return 1;
    size_t inp_len = strlen(inp);
    if (inp_len == 0) {
        *prefix    = NULL;
        *last_word = "";
        return 0;
    }

    size_t i = inp_len - 1;
    while (1) {
        if (inp[i] == ' ') {
            inp[i]     = 0;
            *prefix    = inp;
            *last_word = &inp[i + 1];
            return 0;
        }
        if (i == 0)
            break;
        i--;
    }
    *prefix    = NULL;
    *last_word = inp;
    return 0;
}

static int split_dir_file(char* path, char** dir, char** file)
{
    if (!path)
        return 1;
    size_t path_len = strlen(path);
    if (path_len == 0) {
        *dir  = "";
        *file = "";
        return 0;
    }

    size_t i = path_len - 1;
    while (1) {
        if (path[i] == '/') {
            path[i] = 0;
            *dir    = path;
            *file   = &path[i + 1];
            return 0;
        }
        if (i == 0)
            break;
        i--;
    }
    *dir  = "";
    *file = path;
    return 0;
}

static void file_completion(const char* prefix, const char* word,
                            linenoiseCompletions* lc)
{
    if (word == NULL)
        return;

    char* wordcp = bhex_strdup(word);
    char* dir;
    char* file;
    if (split_dir_file(wordcp, &dir, &file) != 0)
        return;
    if (strlen(dir) == 0)
        dir = (strlen(word) == 0 || word[0] != '/') ? "." : "/";

    size_t         file_len = strlen(file);
    DIR*           dirp     = NULL;
    struct dirent* entry;

    if (!(dirp = opendir(dir)))
        goto end;

    while ((entry = readdir(dirp))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (file_len > strlen(entry->d_name))
            continue;

        if (file_len == 0 || strncmp(file, entry->d_name, file_len) == 0) {
            StringBuilder* sb = strbuilder_new();
            strbuilder_appendf(sb, "%s %s", prefix, dir);
            if (sb->str[sb->size - 1] != '/')
                strbuilder_append_char(sb, '/');
            strbuilder_appendf(sb, "%s", entry->d_name);
            char* str = strbuilder_finalize(sb);
            linenoiseAddCompletion(lc, str);
            bhex_free(str);
        }
    }

end:
    if (dirp)
        closedir(dirp);
    bhex_free(wordcp);
}

static void cmd_completion(const char* word, linenoiseCompletions* lc)
{
    if (word == NULL)
        return;
    if (!g_cc)
        return;

    u64_t   num      = 0;
    size_t  word_len = strlen(word);
    LLNode* curr     = g_cc->commands.head;
    while (curr) {
        Cmd* cmd = (Cmd*)curr->data;
        if (word_len > strlen(cmd->name))
            continue;
        if (!word_len || strncmp(word, cmd->name, word_len) == 0) {
            linenoiseAddCompletion(lc, cmd->name);
            num++;
        }
        curr = curr->next;
    }
    if (num == 0)
        linenoiseAddCompletion(lc, word);
}

void bhex_shell_completion(const char* buf, linenoiseCompletions* lc)
{
    if (!buf)
        return;

    char* bufcp = bhex_strdup(buf);
    char* prefix;
    char* last_word;
    if (split_last_word(bufcp, &prefix, &last_word) != 0)
        goto end;

    if (prefix == NULL)
        // it is the first word
        cmd_completion(last_word, lc);
    else
        file_completion(prefix, last_word, lc);

end:
    bhex_free(bufcp);
}

char* bhex_shell_hint(const char* buf, int* color, int* bold)
{
    if (!g_cc)
        return NULL;
    if (!buf)
        return NULL;

    *bold = 1;
    char* r = NULL;

    char* bufcp = bhex_strdup(buf);
    char* prefix;
    char* last_word;
    if (split_last_word(bufcp, &prefix, &last_word) != 0)
        goto end;
    if (prefix != NULL)
        goto end;
    size_t word_len = strlen(last_word);

    LLNode* curr = g_cc->commands.head;
    while (curr) {
        Cmd* cmd = (Cmd*)curr->data;
        if (cmd->hint != NULL) {
            if (word_len == strlen(cmd->name) &&
                strncmp(last_word, cmd->name, word_len) == 0) {
                r = bhex_strdup(cmd->hint);
                goto end;
            }
            if (word_len == strlen(cmd->alias) &&
                strncmp(last_word, cmd->alias, word_len) == 0) {
                r = bhex_strdup(cmd->hint);
                goto end;
            }
        }
        curr = curr->next;
    }

end:
    bhex_free(bufcp);
    return r;
}
