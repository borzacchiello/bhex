#include "test.h"

#include <string.h>
#include <ll.h>

#include "../parser.h"

int  tokenize(const char* str, LL* o_result);
void destroy_token(uptr_t tptr);

__attribute__((unused)) static void print_token(uptr_t token)
{
    printf("<%s>", (char*)token);
}

static int check_eq(LL* ll, const char** arr, size_t size)
{
    LLNode* curr = ll->head;
    u32_t   i    = 0;
    while (curr) {
        if (i >= size)
            return 0;
        if (strcmp((const char*)curr->data, arr[i]) != 0)
            return 0;
        curr = curr->next;
        i++;
    }
    return 1;
}

static int test_tokenize_simple()
{
    LL  ll;
    int r = tokenize("ciao ciao come va\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"ciao", "ciao", "come", "va"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

static int test_tokenize_simple_spaces()
{
    LL  ll;
    int r = tokenize("    ciao   ciao \t\tcome va    \n\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"ciao", "ciao", "come", "va"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

static int test_tokenize_quotation_ok()
{
    LL  ll;
    int r = tokenize("ciao \"Mario Rossi\"\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"ciao", "Mario Rossi"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

static int test_tokenize_quotation_err()
{
    LL  ll;
    int r = tokenize("ciao \"Mario Rossi\n", &ll);
    return r == PARSER_ERR_UNCLOSED_QUOTATION;
}

static int test_tokenize_cmd_params()
{
    LL  ll;
    int r = tokenize("w/x/+16 aabbccdd\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"w", "/", "x", "/", "+16", "aabbccdd"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

static int test_tokenize_cmd_help()
{
    LL  ll;
    int r = tokenize("w?\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"w", "?"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

static int test_tokenize_cmd_params_slash_in_arg()
{
    LL  ll;
    int r = tokenize("w/x/+16 /ciao/ciao/ciao\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"w", "/", "x", "/", "+16", "/ciao/ciao/ciao"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

static int test_parser_simple()
{
    ParsedCommand* pc;

    int r = parse("help", &pc);
    if (r != PARSER_OK)
        return 0;

    r = 1;
    if (strcmp(pc->cmd, "help") != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->cmd_modifiers.size != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->args.size != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->print_help) {
        r = 0;
        goto EXIT;
    }

EXIT:
    parsed_command_destroy(pc);
    return r;
}

static int test_parser_with_args()
{
    ParsedCommand* pc;

    int r = parse("help a1 a2", &pc);
    if (r != PARSER_OK)
        return 0;

    r = 1;
    if (strcmp(pc->cmd, "help") != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->cmd_modifiers.size != 0) {
        r = 0;
        goto EXIT;
    }

    const char* arr[] = {"a1", "a2"};
    if (!check_eq(&pc->args, (const char**)&arr, sizeof(arr) / sizeof(char*))) {
        r = 0;
        goto EXIT;
    }
    if (pc->print_help) {
        r = 0;
        goto EXIT;
    }

EXIT:
    parsed_command_destroy(pc);
    return r;
}

static int test_parser_with_cmdmod()
{
    ParsedCommand* pc;

    int r = parse("w/x/+16", &pc);
    if (r != PARSER_OK)
        return 0;

    r = 1;
    if (strcmp(pc->cmd, "w") != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->args.size != 0) {
        r = 0;
        goto EXIT;
    }

    const char* arr[] = {"x", "+16"};
    if (!check_eq(&pc->cmd_modifiers, (const char**)&arr,
                  sizeof(arr) / sizeof(char*))) {
        r = 0;
        goto EXIT;
    }
    if (pc->print_help) {
        r = 0;
        goto EXIT;
    }

EXIT:
    parsed_command_destroy(pc);
    return r;
}

static int test_parser_with_args_cmdmod()
{
    ParsedCommand* pc;

    int r = parse("w/x/+16 aabbccdd", &pc);
    if (r != PARSER_OK)
        return 0;

    r = 1;
    if (strcmp(pc->cmd, "w") != 0) {
        r = 0;
        goto EXIT;
    }

    const char* arr1[] = {"aabbccdd"};
    if (!check_eq(&pc->args, (const char**)&arr1,
                  sizeof(arr1) / sizeof(char*))) {
        r = 0;
        goto EXIT;
    }

    const char* arr2[] = {"x", "+16"};
    if (!check_eq(&pc->cmd_modifiers, (const char**)&arr2,
                  sizeof(arr2) / sizeof(char*))) {
        r = 0;
        goto EXIT;
    }
    if (pc->print_help) {
        r = 0;
        goto EXIT;
    }

EXIT:
    parsed_command_destroy(pc);
    return r;
}

static int test_parser_help_mod()
{
    ParsedCommand* pc;

    int r = parse("w?", &pc);
    if (r != PARSER_OK)
        return 0;

    r = 1;
    if (strcmp(pc->cmd, "w") != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->cmd_modifiers.size != 0) {
        r = 0;
        goto EXIT;
    }
    if (pc->args.size != 0) {
        r = 0;
        goto EXIT;
    }
    if (!pc->print_help) {
        r = 0;
        goto EXIT;
    }

EXIT:
    parsed_command_destroy(pc);
    return r;
}

static int test_parser_err_trailing_data()
{
    ParsedCommand* pc;

    int r = parse("w? ciao", &pc);
    return r == PARSER_ERR_UNEXPECTED_TRAILING_DATA;
}

static int test_parser_err_cmdmod_before_cmd()
{
    ParsedCommand* pc;

    int r = parse("/w", &pc);
    return r == PARSER_ERR_CMDMOD_BEFORE_CMD;
}

static test_t tests[] = {
    {.name = "tokenize_simple", .fptr = &test_tokenize_simple},
    {.name = "tokenize_simple_spaces", .fptr = &test_tokenize_simple_spaces},
    {.name = "tokenize_quotation_ok", .fptr = &test_tokenize_quotation_ok},
    {.name = "tokenize_quotation_err", .fptr = &test_tokenize_quotation_err},
    {.name = "tokenize_cmd_params", .fptr = &test_tokenize_cmd_params},
    {.name = "tokenize_cmd_help", .fptr = &test_tokenize_cmd_help},
    {.name = "tokenize_cmd_params_slash_in_arg",
     .fptr = &test_tokenize_cmd_params_slash_in_arg},

    {.name = "parser_simple", .fptr = &test_parser_simple},
    {.name = "parser_with_args", .fptr = &test_parser_with_args},
    {.name = "parser_with_cmdmod", .fptr = &test_parser_with_cmdmod},
    {.name = "parser_with_args_cmdmod", .fptr = &test_parser_with_args_cmdmod},
    {.name = "parser_help_mod", .fptr = &test_parser_help_mod},
    {.name = "parser_err_trailing_data",
     .fptr = &test_parser_err_trailing_data},
    {.name = "parser_err_cmdmod_before_cmd",
     .fptr = &test_parser_err_cmdmod_before_cmd},
};

int main(int argc, char const* argv[])
{
    RUN_TESTS(tests);
    return 0;
}
