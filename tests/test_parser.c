#include <string.h>

#include <cmdline_parser.h>
#include <ll.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

int  tokenize(const char* str, ll_t* o_result);
void destroy_token(uptr_t tptr);

int check_eq(ll_t* ll, const char** arr, size_t size)
{
    ll_node_t* curr = ll->head;
    u32_t      i    = 0;
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

int TEST(tokenize_simple)()
{
    ll_t ll;
    int  r = tokenize("ciao ciao come va\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"ciao", "ciao", "come", "va"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

int TEST(tokenize_simple_spaces)()
{
    ll_t ll;
    int  r = tokenize("    ciao   ciao \t\tcome va    \n\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"ciao", "ciao", "come", "va"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

int TEST(tokenize_quotation_ok)()
{
    ll_t ll;
    int  r = tokenize("ciao \"Mario Rossi\"\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"ciao", "Mario Rossi"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

int TEST(tokenize_quotation_err)()
{
    ll_t ll;
    int  r = tokenize("ciao \"Mario Rossi\n", &ll);
    return r == PARSER_ERR_UNCLOSED_QUOTATION;
}

int TEST(tokenize_cmd_params)()
{
    ll_t ll;
    int  r = tokenize("w/x/+16 aabbccdd\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"w", "/", "x", "/", "+16", "aabbccdd"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

int TEST(tokenize_cmd_help)()
{
    ll_t ll;
    int  r = tokenize("w?\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"w", "?"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

int TEST(tokenize_cmd_params_slash_in_arg)()
{
    ll_t ll;
    int  r = tokenize("w/x/+16 /ciao/ciao/ciao\n", &ll);
    if (r != PARSER_OK)
        return 0;

    const char* arr[] = {"w", "/", "x", "/", "+16", "/ciao/ciao/ciao"};
    r = check_eq(&ll, (const char**)&arr, sizeof(arr) / sizeof(char*));

    ll_clear(&ll, destroy_token);
    return r;
}

int TEST(parser_simple)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("help", &pc);
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

int TEST(parser_with_args)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("help a1 a2", &pc);
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

int TEST(parser_with_cmdmod)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("w/x/+16", &pc);
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

int TEST(parser_with_args_cmdmod)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("w/x/+16 aabbccdd", &pc);
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

int TEST(parser_help_mod)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("w?", &pc);
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

int TEST(parser_err_trailing_data)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("w? ciao", &pc);
    return r == PARSER_ERR_UNEXPECTED_TRAILING_DATA;
}

int TEST(parser_err_cmdmod_before_cmd)()
{
    ParsedCommand* pc;

    int r = cmdline_parse("/w", &pc);
    return r == PARSER_ERR_CMDMOD_BEFORE_CMD;
}
