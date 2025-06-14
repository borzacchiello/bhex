#include "cmdline_parser.h"
#include "defs.h"
#include "strbuilder.h"

#include <string.h>
#include <alloc.h>
#include <ll.h>

static const char* space_tokens   = " \t\n";
static const char  quotation_char = '"';
static const char  backslash_char = '\\';

const char* parser_err_to_string(int err)
{
    switch (err) {
        case PARSER_OK:
            return "no error";
        case PARSER_ERR_UNCLOSED_QUOTATION:
            return "unclosed quotation";
        case PARSER_ERR_UNEXPECTED_SPACE:
            return "unexpected space";
        case PARSER_ERR_UNEXPECTED_EMPTY_STRING:
            return "unexpected empty string";
        case PARSER_ERR_NO_TOKENS:
            return "no tokens";
        case PARSER_ERR_CMDMOD_BEFORE_CMD:
            return "cmd modifier before cmd name";
        case PARSER_ERR_UNEXPECTED_TRAILING_DATA:
            return "unexpected data at the end";
        case PARSER_ERR_INVALID_HELP_SWITCH:
            return "invalid help (?) switch";
        case PARSER_ERR_INVALID_CMDMOD:
            return "invalid command modifier";
        default:
            break;
    }
    return "unknown";
}

static int is_token(char c, const char* one_char_tokens)
{
    const char* curr = one_char_tokens;
    while (*curr) {
        if (*curr == c)
            return 1;
        curr += 1;
    }
    return 0;
}

// The API is public to access it in the "test" binary
void destroy_token(uptr_t tptr) { bhex_free((void*)tptr); }

static u32_t skip_spaces(const char* s)
{
    u32_t       off  = 0;
    const char* curr = s;

    while (*curr && is_token(*curr, space_tokens)) {
        curr += 1;
        off += 1;
    }

    return off;
}

static int gen_token(const char* s, const char* one_char_tokens, char** o_token,
                     u32_t* o_off)
{
    *o_token = NULL;
    *o_off   = 0;

    if (!*s)
        return PARSER_ERR_UNEXPECTED_EMPTY_STRING;
    if (is_token(*s, space_tokens))
        return PARSER_ERR_UNEXPECTED_SPACE;

    u32_t       begin_off = 0;
    u32_t       end_off   = 0;
    u32_t       len       = 0;
    const char* curr      = s;

    if (is_token(*curr, one_char_tokens)) {
        // The character is a "one_char_token"
        len = 1;
    } else if (*s == quotation_char) {

        // eat all the characters (including spaces, tabs and tokens)
        // until we encounter a new "
        int            prev_was_backslash = 0;
        StringBuilder* o_token_sb         = strbuilder_new();

        // remove first quote
        curr += 1;
        while (*curr) {
            if (*curr == quotation_char && !prev_was_backslash) {
                // end of the quotation
                break;
            }

            if (prev_was_backslash && *curr != quotation_char &&
                *curr != backslash_char)
                strbuilder_append_char(o_token_sb, backslash_char);

            if (*curr != backslash_char)
                strbuilder_append_char(o_token_sb, *curr);
            else if (*curr == backslash_char && prev_was_backslash)
                strbuilder_append_char(o_token_sb, backslash_char);

            prev_was_backslash =
                (*curr == backslash_char && !prev_was_backslash);
            len += 1;
            curr += 1;
        }
        if (*curr != quotation_char) {
            // quote not closed
            bhex_free(strbuilder_finalize(o_token_sb));
            return PARSER_ERR_UNCLOSED_QUOTATION;
        }

        *o_off   = len + 2; // +2 for the two quotes
        *o_token = strbuilder_finalize(o_token_sb);
        return PARSER_OK;

    } else {
        // eat all the character until we encounter a space token or a
        // one_char_token
        while (*curr && !is_token(*curr, space_tokens) &&
               !is_token(*curr, one_char_tokens)) {
            len += 1;
            curr += 1;
        }
    }

    if (len == 0)
        return PARSER_ERR_UNEXPECTED_EMPTY_STRING;

    *o_token = bhex_malloc(len + 1);
    strncpy(*o_token, s + begin_off, len);
    (*o_token)[len] = 0;
    *o_off          = len + begin_off + end_off;
    return PARSER_OK;
}

// The API is public to access it in the "test" binary
int tokenize(const char* str, ll_t* o_result)
{
    static const char* phase1_tokens = "/?";
    static const char* phase2_tokens = "";

    *o_result = ll_create();

    const char* one_char_tokens = phase1_tokens;
    const char* curr            = str;

    curr += skip_spaces(curr);
    while (*curr) {
        char* token;
        u32_t off;
        int   r = gen_token(curr, one_char_tokens, &token, &off);
        if (r != PARSER_OK) {
            ll_clear(o_result, destroy_token);
            return r;
        }
        if (off == 0)
            break;

        curr += off;
        u32_t n_spaces = skip_spaces(curr);
        if (n_spaces > 0)
            // when we get the first space (ignoring the trailing initial
            // spaces), we disallow the "/" token for command parameters
            one_char_tokens = phase2_tokens;

        curr += n_spaces;
        ll_add(o_result, (uptr_t)token);
    }

    ll_invert(o_result);
    return PARSER_OK;
}

int cmdline_parse(const char* str, ParsedCommand** o_cmd)
{
    *o_cmd = NULL;

    ll_t tokens = ll_create();
    int  r      = tokenize(str, &tokens);
    if (r != PARSER_OK) {
        ll_clear(&tokens, destroy_token);
        return r;
    }
    if (tokens.size == 0)
        return PARSER_ERR_NO_TOKENS;

    ParsedCommand* pc = bhex_malloc(sizeof(ParsedCommand));
    pc->cmd           = NULL;
    pc->args          = ll_create();
    pc->cmd_modifiers = ll_create();
    pc->print_help    = 0;

    int        err              = PARSER_OK;
    int        next_is_modifier = 0;
    ll_node_t* token            = ll_pop(&tokens);
    while (token) {
        if (strcmp((char*)token->data, "/") == 0) {
            if (pc->cmd == NULL) {
                err = PARSER_ERR_CMDMOD_BEFORE_CMD;
                destroy_token(token->data);
                bhex_free(token);
                break;
            }
            if (next_is_modifier) {
                err = PARSER_ERR_INVALID_CMDMOD;
                destroy_token(token->data);
                bhex_free(token);
                break;
            }

            next_is_modifier = 1;
            destroy_token(token->data);
        } else if (strcmp((char*)token->data, "?") == 0) {
            if (pc->cmd == NULL) {
                err = PARSER_ERR_CMDMOD_BEFORE_CMD;
                destroy_token(token->data);
                bhex_free(token);
                break;
            }
            if (pc->cmd_modifiers.size != 0 || pc->args.size != 0) {
                err = PARSER_ERR_INVALID_HELP_SWITCH;
                destroy_token(token->data);
                bhex_free(token);
                break;
            }

            pc->print_help = 1;
            destroy_token(token->data);
            bhex_free(token);
            break;
        } else if (next_is_modifier) {
            next_is_modifier = 0;
            ll_add(&pc->cmd_modifiers, token->data);
        } else if (pc->cmd == NULL) {
            pc->cmd = (char*)token->data;
        } else {
            ll_add(&pc->args, token->data);
        }

        bhex_free(token);
        token = ll_pop(&tokens);
    }

    if (next_is_modifier) {
        err = PARSER_ERR_INVALID_CMDMOD;
    }
    if (err == PARSER_OK && tokens.size != 0) {
        err = PARSER_ERR_UNEXPECTED_TRAILING_DATA;
        ll_clear(&tokens, destroy_token);
    }
    if (err != PARSER_OK) {
        ll_clear(&tokens, destroy_token);
        parsed_command_destroy(pc);
        return err;
    }

    ll_invert(&pc->cmd_modifiers);
    ll_invert(&pc->args);

    *o_cmd = pc;
    return PARSER_OK;
}

void parsed_command_destroy(ParsedCommand* cmd)
{
    bhex_free(cmd->cmd);
    ll_clear(&cmd->cmd_modifiers, destroy_token);
    ll_clear(&cmd->args, destroy_token);
    bhex_free(cmd);
}
