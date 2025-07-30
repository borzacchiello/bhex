#include "interpreter.h"
#include "builtin.h"
#include "dlist.h"
#include "filebuffer.h"
#include "formatter.h"
#include "strbuilder.h"
#include "value.h"
#include "scope.h"
#include "defs.h"
#include "ast.h"

#include <util/str.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>
#include <map.h>

#define MAX_ARR_PRINT_SIZE 16

#define min(x, y) ((x) < (y) ? (x) : (y))

static fmt_t         format_type  = FMT_TERM;
static void*         imported_ptr = NULL;
static imported_cb_t imported_cb  = NULL;

static int process_stmts(InterpreterContext* ctx, DList* stmts, Scope* scope);
static int process_stmts_no_exc(InterpreterContext* ctx, DList* stmts,
                                Scope* scope);

static TEngineValue* evaluate_expr(InterpreterContext* ctx, Scope* scope,
                                   Expr* e);
static int           eval_to_u64(InterpreterContext* ctx, Scope* scope, Expr* e,
                                 u64_t* o);
static int           eval_to_str(InterpreterContext* ctx, Scope* scope, Expr* e,
                                 const char** o);

void tengine_interpreter_set_fmt_type(fmt_t t) { format_type = t; }

void tengine_raise_exception(InterpreterContext* ctx, const char* fmt, ...)
{
    if (ctx->exc == NULL) {
        ctx->exc     = bhex_calloc(sizeof(InterpreterException));
        ctx->exc->sb = strbuilder_new();
    } else {
        strbuilder_append(ctx->exc->sb, ", ");
    }

    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvs(ctx->exc->sb, fmt, argp);
    va_end(argp);

    ctx->halt = 1;
}

void tengine_raise_exit_request(InterpreterContext* ctx) { ctx->halt = 1; }

static Block* get_struct_body(ASTCtx* ast, const char* name)
{
    if (!map_contains(ast->structs, name))
        return NULL;
    return map_get(ast->structs, name);
}

static Enum* get_enum(ASTCtx* ast, const char* name)
{
    if (!map_contains(ast->enums, name))
        return NULL;
    return map_get(ast->enums, name);
}

static map* process_struct_type(InterpreterContext* ctx, Type* type)
{
    ASTCtx* saved_ast           = ctx->ast;
    u32_t   saved_max_ident_len = ctx->fmt->max_ident_len;

    map* result = NULL;
    if (type->bhe_name != NULL) {
        if (imported_cb == NULL) {
            warning("imported callback not configured");
            return NULL;
        }

        // from now on, and while parsing this type, use this AST
        ctx->ast                = imported_cb(imported_ptr, type->bhe_name);
        ctx->fmt->max_ident_len = ctx->ast->max_ident_len;
    }
    if (!ctx->ast)
        return NULL;

    Block* body = get_struct_body(ctx->ast, type->name);
    if (body == NULL)
        goto end;

    Scope* scope = Scope_new();
    if (process_stmts_no_exc(ctx, body->stmts, scope) != 0) {
        Scope_free(scope);
        goto end;
    }
    result = Scope_free_and_get_filevars(scope);

end:
    ctx->ast                = saved_ast;
    ctx->fmt->max_ident_len = saved_max_ident_len;
    return result;
}

static const char* process_enum_type(InterpreterContext* ctx, Type* type,
                                     u64_t* econst)
{
    ASTCtx* ast = NULL;
    if (type->bhe_name != NULL) {
        if (imported_cb == NULL) {
            warning("imported callback not configured");
            return NULL;
        }
        ast = imported_cb(imported_ptr, type->bhe_name);
    } else {
        ast = ctx->ast;
    }

    if (ast == NULL)
        return NULL;

    Enum* e = get_enum(ast, type->name);
    if (e == NULL)
        return NULL;

    const TEngineBuiltinType* t = get_builtin_type(e->type);
    if (t == NULL) {
        tengine_raise_exception(ctx, "Enum %s has an invalid source type [%s]",
                                type->name, e->type);
        return NULL;
    }

    TEngineValue* v = t->process(ctx);
    if (v == NULL)
        return NULL;

    u64_t val = v->t == TENGINE_UNUM ? v->unum : (u64_t)v->snum;
    if (econst)
        *econst = val;
    TEngineValue_free(v);

    const char* name = Enum_find_const(e, val);
    if (name == NULL) {
        warning("[tengine] Enum %s has no value %llu", type->name, val);
        static char tmpbuf[1024];
        memset(tmpbuf, 0, sizeof(tmpbuf));
        snprintf(tmpbuf, sizeof(tmpbuf) - 1, "UNK [%llu ~ 0x%llx]", val, val);
        return tmpbuf;
    }
    return name;
}

static TEngineValue* process_type(InterpreterContext* ctx, const char* varname,
                                  Type* type, Scope* scope)
{
    if (type->bhe_name == NULL) {
        const TEngineBuiltinType* t = get_builtin_type(type->name);
        if (t != NULL) {
            TEngineValue* r = t->process(ctx);
            if (r == NULL)
                return NULL;
            fmt_process_value(ctx->fmt, r);
            return r;
        }
    }

    map* custom_type_vars = process_struct_type(ctx, type);
    if (custom_type_vars != NULL) {
        TEngineValue* v = TEngineValue_OBJ_new(custom_type_vars);
        return v;
    }

    u64_t       econst;
    const char* enum_var = process_enum_type(ctx, type, &econst);
    if (enum_var != NULL) {
        TEngineValue* v = TEngineValue_ENUM_VALUE_new(enum_var, econst);
        fmt_process_value(ctx->fmt, v);
        return v;
    }

    tengine_raise_exception(ctx, "unknown type %s", type->name);
    return NULL;
}

static TEngineValue* handle_function_call(InterpreterContext* ctx, Function* fn,
                                          DList* params_exprs,
                                          Scope* caller_scope)
{
    TEngineValue* result   = NULL;
    Scope*        fn_scope = NULL;

    u64_t nparams         = params_exprs ? params_exprs->size : 0;
    u64_t expected_params = fn->params ? fn->params->size : 0;
    if (nparams != expected_params) {
        tengine_raise_exception(
            ctx,
            "invalid number of parameters while calling %s: "
            "expected %llu, got %llu",
            fn->name, expected_params, nparams);
        goto end;
    }

    fn_scope = Scope_new();
    Scope_add_local(fn_scope, "result", TEngineValue_UNUM_new(0, 8));
    for (u64_t i = 0; i < nparams; ++i)
        Scope_add_local(fn_scope, fn->params->data[i],
                        TEngineValue_dup(params_exprs->data[i]));

    if (process_stmts_no_exc(ctx, fn->block->stmts, fn_scope) != 0)
        goto end;
    result   = Scope_free_and_get_result(fn_scope);
    fn_scope = NULL;

end:
    if (fn_scope)
        Scope_free(fn_scope);
    return result;
}

static DList* evaluate_list_of_exprs(InterpreterContext* ctx, Scope* scope,
                                     DList* l)
{
    DList* r = NULL;
    if (l) {
        r = DList_new();
        for (u64_t i = 0; i < l->size; ++i) {
            TEngineValue* el = evaluate_expr(ctx, scope, l->data[i]);
            if (el == NULL) {
                DList_destroy(r, (void (*)(void*))TEngineValue_free);
                return NULL;
            }
            DList_add(r, el);
        }
    }
    return r;
}

static TEngineValue* evaluate_expr(InterpreterContext* ctx, Scope* scope,
                                   Expr* e)
{
#define evaluate_check_null                                                    \
    if (!lhs || !rhs) {                                                        \
        TEngineValue_free(lhs);                                                \
        TEngineValue_free(rhs);                                                \
        return NULL;                                                           \
    }

    switch (e->t) {
        case EXPR_SCONST:
            return TEngineValue_SNUM_new(e->sconst_value, e->sconst_size);
        case EXPR_UCONST:
            return TEngineValue_UNUM_new(e->uconst_value, e->uconst_size);
        case EXPR_ENUM_CONST: {
            if (!map_contains(ctx->ast->enums, e->enum_name)) {
                tengine_raise_exception(ctx, "no such enum '%s'", e->enum_name);
                return NULL;
            }
            u64_t v;
            Enum* enumptr = map_get(ctx->ast->enums, e->enum_name);
            if (Enum_find_value(enumptr, e->enum_field, &v) != 0) {
                tengine_raise_exception(ctx, "enum '%s' has no such field '%s'",
                                        e->enum_name, e->enum_field);
                return NULL;
            }
            return TEngineValue_UNUM_new(v, 8);
        }
        case EXPR_STRING:
            return TEngineValue_STRING_new(e->str, e->str_len);
        case EXPR_VAR: {
            TEngineValue* value = Scope_get_anyvar(scope, e->name);
            if (!value) {
                tengine_raise_exception(ctx, "no such variable '%s'", e->name);
                return NULL;
            }
            return TEngineValue_dup(value);
        }
        case EXPR_SUBSCR: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->subscr_e);
            if (!lhs)
                return NULL;
            if (lhs->t != TENGINE_OBJ) {
                TEngineValue_free(lhs);
                tengine_raise_exception(
                    ctx, "invalid subscription operator: e is not an "
                         "object");
                return NULL;
            }

            if (!map_contains(lhs->subvals, e->subscr_name)) {
                TEngineValue_free(lhs);
                tengine_raise_exception(
                    ctx,
                    "invalid subscription operator: e does not "
                    "contain '%s'",
                    e->subscr_name);
                return NULL;
            }
            TEngineValue* val = map_get(lhs->subvals, e->subscr_name);
            if (val == NULL)
                panic("[tengine] NULL during subscription operator");
            TEngineValue* res = TEngineValue_dup(val);
            TEngineValue_free(lhs);
            return res;
        }
        case EXPR_ARRAY_SUB: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->array_sub_e);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->array_sub_n);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_array_sub(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_FUN_CALL: {
            const TEngineBuiltinFunc* builtin_func = get_builtin_func(e->fname);
            if (builtin_func != NULL) {
                DList* params_vals = NULL;
                if (e->params) {
                    params_vals = evaluate_list_of_exprs(ctx, scope, e->params);
                    if (params_vals == NULL)
                        return NULL;
                }
                TEngineValue* r = builtin_func->process(ctx, params_vals);
                if (params_vals)
                    DList_destroy(params_vals,
                                  (void (*)(void*))TEngineValue_free);
                if (r == NULL)
                    tengine_raise_exception(ctx, "call to '%s' failed",
                                            e->fname);
                return r;
            }
            if (map_contains(ctx->ast->functions, e->fname)) {
                // Custom function
                DList* params_vals = NULL;
                if (e->params) {
                    params_vals = evaluate_list_of_exprs(ctx, scope, e->params);
                    if (params_vals == NULL)
                        return NULL;
                }
                Function*     fn = map_get(ctx->ast->functions, e->fname);
                TEngineValue* result =
                    handle_function_call(ctx, fn, params_vals, scope);
                if (params_vals)
                    DList_destroy(params_vals,
                                  (void (*)(void*))TEngineValue_free);
                if (!result)
                    return NULL;
                return result;
            }

            tengine_raise_exception(ctx, "no such non-void function '%s'",
                                    e->fname);
            return NULL;
        }
        case EXPR_ADD: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_add(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_SUB: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_sub(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_MUL: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_mul(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_DIV: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_div(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_MOD: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_mod(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_AND: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_and(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_OR: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_or(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_XOR: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_xor(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BEQ: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_beq(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BLT: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_blt(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BLE: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_ble(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BGT: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_bgt(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BGE: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_bge(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BAND: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_band(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BOR: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_bor(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_SHR: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_shr(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_SHL: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            TEngineValue* res = TEngineValue_shl(ctx, lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BNOT: {
            TEngineValue* child = evaluate_expr(ctx, scope, e->child);
            if (!child)
                return NULL;

            TEngineValue* res = TEngineValue_bnot(ctx, child);
            TEngineValue_free(child);
            return res;
        }
        default:
            break;
    }

    panic("[tengine] invalid expression");
    return NULL;
}

static int eval_to_u64(InterpreterContext* ctx, Scope* scope, Expr* e, u64_t* o)
{
    TEngineValue* v = evaluate_expr(ctx, scope, e);
    if (v == NULL)
        return 1;

    if (TEngineValue_as_u64(ctx, v, o) != 0) {
        TEngineValue_free(v);
        return 1;
    }
    TEngineValue_free(v);
    return 0;
}

__attribute__((unused)) static int
eval_to_str(InterpreterContext* ctx, Scope* scope, Expr* e, const char** o)
{
    TEngineValue* v = evaluate_expr(ctx, scope, e);
    if (v == NULL)
        return 1;

    if (TEngineValue_as_string(ctx, v, o) != 0) {
        TEngineValue_free(v);
        return 1;
    }
    TEngineValue_free(v);
    return 0;
}

static int process_array_type(InterpreterContext* ctx, const char* varname,
                              Type* type, Expr* esize, Scope* scope,
                              TEngineValue** oval)
{
    *oval = NULL;

    u64_t size;
    if (eval_to_u64(ctx, scope, esize, &size) != 0)
        return 1;

    if (size > ctx->fb->size - ctx->fb->off) {
        tengine_raise_exception(
            ctx,
            "invalid array size: %lld, it is bigger than the "
            "remaining file size",
            size);
        return 1;
    }

    if (type->bhe_name == NULL) {
        if (strcmp(type->name, "char") == 0) {
            // Special case, the output variable is a string
            u64_t       final_off = ctx->fb->off + size;
            u8_t*       tmp       = bhex_calloc(size + 1);
            const u8_t* buf       = fb_read(ctx->fb, size);
            if (buf == NULL)
                return 1;
            memcpy(tmp, buf, size);
            *oval = TEngineValue_STRING_new(tmp, size);
            fmt_process_value(ctx->fmt, *oval);
            bhex_free(tmp);
            fb_seek(ctx->fb, final_off);
            return 0;
        }
        if (strcmp(type->name, "u8") == 0) {
            // Special case, buf
            u64_t final_off = ctx->fb->off + size;
            *oval           = TEngineValue_BUF_new(ctx->fb->off, size);
            fmt_process_buffer_value(ctx->fmt, ctx->fb, size);
            fb_seek(ctx->fb, final_off);
            return 0;
        }

        fmt_start_array(ctx->fmt, type);
        const TEngineBuiltinType* t = get_builtin_type(type->name);
        if (t != NULL) {
            // A builtin type
            *oval = TEngineValue_ARRAY_new();

            for (u64_t i = 0; i < size; ++i) {
                TEngineValue* val = t->process(ctx);
                if (val == NULL)
                    return 1;
                fmt_notify_array_el(ctx->fmt, i);
                fmt_process_value(ctx->fmt, val);
                TEngineValue_ARRAY_append(*oval, val);
            }
            fmt_end_array(ctx->fmt);
            return 0;
        }
    }

    // Array of custom type
    *oval = TEngineValue_ARRAY_new();
    for (u64_t i = 0; i < size; ++i) {
        fmt_notify_array_el(ctx->fmt, i);
        map* custom_type_vars = process_struct_type(ctx, type);
        if (custom_type_vars == NULL) {
            tengine_raise_exception(ctx, "unknown type %s", type->name);
            TEngineValue_free(*oval);
            *oval = NULL;
            return 1;
        }

        TEngineValue* el = TEngineValue_OBJ_new(custom_type_vars);
        TEngineValue_ARRAY_append(*oval, el);
    }
    fmt_end_array(ctx->fmt);
    return 0;
}

static int process_FILE_VAR_DECL(InterpreterContext* ctx, Stmt* stmt,
                                 Scope* scope)
{
    fmt_start_var(ctx->fmt, stmt->name, stmt->type->name,
                  ctx->fb->off - ctx->initial_off);
    if (stmt->arr_size == NULL) {
        // Not an array
        TEngineValue* val = process_type(ctx, stmt->name, stmt->type, scope);
        if (val == NULL)
            return 1;
        Scope_add_filevar(scope, stmt->name, val);
    } else {
        // Array type
        TEngineValue* val = NULL;
        if (process_array_type(ctx, stmt->name, stmt->type, stmt->arr_size,
                               scope, &val) != 0)
            return 1;
        if (!val)
            panic("[tengine] process_array_type did not valorize an array");
        Scope_add_filevar(scope, stmt->name, val);
    }
    fmt_end_var(ctx->fmt, stmt->name);
    return 0;
}

static int process_LOCAL_VAR_DECL(InterpreterContext* ctx, Stmt* stmt,
                                  Scope* scope)
{
    TEngineValue* v = evaluate_expr(ctx, scope, stmt->local_value);
    if (v == NULL)
        return 1;

    Scope_add_local(scope, stmt->local_name, v);
    return 0;
}

static int process_LOCAL_VAR_ASS(InterpreterContext* ctx, Stmt* stmt,
                                 Scope* scope)
{
    TEngineValue* v = evaluate_expr(ctx, scope, stmt->local_value);
    if (v == NULL)
        return 1;

    if (Scope_get_local(scope, stmt->local_name) == NULL) {
        tengine_raise_exception(ctx, "no such local variable '%s",
                                stmt->local_name);
        TEngineValue_free(v);
        return 1;
    }

    Scope_add_local(scope, stmt->local_name, v);
    return 0;
}

static int process_VOID_FUNC_CALL(InterpreterContext* ctx, Stmt* stmt,
                                  Scope* scope)
{
    const TEngineBuiltinFunc* builtin_func = get_builtin_func(stmt->fname);
    if (builtin_func != NULL) {
        DList* params_vals = NULL;
        if (stmt->params) {
            params_vals = evaluate_list_of_exprs(ctx, scope, stmt->params);
            if (params_vals == NULL)
                return 1;
        }
        TEngineValue* r = builtin_func->process(ctx, params_vals);
        if (params_vals)
            DList_destroy(params_vals, (void (*)(void*))TEngineValue_free);
        TEngineValue_free(r);
        return 0;
    }
    if (map_contains(ctx->ast->functions, stmt->fname)) {
        // Custom function
        DList* params_vals = NULL;
        if (stmt->params) {
            params_vals = evaluate_list_of_exprs(ctx, scope, stmt->params);
            if (params_vals == NULL)
                return 1;
        }
        Function*     fn = map_get(ctx->ast->functions, stmt->fname);
        TEngineValue* result =
            handle_function_call(ctx, fn, params_vals, scope);
        if (params_vals)
            DList_destroy(params_vals, (void (*)(void*))TEngineValue_free);
        if (!result)
            return 1;
        TEngineValue_free(result);
        return 0;
    }

    tengine_raise_exception(ctx, "no such function '%s'", stmt->fname);
    return 1;
}

static int process_STMT_IF_ELIF_ELSE(InterpreterContext* ctx, Stmt* stmt,
                                     Scope* scope)
{
    // TODO: we are using the same context of the current block, to do the
    // things correctly we should define a new var context and delete the
    // new variables afterwards
    // Ex, this is currently correct (for now it is fine though):
    //   if (1) { u8 a; }
    //   if (a) { u8 b; }

    for (u64_t i = 0; i < stmt->if_conditions->size; ++i) {
        IfCond* ic = stmt->if_conditions->data[i];
        u64_t   cond;
        if (eval_to_u64(ctx, scope, ic->cond, &cond) != 0)
            return 1;
        if (cond)
            return process_stmts_no_exc(ctx, ic->block->stmts, scope);
    }
    if (stmt->else_block)
        return process_stmts_no_exc(ctx, stmt->else_block->stmts, scope);
    return 0;
}

static int process_STMT_WHILE(InterpreterContext* ctx, Stmt* stmt, Scope* scope)
{
    // TODO: same problem WRT STMT_IF

    u64_t cond;
    if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0)
        return 1;

    int ret            = 1;
    ctx->break_allowed = 1;
    while (cond != 0) {
        DList* stmts = stmt->body->stmts;
        if (process_stmts_no_exc(ctx, stmts, scope) != 0) {
            ctx->break_allowed = 0;
            goto end;
        }
        if (ctx->breaked) {
            ctx->breaked = 0;
            break;
        }
        if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0)
            goto end;
    }
    ret = 0;

end:
    ctx->break_allowed = 0;
    return ret;
}

static int process_stmt(InterpreterContext* ctx, Stmt* stmt, Scope* scope)
{
    // do not use directly this function in a loop, but always use
    // "process_stmts" or "process_stmts_no_exc"

    ctx->curr_stmt = stmt;

    int ret = 1;
    switch (stmt->t) {
        case FILE_VAR_DECL:
            ret = process_FILE_VAR_DECL(ctx, stmt, scope);
            break;
        case LOCAL_VAR_DECL:
            ret = process_LOCAL_VAR_DECL(ctx, stmt, scope);
            break;
        case LOCAL_VAR_ASS:
            ret = process_LOCAL_VAR_ASS(ctx, stmt, scope);
            break;
        case VOID_FUNC_CALL:
            ret = process_VOID_FUNC_CALL(ctx, stmt, scope);
            break;
        case STMT_IF_ELIF_ELSE:
            ret = process_STMT_IF_ELIF_ELSE(ctx, stmt, scope);
            break;
        case STMT_WHILE:
            ret = process_STMT_WHILE(ctx, stmt, scope);
            break;
        case STMT_BREAK:
            if (!ctx->break_allowed) {
                tengine_raise_exception(ctx, "unexpected break");
                break;
            }
            ctx->breaked = 1;
            ret          = 0;
            break;
        default: {
            tengine_raise_exception(ctx, "invalid stmt type %d", stmt->t);
            break;
        }
    }
    return ret;
}

static int process_stmts_no_exc(InterpreterContext* ctx, DList* stmts,
                                Scope* scope)
{
    // this function propagates errors without printing any exception
    // it must be used while processing inner statements (e.g., while, if, fn)
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0)
            return 1;
        if (ctx->halt || ctx->breaked)
            return 0;
    }
    return 0;
}

static int process_stmts(InterpreterContext* ctx, DList* stmts, Scope* scope)
{
    int ret = 0;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0) {
            // it should fail only in case of an exception
            if (ctx->exc == NULL)
                panic("process_stmt: unexpected state");
            goto end;
        }
        if (ctx->halt || ctx->breaked)
            goto end;
    }
    return ret;

end:
    if (ctx->exc) {
        char* exc_msg = strbuilder_finalize(ctx->exc->sb);
        error("Exception @ line %d, col %d > %s", ctx->curr_stmt->line_of_code,
              ctx->curr_stmt->column, exc_msg);
        bhex_free(exc_msg);
        bhex_free(ctx->exc);
        ctx->exc = NULL;
        ret      = 1;
    }
    return ret;
}

static void interpreter_context_init(InterpreterContext* ctx, ASTCtx* ast,
                                     FileBuffer* fb)
{
    memset(ctx, 0, sizeof(InterpreterContext));
    ctx->ast                = ast;
    ctx->fb                 = fb;
    ctx->proc_scope         = Scope_new();
    ctx->endianess          = TE_LITTLE_ENDIAN;
    ctx->fmt                = fmt_new(format_type);
    ctx->fmt->max_ident_len = ast->max_ident_len;
    ctx->fmt->print_in_hex  = 1;
}

static Scope* interpreter_deinit_and_get_context(InterpreterContext* ctx)
{
    Scope* scope = ctx->proc_scope;
    fmt_dispose(ctx->fmt);
    if (ctx->exc) {
        bhex_free(strbuilder_finalize(ctx->exc->sb));
    }
    return scope;
}

static void interpreter_context_deinit(InterpreterContext* ctx)
{
    Scope_free(interpreter_deinit_and_get_context(ctx));
}

void tengine_interpreter_set_imported_types_callback(imported_cb_t cb,
                                                     void*         userptr)
{
    imported_ptr = userptr;
    imported_cb  = cb;
}

int tengine_interpreter_process_filename(FileBuffer* fb, const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return 1;
    }

    int r = tengine_interpreter_process_file(fb, f);
    fclose(f);
    return r;
}

int tengine_interpreter_process_file(FileBuffer* fb, FILE* f)
{
    ASTCtx* ast = tengine_parse_file(f);
    if (ast == NULL)
        return 1;

    int r = tengine_interpreter_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

Scope* tengine_interpreter_run_on_string(FileBuffer* fb, const char* str)
{
    ASTCtx* ast = tengine_parse_string(str);
    if (ast == NULL) {
        return NULL;
    }

    if (!ast->proc) {
        error("the AST has not proc");
        ASTCtx_delete(ast);
        return NULL;
    }

    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);

    Scope* result = NULL;
    if (process_stmts(&ctx, ast->proc->stmts, ctx.proc_scope) != 0) {
        interpreter_context_deinit(&ctx);
        goto end;
    }
    result = interpreter_deinit_and_get_context(&ctx);

end:
    ASTCtx_delete(ast);
    return result;
}

int tengine_interpreter_process_string(FileBuffer* fb, const char* str)
{
    ASTCtx* ast = tengine_parse_string(str);
    if (ast == NULL)
        return 1;

    int r = tengine_interpreter_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

int tengine_interpreter_process_ast(FileBuffer* fb, ASTCtx* ast)
{
    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);

    if (!ast->proc) {
        error("the AST has not proc");
        return 1;
    }

    int r = process_stmts(&ctx, ast->proc->stmts, ctx.proc_scope);
    interpreter_context_deinit(&ctx);
    return r;
}

int tengine_interpreter_process_ast_struct(FileBuffer* fb, ASTCtx* ast,
                                           const char* s)
{
    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);

    int r = 1;
    if (!map_contains(ast->structs, s)) {
        error("no such struct '%s'", s);
        goto end;
    }

    Block* b = map_get(ast->structs, s);
    r        = process_stmts(&ctx, b->stmts, ctx.proc_scope);

end:
    interpreter_context_deinit(&ctx);
    return r;
}

int tengine_interpreter_process_ast_named_proc(FileBuffer* fb, ASTCtx* ast,
                                               const char* s)
{
    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);
    ctx.fmt->quiet_mode = 1;

    int r = 1;
    if (!map_contains(ast->named_procs, s)) {
        error("no such named proc '%s'", s);
        goto end;
    }

    Block* b = map_get(ast->named_procs, s);
    r        = process_stmts(&ctx, b->stmts, ctx.proc_scope);

end:
    interpreter_context_deinit(&ctx);
    return r;
}
