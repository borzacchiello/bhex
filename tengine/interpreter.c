#include "interpreter.h"
#include "builtin.h"
#include "dlist.h"
#include "filebuffer.h"
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

#define interpreter_printf(ctx, ...)                                           \
    do {                                                                       \
        if (!ctx->quiet_mode) {                                                \
            display_printf(__VA_ARGS__);                                       \
        }                                                                      \
    } while (0)

#define min(x, y) ((x) < (y) ? (x) : (y))

static void*         imported_ptr = NULL;
static imported_cb_t imported_cb  = NULL;

static int           process_stmt(InterpreterContext* ctx, Stmt* stmt,
                                  struct Scope* scope);
static TEngineValue* evaluate_expr(InterpreterContext* ctx, Scope* scope,
                                   Expr* e);
static int           eval_to_u64(InterpreterContext* ctx, Scope* scope, Expr* e,
                                 u64_t* o);
static int           eval_to_str(InterpreterContext* ctx, Scope* scope, Expr* e,
                                 const char** o);

static void interpreter_context_soft_clone(InterpreterContext* dst,
                                           InterpreterContext* src)
{
    memcpy(dst, src, sizeof(InterpreterContext));
}

void tengine_raise_exception(InterpreterContext* ictx, const char* fmt, ...)
{
    if (ictx->exc == NULL) {
        ictx->exc     = bhex_calloc(sizeof(InterpreterException));
        ictx->exc->sb = strbuilder_new();
    } else {
        strbuilder_append(ictx->exc->sb, ", ");
    }

    ictx->stop_execution = 1;

    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvs(ictx->exc->sb, fmt, argp);
    va_end(argp);
}

static void value_pp(InterpreterContext* e, u32_t off, TEngineValue* v)
{
    char* value_str = TEngineValue_tostring(v, e->print_in_hex);
    if (off && count_chars_in_str(value_str, '\n'))
        value_str = str_indent(value_str, off);
    interpreter_printf(e, "%s", value_str);
    bhex_free(value_str);
}

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
    InterpreterContext cloned_ctx;
    interpreter_context_soft_clone(&cloned_ctx, ctx);

    map* result = NULL;
    if (type->bhe_name != NULL) {
        if (imported_cb == NULL) {
            warning("imported callback not configured");
            return NULL;
        }

        // from now on, and while parsing this type, use this AST
        ctx->ast = imported_cb(imported_ptr, type->bhe_name);
    }
    if (!ctx->ast)
        return NULL;

    Block* body = get_struct_body(ctx->ast, type->name);
    if (body == NULL)
        goto end;

    Scope* scope = Scope_new();

    interpreter_printf(ctx, "\n");
    ctx->print_off += 4;
    for (u64_t i = 0; i < body->stmts->size; ++i) {
        Stmt* stmt = (Stmt*)body->stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0) {
            Scope_free(scope);
            goto end;
        }
        if (ctx->stop_execution) {
            Scope_free(scope);
            cloned_ctx.stop_execution = 1;
            goto end;
        }
    }
    ctx->print_off -= 4;
    result = Scope_free_and_get_filevars(scope);

end:
    interpreter_context_soft_clone(ctx, &cloned_ctx);
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

            value_pp(ctx, ctx->print_off, r);
            interpreter_printf(ctx, "\n");
            return r;
        }
    }

    map* custom_type_vars = process_struct_type(ctx, type);
    if (ctx->stop_execution)
        return NULL;
    if (custom_type_vars != NULL) {
        TEngineValue* v = TEngineValue_OBJ_new(custom_type_vars);
        return v;
    }

    u64_t       econst;
    const char* enum_var = process_enum_type(ctx, type, &econst);
    if (enum_var != NULL) {
        TEngineValue* v = TEngineValue_ENUM_VALUE_new(enum_var, econst);
        value_pp(ctx, ctx->print_off, v);
        interpreter_printf(ctx, "\n");
        return v;
    }

    if (!ctx->stop_execution)
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

    for (u64_t i = 0; i < fn->block->stmts->size; ++i) {
        Stmt* stmt = fn->block->stmts->data[i];
        if (process_stmt(ctx, stmt, fn_scope) != 0)
            goto end;
        if (ctx->stop_execution)
            goto end;
    }
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
            value_pp(ctx, ctx->print_off, *oval);
            interpreter_printf(ctx, "\n");
            bhex_free(tmp);
            fb_seek(ctx->fb, final_off);
            return 0;
        }
        if (strcmp(type->name, "u8") == 0) {
            // Special case, buf
            u64_t       final_off     = ctx->fb->off + size;
            u64_t       size_to_print = min(MAX_ARR_PRINT_SIZE, size);
            const u8_t* buf           = fb_read(ctx->fb, size_to_print);
            if (buf == NULL)
                return 1;
            for (u64_t i = 0; i < size_to_print; ++i)
                interpreter_printf(ctx, "%02x", buf[i]);
            if (size_to_print < size)
                interpreter_printf(ctx, "...");
            interpreter_printf(ctx, "\n");

            *oval = TEngineValue_BUF_new(ctx->fb->off, size);
            fb_seek(ctx->fb, final_off);
            return 0;
        }
        const TEngineBuiltinType* t = get_builtin_type(type->name);
        if (t != NULL) {
            // A builtin type
            *oval = TEngineValue_ARRAY_new();

            u64_t printed = 0;
            interpreter_printf(ctx, "[ ");
            while (printed < size) {
                TEngineValue* val = t->process(ctx);
                if (val == NULL)
                    return 1;
                if (printed++ < MAX_ARR_PRINT_SIZE) {
                    value_pp(ctx, ctx->print_off, val);
                    if (printed <= size - 1)
                        interpreter_printf(ctx, ", ");
                }
                if (printed == MAX_ARR_PRINT_SIZE && size < printed)
                    interpreter_printf(ctx, "...");
                TEngineValue_ARRAY_append(*oval, val);
            }
            interpreter_printf(ctx, " ]\n");
            return 0;
        }
    }

    // Array of custom type
    u64_t printed = 0;
    *oval         = TEngineValue_ARRAY_new();

    interpreter_printf(ctx, "\n");
    for (u32_t i = 0; i < ctx->print_off + 11 + ctx->alignment_off; ++i)
        interpreter_printf(ctx, " ");
    interpreter_printf(ctx, "[%lld]", printed);
    for (printed = 0; printed < size; ++printed) {
        map* custom_type_vars = process_struct_type(ctx, type);
        if (ctx->stop_execution)
            return 1;
        if (custom_type_vars == NULL) {
            tengine_raise_exception(ctx, "unknown type %s", type->name);
            return 1;
        }
        if (printed < size - 1) {
            for (u32_t i = 0; i < ctx->print_off + 11 + ctx->alignment_off; ++i)
                interpreter_printf(ctx, " ");
            interpreter_printf(ctx, "[%lld]", printed + 1);
        }

        TEngineValue* el = TEngineValue_OBJ_new(custom_type_vars);
        TEngineValue_ARRAY_append(*oval, el);
    }
    return 0;
}

static int process_FILE_VAR_DECL(InterpreterContext* ctx, Stmt* stmt,
                                 Scope* scope)
{
    interpreter_printf(ctx, "b+%08llx ", ctx->fb->off - ctx->initial_off);
    for (u32_t i = 0; i < ctx->print_off; ++i)
        interpreter_printf(ctx, " ");
    interpreter_printf(ctx, " %*s: ", ctx->ast->max_ident_len, stmt->name);

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
        if (cond) {
            for (u64_t i = 0; i < ic->block->stmts->size; ++i) {
                Stmt* s = ic->block->stmts->data[i];
                if (process_stmt(ctx, s, scope) != 0)
                    return 1;
                if (ctx->stop_execution)
                    break;
            }
            return 0;
        }
    }
    if (stmt->else_block) {
        for (u64_t i = 0; i < stmt->else_block->stmts->size; ++i) {
            Stmt* s = stmt->else_block->stmts->data[i];
            if (process_stmt(ctx, s, scope) != 0)
                return 1;
            if (ctx->stop_execution)
                break;
        }
        return 0;
    }
    return 0;
}

static int process_STMT_WHILE(InterpreterContext* ctx, Stmt* stmt, Scope* scope)
{
    // TODO: same problem WRT STMT_IF

    u64_t cond;
    if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0)
        return 1;

    int breaked = 0;
    while (cond != 0) {
        DList* stmts = stmt->body->stmts;
        for (u64_t i = 0; i < stmts->size; ++i) {
            Stmt* stmt = (Stmt*)stmts->data[i];
            if (process_stmt(ctx, stmt, scope) != 0)
                return 1;
            if (ctx->should_break || ctx->stop_execution) {
                ctx->should_break = 0;
                breaked           = 1;
                break;
            }
        }
        if (breaked)
            break;

        if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0)
            return 1;
    }
    return 0;
}

static int process_stmt_internal(InterpreterContext* ctx, Stmt* stmt,
                                 Scope* scope)
{
    switch (stmt->t) {
        case FILE_VAR_DECL:
            return process_FILE_VAR_DECL(ctx, stmt, scope);
        case LOCAL_VAR_DECL:
            return process_LOCAL_VAR_DECL(ctx, stmt, scope);
        case LOCAL_VAR_ASS:
            return process_LOCAL_VAR_ASS(ctx, stmt, scope);
        case VOID_FUNC_CALL:
            return process_VOID_FUNC_CALL(ctx, stmt, scope);
        case STMT_IF_ELIF_ELSE:
            return process_STMT_IF_ELIF_ELSE(ctx, stmt, scope);
        case STMT_WHILE:
            return process_STMT_WHILE(ctx, stmt, scope);
        case STMT_BREAK:
            ctx->should_break = 1;
            return 0;
        default: {
            tengine_raise_exception(ctx, "invalid stmt type %d", stmt->t);
            break;
        }
    }
    return 1;
}

static int process_stmt(InterpreterContext* ctx, Stmt* stmt, Scope* scope)
{
    int r = process_stmt_internal(ctx, stmt, scope);
    if (ctx->exc != NULL) {
        // process the exception, as of today we just print it
        char* exc_msg = strbuilder_finalize(ctx->exc->sb);
        error("Exception @ line %d, col %d > %s", stmt->line_of_code,
              stmt->column, exc_msg);

        bhex_free(exc_msg);
        bhex_free(ctx->exc);
        ctx->exc = NULL;
    }
    return r;
}

static int process_ast(InterpreterContext* ictx)
{
    if (!ictx->ast->proc) {
        tengine_raise_exception(ictx, "no proc");
        return 1;
    }

    InterpreterContext cloned_ctx;
    interpreter_context_soft_clone(&cloned_ctx, ictx);

    DList* stmts = ictx->ast->proc->stmts;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(&cloned_ctx, stmt, ictx->proc_scope) != 0)
            return 1;
        if (cloned_ctx.stop_execution)
            break;
    }
    return 0;
}

static void interpreter_context_init(InterpreterContext* ictx, ASTCtx* ast,
                                     FileBuffer* fb)
{
    memset(ictx, 0, sizeof(InterpreterContext));
    ictx->ast           = ast;
    ictx->alignment_off = ast->max_ident_len;
    ictx->fb            = fb;
    ictx->proc_scope    = Scope_new();
    ictx->endianess     = TE_LITTLE_ENDIAN;
    ictx->print_in_hex  = 1;
}

static void interpreter_context_deinit(InterpreterContext* ictx)
{
    Scope_free(ictx->proc_scope);
    if (ictx->exc) {
        bhex_free(strbuilder_finalize(ictx->exc->sb));
    }
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

    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);

    if (process_ast(&ctx) != 0) {
        ASTCtx_delete(ast);
        interpreter_context_deinit(&ctx);
        return NULL;
    }
    ASTCtx_delete(ast);
    return ctx.proc_scope;
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
    InterpreterContext eng = {0};
    interpreter_context_init(&eng, ast, fb);

    int r = process_ast(&eng);
    interpreter_context_deinit(&eng);
    return r;
}

int tengine_interpreter_process_ast_struct(FileBuffer* fb, ASTCtx* ast,
                                           const char* s)
{
    InterpreterContext eng = {0};
    interpreter_context_init(&eng, ast, fb);

    int r = 1;
    if (!map_contains(ast->structs, s)) {
        error("no such struct '%s'", s);
        goto end;
    }

    InterpreterContext cloned_ctx;
    interpreter_context_soft_clone(&cloned_ctx, &eng);

    Block* b = map_get(ast->structs, s);
    for (u64_t i = 0; i < b->stmts->size; ++i) {
        Stmt* stmt = (Stmt*)b->stmts->data[i];
        if (process_stmt(&cloned_ctx, stmt, eng.proc_scope) != 0)
            goto end;
        if (cloned_ctx.stop_execution)
            break;
    }
    r = 0;

end:
    interpreter_context_deinit(&eng);
    return r;
}

void tengine_interpreter_pp(InterpreterContext* e)
{
    int orig_quiet_mode = e->quiet_mode;
    e->quiet_mode       = 0;

    printf("InterpreterContext\n\n");
    ASTCtx_pp(e->ast);

    printf("\nProc File Variables\n");
    printf("=========\n");
    for (const char* key = map_first(e->proc_scope->filevars); key != NULL;
         key             = map_next(e->proc_scope->filevars, key)) {
        printf("%s ", key);
        TEngineValue* v = map_get(e->proc_scope->filevars, key);
        value_pp(e, 0, v);
    }
    printf("\n");

    printf("\nProc Local Variables\n");
    printf("=========\n");
    for (const char* key = map_first(e->proc_scope->locals); key != NULL;
         key             = map_next(e->proc_scope->locals, key)) {
        printf("%s ", key);
        TEngineValue* v = map_get(e->proc_scope->locals, key);
        value_pp(e, 0, v);
    }
    printf("\n");

    e->quiet_mode = orig_quiet_mode;
}
