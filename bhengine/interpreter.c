// Copyright (c) 2022-2026, bageyelet

#include "interpreter.h"
#include "formatter.h"
#include "builtin.h"
#include "value.h"
#include "scope.h"
#include "ast.h"

#include <filebuffer.h>
#include <strbuilder.h>
#include <util/str.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <dlist.h>
#include <defs.h>
#include <log.h>
#include <map.h>

#define MAX_ARR_PRINT_SIZE 16

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

static fmt_t         format_type  = FMT_TERM;
static void*         imported_ptr = NULL;
static imported_cb_t imported_cb  = NULL;

static int process_stmts(InterpreterContext* ctx, DList* stmts, Scope* scope);
static int process_stmts_no_exc(InterpreterContext* ctx, DList* stmts,
                                Scope* scope);

static BHEngineValue* evaluate_expr(InterpreterContext* ctx, Scope* scope,
                                    Expr* e);
static int eval_to_u64(InterpreterContext* ctx, Scope* scope, Expr* e,
                       u64_t* o);
static int eval_to_str(InterpreterContext* ctx, Scope* scope, Expr* e,
                       const char** o);

void bhengine_interpreter_set_fmt_type(fmt_t t) { format_type = t; }

void bhengine_raise_exception(InterpreterContext* ctx, const char* fmt, ...)
{
    if (ctx->exc == NULL) {
        ctx->exc     = bhex_calloc(sizeof(InterpreterException));
        ctx->exc->sb = strbuilder_new();
    } else {
        // Deeply nested constructs unwind through here once per level; keep the
        // first few messages (the informative ones) and drop the rest instead
        // of emitting hundreds of identical lines.
        if (ctx->exc->nmsgs >= BHENGINE_MAX_EXC_MSGS) {
            ctx->halt = 1;
            return;
        }
        strbuilder_append(ctx->exc->sb, ", ");
    }
    ctx->exc->nmsgs += 1;

    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvs(ctx->exc->sb, fmt, argp);
    va_end(argp);

    ctx->halt = 1;
}

void bhengine_raise_exit_request(InterpreterContext* ctx) { ctx->halt = 1; }

static Block* get_struct_body(ASTCtx* ast, const char* name)
{
    return map_get_or_null(ast->structs, name);
}

static Enum* get_enum(ASTCtx* ast, const char* name)
{
    return map_get_or_null(ast->enums, name);
}

// The file var names are right adjusted on a column that is the same for all
// the fields of a nesting level, and that moves right by FMT_PRINT_OFF_STEP at
// every level. The base width of that column is computed here, once, before
// running the template: the column of a name at level N is already N *
// FMT_PRINT_OFF_STEP characters wider, so what that name asks of the base width
// is its length minus the indentation of its level. The maximum over all the
// file vars of the template (the imported ones included) is then the narrowest
// column that fits every name
#define NAME_COL_MAX_DEPTH 32

typedef struct NameColCtx {
    // the blocks already visited, mapped to the shallowest level they were
    // visited at: recursive structs would loop forever otherwise
    map*  visited;
    u64_t width;
} NameColCtx;

static void name_col_block(NameColCtx* nc, ASTCtx* ast, Block* b, u32_t level);

static void name_col_call(NameColCtx* nc, ASTCtx* ast, const char* fname,
                          DList* params, u32_t level);

static void name_col_expr(NameColCtx* nc, ASTCtx* ast, Expr* e, u32_t level)
{
    if (e == NULL)
        return;

    switch (e->t) {
        case EXPR_FUN_CALL:
            name_col_call(nc, ast, e->fname, e->params, level);
            break;
        case EXPR_BNOT:
            name_col_expr(nc, ast, e->child, level);
            break;
        case EXPR_SUBSCR:
            name_col_expr(nc, ast, e->subscr_e, level);
            break;
        case EXPR_ARRAY_SUB:
            name_col_expr(nc, ast, e->array_sub_e, level);
            name_col_expr(nc, ast, e->array_sub_n, level);
            break;
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_MUL:
        case EXPR_DIV:
        case EXPR_MOD:
        case EXPR_AND:
        case EXPR_OR:
        case EXPR_XOR:
        case EXPR_BEQ:
        case EXPR_BLT:
        case EXPR_BLE:
        case EXPR_BGT:
        case EXPR_BGE:
        case EXPR_BAND:
        case EXPR_BOR:
        case EXPR_SHL:
        case EXPR_SHR:
            name_col_expr(nc, ast, e->lhs, level);
            name_col_expr(nc, ast, e->rhs, level);
            break;
        default:
            // a leaf: nothing to visit
            break;
    }
}

// A function prints its file vars at the level of its caller
static void name_col_call(NameColCtx* nc, ASTCtx* ast, const char* fname,
                          DList* params, u32_t level)
{
    if (params != NULL)
        for (u64_t i = 0; i < params->size; ++i)
            name_col_expr(nc, ast, (Expr*)params->data[i], level);

    Function* fn = map_get_or_null(ast->functions, fname);
    if (fn != NULL)
        name_col_block(nc, ast, fn->block, level);
}

static void name_col_fvar(NameColCtx* nc, ASTCtx* ast, Stmt* stmt, u32_t level)
{
    u64_t indent = (u64_t)level * FMT_PRINT_OFF_STEP;
    u64_t len    = strlen(stmt->name);
    if (len > indent && len - indent > nc->width)
        nc->width = len - indent;

    name_col_expr(nc, ast, stmt->arr_size, level);

    // the fields of the struct, if this is one, are printed one level deeper
    ASTCtx* ty_ast = ast;
    if (stmt->type->bhe_name != NULL) {
        if (imported_cb == NULL)
            return;
        ty_ast = imported_cb(imported_ptr, stmt->type->bhe_name, 1);
        if (ty_ast == NULL)
            return;
    }
    Block* body = get_struct_body(ty_ast, stmt->type->name);
    if (body != NULL)
        name_col_block(nc, ty_ast, body, level + 1);
}

static void name_col_block(NameColCtx* nc, ASTCtx* ast, Block* b, u32_t level)
{
    if (b == NULL || level >= NAME_COL_MAX_DEPTH)
        return;

    // a block visited at a shallower level has already contributed everything
    // it could: at this level its names would need a narrower column
    char key[32];
    snprintf(key, sizeof(key), "%p", (void*)b);
    void* seen = map_get_or_null(nc->visited, key);
    if (seen != NULL && (u32_t)((uptr_t)seen - 1) <= level)
        return;
    map_set(nc->visited, key, (void*)((uptr_t)level + 1));

    for (u64_t i = 0; i < b->stmts->size; ++i) {
        Stmt* stmt = (Stmt*)b->stmts->data[i];
        switch (stmt->t) {
            case FILE_VAR_DECL:
                name_col_fvar(nc, ast, stmt, level);
                break;
            case LOCAL_VAR_DECL:
            case LOCAL_VAR_ASS:
                name_col_expr(nc, ast, stmt->local_value, level);
                break;
            case VOID_FUNC_CALL:
                name_col_call(nc, ast, stmt->fname, stmt->params, level);
                break;
            case STMT_IF_ELIF_ELSE: {
                // the branches print at the level of the block holding them
                for (u64_t j = 0; j < stmt->if_conditions->size; ++j) {
                    IfCond* ic = (IfCond*)stmt->if_conditions->data[j];
                    name_col_expr(nc, ast, ic->cond, level);
                    name_col_block(nc, ast, ic->block, level);
                }
                name_col_block(nc, ast, stmt->else_block, level);
                break;
            }
            case STMT_WHILE:
                name_col_expr(nc, ast, stmt->cond, level);
                name_col_block(nc, ast, stmt->body, level);
                break;
            default:
                break;
        }
    }
}

static u64_t compute_name_col_width(ASTCtx* ast, Block* entry)
{
    NameColCtx nc = {.visited = map_create(), .width = 0};
    name_col_block(&nc, ast, entry, 0);
    map_destroy(nc.visited);
    return nc.width;
}

static map* process_struct_type(InterpreterContext* ctx, Type* type)
{
    if (ctx->call_depth >= BHENGINE_MAX_CALL_DEPTH) {
        bhengine_raise_exception(
            ctx, "too many nested structs while processing %s", type->name);
        return NULL;
    }
    ctx->call_depth += 1;

    ASTCtx* saved_ast             = ctx->ast;
    int     saved_endianess       = ctx->endianess;
    int     saved_quiet_mode      = ctx->fmt->quiet_mode;
    u64_t   saved_max_array_print = ctx->fmt->max_array_print;

    map* result = NULL;
    if (type->bhe_name != NULL) {
        if (imported_cb == NULL) {
            warning("imported callback not configured");
            goto end;
        }

        // from now on, and while parsing this type, use this AST
        ctx->ast = imported_cb(imported_ptr, type->bhe_name, 0);
        if (ctx->ast == NULL)
            goto end;
    }
    if (!ctx->ast)
        goto end;

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
    ctx->call_depth -= 1;
    ctx->endianess            = saved_endianess;
    ctx->fmt->quiet_mode      = saved_quiet_mode;
    ctx->ast                  = saved_ast;
    ctx->fmt->max_array_print = saved_max_array_print;
    return result;
}

static char* process_enum_type(InterpreterContext* ctx, Type* type,
                               u64_t* econst)
{
    ASTCtx* ast = NULL;
    if (type->bhe_name != NULL) {
        if (imported_cb == NULL) {
            warning("imported callback not configured");
            return NULL;
        }
        ast = imported_cb(imported_ptr, type->bhe_name, 0);
    } else {
        ast = ctx->ast;
    }

    if (ast == NULL)
        return NULL;

    Enum* e = get_enum(ast, type->name);
    if (e == NULL)
        return NULL;

    const BHEngineBuiltinType* t = get_builtin_type(e->type);
    if (t == NULL) {
        bhengine_raise_exception(ctx, "Enum %s has an invalid source type [%s]",
                                 type->name, e->type);
        return NULL;
    }

    BHEngineValue* v = t->process(ctx);
    if (v == NULL)
        return NULL;

    u64_t val = v->t == TENGINE_UNUM ? v->unum : (u64_t)v->snum;
    if (econst)
        *econst = val;
    BHEngineValue_free(v);

    char* name = Enum_find_const(e, val);
    if (name == NULL) {
        warning("[tengine] Enum %s has no value %llu", type->name, val);
        StringBuilder* sb = strbuilder_new();
        strbuilder_appendf(sb, "UNK [%llu ~ 0x%llx]", val, val);
        return strbuilder_finalize(sb);
    }
    return name;
}

static BHEngineValue* process_type(InterpreterContext* ctx, const char* varname,
                                   Type* type, Scope* scope)
{
    if (type->bhe_name == NULL) {
        const BHEngineBuiltinType* t = get_builtin_type(type->name);
        if (t != NULL) {
            BHEngineValue* r = t->process(ctx);
            if (r == NULL)
                return NULL;
            fmt_process_value(ctx->fmt, r);
            return r;
        }
    } else {
        // An imported type. Resolve the template it comes from once and
        // quietly: both attempts below ask for it, so letting them report a
        // missing file would say the same thing twice, and neither of them
        // would mention which template was meant to hold the type
        if (imported_cb == NULL) {
            bhengine_raise_exception(
                ctx,
                "cannot import from '%s': no template loader is configured",
                type->bhe_name);
            return NULL;
        }
        if (imported_cb(imported_ptr, type->bhe_name, 1) == NULL) {
            bhengine_raise_exception(ctx, "cannot load template '%s'",
                                     type->bhe_name);
            return NULL;
        }
    }

    map* custom_type_vars = process_struct_type(ctx, type);
    if (custom_type_vars != NULL) {
        BHEngineValue* v = BHEngineValue_OBJ_new(custom_type_vars);
        return v;
    }

    u64_t econst;
    char* enum_var = process_enum_type(ctx, type, &econst);
    if (enum_var != NULL) {
        BHEngineValue* v = BHEngineValue_ENUM_VALUE_new(enum_var, econst);
        bhex_free(enum_var);
        fmt_process_value(ctx->fmt, v);
        return v;
    }

    // Name the template an imported type came from: "error while processing
    // eth_header" gives no hint about where it was looked for
    if (type->bhe_name != NULL)
        bhengine_raise_exception(ctx, "error while processing %s#%s",
                                 type->bhe_name, type->name);
    else
        bhengine_raise_exception(ctx, "error while processing %s", type->name);
    return NULL;
}

static BHEngineValue* handle_function_call(InterpreterContext* ctx,
                                           Function* fn, DList* params_exprs,
                                           Scope* caller_scope)
{
    if (ctx->call_depth >= BHENGINE_MAX_CALL_DEPTH) {
        bhengine_raise_exception(ctx, "too many nested calls while calling %s",
                                 fn->name);
        return NULL;
    }
    ctx->call_depth += 1;

    BHEngineValue* result                = NULL;
    Scope*         fn_scope              = NULL;
    int            saved_quiet_mode      = ctx->fmt->quiet_mode;
    int            saved_endianess       = ctx->endianess;
    u64_t          saved_max_array_print = ctx->fmt->max_array_print;
    int saved_break_or_continue_allowed  = ctx->break_or_continue_allowed;
    int saved_return_allowed             = ctx->return_allowed;
    int saved_breaked                    = ctx->breaked;
    int saved_continued                  = ctx->continued;
    int saved_returned                   = ctx->returned;
    ctx->break_or_continue_allowed       = 0;
    ctx->return_allowed                  = 1;
    ctx->breaked                         = 0;
    ctx->continued                       = 0;
    ctx->returned                        = 0;

    u64_t nparams         = params_exprs ? params_exprs->size : 0;
    u64_t expected_params = fn->params ? fn->params->size : 0;
    if (nparams != expected_params) {
        bhengine_raise_exception(
            ctx,
            "invalid number of parameters while calling %s: "
            "expected %llu, got %llu",
            fn->name, expected_params, nparams);
        goto end;
    }

    fn_scope = Scope_new();
    Scope_add_local(fn_scope, "result", BHEngineValue_UNUM_new(0, 8));
    for (u64_t i = 0; i < nparams; ++i)
        Scope_add_local(fn_scope, fn->params->data[i],
                        BHEngineValue_retain(params_exprs->data[i]));

    if (process_stmts_no_exc(ctx, fn->block->stmts, fn_scope) != 0)
        goto end;
    if (ctx->returned)
        ctx->returned = 0;
    result   = Scope_free_and_get_result(fn_scope);
    fn_scope = NULL;

end:
    ctx->call_depth -= 1;
    ctx->break_or_continue_allowed = saved_break_or_continue_allowed;
    ctx->return_allowed            = saved_return_allowed;
    ctx->breaked                   = saved_breaked;
    ctx->continued                 = saved_continued;
    ctx->returned                  = saved_returned;
    if (fn_scope)
        Scope_free(fn_scope);
    ctx->fmt->quiet_mode      = saved_quiet_mode;
    ctx->endianess            = saved_endianess;
    ctx->fmt->max_array_print = saved_max_array_print;
    return result;
}

// Arguments of a builtin call. A heap DList costs two allocations and two
// frees per call, and a template is mostly builtin calls with one or two
// arguments, so the list is built in the caller's frame whenever it fits. The
// builtin only ever reads size/data, and the list dies with the call.
#define BUILTIN_STACK_PARAMS 8

typedef struct BuiltinParams {
    DList list;
    void* slots[BUILTIN_STACK_PARAMS];
    int   on_heap;
} BuiltinParams;

static DList* evaluate_list_of_exprs(InterpreterContext* ctx, Scope* scope,
                                     DList* l);

// Returns the list to hand to the builtin: NULL both when the call takes no
// argument and when evaluating one failed, which *o_err tells apart.
static DList* builtin_params_eval(InterpreterContext* ctx, Scope* scope,
                                  DList* exprs, BuiltinParams* p, int* o_err)
{
    *o_err     = 0;
    p->on_heap = 0;
    if (exprs == NULL)
        return NULL;

    if (exprs->size > BUILTIN_STACK_PARAMS) {
        p->on_heap  = 1;
        DList* heap = evaluate_list_of_exprs(ctx, scope, exprs);
        if (heap == NULL)
            *o_err = 1;
        return heap;
    }

    // DList_add only grows when size reaches capacity, and it cannot here
    p->list.data     = p->slots;
    p->list.size     = 0;
    p->list.capacity = BUILTIN_STACK_PARAMS;
    for (u64_t i = 0; i < exprs->size; ++i) {
        BHEngineValue* el = evaluate_expr(ctx, scope, exprs->data[i]);
        if (el == NULL) {
            for (u64_t j = 0; j < p->list.size; ++j)
                BHEngineValue_free(p->list.data[j]);
            *o_err = 1;
            return NULL;
        }
        DList_add(&p->list, el);
    }
    return &p->list;
}

static void builtin_params_release(BuiltinParams* p, DList* params)
{
    if (params == NULL)
        return;
    if (p->on_heap) {
        DList_destroy(params, (void (*)(void*))BHEngineValue_free);
        return;
    }
    for (u64_t i = 0; i < params->size; ++i)
        BHEngineValue_free(params->data[i]);
}

// Kept out of evaluate_expr(), which is recursive and hot: the argument slots
// would otherwise sit in its frame on every call, builtin or not, and that
// costs more than it saves.
static BHEngineValue* call_builtin(InterpreterContext* ctx, Scope* scope,
                                   const BHEngineBuiltinFunc* bf,
                                   DList* param_exprs, int* o_failed)
{
    int           err = 0;
    BuiltinParams p;
    DList* params = builtin_params_eval(ctx, scope, param_exprs, &p, &err);
    if (err) {
        *o_failed = 1;
        return NULL;
    }

    if (check_builtin_arity(ctx, bf, params) != 0) {
        builtin_params_release(&p, params);
        *o_failed = 1;
        return NULL;
    }

    BHEngineValue* r = bf->process(ctx, params);
    builtin_params_release(&p, params);
    *o_failed = 0;
    return r;
}

static DList* evaluate_list_of_exprs(InterpreterContext* ctx, Scope* scope,
                                     DList* l)
{
    DList* r = NULL;
    if (l) {
        r = DList_new();
        for (u64_t i = 0; i < l->size; ++i) {
            BHEngineValue* el = evaluate_expr(ctx, scope, l->data[i]);
            if (el == NULL) {
                DList_destroy(r, (void (*)(void*))BHEngineValue_free);
                return NULL;
            }
            DList_add(r, el);
        }
    }
    return r;
}

static BHEngineValue* evaluate_expr(InterpreterContext* ctx, Scope* scope,
                                    Expr* e)
{
#define evaluate_check_null                                                    \
    if (!lhs || !rhs) {                                                        \
        BHEngineValue_free(lhs);                                               \
        BHEngineValue_free(rhs);                                               \
        return NULL;                                                           \
    }

    switch (e->t) {
        // A literal builds the same value on every evaluation, and values are
        // immutable once constructed, so the node builds one and hands out
        // references to it. Templates are full of magic numbers and masks, and
        // each of them used to be an allocation per pass
        case EXPR_SCONST:
            if (e->res_ptr == NULL)
                e->res_ptr =
                    BHEngineValue_SNUM_new(e->sconst_value, e->sconst_size);
            return BHEngineValue_retain((BHEngineValue*)e->res_ptr);
        case EXPR_UCONST:
            if (e->res_ptr == NULL)
                e->res_ptr =
                    BHEngineValue_UNUM_new(e->uconst_value, e->uconst_size);
            return BHEngineValue_retain((BHEngineValue*)e->res_ptr);
        case EXPR_ENUM_CONST: {
            // Resolving this means a map lookup plus a linear scan of the
            // enum's constants, for a value that is fixed at parse time. Cache
            // it against the AST it came from: the same node evaluated while
            // another AST is current (an imported type) has to resolve again
            if (e->res_ptr == ctx->ast)
                return BHEngineValue_UNUM_new(e->res_val, 8);

            Enum* enumptr = map_get_or_null(ctx->ast->enums, e->enum_name);
            if (!enumptr) {
                bhengine_raise_exception(ctx, "no such enum '%s'",
                                         e->enum_name);
                return NULL;
            }
            u64_t v;
            if (Enum_find_value(enumptr, e->enum_field, &v) != 0) {
                bhengine_raise_exception(ctx,
                                         "enum '%s' has no such field '%s'",
                                         e->enum_name, e->enum_field);
                return NULL;
            }
            e->res_ptr = ctx->ast;
            e->res_val = v;
            return BHEngineValue_UNUM_new(v, 8);
        }
        case EXPR_STRING:
            if (e->res_ptr == NULL)
                e->res_ptr = BHEngineValue_STRING_new(e->str, e->str_len);
            return BHEngineValue_retain((BHEngineValue*)e->res_ptr);
        case EXPR_VAR: {
            if (e->name_hash == 0)
                e->name_hash = map_hash(e->name);
            BHEngineValue* value =
                Scope_get_filevar_h(scope, e->name, e->name_hash);
            if (value)
                return BHEngineValue_retain(value);
            value = Scope_get_local_h(scope, e->name, e->name_hash);
            if (!value) {
                bhengine_raise_exception(ctx, "no such variable '%s'", e->name);
                return NULL;
            }
            // A reference, not a copy: values are immutable once built (an
            // array is only ever appended to while it is still being built,
            // before anything can name it), so reading a local no longer
            // deep-copies it. This is the same thing the file var branch above
            // has always done
            return BHEngineValue_retain(value);
        }
        case EXPR_SUBSCR: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->subscr_e);
            if (!lhs)
                return NULL;
            if (lhs->t != TENGINE_OBJ) {
                BHEngineValue_free(lhs);
                bhengine_raise_exception(
                    ctx, "invalid subscription operator: e is not an "
                         "object");
                return NULL;
            }

            BHEngineValue* val = map_get_or_null(lhs->subvals, e->subscr_name);
            if (val == NULL) {
                BHEngineValue_free(lhs);
                bhengine_raise_exception(
                    ctx,
                    "invalid subscription operator: e does not "
                    "contain '%s'",
                    e->subscr_name);
                return NULL;
            }
            BHEngineValue_retain(val);
            BHEngineValue_release(lhs);
            return val;
        }
        case EXPR_ARRAY_SUB: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->array_sub_e);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->array_sub_n);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_array_sub(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_FUN_CALL: {
            // The builtin table is immutable, so the answer is cached for good
            // -- including the "not a builtin" one, which sends the call down
            // to the fn lookup below
            if (!e->res_done) {
                e->res_ptr  = get_builtin_func(e->fname);
                e->res_done = 1;
            }
            const BHEngineBuiltinFunc* builtin_func =
                (const BHEngineBuiltinFunc*)e->res_ptr;
            if (builtin_func != NULL) {
                int            failed = 0;
                BHEngineValue* r =
                    call_builtin(ctx, scope, builtin_func, e->params, &failed);
                // a builtin that already raised has a better message than ours
                if (!failed && r == NULL && ctx->exc == NULL)
                    bhengine_raise_exception(ctx, "call to '%s' failed",
                                             e->fname);
                return r;
            }
            Function* fn_expr = map_get_or_null(ctx->ast->functions, e->fname);
            if (fn_expr != NULL) {
                // Custom function
                DList* params_vals = NULL;
                if (e->params) {
                    params_vals = evaluate_list_of_exprs(ctx, scope, e->params);
                    if (params_vals == NULL)
                        return NULL;
                }
                Function*      fn = fn_expr;
                BHEngineValue* result =
                    handle_function_call(ctx, fn, params_vals, scope);
                if (params_vals)
                    DList_destroy(params_vals,
                                  (void (*)(void*))BHEngineValue_free);
                if (!result)
                    return NULL;
                return result;
            }

            bhengine_raise_exception(ctx, "no such non-void function '%s'",
                                     e->fname);
            return NULL;
        }
        case EXPR_ADD: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_add(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_SUB: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_sub(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_MUL: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_mul(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_DIV: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_div(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_MOD: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_mod(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_AND: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_and(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_OR: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_or(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_XOR: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_xor(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_BEQ: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_beq(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_BLT: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_blt(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_BLE: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_ble(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_BGT: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_bgt(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_BGE: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_bge(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        // '&&' and '||' short circuit: the right hand side is evaluated only
        // when it can still change the result. Templates rely on it to guard a
        // call that would raise on the very values the left hand side is
        // checking for, e.g. `off() + 4 <= size() && peek_u32(4) == 0`.
        case EXPR_BAND: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            int            l   = BHEngineValue_truth(ctx, lhs, "band");
            BHEngineValue_free(lhs);
            if (l < 0)
                return NULL;
            if (l == 0)
                return BHEngineValue_UNUM_new(0, 1);

            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            int            r   = BHEngineValue_truth(ctx, rhs, "band");
            BHEngineValue_free(rhs);
            if (r < 0)
                return NULL;
            return BHEngineValue_UNUM_new(r, 1);
        }
        case EXPR_BOR: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            int            l   = BHEngineValue_truth(ctx, lhs, "bor");
            BHEngineValue_free(lhs);
            if (l < 0)
                return NULL;
            if (l == 1)
                return BHEngineValue_UNUM_new(1, 1);

            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            int            r   = BHEngineValue_truth(ctx, rhs, "bor");
            BHEngineValue_free(rhs);
            if (r < 0)
                return NULL;
            return BHEngineValue_UNUM_new(r, 1);
        }
        case EXPR_SHR: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_shr(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_SHL: {
            BHEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            BHEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);
            evaluate_check_null;

            BHEngineValue* res = BHEngineValue_shl(ctx, lhs, rhs);
            BHEngineValue_free(lhs);
            BHEngineValue_free(rhs);
            return res;
        }
        case EXPR_BNOT: {
            BHEngineValue* child = evaluate_expr(ctx, scope, e->child);
            if (!child)
                return NULL;

            BHEngineValue* res = BHEngineValue_bnot(ctx, child);
            BHEngineValue_free(child);
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
    BHEngineValue* v = evaluate_expr(ctx, scope, e);
    if (v == NULL)
        return 1;

    if (BHEngineValue_as_u64(ctx, v, o) != 0) {
        BHEngineValue_free(v);
        return 1;
    }
    BHEngineValue_free(v);
    return 0;
}

__attribute__((unused)) static int
eval_to_str(InterpreterContext* ctx, Scope* scope, Expr* e, const char** o)
{
    BHEngineValue* v = evaluate_expr(ctx, scope, e);
    if (v == NULL)
        return 1;

    if (BHEngineValue_as_string(ctx, v, o) != 0) {
        BHEngineValue_free(v);
        return 1;
    }
    BHEngineValue_free(v);
    return 0;
}

static int process_array_type(InterpreterContext* ctx, const char* varname,
                              Type* type, Expr* esize, Scope* scope,
                              BHEngineValue** oval)
{
    *oval = NULL;

    u64_t size;
    if (eval_to_u64(ctx, scope, esize, &size) != 0)
        return 1;

    if (size > ctx->fb->size - ctx->fb->off) {
        bhengine_raise_exception(
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
            *oval = BHEngineValue_STRING_new(tmp, size);
            fmt_process_value(ctx->fmt, *oval);
            bhex_free(tmp);
            fb_seek(ctx->fb, final_off);
            return 0;
        }
        if (strcmp(type->name, "wchar") == 0) {
            // Special case, the output variable is a wstring
            u64_t       final_off = ctx->fb->off + size * 2;
            u16_t*      tmp       = bhex_calloc(size * 2 + 2);
            const u8_t* buf       = fb_read(ctx->fb, size * 2);
            if (buf == NULL)
                return 1;
            for (u32_t i = 0; i < size; ++i) {
                tmp[i] =
                    ctx->endianess == TE_BIG_ENDIAN
                        ? (((u16_t)buf[i * 2] << 8) | (u16_t)buf[i * 2 + 1])
                        : (((u16_t)buf[i * 2 + 1] << 8) | (u16_t)buf[i * 2]);
            }
            *oval = BHEngineValue_WSTRING_new(tmp, size);
            fmt_process_value(ctx->fmt, *oval);
            bhex_free(tmp);
            fb_seek(ctx->fb, final_off);
            return 0;
        }
        if (strcmp(type->name, "u8") == 0) {
            // Special case, buf
            u64_t final_off = ctx->fb->off + size;
            *oval           = BHEngineValue_BUF_new(ctx->fb->off, size);
            fmt_process_buffer_value(ctx->fmt, ctx->fb, size);
            fb_seek(ctx->fb, final_off);
            return 0;
        }

        fmt_start_array(ctx->fmt, type);
        const BHEngineBuiltinType* t = get_builtin_type(type->name);
        if (t != NULL) {
            // A builtin type
            *oval = BHEngineValue_ARRAY_new();

            for (u64_t i = 0; i < size; ++i) {
                BHEngineValue* val = t->process(ctx);
                if (val == NULL) {
                    // the elements read so far go with it, the same way the
                    // custom type loop below discards a partial array
                    BHEngineValue_free(*oval);
                    *oval = NULL;
                    return 1;
                }
                fmt_notify_array_el(ctx->fmt, i);
                fmt_process_value(ctx->fmt, val);
                BHEngineValue_ARRAY_append(*oval, val);
            }
            fmt_end_array(ctx->fmt);
            return 0;
        }
    }

    // Array of custom type
    *oval = BHEngineValue_ARRAY_new();
    for (u64_t i = 0; i < size; ++i) {
        fmt_notify_array_el(ctx->fmt, i);
        map* custom_type_vars = process_struct_type(ctx, type);
        if (custom_type_vars == NULL) {
            bhengine_raise_exception(ctx, "error while processing %s",
                                     type->name);
            BHEngineValue_free(*oval);
            *oval = NULL;
            return 1;
        }

        BHEngineValue* el = BHEngineValue_OBJ_new(custom_type_vars);
        BHEngineValue_ARRAY_append(*oval, el);
    }
    fmt_end_array(ctx->fmt);
    return 0;
}

char* get_type_name(Stmt* v)
{
    if (v->t != FILE_VAR_DECL)
        return NULL;
    StringBuilder* sb = strbuilder_new();
    if (v->type->bhe_name != NULL)
        strbuilder_appendf(sb, "%s::", v->type->bhe_name);
    strbuilder_append(sb, v->type->name);
    if (v->arr_size != NULL)
        strbuilder_append(sb, "[]");
    return strbuilder_finalize(sb);
}

static int process_FILE_VAR_DECL(InterpreterContext* ctx, Stmt* stmt,
                                 Scope* scope)
{
    int ret                             = 0;
    int saved_break_or_continue_allowed = ctx->break_or_continue_allowed;
    int saved_return_allowed            = ctx->return_allowed;
    ctx->break_or_continue_allowed = ctx->return_allowed = 0;

    char* ty_name = get_type_name(stmt);
    fmt_start_var(ctx->fmt, stmt->name, ty_name,
                  ctx->fb->off - ctx->initial_off);
    bhex_free(ty_name);
    if (stmt->arr_size == NULL) {
        // Not an array
        BHEngineValue* val = process_type(ctx, stmt->name, stmt->type, scope);
        if (val == NULL)
            goto fail;
        Scope_add_filevar(scope, stmt->name, val);
    } else {
        // Array type
        BHEngineValue* val = NULL;
        if (process_array_type(ctx, stmt->name, stmt->type, stmt->arr_size,
                               scope, &val) != 0)
            goto fail;
        if (!val)
            panic("[tengine] process_array_type did not valorize an array");
        Scope_add_filevar(scope, stmt->name, val);
    }
    fmt_end_var(ctx->fmt, stmt->name);

end:
    ctx->break_or_continue_allowed = saved_break_or_continue_allowed;
    ctx->return_allowed            = saved_return_allowed;
    return ret;

fail:
    ret = 1;
    goto end;
}

static int process_LOCAL_VAR_DECL(InterpreterContext* ctx, Stmt* stmt,
                                  Scope* scope)
{
    BHEngineValue* v = evaluate_expr(ctx, scope, stmt->local_value);
    if (v == NULL)
        return 1;

    if (stmt->name_hash == 0)
        stmt->name_hash = map_hash(stmt->local_name);
    Scope_add_local_h(scope, stmt->local_name, v, stmt->name_hash);
    return 0;
}

static int process_LOCAL_VAR_ASS(InterpreterContext* ctx, Stmt* stmt,
                                 Scope* scope)
{
    BHEngineValue* v = evaluate_expr(ctx, scope, stmt->local_value);
    if (v == NULL)
        return 1;

    if (stmt->name_hash == 0)
        stmt->name_hash = map_hash(stmt->local_name);
    if (!Scope_update_local_h(scope, stmt->local_name, v, stmt->name_hash)) {
        bhengine_raise_exception(ctx, "no such local variable '%s",
                                 stmt->local_name);
        BHEngineValue_free(v);
        return 1;
    }
    return 0;
}

static int process_VOID_FUNC_CALL(InterpreterContext* ctx, Stmt* stmt,
                                  Scope* scope)
{
    // Cached like the expression form, see EXPR_FUN_CALL
    if (!stmt->res_done) {
        stmt->res_ptr  = get_builtin_func(stmt->fname);
        stmt->res_done = 1;
    }
    const BHEngineBuiltinFunc* builtin_func =
        (const BHEngineBuiltinFunc*)stmt->res_ptr;
    if (builtin_func != NULL) {
        int            failed = 0;
        BHEngineValue* r =
            call_builtin(ctx, scope, builtin_func, stmt->params, &failed);
        BHEngineValue_free(r);
        return failed;
    }
    Function* fn_stmt = map_get_or_null(ctx->ast->functions, stmt->fname);
    if (fn_stmt != NULL) {
        // Custom function
        DList* params_vals = NULL;
        if (stmt->params) {
            params_vals = evaluate_list_of_exprs(ctx, scope, stmt->params);
            if (params_vals == NULL)
                return 1;
        }
        Function*      fn = fn_stmt;
        BHEngineValue* result =
            handle_function_call(ctx, fn, params_vals, scope);
        if (params_vals)
            DList_destroy(params_vals, (void (*)(void*))BHEngineValue_free);
        if (!result)
            return 1;
        BHEngineValue_free(result);
        return 0;
    }

    bhengine_raise_exception(ctx, "no such function '%s'", stmt->fname);
    return 1;
}

static int process_STMT_IF_ELIF_ELSE(InterpreterContext* ctx, Stmt* stmt,
                                     Scope* scope)
{
    for (u64_t i = 0; i < stmt->if_conditions->size; ++i) {
        IfCond* ic = stmt->if_conditions->data[i];
        u64_t   cond;
        if (eval_to_u64(ctx, scope, ic->cond, &cond) != 0)
            return 1;
        if (cond) {
            Scope* inner = Scope_push(scope);
            int    ret   = process_stmts_no_exc(ctx, ic->block->stmts, inner);
            Scope_pop(inner);
            return ret;
        }
    }
    if (stmt->else_block) {
        Scope* inner = Scope_push(scope);
        int    ret = process_stmts_no_exc(ctx, stmt->else_block->stmts, inner);
        Scope_pop(inner);
        return ret;
    }
    return 0;
}

static int process_STMT_WHILE(InterpreterContext* ctx, Stmt* stmt, Scope* scope)
{
    int ret                             = 0;
    int saved_break_or_continue_allowed = ctx->break_or_continue_allowed;
    ctx->break_or_continue_allowed      = 1;

    u64_t cond;
    if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0)
        goto fail;

    // Reuse a single inner scope across all iterations: it is emptied (rather
    // than freed and reallocated) at the end of each pass, which keeps the
    // hot loop off the allocator when the body declares no locals.
    Scope* inner = cond != 0 ? Scope_push(scope) : NULL;
    while (cond != 0) {
        DList* stmts = stmt->body->stmts;
        int    r     = process_stmts_no_exc(ctx, stmts, inner);
        if (r != 0) {
            Scope_pop(inner);
            goto fail;
        }
        if (ctx->breaked || ctx->halt || ctx->returned) {
            Scope_pop(inner);
            goto end;
        }
        if (ctx->continued)
            ctx->continued = 0;
        if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0) {
            Scope_pop(inner);
            goto fail;
        }
        if (cond != 0)
            Scope_reset(inner);
        else
            Scope_pop(inner);
    }

end:
    ctx->breaked                   = 0;
    ctx->continued                 = 0;
    ctx->break_or_continue_allowed = saved_break_or_continue_allowed;
    return ret;

fail:
    ret = 1;
    goto end;
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
            if (!ctx->break_or_continue_allowed) {
                bhengine_raise_exception(ctx, "unexpected break");
                break;
            }
            ctx->breaked = 1;
            ret          = 0;
            break;
        case STMT_CONTINUE:
            if (!ctx->break_or_continue_allowed) {
                bhengine_raise_exception(ctx, "unexpected continue");
                break;
            }
            ctx->continued = 1;
            ret            = 0;
            break;
        case STMT_RETURN:
            if (!ctx->return_allowed) {
                bhengine_raise_exception(ctx, "unexpected return");
                break;
            }
            ctx->returned = 1;
            ret           = 0;
            break;
        default: {
            bhengine_raise_exception(ctx, "invalid stmt type %d", stmt->t);
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
        if (ctx->halt || ctx->breaked || ctx->continued || ctx->returned)
            return 0;
    }
    return 0;
}

static void print_exception_context(InterpreterContext* ctx, int lineno,
                                    int column)
{
    if (!ctx->ast->source)
        return;
    char *line, *curr, *tofree;
    tofree = curr = bhex_strdup(ctx->ast->source);

    int curr_lineno      = 1;
    int min_print_lineno = max(lineno - 2, 0);
    int max_print_lineno = lineno + 2;
    while ((line = _strsep(&curr, "\n")) != NULL) {
        if (curr_lineno >= min_print_lineno && curr_lineno <= max_print_lineno)
            error("%03d: %s", curr_lineno, line);
        if (curr_lineno == lineno) {
            StringBuilder* sb = strbuilder_new();
            strbuilder_append(sb, "     ");
            for (int i = 0; i < column - 1; ++i)
                strbuilder_append_char(sb, '_');
            strbuilder_append_char(sb, '^');
            char* errstr = strbuilder_finalize(sb);
            error("%s", errstr);
            bhex_free(errstr);
        }

        curr_lineno += 1;
    }
    bhex_free(tofree);
}

static int process_stmts(InterpreterContext* ctx, DList* stmts, Scope* scope)
{
    int ret = 0;

    fmt_start(ctx->fmt);
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0) {
            // it should fail only in case of an exception
            if (ctx->exc == NULL)
                bhengine_raise_exception(ctx, "RUNTIME ERROR");
            goto end;
        }
        // 'returned' can only be set where return_allowed was, which at this
        // level means the identify proc: it is the one entry point allowed to
        // answer early
        if (ctx->halt || ctx->breaked || ctx->returned)
            goto end;
    }

end:
    if (ctx->exc) {
        char* exc_msg = strbuilder_finalize(ctx->exc->sb);
        if (!ctx->silent_exc) {
            print_exception_context(ctx, ctx->curr_stmt->line_of_code,
                                    ctx->curr_stmt->column);
            error("Exception @ line %d, col %d > %s",
                  ctx->curr_stmt->line_of_code, ctx->curr_stmt->column,
                  exc_msg);
        }
        bhex_free(exc_msg);
        bhex_free(ctx->exc);
        ctx->exc = NULL;
        ret      = 1;
    }
    fmt_end(ctx->fmt);
    return ret;
}

static void interpreter_context_init(InterpreterContext* ctx, ASTCtx* ast,
                                     FileBuffer* fb)
{
    memset(ctx, 0, sizeof(InterpreterContext));
    ctx->ast               = ast;
    ctx->fb                = fb;
    ctx->proc_scope        = Scope_new();
    ctx->endianess         = TE_LITTLE_ENDIAN;
    ctx->fmt               = fmt_new(format_type);
    ctx->fmt->max_fvar_len = compute_name_col_width(ast, ast->proc);
    ctx->fmt->print_in_hex = 1;
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

void bhengine_interpreter_set_imported_types_callback(imported_cb_t cb,
                                                      void*         userptr)
{
    imported_ptr = userptr;
    imported_cb  = cb;
}

void* bhengine_interpreter_get_imported_types_userptr(void)
{
    return imported_ptr;
}

int bhengine_interpreter_process_filename(FileBuffer* fb, const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return 1;
    }

    int r = bhengine_interpreter_process_file(fb, f);
    fclose(f);
    return r;
}

int bhengine_interpreter_process_file(FileBuffer* fb, FILE* f)
{
    ASTCtx* ast = bhengine_parse_file(f);
    if (ast == NULL)
        return 1;

    int r = bhengine_interpreter_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

Scope* bhengine_interpreter_run_on_string(FileBuffer* fb, const char* str)
{
    ASTCtx* ast = bhengine_parse_string(str);
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

int bhengine_interpreter_process_string(FileBuffer* fb, const char* str)
{
    ASTCtx* ast = bhengine_parse_string(str);
    if (ast == NULL)
        return 1;

    int r = bhengine_interpreter_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

int bhengine_interpreter_process_ast(FileBuffer* fb, ASTCtx* ast)
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

int bhengine_interpreter_process_ast_struct(FileBuffer* fb, ASTCtx* ast,
                                            const char* s)
{
    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);

    int    r = 1;
    Block* b = map_get_or_null(ast->structs, s);
    if (!b) {
        error("no such struct '%s'", s);
        goto end;
    }

    ctx.fmt->max_fvar_len = compute_name_col_width(ast, b);
    r                     = process_stmts(&ctx, b->stmts, ctx.proc_scope);

end:
    interpreter_context_deinit(&ctx);
    return r;
}

struct BHEngineIdentifier {
    InterpreterContext ctx;
    Block*             body;
    unsigned int       result_hash;
    DList*             magics; // of BHEngineMagic*, possibly empty
};

void BHEngineMagic_delete(BHEngineMagic* m)
{
    bhex_free(m->pattern);
    bhex_free(m);
}

// Runs BHENGINE_IDENTIFY_MAGIC_PROC once, with a sink in place for magic() to
// append to. A proc that raises leaves whatever it managed to declare before
// the exception, which would be a subset of the truth and could hide a format,
// so its declarations are dropped entirely -- an empty list is the safe answer
// and only costs speed. The exception itself is printed: unlike "_identify",
// this runs once and a broken declaration is worth knowing about.
static DList* collect_magics(InterpreterContext* ctx, ASTCtx* ast)
{
    DList* magics = DList_new();

    Block* body =
        map_get_or_null(ast->named_procs, BHENGINE_IDENTIFY_MAGIC_PROC);
    if (body == NULL)
        return magics;

    Scope_reset(ctx->proc_scope);
    ctx->initial_off               = 0;
    ctx->endianess                 = TE_LITTLE_ENDIAN;
    ctx->call_depth                = 0;
    ctx->break_or_continue_allowed = 0;
    ctx->return_allowed            = 1;
    ctx->breaked                   = 0;
    ctx->continued                 = 0;
    ctx->returned                  = 0;
    ctx->halt                      = 0;

    int saved_silent = ctx->silent_exc;
    ctx->silent_exc  = 0;
    ctx->magics      = magics;

    int failed = process_stmts(ctx, body->stmts, ctx->proc_scope) != 0;

    ctx->magics     = NULL;
    ctx->silent_exc = saved_silent;

    if (failed) {
        warning("'" BHENGINE_IDENTIFY_MAGIC_PROC
                "' failed, falling back to scanning every offset");
        DList_destroy(magics, (void (*)(void*))BHEngineMagic_delete);
        return DList_new();
    }
    return magics;
}

const DList* bhengine_identifier_magics(BHEngineIdentifier* id)
{
    return id->magics;
}

BHEngineIdentifier* bhengine_identifier_new(FileBuffer* fb, ASTCtx* ast)
{
    Block* body = map_get_or_null(ast->named_procs, BHENGINE_IDENTIFY_PROC);
    if (body == NULL)
        return NULL;

    BHEngineIdentifier* id = bhex_calloc(sizeof(BHEngineIdentifier));
    interpreter_context_init(&id->ctx, ast, fb);
    id->ctx.fmt->quiet_mode = 1;
    id->ctx.silent_exc      = 1;
    id->body                = body;
    id->result_hash         = map_hash("result");
    id->magics              = collect_magics(&id->ctx, ast);
    return id;
}

void bhengine_identifier_free(BHEngineIdentifier* id)
{
    if (id == NULL)
        return;
    DList_destroy(id->magics, (void (*)(void*))BHEngineMagic_delete);
    interpreter_context_deinit(&id->ctx);
    bhex_free(id);
}

u64_t bhengine_identifier_run(BHEngineIdentifier* id, u64_t off)
{
    InterpreterContext* ctx = &id->ctx;

    if (fb_seek(ctx->fb, off) != 0)
        return 0;

    // Everything the previous offset may have left behind has to go, but the
    // scope is emptied rather than freed and reallocated: this runs once per
    // byte of the file, so the allocator is the first thing to keep out of the
    // loop
    Scope_reset(ctx->proc_scope);
    Scope_add_local_h(ctx->proc_scope, "result", BHEngineValue_UNUM_new(0, 8),
                      id->result_hash);

    ctx->initial_off               = off;
    ctx->endianess                 = TE_LITTLE_ENDIAN;
    ctx->call_depth                = 0;
    ctx->break_or_continue_allowed = 0;
    ctx->return_allowed            = 1;
    ctx->breaked                   = 0;
    ctx->continued                 = 0;
    ctx->returned                  = 0;
    ctx->halt                      = 0;

    // A non-zero return means an exception was raised and swallowed, which is
    // the normal way for a template to say "not my format"
    if (process_stmts(ctx, id->body->stmts, ctx->proc_scope) != 0)
        return 0;

    BHEngineValue* result = Scope_get_local(ctx->proc_scope, "result");
    if (result == NULL)
        return 0;

    // A 'result' that is not a number raises an exception here; discard it the
    // same way, the answer is just "no"
    u64_t skip = 0;
    if (BHEngineValue_as_u64(ctx, result, &skip) != 0)
        skip = 0;
    if (ctx->exc) {
        bhex_free(strbuilder_finalize(ctx->exc->sb));
        bhex_free(ctx->exc);
        ctx->exc = NULL;
    }
    return skip;
}

int bhengine_interpreter_process_ast_named_proc(FileBuffer* fb, ASTCtx* ast,
                                                const char* s)
{
    InterpreterContext ctx = {0};
    interpreter_context_init(&ctx, ast, fb);
    ctx.fmt->quiet_mode = 1;

    int    r = 1;
    Block* b = map_get_or_null(ast->named_procs, s);
    if (!b) {
        error("no such named proc '%s'", s);
        goto end;
    }

    // A named proc answers the same way a fn does, through 'result', and may
    // 'return' early to do it. Nothing forces it to -- most named procs are
    // alternative views and ignore the variable -- but it is what makes
    // "_identify" runnable on its own, with its exceptions printed, which is
    // the only way to debug one
    Scope_add_local(ctx.proc_scope, "result", BHEngineValue_UNUM_new(0, 8));
    ctx.return_allowed = 1;

    // "_identify_magic" declares through magic(), which needs somewhere to
    // append to; running it by hand is how an author sees what a template
    // actually claims
    DList* magics = NULL;
    if (strcmp(s, BHENGINE_IDENTIFY_MAGIC_PROC) == 0) {
        magics     = DList_new();
        ctx.magics = magics;
    }

    ctx.fmt->max_fvar_len = compute_name_col_width(ast, b);
    r                     = process_stmts(&ctx, b->stmts, ctx.proc_scope);
    ctx.magics            = NULL;

    if (r == 0 && magics != NULL) {
        display_printf("%llu magic pattern(s):\n", magics->size);
        for (u64_t i = 0; i < magics->size; ++i) {
            BHEngineMagic* m = (BHEngineMagic*)magics->data[i];
            display_printf("  +%-5llu ", m->offset);
            for (u32_t j = 0; j < m->size; ++j)
                display_printf("%02x ", m->pattern[j]);
            display_printf(" '");
            for (u32_t j = 0; j < m->size; ++j)
                display_printf("%c",
                               (m->pattern[j] >= 0x20 && m->pattern[j] < 0x7f)
                                   ? (char)m->pattern[j]
                                   : '.');
            display_printf("'\n");
        }
    }
    if (magics != NULL)
        DList_destroy(magics, (void (*)(void*))BHEngineMagic_delete);

    if (r == 0) {
        BHEngineValue* result = Scope_get_local(ctx.proc_scope, "result");
        u64_t          v      = 0;
        if (result && BHEngineValue_as_u64(&ctx, result, &v) == 0 && v != 0)
            display_printf("result: %llu\n", v);
    }

end:
    interpreter_context_deinit(&ctx);
    return r;
}
