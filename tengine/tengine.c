#include "tengine.h"
#include "builtin.h"
#include "local.h"
#include "value.h"
#include "scope.h"
#include "ast.h"

#include <string.h>

#include <util/str.h>
#include <alloc.h>
#include <log.h>
#include <map.h>

#define MAX_ARR_PRINT_SIZE 16

typedef struct yy_buffer_state* YY_BUFFER_STATE;
extern int                      yyparse();
extern YY_BUFFER_STATE          yy_scan_string(const char* str);
extern void                     yy_delete_buffer(YY_BUFFER_STATE buffer);

typedef struct ProcessContext {
    FileBuffer* fb;
    TEngine*    engine;
    u64_t       initial_off;
    int         print_off;
    int         should_break;
} ProcessContext;

static int process_stmt(ProcessContext* ctx, Stmt* stmt, struct Scope* scope);
static TEngineValue* evaluate_expr(ProcessContext* ctx, Scope* scope, Expr* e);
static int eval_to_u64(ProcessContext* ctx, Scope* scope, Expr* e, u64_t* o);
static int eval_to_str(ProcessContext* ctx, Scope* scope, Expr* e,
                       const char** o);

static void value_pp(TEngine* e, u32_t off, TEngineValue* v)
{
    char* value_str = TEngineValue_tostring(v, e->print_in_hex);
    if (off && count_chars_in_str(value_str, '\n'))
        value_str = str_indent(value_str, off);
    engine_printf(e, value_str);
    bhex_free(value_str);
}

static Block* get_struct_body(TEngine* e, const char* name)
{
    for (const char* key = map_first(e->ast->structs); key != NULL;
         key             = map_next(e->ast->structs, key)) {
        if (strcmp(name, key) != 0)
            continue;
        return map_get(e->ast->structs, key);
    }
    return NULL;
}

static Enum* get_enum(TEngine* e, const char* name)
{
    for (const char* key = map_first(e->ast->enums); key != NULL;
         key             = map_next(e->ast->enums, key)) {
        if (strcmp(name, key) != 0)
            continue;
        return map_get(e->ast->enums, key);
    }
    return NULL;
}

static map* process_struct_type(ProcessContext* ctx, const char* type)
{
    Block* body = get_struct_body(ctx->engine, type);
    if (body == NULL)
        return NULL;

    Scope* scope = Scope_new();

    engine_printf(ctx->engine, "\n");
    ctx->print_off += 4;
    for (u64_t i = 0; i < body->stmts->size; ++i) {
        Stmt* stmt = (Stmt*)body->stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0) {
            Scope_free(scope);
            return NULL;
        }
    }
    ctx->print_off -= 4;
    return Scope_free_and_get_filevars(scope);
}

static const char* process_enum_type(ProcessContext* ctx, const char* type,
                                     u64_t* econst)
{
    Enum* e = get_enum(ctx->engine, type);
    if (e == NULL)
        return NULL;

    const TEngineBuiltinType* t = get_builtin_type(e->type);
    if (t == NULL) {
        error("[tengine] Enum %s has an invalid source type [%s]", type,
              e->type);
        return NULL;
    }

    TEngineValue* v = t->process(ctx->engine, ctx->fb);
    if (v == NULL)
        return NULL;

    u64_t val = v->t == TENGINE_UNUM ? v->unum : (u64_t)v->snum;
    if (econst)
        *econst = val;
    TEngineValue_free(v);

    const char* name = Enum_find_const(e, val);
    if (name == NULL) {
        warning("[tengine] Enum %s has no value %llu", type, val);
        static char tmpbuf[1024];
        memset(tmpbuf, 0, sizeof(tmpbuf));
        snprintf(tmpbuf, sizeof(tmpbuf) - 1, "UNK [%llu ~ 0x%llx]", val, val);
        return tmpbuf;
    }
    return name;
}

static TEngineValue* process_type(ProcessContext* ctx, const char* varname,
                                  const char* type, Scope* scope)
{
    const TEngineBuiltinType* t = get_builtin_type(type);
    if (t != NULL) {
        TEngineValue* r = t->process(ctx->engine, ctx->fb);
        if (r == NULL)
            return NULL;

        value_pp(ctx->engine, ctx->print_off, r);
        engine_printf(ctx->engine, "\n");
        return r;
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
        value_pp(ctx->engine, ctx->print_off, v);
        engine_printf(ctx->engine, "\n");
        return v;
    }

    error("[tengine] unknown type %s", type);
    return NULL;
}

static DList* evaluate_list_of_exprs(ProcessContext* ctx, Scope* scope,
                                     DList* l)
{
    DList* r = NULL;
    if (l) {
        r = DList_new();
        for (u64_t i = 0; i < l->size; ++i) {
            TEngineValue* el = evaluate_expr(ctx, scope, l->data[i]);
            if (el == NULL) {
                DList_foreach(r, (void (*)(void*))TEngineValue_free);
                DList_deinit(r);
                return NULL;
            }
            DList_add(r, el);
        }
    }
    return r;
}

static TEngineValue* evaluate_expr(ProcessContext* ctx, Scope* scope, Expr* e)
{
    switch (e->t) {
        case EXPR_CONST:
            return TEngineValue_SNUM_new(e->value, 64);
        case EXPR_VAR: {
            TEngineValue* value = Scope_get_anyvar(scope, e->name);
            if (!value) {
                error("[tengine] no such variable '%s'", e->name);
                return NULL;
            }
            return TEngineValue_dup(value);
        }
        case EXPR_VARCHAIN: {
            if (e->chain->size == 0) {
                panic("[tengine] varchain with size zero");
                return NULL;
            }

            // Only FILEVARS can have custom types
            TEngineValue* val = Scope_get_filevar(scope, e->chain->data[0]);
            u64_t         i   = 1;
            if (val->t == TENGINE_OBJ) {
                map* vars = val->subvals;
                for (; i < e->chain->size; ++i) {
                    char* n = e->chain->data[i];
                    if (!map_contains(vars, n)) {
                        error("[tengine] no such variable (in chain) '%s'", n);
                        return NULL;
                    }
                    val = map_get(vars, n);
                    if (val->t != TENGINE_OBJ)
                        break;
                    vars = val->subvals;
                }
            }
            if (val == NULL || i != e->chain->size - 1) {
                error("[tengine] invalid chain");
                return NULL;
            }
            return TEngineValue_dup(val);
        }
        case EXPR_FUN_CALL: {
            const TEngineBuiltinFunc* func = get_builtin_func(e->fname);
            if (func == NULL) {
                error("[tengine] no such non-void function '%s'", e->fname);
                return NULL;
            }
            DList* params_vals = evaluate_list_of_exprs(ctx, scope, e->params);
            TEngineValue* r = func->process(ctx->engine, ctx->fb, params_vals);
            if (params_vals) {
                DList_foreach(params_vals, (void (*)(void*))TEngineValue_free);
                DList_deinit(params_vals);
            }
            return r;
        }
        case EXPR_ADD: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_add(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_SUB: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_sub(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_MUL: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_mul(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BEQ: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_beq(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BLT: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_blt(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BLE: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_ble(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BGT: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_bgt(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        case EXPR_BGE: {
            TEngineValue* lhs = evaluate_expr(ctx, scope, e->lhs);
            TEngineValue* rhs = evaluate_expr(ctx, scope, e->rhs);

            TEngineValue* res = TEngineValue_bge(lhs, rhs);
            TEngineValue_free(lhs);
            TEngineValue_free(rhs);
            return res;
        }
        default:
            break;
    }

    panic("[tengine] invalid expression");
    return NULL;
}

static int eval_to_u64(ProcessContext* ctx, Scope* scope, Expr* e, u64_t* o)
{
    TEngineValue* v = evaluate_expr(ctx, scope, e);
    if (v == NULL)
        return 1;

    if (TEngineValue_as_u64(v, o) != 0) {
        TEngineValue_free(v);
        return 1;
    }
    TEngineValue_free(v);
    return 0;
}

__attribute__((unused)) static int
eval_to_str(ProcessContext* ctx, Scope* scope, Expr* e, const char** o)
{
    TEngineValue* v = evaluate_expr(ctx, scope, e);
    if (v == NULL)
        return 1;

    if (TEngineValue_as_string(v, o) != 0) {
        TEngineValue_free(v);
        return 1;
    }
    TEngineValue_free(v);
    return 0;
}

static int process_array_type(ProcessContext* ctx, const char* varname,
                              const char* type, Expr* esize, Scope* scope,
                              TEngineValue** oval)
{
    *oval = NULL;

    u64_t size;
    if (eval_to_u64(ctx, scope, esize, &size) != 0)
        return 1;

    if (size > ctx->fb->size - ctx->fb->off) {
        error("[tengine] invalid array size: %lld, it is bigger than the "
              "remaining file size",
              size);
        return 1;
    }

    u64_t final_off = ctx->fb->off + size;

    int is_char = strcmp(type, "char") == 0;
    if (is_char) {
        // Special case, the output variable is a string
        char*          tmp = bhex_calloc(size + 1);
        const uint8_t* buf = fb_read(ctx->fb, size);
        memcpy(tmp, buf, size);
        *oval = TEngineValue_STRING_new(tmp);
        value_pp(ctx->engine, ctx->print_off, *oval);
        engine_printf(ctx->engine, "\n");
        bhex_free(tmp);
        fb_seek(ctx->fb, final_off);
        return 0;
    }

    // Let's threat uint8_t arrays as byte arrays, we will print them in hex
    int                       is_uint8 = strcmp(type, "uint8_t") == 0;
    const TEngineBuiltinType* t        = get_builtin_type(type);
    s64_t                     printed  = 0;
    if (t != NULL) {
        if (!is_uint8)
            engine_printf(ctx->engine, "[ ");
        while (printed < size) {
            TEngineValue* val = t->process(ctx->engine, ctx->fb);
            if (val == NULL)
                return 1;
            if (is_uint8) {
                int tmp                   = ctx->engine->print_in_hex;
                ctx->engine->print_in_hex = 1;
                value_pp(ctx->engine, ctx->print_off, val);
                ctx->engine->print_in_hex = tmp;
            } else {
                value_pp(ctx->engine, ctx->print_off, val);
                if (printed < size - 1)
                    engine_printf(ctx->engine, ", ");
            }
            // TODO save the value!
            TEngineValue_free(val);
            if (printed++ >= MAX_ARR_PRINT_SIZE) {
                engine_printf(ctx->engine, "...");
                break;
            }
        }
        if (!is_uint8)
            engine_printf(ctx->engine, " ]");
        engine_printf(ctx->engine, "\n");

        fb_seek(ctx->fb, final_off);
        return 0;
    }

    // Array of custom type
    engine_printf(ctx->engine, "\n");
    for (int i = 0; i < ctx->print_off + 11 + yymax_ident_len; ++i)
        engine_printf(ctx->engine, " ");
    engine_printf(ctx->engine, "[%lld]", printed);
    for (printed = 0; printed < size; ++printed) {
        map* custom_type_vars = process_struct_type(ctx, type);
        if (custom_type_vars == NULL) {
            error("[tengine] unknown type %s", type);
            return 1;
        }
        if (printed < size - 1) {
            for (int i = 0; i < ctx->print_off + 11 + yymax_ident_len; ++i)
                engine_printf(ctx->engine, " ");
            engine_printf(ctx->engine, "[%lld]", printed + 1);
        }
        // TODO save the array!
        map_destroy(custom_type_vars);
    }
    return 0;
}

static int process_FILE_VAR_DECL(ProcessContext* ctx, Stmt* stmt, Scope* scope)
{
    engine_printf(ctx->engine, "b+%08llx ", ctx->fb->off - ctx->initial_off);
    for (int i = 0; i < ctx->print_off; ++i)
        engine_printf(ctx->engine, " ");
    engine_printf(ctx->engine, " %*s: ", yymax_ident_len, stmt->name);

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
        // TODO: valorize always TEngineValue
        if (val)
            Scope_add_filevar(scope, stmt->name, val);
    }
    return 0;
}

static int process_LOCAL_VAR_DECL(ProcessContext* ctx, Stmt* stmt, Scope* scope)
{
    TEngineValue* v = evaluate_expr(ctx, scope, stmt->local_value);
    if (v == NULL)
        return 1;

    Scope_add_local(scope, stmt->local_name, v);
    return 0;
}

static int process_LOCAL_VAR_ASS(ProcessContext* ctx, Stmt* stmt, Scope* scope)
{
    TEngineValue* v = evaluate_expr(ctx, scope, stmt->local_value);
    if (v == NULL)
        return 1;

    if (Scope_get_local(scope, stmt->local_name) == NULL) {
        error("[tengine] no such local variable '%s", stmt->local_name);
        return 1;
    }

    Scope_add_local(scope, stmt->local_name, v);
    return 0;
}

static int process_VOID_FUNC_CALL(ProcessContext* ctx, Stmt* stmt, Scope* scope)
{
    const TEngineBuiltinFunc* func = get_builtin_func(stmt->fname);
    if (func == NULL) {
        error("[tengine] no such function '%s'", stmt->fname);
        return 1;
    }

    DList* params_vals = evaluate_list_of_exprs(ctx, scope, stmt->params);
    TEngineValue* r    = func->process(ctx->engine, ctx->fb, params_vals);
    if (params_vals) {
        DList_foreach(params_vals, (void (*)(void*))TEngineValue_free);
        DList_deinit(params_vals);
    }
    TEngineValue_free(r);
    return 0;
}

static int process_STMT_IF(ProcessContext* ctx, Stmt* stmt, Scope* scope)
{
    u64_t cond;
    if (eval_to_u64(ctx, scope, stmt->cond, &cond) != 0)
        return 1;

    if (cond != 0) {
        // TODO: we are using the same context of the current block, to do the
        // things correctly we should define a new var context and delete the
        // new variables afterwards
        // Ex, this is currently correct (for now it is fine though):
        //   if (1) { uint8_t a; }
        //   if (a) { uint8_t b; }
        DList* stmts = stmt->body->stmts;
        for (u64_t i = 0; i < stmts->size; ++i) {
            Stmt* stmt = (Stmt*)stmts->data[i];
            if (process_stmt(ctx, stmt, scope) != 0)
                return 1;
        }
    }
    return 0;
}

static int process_STMT_IF_ELSE(ProcessContext* ctx, Stmt* stmt, Scope* scope)
{
    u64_t cond;
    if (eval_to_u64(ctx, scope, stmt->if_else_cond, &cond) != 0)
        return 1;

    // TODO: same problem WRT STMT_IF
    DList* stmts = stmt->if_else_true_body->stmts;
    if (cond == 0)
        stmts = stmt->if_else_false_body->stmts;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0)
            return 1;
    }
    return 0;
}

static int process_STMT_WHILE(ProcessContext* ctx, Stmt* stmt, Scope* scope)
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
            if (ctx->should_break) {
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

static int process_stmt(ProcessContext* ctx, Stmt* stmt, Scope* scope)
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
        case STMT_IF:
            return process_STMT_IF(ctx, stmt, scope);
        case STMT_IF_ELSE:
            return process_STMT_IF_ELSE(ctx, stmt, scope);
        case STMT_WHILE:
            return process_STMT_WHILE(ctx, stmt, scope);
        case STMT_BREAK:
            ctx->should_break = 1;
            return 0;
        default: {
            error("[tengine] invalid stmt type %d", stmt->t);
            break;
        }
    }
    return 1;
}

static int process_ast(TEngine* engine, FileBuffer* fb)
{
    if (!engine->ast->proc) {
        error("[tengine] no proc");
        return 1;
    }

    ProcessContext ctx   = {fb, engine, fb->off, 0};
    DList*         stmts = engine->ast->proc->stmts;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(&ctx, stmt, engine->proc_scope) != 0)
            return 1;
    }
    return 0;
}

ASTCtx* TEngine_parse_filename(const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return NULL;
    }

    ASTCtx* ast = TEngine_parse_file(f);
    fclose(f);
    return ast;
}

ASTCtx* TEngine_parse_file(FILE* f)
{
    ASTCtx* ast = ASTCtx_new();

    yyset_in(f);
    yyset_ctx(ast);

    if (yyparse() != 0) {
        error("parsing failed");
        ASTCtx_delete(ast);
        return NULL;
    }
    return ast;
}

ASTCtx* TEngine_parse_string(const char* str)
{
    ASTCtx* ast = ASTCtx_new();

    yyset_ctx(ast);
    YY_BUFFER_STATE state = yy_scan_string(str);
    if (yyparse() != 0) {
        error("parsing failed");
        ASTCtx_delete(ast);
        yy_delete_buffer(state);
        return NULL;
    }

    yy_delete_buffer(state);
    return ast;
}

void TEngine_init(TEngine* engine, ASTCtx* ast)
{
    engine->ast          = ast;
    engine->proc_scope   = Scope_new();
    engine->endianess    = TE_LITTLE_ENDIAN;
    engine->print_in_hex = 1;
    engine->quiet_mode   = 0;
}

void TEngine_deinit(TEngine* engine) { Scope_free(engine->proc_scope); }

int TEngine_process_filename(FileBuffer* fb, const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return 1;
    }

    int r = TEngine_process_file(fb, f);
    fclose(f);
    return r;
}

int TEngine_process_file(FileBuffer* fb, FILE* f)
{
    ASTCtx* ast = TEngine_parse_file(f);
    if (ast == NULL)
        return 1;

    int r = TEngine_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

TEngine* TEngine_run_on_string(FileBuffer* fb, const char* str)
{
    ASTCtx* ast = TEngine_parse_string(str);
    if (ast == NULL)
        return NULL;

    TEngine* e = bhex_calloc(sizeof(TEngine));
    TEngine_init(e, ast);

    if (process_ast(e, fb) != 0) {
        ASTCtx_delete(ast);
        TEngine_deinit(e);
        bhex_free(e);
        return NULL;
    }
    ASTCtx_delete(ast);
    return e;
}

int TEngine_process_string(FileBuffer* fb, const char* str)
{
    ASTCtx* ast = TEngine_parse_string(str);
    if (ast == NULL)
        return 1;

    int r = TEngine_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

int TEngine_process_ast(FileBuffer* fb, ASTCtx* ast)
{
    TEngine eng;
    TEngine_init(&eng, ast);

    int r = process_ast(&eng, fb);
    TEngine_deinit(&eng);
    return r;
}

int TEngine_process_ast_struct(FileBuffer* fb, ASTCtx* ast, const char* s)
{
    TEngine eng;
    TEngine_init(&eng, ast);

    int r = 1;
    if (!map_contains(ast->structs, s)) {
        error("[tengine] no such struct '%s'", s);
        goto end;
    }

    ProcessContext ctx = {fb, &eng, fb->off, 0};
    Block*         b   = map_get(ast->structs, s);
    for (u64_t i = 0; i < b->stmts->size; ++i) {
        Stmt* stmt = (Stmt*)b->stmts->data[i];
        if (process_stmt(&ctx, stmt, eng.proc_scope) != 0)
            goto end;
    }
    r = 0;

end:
    TEngine_deinit(&eng);
    return r;
}

void TEngine_pp(TEngine* e)
{
    int orig_quiet_mode = e->quiet_mode;
    e->quiet_mode       = 0;

    printf("TEngine\n\n");
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
