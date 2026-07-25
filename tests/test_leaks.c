// Copyright (c) 2022-2026, bageyelet
//
// Leak regression tests.
//
// These use the allocation tracker (see common/alloc.c) rather than an external
// tool: a command or a bhengine program is run inside a tracking scope, every
// side effect it may have left behind is undone inside the same scope, and the
// number of allocations still live afterwards must not grow. That catches leaks
// on error paths, which are the ones that escape ordinary tests.

#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#include "../bhengine/interpreter.h"
#include "../bhengine/scope.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static void leaks_swallow_log(const char* s) { (void)s; }

// Commands, with an emphasis on the failure paths: a command that bails out
// after allocating its argument buffer used to leak it (cmd_write.c parsed the
// number *after* allocating the destination, cmd_import.c handed a buffer to
// fb_insert/fb_write without reclaiming it when the call failed).
static const char* const leak_cmds[] = {
    // write: every input type against every way of failing to parse
    "w 41", "w/s hello", "w/s \\q", "w/s \\", "w/x 4142", "w/x zz", "w/x 4",
    "w/b 42", "w/b zz", "w/b 999", "w/b -999", "w/b/u -1", "w/b/i 42",
    "w/w 4142", "w/w zz", "w/w 99999", "w/w/u -1", "w/w/be 1", "w/w/i 1",
    "w/d 41424344", "w/d zz", "w/d 99999999999", "w/d/u -1", "w/d/be 1",
    "w/q 1", "w/q zz", "w/q 99999999999999999999", "w/q/u -1", "w/q/be 1",
    "w/q/i/be 1", "w", "w a b", "w/nosuch 1",
    "w/q zz ; w/d zz ; w/w zz ; w/b zz",
    // seek / print
    "s 0", "s 10", "s +5", "s -5", "s -", "s zz", "s 999999999", "s",
    "p", "p 16", "p -", "p 0", "p 999999999", "p zz", "p/x 8", "p/w 8",
    "p/d 8", "p/q 8", "p/a 8", "p/C 8", "p/x/be 8", "p/r 8", "p/W 8",
    "p/x/+ 8", "p/x/- 8", "p/nosuch 8",
    // search
    "src /abc", "src abc", "src/x 4142", "src/x zz", "src/sk abc",
    "src/p abc", "src/x/sk/p 4142", "src", "src a b",
    // hashes / checksums / crc
    "hh md5", "hh sha256", "hh *", "hh nosuch", "hh md5 4 0",
    "hh md5 999999999 0", "hh/l", "hh",
    "cs adler32", "cs *", "cs nosuch", "cs adler32 4 0", "cs/l", "cs",
    "cr crc32_iso_hdlc", "cr *", "cr nosuch", "cr crc32_iso_hdlc 4 0", "cr/l",
    // strings
    "str", "str abc 3", "str * 1", "str a 0", "str a zz", "str/n", "str/a",
    "str/w", "str/n/a", "str/n/w abc 2",
    // entropy / info / setbase / echo
    "e", "e 10 100", "e - 100", "e 0 0", "e zz", "i", "i x",
    "sb", "sb 16", "sb 0x1000", "sb zz",
    "ec 1", "ec 1+2", "ec `1+2`", "ec `1/0`", "ec `(((1)))`", "ec `1<<99`",
    "ec `zz`", "ec/x 1", "ec/d 1", "ec",
    // delete / undo / commit
    "d", "d 1", "d 0", "d 999999999", "d zz", "u", "u/a", "c/l",
    // templates
    "t elf", "t nosuch", "t nosuch.struct", "t/l", "t/l elf", "t/x elf",
    "t/i proc { disable_print(); }",
    "t/i proc { disable_print(); local x = 1/0; }",
    "t/i proc { disable_print(); error(\"x\"); }",
    "t/i struct A { u32 a; } proc { disable_print(); A v; }",
    "t/i @@@", "t/i proc {", "t/i",
    "t/i/x struct A { u32 a; } proc { A v; }",
    // quoted inline code: the ';' must not split the command line
    "t/i \"disable_print(); u8 a; enable_print(); u8 b;\"",
    "t/i/x \"disable_print(); char s[2]; enable_print(); u8 b;\"",
    // the builtins added for text-oriented formats, on their error paths too
    "t/i \"disable_print(); local a = peek(4); local b = read(2);\"",
    "t/i \"disable_print(); local a = scan_while(\\\"abc\\\");\"",
    "t/i \"disable_print(); local a = scan_while(\\\"\\\");\"",
    "t/i \"disable_print(); local a = find_next(\\\"zz\\\");\"",
    "t/i \"disable_print(); local a = find_next(\\\"\\\");\"",
    "t/i \"disable_print(); local a = to_int(\\\"zz\\\", 16);\"",
    "t/i \"disable_print(); local a = to_int(\\\"1\\\", 99);\"",
    "t/i \"disable_print(); local a = substr(\\\"abc\\\", 99);\"",
    "t/i \"disable_print(); local a = crc(\\\"nosuch\\\");\"",
    "t/i \"disable_print(); local a = hash(\\\"nosuch\\\");\"",
    "t/i \"disable_print(); local a = hash(\\\"md5\\\");\"",
    "t/i \"disable_print(); local a = checksum(\\\"ADLER-32\\\");\"",
    "t/i \"disable_print(); local a = entropy();\"",
    "t/i \"disable_print(); assert(0, \\\"boom\\\");\"",
    "t/i \"disable_print(); min(1); \"",
    // sequences, so state carried between commands is covered too
    "s 4 ; w/x 4142 ; p/r 2 ; u",
    "w/b 1 ; w/b 2 ; u/a",
    "s 0 ; d 4 ; p/r 4 ; u/a",
    "sb 0x1000 ; s 0x1000 ; p/r 4 ; sb 0",
    "nosuchcommand",
};

// Runs `cmd`, then undoes everything it may have left behind (pending
// modifications, seek, base address, output buffers) -- all inside the tracked
// window -- and returns the number of allocations still live. reset_global_state()
// itself allocates a fixed amount, so the result is only meaningful against the
// baseline of a command known to be clean.
static size_t leaks_live_after(const char* cmd)
{
    // warm-up run: one-time lazy initialisation (caches, tables) is not a leak
    reset_global_state();
    exec_commands(cmd);

    reset_global_state();
    bhex_alloc_track_start();
    exec_commands(cmd);
    reset_global_state();
    size_t live = bhex_alloc_live_count();
    bhex_alloc_track_stop();
    return live;
}

int TEST(commands_do_not_leak)(void)
{
    int failures = 0;

    // Note the callbacks are deliberately left as the harness installed them,
    // i.e. allocating ones: a template syntax error reaches yyerror(), which
    // logs, which allocates. The parser must not disturb that.

    // a no-op seek: whatever it leaves live is the harness's own fixed overhead
    size_t baseline = leaks_live_after("s 0");

    for (size_t i = 0; i < sizeof(leak_cmds) / sizeof(leak_cmds[0]); ++i) {
        size_t live = leaks_live_after(leak_cmds[i]);
        if (live > baseline) {
            printf("[!] %zu live allocs (baseline %zu) after: '%s'\n", live,
                   baseline, leak_cmds[i]);
            failures++;
        }
    }

    reset_global_state();

    return failures == 0 ? TEST_SUCCEEDED : TEST_FAILED;
}

// bhengine programs, with an emphasis on raising an exception while values with
// heap payloads (strings, arrays, objects) are alive and have to be unwound.
static const char* const leak_progs[] = {
    "proc { disable_print(); }",
    "proc { disable_print(); local u32 x = 1; }",
    "struct A { u32 a; u32 b; } proc { disable_print(); A v; }",

    // runtime errors raised mid-expression
    "proc { disable_print(); local x = 1 / 0; }",
    "proc { disable_print(); local x = 1 % 0; }",
    "proc { disable_print(); local x = \"abc\" + 1; }",
    "proc { disable_print(); local x = 1 + \"abc\"; }",
    "proc { disable_print(); local x = \"a\" * \"b\"; }",
    "proc { disable_print(); local x = -\"abc\"; }",
    "proc { disable_print(); local x = 1 << 999; }",
    "proc { disable_print(); local x = nosuchvar; }",
    "proc { disable_print(); nosuchfn(); }",
    "proc { disable_print(); local x = nosuchfn(); }",
    "proc { disable_print(); error(\"boom\"); }",
    "proc { disable_print(); error(1); }",
    "proc { disable_print(); local a = [1,2,3]; local b = a[99]; }",
    "proc { disable_print(); local a = [1,2,3]; local b = a[-1]; }",
    "proc { disable_print(); local s = \"abc\"; local c = s[99]; }",

    // errors raised while heap-backed values are live
    "proc { disable_print(); local s = \"abc\"; local x = s + s; error(\"b\"); }",
    "proc { disable_print(); local a = [1,2,3]; error(\"boom\"); }",
    "proc { disable_print(); local s = \"a\" + \"b\" + \"c\"; local x = 1/0; }",
    "proc { disable_print(); local a = [\"a\",\"b\"]; local x = 1/0; }",
    "proc { disable_print(); local a = [[1,2],[3,4]]; local x = 1/0; }",
    "fn f() { return \"hi\"; } proc { disable_print(); local s = f(); local x = 1/0; }",
    "fn f() { local s = \"hi\"; error(\"boom\"); return s; } proc { disable_print(); f(); }",

    // control-flow unwinding
    "proc { disable_print(); while (1) { local s = \"x\"; error(\"boom\"); } }",
    "proc { disable_print(); for (local i = 0; i < 10; i = i + 1) { local s = \"x\"; if (i == 5) { error(\"b\"); } } }",
    "proc { disable_print(); if (1) { local s = \"x\"; error(\"boom\"); } }",
    "proc { disable_print(); break; }",
    "proc { disable_print(); continue; }",
    "proc { disable_print(); return 1; }",
    "fn f() { return f(); } proc { disable_print(); f(); }",

    // struct / file reads that fail
    "struct A { u32 a[999999999]; } proc { disable_print(); A v; }",
    "struct A { u8 a; A b; } proc { disable_print(); A v; }",
    "struct A { u32 a; } proc { disable_print(); A v; local x = v.nosuchfield; }",
    "struct A { u32 a; } proc { disable_print(); A v; local x = 1/0; }",
    "struct A { u32 a; if (a > 0) { u32 b; } } proc { disable_print(); A v; }",
    "enum E : u8 { X = 1, Y = 2 } proc { disable_print(); local x = E.Z; }",
    "enum E : u8 { X = 1 } struct A { E e; } proc { disable_print(); A v; }",

    // builtins
    "proc { disable_print(); find(\"abc\", 0); }",
    "proc { disable_print(); find(1, 2); }",
    "proc { disable_print(); local x = strlen(1); }",
    "proc { disable_print(); local x = to_int(\"zz\"); }",
    "proc { disable_print(); seek(999999999999); local u32 x; }",
    "proc { disable_print(); local b = read(4); local x = 1/0; }",
    "proc { disable_print(); local b = read(999999999); }",

    // Parse failures. Everything bison had already reduced belongs to the
    // ASTCtx, but the nodes still on the parser stack are reachable only
    // through it, and are released by the %destructor rules in parser.y as
    // bison pops them. Each case below leaves a different mix of node types on
    // that stack.
    "proc { disable_print(); ",           // unterminated block: stmts on stack
    "struct A { u32 a",                   // partial fvar_decl: Type* + ident
    "@@@@",                               // dies on the first token
    "proc { disable_print(); local x = ; }",
    "fn f( { }",
    "",
    "struct A { u32 a; } struct A { u32 b; } proc { disable_print(); A v; }",
    // deep expression tree abandoned mid-way
    "proc { local x = 1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+ ; }",
    // error deep inside nested blocks: several `stmts` lists at once
    "proc { if (1) { while (1) { if (1) { local x = ; } } } }",
    // a complete struct and fn already stored in the ASTCtx, then a failure
    "struct A { u32 a; } fn g() { return 1; } proc { local x = @@@; }",
    // half-built parameter lists (both flavours: expressions and names)
    "fn f(a, b, ) { return 1; }",
    "proc { disable_print(); f(1, 2, ); }",
    // half-built enum list
    "enum E : u8 { A = 1, B = }",
    "enum E : u8 { A = 1, ",
    // unterminated string literal
    "proc { local s = \"abc; }",
    // two procs: reaches YYABORT with a full `stmts` list on the stack
    "proc { u32 a; } proc { u32 b; }",
};

int TEST(bhengine_programs_do_not_leak)(void)
{
    static const u8_t data[512] = {0};
    int               failures  = 0;

    register_log_callback(leaks_swallow_log);

    for (size_t i = 0; i < sizeof(leak_progs) / sizeof(leak_progs[0]); ++i) {
        DummyFilebuffer* dfb = dummyfilebuffer_create(data, sizeof(data));

        // warm-up run: one-time lazy initialisation is not a leak
        Scope* warm = bhengine_interpreter_run_on_string(dfb->fb, leak_progs[i]);
        if (warm)
            Scope_free(warm);

        bhex_alloc_track_start();
        Scope* s = bhengine_interpreter_run_on_string(dfb->fb, leak_progs[i]);
        if (s)
            Scope_free(s);
        size_t live = bhex_alloc_live_count();
        bhex_alloc_track_stop();

        dummyfilebuffer_destroy(dfb);

        if (live != 0) {
            printf("[!] %zu live allocs after: %s\n", live, leak_progs[i]);
            failures++;
        }
    }

    register_log_callback(log_on_err_strbuilder);
    reset_global_state();

    return failures == 0 ? TEST_SUCCEEDED : TEST_FAILED;
}

// bhengine_parse_file() is the other entry point into the parser, and it takes
// a different route in and out (yyrestart/yylex_destroy rather than a scan
// buffer). The %destructor rules are shared, but the cleanup around them is
// not, so cover it separately.
int TEST(bhe_file_parse_failure_does_not_leak)(void)
{
    static const u8_t data[64] = {0};
    int               failures = 0;

    static const char* const bad_sources[] = {
        "struct A { u32 a; }\nfn g() { return 1; }\nproc { local x = @@@; }\n",
        "proc { u32 a; }\nproc { u32 b; }\n", // duplicate proc: YYABORT path
        "enum E : u8 { A = 1, B = }\n",
        "proc { if (1) { while (1) { local x = ; } } }\n",
        "proc { u32 a;\n", // unterminated
    };

    register_log_callback(leaks_swallow_log);

    for (size_t i = 0; i < sizeof(bad_sources) / sizeof(bad_sources[0]); ++i) {
        DummyFilebuffer* dfb = dummyfilebuffer_create(data, sizeof(data));

        char path[64];
        snprintf(path, sizeof(path), "%s.bhe", dfb->fname);
        FILE* f = fopen(path, "wb");
        if (!f) {
            dummyfilebuffer_destroy(dfb);
            register_log_callback(log_on_err_strbuilder);
            return TEST_FAILED;
        }
        fputs(bad_sources[i], f);
        fclose(f);

        // warm-up run: one-time lazy initialisation is not a leak
        bhengine_interpreter_process_filename(dfb->fb, path);

        bhex_alloc_track_start();
        bhengine_interpreter_process_filename(dfb->fb, path);
        size_t live = bhex_alloc_live_count();
        bhex_alloc_track_stop();

        unlink(path);
        dummyfilebuffer_destroy(dfb);

        if (live != 0) {
            printf("[!] %zu live allocs after parsing: %s\n", live,
                   bad_sources[i]);
            failures++;
        }
    }

    register_log_callback(log_on_err_strbuilder);
    reset_global_state();

    return failures == 0 ? TEST_SUCCEEDED : TEST_FAILED;
}

// The tracker must nest: bhengine_parse_string() opens a scope of its own, and
// a caller (such as the tests above) may already have one open. An inner
// free_all() must not touch the outer scope's allocations -- doing so used to
// hand the caller freed pointers, and silently switched tracking off.
int TEST(alloc_tracker_nests)(void)
{
    int r = TEST_SUCCEEDED;

    bhex_alloc_track_start();
    void* outer = bhex_malloc(16);
    ASSERT(bhex_alloc_live_count() == 1);

    bhex_alloc_track_start();
    ASSERT(bhex_alloc_live_count() == 0); // inner scope starts empty
    void* inner = bhex_malloc(16);
    (void)inner;
    ASSERT(bhex_alloc_live_count() == 1);

    bhex_alloc_track_free_all(); // must free `inner` only
    ASSERT(bhex_alloc_live_count() == 0);
    bhex_alloc_track_stop();

    // the outer scope is intact, and still tracking
    ASSERT(bhex_alloc_is_tracking());
    ASSERT(bhex_alloc_live_count() == 1);

    bhex_free(outer); // would be a double free if free_all() had taken it
    ASSERT(bhex_alloc_live_count() == 0);

    bhex_alloc_track_stop();
    ASSERT(!bhex_alloc_is_tracking());
    return r;

fail:
    // leave tracking off whatever happened, so later tests are unaffected
    while (bhex_alloc_is_tracking())
        bhex_alloc_track_stop();
    return TEST_FAILED;
}

// Allocations an inner scope leaves behind become the outer scope's
// responsibility rather than being forgotten.
int TEST(alloc_tracker_inner_survivors_carry_over)(void)
{
    int r = TEST_SUCCEEDED;

    bhex_alloc_track_start();
    bhex_alloc_track_start();
    void* p = bhex_malloc(16);
    bhex_alloc_track_stop(); // `p` was not freed: it is now the outer scope's

    ASSERT(bhex_alloc_live_count() == 1);
    bhex_alloc_track_free_all();
    ASSERT(bhex_alloc_live_count() == 0);
    bhex_alloc_track_stop();
    (void)p;
    return r;

fail:
    while (bhex_alloc_is_tracking())
        bhex_alloc_track_stop();
    return TEST_FAILED;
}
