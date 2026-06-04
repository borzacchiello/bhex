// Copyright (c) 2022-2026, bageyelet
//
// Performance benchmarks for the bhengine template interpreter.
//
// These live in the regular test executable (discovered by gen_tests.py like
// any other `test_*.c` file), but unlike correctness tests their purpose is to
// track *relative* performance over time. Each benchmark runs a workload a few
// times and prints the best/avg wall-clock time as a side effect; it only
// fails (TEST_FAILED) if the engine errors out while running the workload.
//
// Run just these with:  ./bhex_tests bench_bhengine

#include "dummy_filebuffer.h"
#include "../bhengine/interpreter.h"
#include "t.h"

#include <alloc.h>
#include <defs.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static double bench_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static u8_t* bench_make_buffer(size_t size)
{
    u8_t* buf = bhex_malloc(size);
    // Deterministic content with a NUL terminator every 64 bytes, so the
    // "strings" workload reads ~63-byte strings rather than running to EOF.
    for (size_t i = 0; i < size; ++i)
        buf[i] = ((i % 64) == 63)
                     ? 0
                     : (((u8_t)((i * 1103515245u + 12345u) >> 16)) | 1);
    return buf;
}

// Run `prog` against a freshly generated file buffer `iters` times (after one
// warm-up run) and report timing. Returns a TEST_* status.
static int bench_run(const char* name, const char* prog, size_t buf_size,
                     int iters)
{
    u8_t*            buf = bench_make_buffer(buf_size);
    DummyFilebuffer* dfb = dummyfilebuffer_create(buf, buf_size);
    bhex_free(buf);

    int result = TEST_FAILED;

    // Warm-up (page cache, lazy init of builtin maps, branch predictors).
    if (bhengine_interpreter_process_string(dfb->fb, prog) != 0)
        goto end;
    fb_seek(dfb->fb, 0);

    double best = 1e300;
    double sum  = 0;
    for (int i = 0; i < iters; ++i) {
        double t0 = bench_now_ms();
        if (bhengine_interpreter_process_string(dfb->fb, prog) != 0)
            goto end;
        fb_seek(dfb->fb, 0);
        double dt = bench_now_ms() - t0;
        if (dt < best)
            best = dt;
        sum += dt;
    }

    printf("    [bench] %-14s best %8.3f ms   avg %8.3f ms   (%d iters)\n",
           name, best, sum / iters, iters);
    result = TEST_SUCCEEDED;

end:
    dummyfilebuffer_destroy(dfb);
    return result;
}

// Parse a large array of fixed-size structs. Stresses the per-field read path
// (fb_read / fb_seek) and the value allocation / scope machinery.
int TEST(struct_array)(void)
{
    const char* prog = "struct Entry {"
                       "  u32 a; u32 b; u16 c; u16 d; u8 e; u8 f;"
                       "}"
                       "proc {"
                       "  disable_print();"
                       "  Entry entries[16384];"
                       "}";
    return bench_run("struct_array", prog, 1u << 20, 10);
}

// Parse many NUL-terminated strings. Stresses the byte-at-a-time read path.
int TEST(strings)(void)
{
    const char* prog = "proc {"
                       "  disable_print();"
                       "  local i = 0;"
                       "  while (i < 8192) {"
                       "    string s;"
                       "    i = i + 1;"
                       "  }"
                       "}";
    return bench_run("strings", prog, 1u << 20, 10);
}

// Tight interpreter loop with arithmetic but no file reads. Isolates the
// expression-evaluation / scope overhead from the I/O path.
int TEST(arith)(void)
{
    const char* prog = "proc {"
                       "  disable_print();"
                       "  local i = 0;"
                       "  local acc = 0;"
                       "  while (i < 1000000) {"
                       "    acc = acc + i * 3 - 1;"
                       "    i = i + 1;"
                       "  }"
                       "}";
    return bench_run("arith", prog, 4096, 3);
}
