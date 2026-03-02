#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"
#include "data/asm_snippets.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(invalid_num_args)(void)
{
#ifndef DISABLE_CAPSTONE
    return exec_commands("ds") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(invalid_arch)(void)
{
#ifndef DISABLE_CAPSTONE
    return exec_commands("ds invalid_arch") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(list_archs)(void)
{
#ifndef DISABLE_CAPSTONE
    const char* expected = "Supported architectures:\n"
                           "    x64\n"
                           "    x86\n"
                           "    i8086\n"
                           "    arm32\n"
                           "    arm64\n"
                           "    arm32-thumb\n"
                           "    mips32\n"
                           "    mips64\n"
                           "    mipsel32\n"
                           "    mipsel64\n"
                           "    ppc32\n"
                           "    ppc64\n"
                           "    ppcle32\n"
                           "    ppcle64\n"
                           "    bpf\n"
                           "    ebpf\n";

    int r = TEST_FAILED;
    if (exec_commands("ds/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_nop)(void)
{
#ifndef DISABLE_CAPSTONE
    /* Two bytes: the second is needed because do_disas uses code_size - 1 */
    const u8_t       nop_bytes[] = {0x90, 0x90};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_ret)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       ret_bytes[] = {0xC3, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(ret_bytes, sizeof(ret_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "ret") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x86_nop)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       nop_bytes[] = {0x90, 0x90};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x86 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_too_many_args)(void)
{
#ifndef DISABLE_CAPSTONE
    return exec_commands("ds/i a b") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_produces_output)(void)
{
#ifndef DISABLE_CAPSTONE
    int r = TEST_FAILED;
    if (exec_commands("ds/i") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "Architecture identification") != NULL;
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_lists_all_archs)(void)
{
#ifndef DISABLE_CAPSTONE
    int r = TEST_FAILED;
    if (exec_commands("ds/i") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "x64") != NULL && strstr(out, "arm32") != NULL &&
        strstr(out, "mips32") != NULL && strstr(out, "mipsel64") != NULL &&
        strstr(out, "ppc32") != NULL;
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_custom_nbytes)(void)
{
#ifndef DISABLE_CAPSTONE
    /* ds/i <nbytes> should succeed and produce output */
    int r = TEST_FAILED;
    if (exec_commands("ds/i 4") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "Architecture identification") != NULL;
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_too_many_args2)(void)
{
#ifndef DISABLE_CAPSTONE
    /* ds/i with two numeric args must be rejected */
    return exec_commands("ds/i 4 8") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_blr)(void)
{
#ifndef DISABLE_CAPSTONE
    /* PPC blr = 4E 80 00 20 (big-endian, fixed 4 bytes) */
    const u8_t       blr_bytes[] = {0x4E, 0x80, 0x00, 0x20, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(blr_bytes, sizeof(blr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc32 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "blr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_nop)(void)
{
#ifndef DISABLE_CAPSTONE
    /* PPC nop = 60 00 00 00 (ori 0,0,0) */
    const u8_t       nop_bytes[] = {0x60, 0x00, 0x00, 0x00, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc32 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc64_mflr)(void)
{
#ifndef DISABLE_CAPSTONE
    /* PPC mflr r0 = 7C 08 02 A6 (big-endian) */
    const u8_t       mflr_bytes[] = {0x7C, 0x08, 0x02, 0xA6, 0x00};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(mflr_bytes, sizeof(mflr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "mflr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_add)(void)
{
#ifndef DISABLE_CAPSTONE
    /* PPC add 1,2,3 = 7C 22 1A 14 (big-endian) */
    const u8_t       add_bytes[] = {0x7C, 0x22, 0x1A, 0x14, 0x00};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(add_bytes, sizeof(add_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc32 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "add") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppcle64_blr)(void)
{
#ifndef DISABLE_CAPSTONE
    /* PPC blr in little-endian = 20 00 80 4E */
    const u8_t       blr_bytes[] = {0x20, 0x00, 0x80, 0x4E, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(blr_bytes, sizeof(blr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppcle64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "blr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

/*
 * Helper: run ds/i on a snippet and check the top-scoring arch name
 * contains `expected_substr`.  Returns TEST_SUCCEEDED / TEST_FAILED /
 * TEST_SKIPPED.
 */
static int check_identify(const u8_t* data, size_t size,
                           const char* expected_substr)
{
#ifndef DISABLE_CAPSTONE
    DummyFilebuffer* tfb = dummyfilebuffer_create(data, size);
    int              r   = TEST_FAILED;

    if (exec_commands_on("ds/i", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);

    /* Find the header line, then grab the first scored line after it */
    const char* hdr = strstr(out, "Architecture identification");
    if (!hdr)
        goto free_out;
    const char* nl = strchr(hdr, '\n');
    if (!nl)
        goto free_out;
    const char* first_line = nl + 1;
    const char* end_line   = strchr(first_line, '\n');
    if (!end_line)
        goto free_out;

    /* Copy the first result line into a local buffer and search it */
    size_t line_len = (size_t)(end_line - first_line);
    char   line_buf[256];
    if (line_len >= sizeof(line_buf))
        line_len = sizeof(line_buf) - 1;
    memcpy(line_buf, first_line, line_len);
    line_buf[line_len] = '\0';

    if (strstr(line_buf, expected_substr) != NULL)
        r = TEST_SUCCEEDED;

free_out:
    bhex_free(out);
end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_snippet_x64)(void)
{
    /* x86-family modes (i8086/x86/x64) are hard to distinguish; accept any */
#ifndef DISABLE_CAPSTONE
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(snippet_x64, sizeof(snippet_x64));
    int r = TEST_FAILED;

    if (exec_commands_on("ds/i", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    const char* hdr = strstr(out, "Architecture identification");
    if (!hdr)
        goto free_out;
    const char* nl = strchr(hdr, '\n');
    if (!nl)
        goto free_out;
    const char* fl = nl + 1;
    const char* el = strchr(fl, '\n');
    if (!el)
        goto free_out;
    size_t ll = (size_t)(el - fl);
    char   lb[256];
    if (ll >= sizeof(lb))
        ll = sizeof(lb) - 1;
    memcpy(lb, fl, ll);
    lb[ll] = '\0';

    if (strstr(lb, "x64") || strstr(lb, "x86") || strstr(lb, "8086"))
        r = TEST_SUCCEEDED;

free_out:
    bhex_free(out);
end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(identify_snippet_arm64)(void)
{
    return check_identify(snippet_arm64, sizeof(snippet_arm64), "arm64");
}

int TEST(identify_snippet_arm32)(void)
{
    return check_identify(snippet_arm32, sizeof(snippet_arm32), "arm32");
}

int TEST(identify_snippet_mips32)(void)
{
    return check_identify(snippet_mips32, sizeof(snippet_mips32), "mips32");
}

int TEST(identify_snippet_mipsel32)(void)
{
    return check_identify(snippet_mipsel32, sizeof(snippet_mipsel32),
                          "mipsel32");
}

int TEST(identify_snippet_ppc32)(void)
{
    return check_identify(snippet_ppc32, sizeof(snippet_ppc32), "ppc32");
}

int TEST(identify_snippet_ppcle64)(void)
{
    /* ppcle32 and ppcle64 score nearly identically; accept either */
    return check_identify(snippet_ppcle64, sizeof(snippet_ppcle64), "ppcle");
}
