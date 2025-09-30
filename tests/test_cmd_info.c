#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(notkitty)(void)
{
    // clang-format off
    const char* expected =
    "  path:    /tmp/testfb_XXXXXXXX\n"
    "  size:    324 Bytes\n"
    "  entropy: 2.509 / 8.000\n"
    "  md5:     29aedda82de8f860e085d0a3fa7b8b7b\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("info") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(empty)(void)
{
    // clang-format off
    const char* expected =
    "  path:    /tmp/testfb_XXXXXXXX\n"
    "  size:    0 Bytes\n"
    "  entropy: 0.000 / 8.000\n"
    "  md5:     \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0; d 324 ; info; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
