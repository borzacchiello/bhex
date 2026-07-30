// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "dummy_filebuffer.h"
#include "t.h"

#include "../bhengine/vm.h"

#include "data/not_kitty_png.h"
#include "data/sample_gzip.h"
#include "data/sample_zip.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

// The tests come up with an empty VM (see bhengine_vm_skip_search), so the
// templates a scan needs are registered here and dropped again afterwards:
// they live in the one VM every command shares, and the template tests assert
// that 't/l' lists nothing
static void identify_load_templates(void)
{
    bhengine_vm_add_template(bhengine_vm_get(), "png", "./templates/png.bhe");
    bhengine_vm_add_template(bhengine_vm_get(), "gzip", "./templates/gzip.bhe");
}

static void identify_unload_templates(void)
{
    bhengine_vm_remove_template(bhengine_vm_get(), "png");
    bhengine_vm_remove_template(bhengine_vm_get(), "gzip");
}

// The summary of a scan carries timings, so only the hit lines -- everything
// up to the blank line that follows them -- can be compared
static char* hits_only(char* out)
{
    char* sep = strstr(out, "\n\n");
    if (sep)
        sep[1] = '\0';
    return out;
}

int TEST(identify_png)(void)
{
    // clang-format off
    const char* expected =
        "  0x00000000  png          218 bytes\n";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = NULL;

    identify_load_templates();
    tfb = dummyfilebuffer_create(not_kitty_png, sizeof(not_kitty_png));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("id", tfb) == 0);

    out = strbuilder_reset(sb);
    r   = compare_strings_ignoring_X(expected, hits_only(out));

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(identify_embedded)(void)
{
    // A PNG buried in filler, which is what the scan exists for: the hit has
    // to land on the offset the file actually starts at
    // clang-format off
    const char* expected =
        "  0x00000064  png          218 bytes\n";
    // clang-format on

    int              r    = TEST_SUCCEEDED;
    char*            out  = NULL;
    DummyFilebuffer* tfb  = NULL;
    u8_t*            buf  = NULL;
    size_t           size = 100 + sizeof(not_kitty_png) + 100;

    identify_load_templates();
    buf = bhex_calloc(size);
    memcpy(buf + 100, not_kitty_png, sizeof(not_kitty_png));

    tfb = dummyfilebuffer_create(buf, size);
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("id", tfb) == 0);

    out = strbuilder_reset(sb);
    r   = compare_strings_ignoring_X(expected, hits_only(out));

end:
    bhex_free(out);
    bhex_free(buf);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(identify_no_match)(void)
{
    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = NULL;
    u8_t             buf[256];

    identify_load_templates();
    // 0x00..0xff, which no template must claim
    for (int i = 0; i < 256; ++i)
        buf[i] = (u8_t)i;

    tfb = dummyfilebuffer_create(buf, sizeof(buf));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("id", tfb) == 0);

    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "0 hits in 256 bytes") != NULL);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(identify_skips_what_it_found)(void)
{
    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = NULL;

    identify_load_templates();
    tfb = dummyfilebuffer_create(not_kitty_png, sizeof(not_kitty_png));
    ASSERT(tfb != NULL);

    // the PNG covers the whole buffer, so the scan is one offset long
    ASSERT(exec_commands_on("id", tfb) == 0);
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "1 offsets") != NULL);
    bhex_free(out);

    // ... unless both the prefilter and the skip are turned off, and then
    // every byte is looked at
    ASSERT(exec_commands_on("id/n/e", tfb) == 0);
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "218 offsets") != NULL);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(identify_len_arg)(void)
{
    int              r    = TEST_SUCCEEDED;
    char*            out  = NULL;
    DummyFilebuffer* tfb  = NULL;
    u8_t*            buf  = NULL;
    size_t           size = 100 + sizeof(not_kitty_png);

    identify_load_templates();
    buf = bhex_calloc(size);
    memcpy(buf + 100, not_kitty_png, sizeof(not_kitty_png));

    tfb = dummyfilebuffer_create(buf, size);
    ASSERT(tfb != NULL);

    // the scan stops before the PNG starts, so there is nothing to report
    ASSERT(exec_commands_on("id 100", tfb) == 0);
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "0 hits in 100 bytes") != NULL);

end:
    bhex_free(out);
    bhex_free(buf);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(identify_list)(void)
{
    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = NULL;

    identify_load_templates();
    tfb = dummyfilebuffer_create(sample_gzip, sizeof(sample_gzip));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("id/l", tfb) == 0);

    // the order is the VM's, i.e. the hash map's: only the membership matters,
    // and each template is listed with the magics it declared
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "Templates taking part in the scan:\n") != NULL);
    ASSERT(strstr(out, "png") != NULL);
    ASSERT(strstr(out, "89504e470d0a1a0a") != NULL); // the PNG signature
    ASSERT(strstr(out, "gzip") != NULL);
    ASSERT(strstr(out, "1f8b08") != NULL);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// The prefilter must not change what is found, only how long it takes: a magic
// that is not a necessary condition for its "_identify" would hide files, and
// this is the check that catches it
int TEST(identify_prefilter_agrees_with_exhaustive)(void)
{
    int              r    = TEST_SUCCEEDED;
    char*            fast = NULL;
    char*            slow = NULL;
    DummyFilebuffer* tfb  = NULL;
    u8_t*            buf  = NULL;
    size_t           size = 700 + sizeof(not_kitty_png) + 300;

    identify_load_templates();
    buf = bhex_calloc(size);
    // filler that is not a PNG, with one buried in it
    for (size_t i = 0; i < size; ++i)
        buf[i] = (u8_t)(i * 7 + 3);
    memcpy(buf + 700, not_kitty_png, sizeof(not_kitty_png));

    tfb = dummyfilebuffer_create(buf, size);
    ASSERT(tfb != NULL);

    ASSERT(exec_commands_on("id/n", tfb) == 0);
    fast = strbuilder_reset(sb);
    ASSERT(exec_commands_on("id/n/e", tfb) == 0);
    slow = strbuilder_reset(sb);

    // the hit lines have to be identical; the summaries differ on purpose
    ASSERT(compare_strings_ignoring_X(hits_only(fast), hits_only(slow)));
    ASSERT(strstr(fast, "0x000002bc") != NULL); // 700

end:
    bhex_free(fast);
    bhex_free(slow);
    bhex_free(buf);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// A prefiltered scan only asks where a pattern matched, so it visits a handful
// of offsets instead of every one
int TEST(identify_prefilter_narrows_the_scan)(void)
{
    int              r    = TEST_SUCCEEDED;
    char*            out  = NULL;
    DummyFilebuffer* tfb  = NULL;
    u8_t*            buf  = NULL;
    size_t           size = 4096;

    identify_load_templates();
    buf = bhex_calloc(size);
    for (size_t i = 0; i < size; ++i)
        buf[i] = (u8_t)(i * 7 + 3);

    tfb = dummyfilebuffer_create(buf, size);
    ASSERT(tfb != NULL);

    // no template's magic occurs, so there is nothing to ask and no hit
    ASSERT(exec_commands_on("id", tfb) == 0);
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "0 hits in 4096 bytes") != NULL);
    ASSERT(strstr(out, "0 candidates") != NULL);
    ASSERT(strstr(out, "0 offsets") != NULL);

end:
    bhex_free(out);
    bhex_free(buf);
    dummyfilebuffer_destroy(tfb);
    identify_unload_templates();
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// An archive is a run of local file headers, every one of which carries the
// magic: reporting them one by one is the container turning into a pile of
// hits. The whole thing has to come back once, at the offset it starts at
int TEST(identify_archive_reported_once)(void)
{
    // clang-format off
    const char* expected =
        "  0x00000000  zip          877 bytes\n";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = NULL;

    bhengine_vm_add_template(bhengine_vm_get(), "zip", "./templates/zip.bhe");
    tfb = dummyfilebuffer_create(sample_zip, sizeof(sample_zip));
    ASSERT(tfb != NULL);
    ASSERT(sizeof(sample_zip) == 877);

    ASSERT(exec_commands_on("id", tfb) == 0);
    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, hits_only(out)));
    bhex_free(out);

    // ... and the entries behind the first are only reported with the skip
    // turned off (the first one starts where the archive does, and one offset
    // is one hit)
    ASSERT(exec_commands_on("id/n", tfb) == 0);
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "5 hits in 877 bytes") != NULL);
    ASSERT(strstr(out, "0x00000000  zip          877 bytes") != NULL);
    ASSERT(strstr(out, "0x00000047  zip") != NULL); // the second entry, at 71

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    bhengine_vm_remove_template(bhengine_vm_get(), "zip");
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(identify_no_templates)(void)
{
    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = NULL;

    // nothing registered: the command has to say so, not scan for nothing
    tfb = dummyfilebuffer_create(not_kitty_png, sizeof(not_kitty_png));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("id", tfb) == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(out[0] == '\0');
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
