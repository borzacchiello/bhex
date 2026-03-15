// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t.h"

#include <terminal.h>
#include <alloc.h>
#include <log.h>

#include "../cmd/tui.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

static DummyFilebuffer* tui_dfb;

__attribute__((constructor)) static void __tui_init(void)
{
    static const u8_t data[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    };
    tui_dfb = dummyfilebuffer_create(data, sizeof(data));
    if (!tui_dfb)
        panic("unable to create tui dummy fb");
}

__attribute__((destructor)) static void __tui_deinit(void)
{
    if (tui_dfb)
        dummyfilebuffer_destroy(tui_dfb);
}

static TuiState tui_test_reset(void)
{
    fb_seek(tui_dfb->fb, 0);
    fb_undo_all(tui_dfb->fb);

    TuiState ts          = {0};
    ts.fb                = tui_dfb->fb;
    ts.chunk_size        = 16;
    ts.max_visible_addr  = 63;
    return ts;
}

// ScreenWriter tests

int TEST(sw_append_basic)(void)
{
    int r = TEST_SUCCEEDED;
    ScreenWriter sw;
    sw_init_with_size(&sw, 10, 80);

    sw_append(&sw, "hello");
    ASSERT(sw.curr_col == 5);
    ASSERT(sw.len == 3 + 5); // "\x1b[H" + "hello"

end:
    bhex_free(sw.lines);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(sw_append_truncates_at_col_limit)(void)
{
    int r = TEST_SUCCEEDED;
    ScreenWriter sw;
    sw_init_with_size(&sw, 10, 10);

    sw_append(&sw, "1234567890xx");
    ASSERT(sw.curr_col == 10);
    ASSERT(sw.len == 3 + 10);

end:
    bhex_free(sw.lines);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(sw_end_line_pads)(void)
{
    int r = TEST_SUCCEEDED;
    ScreenWriter sw;
    sw_init_with_size(&sw, 10, 20);

    sw_append(&sw, "hi");
    sw_end_line(&sw);
    ASSERT(sw.curr_col == 0);
    ASSERT(sw.curr_row == 1);

end:
    bhex_free(sw.lines);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(sw_add_line)(void)
{
    int r = TEST_SUCCEEDED;
    ScreenWriter sw;
    sw_init_with_size(&sw, 10, 20);

    ASSERT(sw_add_line(&sw, "line one") == 0);
    ASSERT(sw.curr_row == 1);
    ASSERT(sw.curr_col == 0);

    ASSERT(sw_add_line(&sw, "line two") == 0);
    ASSERT(sw.curr_row == 2);

end:
    bhex_free(sw.lines);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(sw_respects_row_limit)(void)
{
    int r = TEST_SUCCEEDED;
    ScreenWriter sw;
    sw_init_with_size(&sw, 3, 20);

    ASSERT(sw_add_line(&sw, "row 0") == 0);
    ASSERT(sw_add_line(&sw, "row 1") == 0);
    ASSERT(sw_add_line(&sw, "row 2") == 0);
    ASSERT(sw_add_line(&sw, "row 3") == 1);

end:
    bhex_free(sw.lines);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// Navigation tests

int TEST(nav_arrow_right)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_process_key(&ts, ARROW_RIGHT, 30);
    ASSERT(ts.selected == 1);

    tui_process_key(&ts, ARROW_RIGHT, 30);
    ASSERT(ts.selected == 2);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_arrow_right_at_end)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.selected = tui_dfb->fb->size;

    tui_process_key(&ts, ARROW_RIGHT, 30);
    ASSERT(ts.selected == tui_dfb->fb->size);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_arrow_left)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.selected = 5;

    tui_process_key(&ts, ARROW_LEFT, 30);
    ASSERT(ts.selected == 4);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_arrow_left_at_zero)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_process_key(&ts, ARROW_LEFT, 30);
    ASSERT(ts.selected == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_arrow_down)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_process_key(&ts, ARROW_DOWN, 30);
    ASSERT(ts.selected == 16);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_arrow_up)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.selected = 32;

    tui_process_key(&ts, ARROW_UP, 30);
    ASSERT(ts.selected == 16);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_arrow_up_at_zero)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.selected = 5;

    tui_process_key(&ts, ARROW_UP, 30);
    ASSERT(ts.selected == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_home)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.selected = 42;

    tui_process_key(&ts, HOME_KEY, 30);
    ASSERT(ts.selected == 0);
    ASSERT(ts.fb->off == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_end)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_process_key(&ts, END_KEY, 30);
    ASSERT(ts.selected == tui_dfb->fb->size);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_tab_toggles_ascii)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ASSERT(ts.in_ascii_panel == 0);

    tui_process_key(&ts, TAB, 30);
    ASSERT(ts.in_ascii_panel == 1);

    tui_process_key(&ts, TAB, 30);
    ASSERT(ts.in_ascii_panel == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_ctrl_l_toggles_insert)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ASSERT(ts.insert_mode == 0);

    tui_process_key(&ts, CTRL_L, 30);
    ASSERT(ts.insert_mode == 1);

    tui_process_key(&ts, CTRL_L, 30);
    ASSERT(ts.insert_mode == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_ctrl_x_quits)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    ASSERT(tui_process_key(&ts, CTRL_X, 30) == 1);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(nav_resets_nibble)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.second_nibble = 1;

    tui_process_key(&ts, ARROW_RIGHT, 30);
    ASSERT(ts.second_nibble == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// write_key tests

int TEST(write_hex_nibble)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_write_key(&ts, 'A');
    ASSERT(ts.second_nibble == 1);

    tui_write_key(&ts, 'B');
    ASSERT(ts.second_nibble == 0);
    ASSERT(ts.selected == 1);

    fb_seek(ts.fb, 0);
    const u8_t* data = fb_read(ts.fb, 1);
    ASSERT(data[0] == 0xAB);

    fb_undo_all(ts.fb);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(write_ascii_panel)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    ts.in_ascii_panel = 1;

    tui_write_key(&ts, 'Z');
    ASSERT(ts.selected == 1);

    fb_seek(ts.fb, 0);
    const u8_t* data = fb_read(ts.fb, 1);
    ASSERT(data[0] == 'Z');

    fb_undo_all(ts.fb);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(write_non_printable_ignored)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_write_key(&ts, 1); // CTRL_A
    ASSERT(ts.selected == 0);
    ASSERT(ts.second_nibble == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(write_invalid_hex_ignored)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();

    tui_write_key(&ts, 'Z');
    ASSERT(ts.second_nibble == 0);
    ASSERT(ts.selected == 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(delete_key)(void)
{
    int r = TEST_SUCCEEDED;
    TuiState ts = tui_test_reset();
    u64_t orig_size = ts.fb->size;

    tui_process_key(&ts, DEL_KEY, 30);
    ASSERT(ts.fb->size == orig_size - 1);

    fb_undo_all(ts.fb);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
