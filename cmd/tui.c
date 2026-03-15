// Copyright (c) 2022-2026, bageyelet

#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <util/byte_to_str.h>
#include <terminal.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>
#include "tui.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

static int refresh_screen(TuiState* ts);

// only for log_callback and signal handler
static TuiState* g_ts;

static void log_callback(const char* msg)
{
    memset(g_ts->msg, 0, sizeof(g_ts->msg));
    strncpy(g_ts->msg, msg, sizeof(g_ts->msg) - 1);
}

static void refresh_signal_handler(int __attribute__((unused)) sig)
{
    refresh_screen(g_ts);
}

void sw_init_with_size(ScreenWriter* sw, int rows, int cols)
{
    sw->lines = NULL;
    sw->len   = 0;

    sw->rows     = rows;
    sw->cols     = cols;
    sw->curr_row = 0;
    sw->curr_col = 0;

    sw_append_raw(sw, "\x1b[H", 3); /* Go home. */
}

static void sw_init(ScreenWriter* sw)
{
    int rows, cols;
    get_window_size(&rows, &cols);
    sw_init_with_size(sw, rows, cols);
}

void sw_append_raw(ScreenWriter* sw, const char* raw, size_t raw_len)
{
    char* new = bhex_realloc(sw->lines, raw_len + sw->len);
    if (new == NULL)
        return;

    memcpy(new + sw->len, raw, raw_len);
    sw->lines = new;
    sw->len += raw_len;
}

void sw_start_highlight(ScreenWriter* sw, int primary)
{
    if (primary)
        sw_append_raw(sw, "\x1b[30;43m", 8);
    else
        sw_append_raw(sw, "\x1b[30;47m", 8);
}

void sw_end_highlight(ScreenWriter* sw) { sw_append_raw(sw, "\x1b[0m", 4); }

int sw_append(ScreenWriter* sw, const char* line)
{
    if (sw->curr_row >= sw->rows)
        return 1;
    if (sw->curr_col >= sw->cols)
        return 1;

    size_t line_len = strlen(line);
    if (line_len == 0)
        return 0;

    size_t row_len = sw->cols - sw->curr_col;
    if (line_len > row_len)
        line_len = row_len;

    sw_append_raw(sw, line, line_len);
    sw->curr_col += line_len;
    return 0;
}

int sw_end_line(ScreenWriter* sw)
{
    if (sw->curr_row >= sw->rows)
        return 1;

    size_t row_len = sw->cols - sw->curr_col;
    char*  new     = bhex_realloc(sw->lines, sw->len + row_len + 2);

    for (size_t i = 0; i < row_len; ++i)
        new[sw->len++] = ' ';
    new[sw->len++] = '\r';
    new[sw->len++] = '\n';
    sw->lines      = new;

    sw->curr_col = 0;
    sw->curr_row += 1;
    return 0;
}

int sw_add_line(ScreenWriter* sw, const char* line)
{
    if (sw_append(sw, line) != 0)
        return 1;
    if (sw_end_line(sw) != 0)
        return 1;
    return 0;
}

void sw_flush(ScreenWriter* sw)
{
    while (sw_end_line(sw) == 0)
        ;

    write(STDOUT_FILENO, sw->lines, sw->len);
    bhex_free(sw->lines);
}

static int refresh_screen(TuiState* ts)
{
#define min_width  78
#define min_height 10
    ScreenWriter sw;
    char         buf[2048] = {0};

    sw_init(&sw);
    if (sw.cols <= 0 || sw.rows <= 0) {
        sw_add_line(&sw, "");
        sw_add_line(&sw, " unable to fetch cols and rows");
        sw_flush(&sw);
        return 0;
    }
    if (sw.cols < min_width || sw.rows < min_height) {
        sw_add_line(&sw, "");
        sw_add_line(&sw, " screen too small");
        sw_flush(&sw);
        return 0;
    }

    if (sw.cols >= 2 * min_width - 10)
        ts->chunk_size = 32;
    else
        ts->chunk_size = 16;

    size_t read_size  = min(ts->chunk_size * (sw.rows - 5), fb_block_size);
    read_size         = min(ts->fb->size - ts->fb->off, read_size);
    const u8_t* bytes = fb_read(ts->fb, read_size);
    if (!bytes) {
        sw_add_line(&sw, "");
        sw_add_line(&sw, " unable to read the file");
        sw_flush(&sw);
        return -1;
    }

    ts->min_visible_addr = ts->fb->off;
    ts->max_visible_addr = ts->min_visible_addr +
                           min(ts->chunk_size * (sw.rows - 5), fb_block_size) -
                           1;

    sw_start_highlight(&sw, 0);
    sw_append(
        &sw, " CTRL-X [Exit] CTRL-U [Undo] CTRL-L [Insert] TAB [Toggle ASCII]");
    sw_end_line(&sw);
    sw_append(&sw, " CTRL-F/B [Page Up/Down] CTRL-A/E [Go to Beginning/End] ");
    sw_end_line(&sw);
    sw_append(&sw, " ");
    sw_append(&sw, ts->msg);
    if (ts->insert_mode)
        sw_append(&sw, " *INSERT* ");
    if (ts->fb->modifications.size > 0)
        sw_append(&sw, " *UNSAVED* ");
    sw_end_line(&sw);
    sw_end_highlight(&sw);
    sw_end_line(&sw);
    sw_append(&sw,
              "           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
    if (ts->chunk_size > 16)
        sw_append(&sw, " 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");

    sw_end_line(&sw);
    sw_append(&sw,
              "           -----------------------------------------------");
    if (ts->chunk_size > 16)
        sw_append(&sw, "------------------------------------------------");
    sw_end_line(&sw);

    u64_t off = 0;
    for (int i = 0; i < sw.rows - 5; ++i) {
        snprintf(buf, sizeof(buf) - 1, " %08llx: ", (u64_t)off + ts->fb->off);
        sw_append(&sw, buf);

        for (u64_t j = 0; j < ts->chunk_size; ++j) {
            if (off + j >= read_size) {
                for (; j < ts->chunk_size; ++j) {
                    if (off + j + ts->fb->off == ts->selected)
                        sw_start_highlight(&sw, ts->in_ascii_panel == 0);
                    sw_append(&sw, "  ");
                    if (off + j + ts->fb->off == ts->selected)
                        sw_end_highlight(&sw);
                    sw_append(&sw, " ");
                }
                break;
            }
            if (off + j + ts->fb->off == ts->selected)
                sw_start_highlight(&sw, ts->in_ascii_panel == 0);
            snprintf(buf, sizeof(buf) - 1, "%02X", bytes[off + j]);
            sw_append(&sw, buf);
            if (off + j + ts->fb->off == ts->selected)
                sw_end_highlight(&sw);
            sw_append(&sw, " ");
        }
        sw_append(&sw, "  ");
        for (u64_t j = 0; j < ts->chunk_size; ++j) {
            if (off + j >= read_size) {
                for (; j < ts->chunk_size; ++j) {
                    if (off + j + ts->fb->off == ts->selected)
                        sw_start_highlight(&sw, ts->in_ascii_panel != 0);
                    sw_append(&sw, " ");
                    if (off + j + ts->fb->off == ts->selected)
                        sw_end_highlight(&sw);
                }
                break;
            }
            if (off + j + ts->fb->off == ts->selected)
                sw_start_highlight(&sw, ts->in_ascii_panel != 0);
            snprintf(buf, sizeof(buf) - 1, "%c",
                     get_printable_ascii_or_dot((u8_t)bytes[off + j]));
            sw_append(&sw, buf);
            if (off + j + ts->fb->off == ts->selected)
                sw_end_highlight(&sw);
        }
        sw_end_line(&sw);
        off += ts->chunk_size;
    }

    sw_flush(&sw);
    return 0;
}

void tui_write_key(TuiState* ts, int k)
{
    u64_t old_off = ts->fb->off;
    fb_seek(ts->fb, ts->selected);

    if (!is_printable_ascii((char)k))
        goto end;

    if (!ts->insert_mode && ts->selected >= ts->fb->size)
        goto end;

    if (ts->in_ascii_panel) {
        u8_t  byte = (u8_t)k;
        u8_t* data = bhex_malloc(1);
        data[0]    = byte;
        if (!ts->insert_mode)
            fb_write(ts->fb, data, 1);
        else
            fb_insert(ts->fb, data, 1);
        ts->selected += 1;
        goto end;
    }

    int b = hex_to_nibble((char)k);
    if (b < 0)
        goto end;

    u8_t byte = (u8_t)b;
    u8_t curr_byte =
        (ts->insert_mode && !ts->second_nibble) ? 0 : *fb_read(ts->fb, 1);
    if (!ts->second_nibble)
        byte = (byte << 4) | (curr_byte & 0xf);
    else
        byte = (curr_byte & 0xf0) | (byte & 0xf);

    u8_t* data = bhex_malloc(1);
    data[0]    = byte;
    if (ts->insert_mode && !ts->second_nibble)
        fb_insert(ts->fb, data, 1);
    else
        fb_write(ts->fb, data, 1);

    if (ts->second_nibble) {
        ts->second_nibble = 0;
        ts->selected += 1;
    } else
        ts->second_nibble = 1;

end:
    fb_seek(ts->fb, old_off);
}

/* Process a single key press.
 * Returns 1 if the TUI should quit, 0 otherwise. */
int tui_process_key(TuiState* ts, int k, int rows)
{
    FileBuffer* fb = ts->fb;

    switch (k) {
        case ARROW_RIGHT:
            ts->second_nibble = 0;
            if (ts->selected < fb->size)
                ts->selected += 1;
            break;
        case ARROW_DOWN:
            ts->second_nibble = 0;
            if (fb->size > ts->chunk_size - 1 &&
                ts->selected <= fb->size - ts->chunk_size)
                ts->selected += ts->chunk_size;
            else
                ts->selected = fb->size;
            break;
        case ARROW_LEFT:
            ts->second_nibble = 0;
            if (ts->selected > 0)
                ts->selected -= 1;
            break;
        case ARROW_UP:
            ts->second_nibble = 0;
            if (ts->selected >= ts->chunk_size)
                ts->selected -= ts->chunk_size;
            else
                ts->selected = 0;
            break;
        case CTRL_B:
        case PAGE_UP: {
            ts->second_nibble = 0;
            u64_t tosub       = (rows - 5) * ts->chunk_size;
            if (tosub < ts->selected && tosub < ts->fb->off) {
                ts->selected -= tosub;
                fb_seek(fb, ts->fb->off - tosub);
            } else {
                ts->selected = 0;
                fb_seek(fb, 0);
            }
            break;
        }
        case CTRL_F:
        case PAGE_DOWN: {
            ts->second_nibble = 0;
            u64_t toadd       = (rows - 5) * ts->chunk_size;
            if (ts->selected + toadd < ts->fb->size) {
                ts->selected += toadd;
                fb_seek(fb, ts->fb->off + toadd);
            } else {
                ts->selected = ts->fb->size;
                if (ts->selected > ts->max_visible_addr) {
                    if (ts->fb->off + toadd < ts->fb->size)
                        fb_seek(fb, ts->fb->off + toadd);
                    else
                        fb_seek(fb, ts->selected & ~(ts->chunk_size - 1));
                }
            }
            break;
        }
        case HOME_KEY:
        case CTRL_A:
            ts->second_nibble = 0;
            ts->selected      = 0;
            fb_seek(fb, 0);
            break;
        case END_KEY:
        case CTRL_E:
            ts->second_nibble = 0;
            ts->selected      = ts->fb->size;
            fb_seek(fb, ts->selected & ~(ts->chunk_size - 1));
            break;
        case TAB:
            ts->second_nibble  = 0;
            ts->in_ascii_panel = !ts->in_ascii_panel;
            break;
        case CTRL_L:
            ts->insert_mode = !ts->insert_mode;
            break;
        case CTRL_U:
            fb_undo_last(ts->fb);
            break;
        case CTRL_X:
            return 1;
        case DEL_KEY: {
            u64_t tmp = ts->fb->off;
            fb_seek(ts->fb, ts->selected);
            fb_delete(ts->fb, 1);
            fb_seek(ts->fb, tmp);
            break;
        }
        default:
            tui_write_key(ts, k);
            break;
    }

    if (k != PAGE_UP && k != PAGE_DOWN && k != CTRL_B && k != CTRL_F &&
        k != CTRL_A && k != CTRL_E) {
        if (ts->selected > ts->max_visible_addr &&
            ts->max_visible_addr < fb->size)
            fb_seek(fb, fb->off + ts->chunk_size);
        if (ts->selected < ts->min_visible_addr)
            fb_seek(fb, fb->off - ts->chunk_size);
    }

    return 0;
}

int tui_enter_loop(FileBuffer* fb)
{
    if (g_ts != NULL)
        panic("tui_enter_loop called while another TUI session is active");

    int res  = 0;
    int rows = 0, cols = 0;

    TuiState ts   = {0};
    ts.fb         = fb;
    ts.selected   = fb->off;
    ts.chunk_size = 16;

    g_ts = &ts;

    struct sigaction sa, priorsa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = SA_RESTART;
    sa.sa_handler = refresh_signal_handler;
    sigaction(SIGWINCH, &sa, &priorsa);

    enable_raw_mode();
    register_log_callback(log_callback);

    if ((fb->off & (ts.chunk_size - 1)) != 0)
        fb_seek(fb, fb->off & ~(ts.chunk_size - 1));

    int quit = 0;
    while (!quit) {
        if (refresh_screen(&ts) != 0) {
            res = -1;
            break;
        }
        if (get_window_size(&rows, &cols) != 0) {
            res = -1;
            break;
        }

        memset(ts.msg, 0, sizeof(ts.msg));
        int k = terminal_read_key();
        if (tui_process_key(&ts, k, rows))
            break;
    }

    ts.in_ascii_panel = 0;
    ts.second_nibble  = 0;
    fb_seek(fb, ts.selected);

    g_ts = NULL;
    signal(SIGWINCH, SIG_DFL);
    disable_raw_mode();
    unregister_log_callback();

    // clear the screen
    get_window_size(&rows, &cols);
    if (rows < 0 || rows > 4096)
        // Just a random maximum value
        rows = 4096;

    for (int i = 0; i < rows; ++i)
        puts("");
    printf("\x1b[H");
    return res;
}
