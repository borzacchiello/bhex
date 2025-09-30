#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <sys/ioctl.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <util/byte_to_str.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>
#include "tui.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

enum KEY_ACTION {
    KEY_NULL  = 0,   /* NULL */
    CTRL_A    = 1,   /* Ctrl-a */
    CTRL_C    = 3,   /* Ctrl-c */
    CTRL_D    = 4,   /* Ctrl-d */
    CTRL_F    = 6,   /* Ctrl-f */
    CTRL_H    = 8,   /* Ctrl-h */
    TAB       = 9,   /* Tab */
    CTRL_L    = 12,  /* Ctrl+l */
    ENTER     = 13,  /* Enter */
    CTRL_Q    = 17,  /* Ctrl-q */
    CTRL_S    = 19,  /* Ctrl-s */
    CTRL_U    = 21,  /* Ctrl-u */
    CTRL_X    = 24,  /* Ctrl-x */
    ESC       = 27,  /* Escape */
    BACKSPACE = 127, /* Backspace */
    /* The following are just soft codes, not really reported by the
     * terminal directly. */
    ARROW_LEFT = 1000,
    ARROW_RIGHT,
    ARROW_UP,
    ARROW_DOWN,
    DEL_KEY,
    HOME_KEY,
    END_KEY,
    PAGE_UP,
    PAGE_DOWN
};

static FileBuffer*    g_fb;           /* Current FileBuffer */
static struct termios g_orig_termios; /* In order to restore at exit.*/
static int            g_rawmode;      /* Terminal raw mode is enabled */

static u64_t g_min_visible_addr;
static u64_t g_max_visible_addr;
static u64_t g_selected;
static u64_t g_chunk_size = 16;
static int   g_second_nibble;
static int   g_insert_mode;
static int   g_in_ascii_panel;
static char  g_msg[2048];

// Log callback

static void log_callback(const char* msg)
{
    memset(g_msg, 0, sizeof(g_msg));
    strncpy(g_msg, msg, sizeof(g_msg) - 1);
}

//                   Low-level terminal APIs
//   *** Most of these functions are taken from KILO by antirez ***
//                   https://github.com/antirez/kilo

/*
    Copyright (c) 2016, Salvatore Sanfilippo <antirez at gmail dot com>

    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

static void disable_raw_mode(void)
{
    /* Don't even check the return value as it's too late. */
    if (g_rawmode) {
        write(1, "\x1b[?25h", 6); /* Show cursor. */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        g_rawmode = 0;
    }
}

/* Raw mode: 1960 magic shit. */
static int enable_raw_mode(void)
{
    struct termios raw;

    if (g_rawmode)
        return 0; /* Already enabled. */
    if (!isatty(STDIN_FILENO))
        goto fatal;
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) == -1)
        goto fatal;

    raw = g_orig_termios; /* modify the original mode */
    /* input modes: no break, no CR to NL, no parity check, no strip char,
     * no start/stop output control. */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    /* output modes - disable post processing */
    raw.c_oflag &= ~(OPOST);
    /* control modes - set 8 bit chars */
    raw.c_cflag |= (CS8);
    /* local modes - choing off, canonical off, no extended functions,
     * no signal chars (^Z,^C) */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    /* control chars - set return condition: min number of bytes and timer. */
    raw.c_cc[VMIN]  = 0; /* Return each byte, or zero for timeout. */
    raw.c_cc[VTIME] = 1; /* 100 ms timeout (unit is tens of second). */

    /* put terminal in raw mode after flushing */
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0)
        goto fatal;

    write(1, "\x1b[?25l", 6); /* Hide cursor. */
    g_rawmode = 1;
    return 0;

fatal:
    errno = ENOTTY;
    return -1;
}

/* Read a key from the terminal put in raw mode, trying to handle
 * escape sequences. */
static int editor_read_key(void)
{
    int  nread;
    char c, seq[3];
    while ((nread = read(STDIN_FILENO, &c, 1)) == 0)
        ;
    if (nread == -1)
        exit(1);

    while (1) {
        switch (c) {
            case ESC: /* escape sequence */
                /* If this is just an ESC, we'll timeout here. */
                if (read(STDIN_FILENO, seq, 1) == 0)
                    return ESC;
                if (read(STDIN_FILENO, seq + 1, 1) == 0)
                    return ESC;

                /* ESC [ sequences. */
                if (seq[0] == '[') {
                    if (seq[1] >= '0' && seq[1] <= '9') {
                        /* Extended escape, read additional byte. */
                        if (read(STDIN_FILENO, seq + 2, 1) == 0)
                            return ESC;
                        if (seq[2] == '~') {
                            switch (seq[1]) {
                                case '3':
                                    return DEL_KEY;
                                case '5':
                                    return PAGE_UP;
                                case '6':
                                    return PAGE_DOWN;
                            }
                        }
                    } else {
                        switch (seq[1]) {
                            case 'A':
                                return ARROW_UP;
                            case 'B':
                                return ARROW_DOWN;
                            case 'C':
                                return ARROW_RIGHT;
                            case 'D':
                                return ARROW_LEFT;
                            case 'H':
                                return HOME_KEY;
                            case 'F':
                                return END_KEY;
                        }
                    }
                }

                /* ESC O sequences. */
                else if (seq[0] == 'O') {
                    switch (seq[1]) {
                        case 'H':
                            return HOME_KEY;
                        case 'F':
                            return END_KEY;
                    }
                }
                break;
            default:
                return c;
        }
    }
}

/* Use the ESC [6n escape sequence to query the horizontal cursor position
 * and return it. On error -1 is returned, on success the position of the
 * cursor is stored at *rows and *cols and 0 is returned. */
static int get_cursor_position(int* rows, int* cols)
{
    char         buf[32];
    unsigned int i = 0;

    /* Report cursor location */
    if (write(STDOUT_FILENO, "\x1b[6n", 4) != 4)
        return -1;

    /* Read the response: ESC [ rows ; cols R */
    while (i < sizeof(buf) - 1) {
        if (read(STDIN_FILENO, buf + i, 1) != 1)
            break;
        if (buf[i] == 'R')
            break;
        i++;
    }
    buf[i] = '\0';

    /* Parse it. */
    if (buf[0] != ESC || buf[1] != '[')
        return -1;
    if (sscanf(buf + 2, "%d;%d", rows, cols) != 2)
        return -1;
    return 0;
}

/* Try to get the number of columns in the current terminal. If the ioctl()
 * call fails the function will try to query the terminal itself.
 * Returns 0 on success, -1 on error. */
static int get_window_size(int* rows, int* cols)
{
    struct winsize ws;

    if (ioctl(1, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
        /* ioctl() failed. Try to query the terminal itself. */
        int orig_row, orig_col, retval;

        /* Get the initial position so we can restore it later. */
        retval = get_cursor_position(&orig_row, &orig_col);
        if (retval == -1)
            goto failed;

        /* Go to right/bottom margin and get position. */
        if (write(STDOUT_FILENO, "\x1b[999C\x1b[999B", 12) != 12)
            goto failed;
        retval = get_cursor_position(rows, cols);
        if (retval == -1)
            goto failed;

        /* Restore position. */
        char seq[32];
        snprintf(seq, 32, "\x1b[%d;%dH", orig_row, orig_col);
        if (write(STDOUT_FILENO, seq, strlen(seq)) == -1) {
            /* Can't recover... */
        }
        return 0;
    } else {
        *cols = ws.ws_col;
        *rows = ws.ws_row - 1;
        return 0;
    }

failed:
    return -1;
}

// Screen print APIs

typedef struct ScreenWriter {
    char* lines;
    int   len;

    int rows, cols;
    int curr_col;
    int curr_row;
} ScreenWriter;

static void sw_append_raw(ScreenWriter* sw, const char* line, size_t line_len);

static void sw_init(ScreenWriter* sw)
{
    sw->lines = NULL;
    sw->len   = 0;

    get_window_size(&sw->rows, &sw->cols);
    sw->curr_row = 0;
    sw->curr_col = 0;

    sw_append_raw(sw, "\x1b[H", 3); /* Go home. */
}

static void sw_append_raw(ScreenWriter* sw, const char* raw, size_t raw_len)
{
    char* new = bhex_realloc(sw->lines, raw_len + sw->len);
    if (new == NULL)
        return;

    memcpy(new + sw->len, raw, raw_len);
    sw->lines = new;
    sw->len += raw_len;
}

static void sw_start_highlight(ScreenWriter* sw, int primary)
{
    if (primary)
        sw_append_raw(sw, "\x1b[30;43m", 8);
    else
        sw_append_raw(sw, "\x1b[30;47m", 8);
}

static void sw_end_highlight(ScreenWriter* sw)
{
    sw_append_raw(sw, "\x1b[0m", 4);
}

static int sw_append(ScreenWriter* sw, const char* line)
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

static int sw_end_line(ScreenWriter* sw)
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

static int sw_add_line(ScreenWriter* sw, const char* line)
{
    if (sw_append(sw, line) != 0)
        return 1;
    if (sw_end_line(sw) != 0)
        return 1;
    return 0;
}

static void sw_flush(ScreenWriter* sw)
{
    while (sw_end_line(sw) == 0)
        ;

    write(STDOUT_FILENO, sw->lines, sw->len);
    bhex_free(sw->lines);
}

static int refresh_screen(void)
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
        g_chunk_size = 32;
    else
        g_chunk_size = 16;

    size_t read_size  = min(g_chunk_size * (sw.rows - 5), fb_block_size);
    read_size         = min(g_fb->size - g_fb->off, read_size);
    const u8_t* bytes = fb_read(g_fb, read_size);
    if (!bytes) {
        sw_add_line(&sw, "");
        sw_add_line(&sw, " unable to read the file");
        sw_flush(&sw);
        return -1;
    }

    g_min_visible_addr = g_fb->off;
    g_max_visible_addr = g_min_visible_addr +
                         min(g_chunk_size * (sw.rows - 5), fb_block_size) - 1;

    sw_start_highlight(&sw, 0);
    sw_append(
        &sw, " CTRL-X [Exit] CTRL-U [Undo] CTRL-A [Insert] TAB [Toggle ASCII]");
    if (g_insert_mode)
        sw_append(&sw, " *INSERT*");
    if (g_fb->modifications.size > 0)
        sw_append(&sw, " *UNSAVED*");
    sw_end_line(&sw);
    sw_append(&sw, " ");
    sw_append(&sw, g_msg);
    sw_end_line(&sw);
    sw_end_highlight(&sw);
    sw_end_line(&sw);
    sw_append(&sw,
              "           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
    if (g_chunk_size > 16)
        sw_append(&sw, " 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");

    sw_end_line(&sw);
    sw_append(&sw,
              "           -----------------------------------------------");
    if (g_chunk_size > 16)
        sw_append(&sw, "------------------------------------------------");
    sw_end_line(&sw);

    u64_t off = 0;
    for (int i = 0; i < sw.rows - 5; ++i) {
        snprintf(buf, sizeof(buf) - 1, " %08llx: ", (u64_t)off + g_fb->off);
        sw_append(&sw, buf);

        for (u64_t j = 0; j < g_chunk_size; ++j) {
            if (off + j >= read_size) {
                for (; j < g_chunk_size; ++j) {
                    if (off + j + g_fb->off == g_selected)
                        sw_start_highlight(&sw, g_in_ascii_panel == 0);
                    sw_append(&sw, "  ");
                    if (off + j + g_fb->off == g_selected)
                        sw_end_highlight(&sw);
                    sw_append(&sw, " ");
                }
                break;
            }
            if (off + j + g_fb->off == g_selected)
                sw_start_highlight(&sw, g_in_ascii_panel == 0);
            snprintf(buf, sizeof(buf) - 1, "%02X", bytes[off + j]);
            sw_append(&sw, buf);
            if (off + j + g_fb->off == g_selected)
                sw_end_highlight(&sw);
            sw_append(&sw, " ");
        }
        sw_append(&sw, "  ");
        for (u64_t j = 0; j < g_chunk_size; ++j) {
            if (off + j >= read_size) {
                for (; j < g_chunk_size; ++j) {
                    if (off + j + g_fb->off == g_selected)
                        sw_start_highlight(&sw, g_in_ascii_panel != 0);
                    sw_append(&sw, " ");
                    if (off + j + g_fb->off == g_selected)
                        sw_end_highlight(&sw);
                }
                break;
            }
            if (off + j + g_fb->off == g_selected)
                sw_start_highlight(&sw, g_in_ascii_panel != 0);
            snprintf(buf, sizeof(buf) - 1, "%c",
                     get_printable_ascii_or_dot((u8_t)bytes[off + j]));
            sw_append(&sw, buf);
            if (off + j + g_fb->off == g_selected)
                sw_end_highlight(&sw);
        }
        sw_end_line(&sw);
        off += g_chunk_size;
    }

    sw_flush(&sw);
    return 0;
}

static void refresh_signal_handler(int __attribute__((unused)) sig)
{
    refresh_screen();
}

static void write_key(int k)
{
    u64_t old_off = g_fb->off;
    fb_seek(g_fb, g_selected);

    if (!is_printable_ascii((char)k))
        goto end;

    if (!g_insert_mode && g_selected >= g_fb->size)
        goto end;

    if (g_in_ascii_panel) {
        u8_t  byte = (u8_t)k;
        u8_t* data = bhex_malloc(1);
        data[0]    = byte;
        if (!g_insert_mode)
            fb_write(g_fb, data, 1);
        else
            fb_insert(g_fb, data, 1);
        g_selected += 1;
        goto end;
    }

    int b = hex_to_nibble((char)k);
    if (b < 0)
        goto end;

    u8_t byte = (u8_t)b;
    u8_t curr_byte =
        (g_insert_mode && !g_second_nibble) ? 0 : *fb_read(g_fb, 1);
    if (!g_second_nibble)
        byte = (byte << 4) | (curr_byte & 0xf);
    else
        byte = (curr_byte & 0xf0) | (byte & 0xf);

    u8_t* data = bhex_malloc(1);
    data[0]    = byte;
    if (g_insert_mode && !g_second_nibble)
        fb_insert(g_fb, data, 1);
    else
        fb_write(g_fb, data, 1);

    if (g_second_nibble) {
        g_second_nibble = 0;
        g_selected += 1;
    } else
        g_second_nibble = 1;

end:
    fb_seek(g_fb, old_off);
}

int tui_enter_loop(FileBuffer* fb)
{
    int res  = 0;
    int rows = 0, cols = 0;

    struct sigaction sa, priorsa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = SA_RESTART;
    sa.sa_handler = refresh_signal_handler;
    sigaction(SIGWINCH, &sa, &priorsa);

    enable_raw_mode();
    register_log_callback(log_callback);

    g_in_ascii_panel = 0;
    g_selected       = fb->off;
    g_fb             = fb;

    if ((fb->off & (g_chunk_size - 1)) != 0)
        fb_seek(fb, fb->off & ~(g_chunk_size - 1));

    int quit = 0;
    while (!quit) {
        if (refresh_screen() != 0) {
            res = -1;
            break;
        }
        if (get_window_size(&rows, &cols) != 0) {
            res = -1;
            break;
        }

        memset(g_msg, 0, sizeof(g_msg));
        int k = editor_read_key();
        switch (k) {
            case ARROW_RIGHT:
                g_second_nibble = 0;
                if (g_selected < fb->size)
                    g_selected += 1;
                break;
            case ARROW_DOWN:
                g_second_nibble = 0;
                if (fb->size > g_chunk_size - 1 &&
                    g_selected <= fb->size - g_chunk_size)
                    g_selected += g_chunk_size;
                else
                    g_selected = fb->size;
                break;
            case ARROW_LEFT:
                g_second_nibble = 0;
                if (g_selected > 0)
                    g_selected -= 1;
                break;
            case ARROW_UP:
                g_second_nibble = 0;
                if (g_selected >= g_chunk_size)
                    g_selected -= g_chunk_size;
                else
                    g_selected = 0;
                break;
            case PAGE_UP:
                g_second_nibble = 0;
                u64_t tosub     = (rows - 5) * g_chunk_size;
                if (tosub < g_selected && tosub < g_fb->off) {
                    g_selected -= tosub;
                    fb_seek(fb, g_fb->off - tosub);
                } else {
                    g_selected = 0;
                    fb_seek(fb, 0);
                }
                break;
            case PAGE_DOWN:
                g_second_nibble = 0;
                u64_t toadd     = (rows - 5) * g_chunk_size;
                if (g_selected + toadd < g_fb->size) {
                    g_selected += toadd;
                    fb_seek(fb, g_fb->off + toadd);
                } else {
                    g_selected = g_fb->size;
                    if (g_selected > g_max_visible_addr) {
                        if (g_fb->off + toadd < g_fb->size)
                            fb_seek(fb, g_fb->off + toadd);
                        else
                            fb_seek(fb, g_selected & ~(g_chunk_size - 1));
                    }
                }
                break;
            case TAB:
                g_second_nibble  = 0;
                g_in_ascii_panel = !g_in_ascii_panel;
                break;
            case CTRL_A:
                g_insert_mode = !g_insert_mode;
                break;
            case CTRL_U:
                fb_undo_last(g_fb);
                break;
            case CTRL_X:
                quit = 1;
                break;
            case DEL_KEY: {
                u64_t tmp = g_fb->off;
                fb_seek(g_fb, g_selected);
                fb_delete(g_fb, 1);
                fb_seek(g_fb, tmp);
                break;
            }
            default:
                write_key(k);
                break;
        }

        if (k != PAGE_UP && k != PAGE_DOWN) {
            if (g_selected > g_max_visible_addr &&
                g_max_visible_addr < fb->size)
                fb_seek(fb, fb->off + g_chunk_size);
            if (g_selected < g_min_visible_addr)
                fb_seek(fb, fb->off - g_chunk_size);
        }
    }

    g_in_ascii_panel = 0;
    g_second_nibble  = 0;
    fb_seek(fb, g_selected);

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
