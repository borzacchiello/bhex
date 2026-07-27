// Copyright (c) 2022-2026, bageyelet

#ifndef TUI_H
#define TUI_H

#include <filebuffer.h>
#include <defs.h>

// Logical styles of the TUI elements. Each one is rendered either with colors
// or with plain attributes (bold/reverse/underline), see `no_colors` below.
typedef enum Style {
    STYLE_RESET = 0,
    STYLE_SEL_PRIMARY,
    STYLE_SEL_SECONDARY,
    STYLE_STATUSBAR,
    STYLE_INSERT,
    STYLE_UNSAVED,
    // addresses on the left and column offsets on top, plus the variant
    // marking the row/column of the cursor
    STYLE_LABEL,
    STYLE_LABEL_SEL,
    STYLE_BYTE_ZERO,
    STYLE_BYTE_FF,
    STYLE_BYTE_ASCII,
    STYLE_BYTE_OTHER,
    STYLE_COUNT
} Style;

typedef struct ScreenWriter {
    char* lines;
    int   len;

    int rows, cols;
    int curr_col;
    int curr_row;

    // when set, styles are rendered without colors
    int no_colors;

    // style currently in effect, used to avoid emitting the same escape
    // sequence over and over while painting a row
    Style style;
} ScreenWriter;

void sw_init_with_size(ScreenWriter* sw, int rows, int cols);
void sw_append_raw(ScreenWriter* sw, const char* raw, size_t raw_len);
void sw_style(ScreenWriter* sw, Style style);
void sw_start_highlight(ScreenWriter* sw, int primary);
void sw_end_highlight(ScreenWriter* sw);
int  sw_append(ScreenWriter* sw, const char* line);
int  sw_end_line(ScreenWriter* sw);
int  sw_add_line(ScreenWriter* sw, const char* line);
void sw_flush(ScreenWriter* sw);

typedef struct TuiState {
    FileBuffer* fb;
    u64_t       min_visible_addr;
    u64_t       max_visible_addr;
    u64_t       selected;
    u64_t       chunk_size;
    int         second_nibble;
    int         insert_mode;
    int         in_ascii_panel;
    int         no_colors;
    // when set, the key bindings panel is drawn in place of the hex view
    int  show_help;
    char msg[2048];
} TuiState;

void tui_write_key(TuiState* ts, int k);
int  tui_process_key(TuiState* ts, int k, int rows);
int  tui_enter_loop(FileBuffer* fb, int no_colors);

#endif
