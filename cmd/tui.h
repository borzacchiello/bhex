// Copyright (c) 2022-2026, bageyelet

#ifndef TUI_H
#define TUI_H

#include <filebuffer.h>
#include <defs.h>

typedef struct ScreenWriter {
    char* lines;
    int   len;

    int rows, cols;
    int curr_col;
    int curr_row;
} ScreenWriter;

void sw_init_with_size(ScreenWriter* sw, int rows, int cols);
void sw_append_raw(ScreenWriter* sw, const char* raw, size_t raw_len);
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
    char        msg[2048];
} TuiState;

void tui_write_key(TuiState* ts, int k);
int  tui_process_key(TuiState* ts, int k, int rows);
int  tui_enter_loop(FileBuffer* fb);

#endif
