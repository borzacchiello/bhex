// Copyright (c) 2022-2026, bageyelet

#ifndef TERMINAL_H
#define TERMINAL_H

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

enum KEY_ACTION {
    KEY_NULL  = 0,   /* NULL */
    CTRL_A    = 1,   /* Ctrl-a */
    CTRL_B    = 2,   /* Ctrl-b */
    CTRL_C    = 3,   /* Ctrl-c */
    CTRL_D    = 4,   /* Ctrl-d */
    CTRL_E    = 5,   /* Ctrl-e */
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

void disable_raw_mode(void);
int  enable_raw_mode(void);
int  terminal_read_key(void);
int  get_window_size(int* rows, int* cols);

#endif
