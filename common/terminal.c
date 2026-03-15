// Copyright (c) 2022-2026, bageyelet

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <sys/ioctl.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "terminal.h"

static struct termios g_orig_termios; /* In order to restore at exit.*/
static int            g_rawmode;      /* Terminal raw mode is enabled */

void disable_raw_mode(void)
{
    /* Don't even check the return value as it's too late. */
    if (g_rawmode) {
        write(1, "\x1b[?25h", 6); /* Show cursor. */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        g_rawmode = 0;
    }
}

/* Raw mode: 1960 magic shit. */
int enable_raw_mode(void)
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
int terminal_read_key(void)
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
int get_window_size(int* rows, int* cols)
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
