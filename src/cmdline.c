/*
** cmdline.c -- The code for hiBus cmdline.
**
** Copyright (c) 2020 FMSoft (http://www.fmsoft.cn)
**
** Author: Vincent Wei (https://github.com/VincentWei)
**
** This file is part of hiBus.
**
** hiBus is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.
**
** hiBus is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** You should have received a copy of the GNU General Public License
** along with this program.  If not, see http://www.gnu.org/licenses/.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <termio.h>
#include <signal.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <hibox/ulog.h>
#include <hibox/json.h>

#include "hibus.h"

#define LEN_COMMAND         63
#define LEN_LAST_ARGUMENT   1023
#define TABLESIZE(table)    (sizeof(table)/sizeof(table[0]))

/* original terminal modes */
static struct run_info {
    int ttyfd;
    bool running;
    time_t last_sigint_time;

    struct termios startup_termios;

    // buffers for current command
    char cmd [LEN_COMMAND + 1];
    char endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];
    char method_bubble [HIBUS_LEN_METHOD_NAME + 1];
    char last_arg [LEN_LAST_ARGUMENT + 1];

    char* curr_edit_buff;
    int curr_edit_pos;
} the_client;

/* command identifiers */
enum {
    CMD_HELP = 0,
    CMD_EXIT,
    CMD_CALL,
    CMD_SUBSCRIBE,
    CMD_UNSUBSCRIBE,
    CMD_LIST_ENDPOINTS,
    CMD_LIST_METHODS,
    CMD_LIST_BUBBLES,
};

/* argument type */
enum {
    AT_NONE = 0,
    AT_ENDPOINT,
    AT_METHOD,
    AT_BUBBLE,
    AT_JSON,
    AT_MAX_NR_ARGS = AT_JSON,
};

static struct cmd_info {
    int cmd;
    const char* long_name;
    const char* short_name;
    int nr_arguments;
    int type_1st_arg;
    int type_2nd_arg;
    int type_3rd_arg;
    int type_4th_arg;
} cmd_info [] = {
    { CMD_HELP,
        "help", "h", 0},
    { CMD_EXIT,
        "exit", "x", 0},
    { CMD_CALL,
        "call", "c", 3, AT_ENDPOINT, AT_METHOD, AT_JSON, },
    { CMD_SUBSCRIBE,
        "subscribe", "sub", 2, AT_ENDPOINT, AT_BUBBLE, },
    { CMD_UNSUBSCRIBE,
        "unsubscribe", "unsub", 2, AT_ENDPOINT, AT_BUBBLE, },
    { CMD_LIST_ENDPOINTS,
        "listendpoints", "listep", 0 },
    { CMD_LIST_METHODS,
        "listendpoints", "listep", 1, AT_ENDPOINT, },
    { CMD_LIST_BUBBLES,
        "listendpoints", "listep", 1, AT_ENDPOINT, },
};

static int setup_tty (void)
{
    int ttyfd;
    struct termios my_termios;

    ttyfd = open ("/dev/tty", O_RDONLY);
    if (ttyfd < 0) {
        ULOG_ERR ("Failed to open /dev/tty: %s.", strerror (errno));
        return -1;
    }

    if (tcgetattr (ttyfd, &the_client.startup_termios) < 0) {
        ULOG_ERR ("Failed to call tcgetattr: %s.", strerror (errno));
        goto error;
    }

    memcpy (&my_termios, &the_client.startup_termios, sizeof ( struct termios));
#if 0
    my_termios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    my_termios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
            | INLCR | IGNCR | ICRNL | IXON);
    my_termios.c_oflag &= ~OPOST;
    my_termios.c_cflag &= ~(CSIZE | PARENB);
    my_termios.c_cflag |= CS8;
#else
    my_termios.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
    my_termios.c_iflag &= ~(ICRNL | INLCR);
    my_termios.c_iflag |= ICRNL;
    my_termios.c_cc[VMIN] = 0;
    my_termios.c_cc[VTIME] = 0;
#endif

    if (tcsetattr (ttyfd, TCSAFLUSH, &my_termios) < 0) {
        ULOG_ERR ("Failed to call tcsetattr: %s.", strerror (errno));
        goto error;
    }

    if (fcntl (ttyfd, F_SETFL, fcntl (ttyfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        ULOG_ERR ("Failed to set TTY as non-blocking: %s.", strerror (errno));
        return -1;
    }

    return ttyfd;

error:
    close (ttyfd);
    return -1;
}

static int restore_tty (int ttyfd)
{
    if (tcsetattr (ttyfd, TCSAFLUSH, &the_client.startup_termios) < 0)
        return -1;

    close (ttyfd);
    return 0;
}

static void handle_signal_action (int sig_number)
{
    if (sig_number == SIGINT) {
        if (the_client.last_sigint_time == 0) {
            fprintf (stderr, "\n");
            fprintf (stderr, "SIGINT caught, press <CTRL+C> again in 5 seconds to quit.\n");
            the_client.last_sigint_time = time (NULL);
        }
        else if (time (NULL) < the_client.last_sigint_time + 5) {
            fprintf (stderr, "SIGINT caught, quit...\n");
            the_client.running = false;
        }
        else {
            fprintf (stderr, "\n");
            fprintf (stderr, "SIGINT caught, press <CTRL+C> again in 5 seconds to quit.\n");
            the_client.running = true;
            the_client.last_sigint_time = time (NULL);
        }
    }
    else if (sig_number == SIGPIPE) {
        fprintf (stderr, "SIGPIPE caught!\n");
    }
}

static int setup_signals (void)
{
    struct sigaction sa;
    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = handle_signal_action;

    if (sigaction (SIGINT, &sa, 0) != 0) {
        ULOG_ERR ("Failed to call sigaction for SIGINT: %s\n", strerror (errno));
        return -1;
    }

    if (sigaction (SIGPIPE, &sa, 0) != 0) {
        ULOG_ERR ("Failed to call sigaction for SIGPIPE: %s\n", strerror (errno));
        return -1;
    }

    return 0;
}

static void on_cmd_help (hibus_conn *conn)
{
    fprintf (stderr, "\n"
            "\n"
            "hiBus - the data bus system for HybridOS.\n"
            "\n"
            "Copyright (C) 2020 FMSoft <https://www.fmsoft.cn>\n"
            "\n"
            "hiBus is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License as published by\n"
            "the Free Software Foundation, either version 3 of the License, or\n"
            "(at your option) any later version.\n"
            "\n"
            "hiBus is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
            "GNU General Public License for more details.\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program.  If not, see http://www.gnu.org/licenses/.\n"
            );
    fprintf (stderr, "\n");
    fprintf (stderr, "Commands:\n\n");
    fprintf (stderr, "\t<help | h>\n");
    fprintf (stderr, "\t\tprint this help message.\n");
    fprintf (stderr, "\t<exit | x>\n");
    fprintf (stderr, "\t\texit this hiBus command line program.\n");
    fprintf (stderr, "\t<call | c> <endpoint> <method> [parameters]\n");
    fprintf (stderr, "\t\tcall a procedure\n");
    fprintf (stderr, "\t<subscribe | sub> <endpoint> <BUBBLE>\n");
    fprintf (stderr, "\t\tsuscribe an event.\n");
    fprintf (stderr, "\t<unsubscribe | unsub> <endpoint> <BUBBLE>\n");
    fprintf (stderr, "\t\tunsuscribe an event.\n");
    fprintf (stderr, "\n");
    fprintf (stderr, "Shortcuts:\n\n");
    fprintf (stderr, "\t<F1>\n\t\tprint this help message.\n");
    fprintf (stderr, "\t<F2>\n\t\tlist all endpoints.\n");
    fprintf (stderr, "\t<ESC>\n\t\texit this hiBus command line program.\n");
    fprintf (stderr, "\t<TAB>\n\t\tauto complete the command.\n");
    fprintf (stderr, "\t<UP>/<DOWN>\n\t\tswitch among available values when editing command line.\n");
    fprintf (stderr, "\n");
}

static void on_cmd_exit (hibus_conn *conn)
{
    struct run_info *info = hibus_conn_get_user_data (conn);

    assert (info);

    fprintf (stderr, "\n");
    fprintf (stderr, "Exiting...\n");
    info->running = false;
}

static void print_prompt (hibus_conn *conn)
{
    struct run_info *info = hibus_conn_get_user_data (conn);

    assert (info);

    // move cursor to the start of the current line and erase whole line
    fputs ("\x1B[0G\x1B[2K", stderr);
    fputs ("hiBusCL >> ", stderr);

    // reset the command information
    info->cmd [0] = '\0';
    info->endpoint [0] = '\0';
    info->method_bubble [0] = '\0';
    info->last_arg [0] = '\0';
    info->curr_edit_buff = info->cmd;
    info->curr_edit_pos = 0;
}

static void on_confirm_command (hibus_conn *conn)
{
    int i, cmd = -1;
    struct run_info *info = hibus_conn_get_user_data (conn);
    
    assert (info);

    // fputs ("\n", stderr);
    // fputs (info->cmd, stderr);

    for (i = 0; i < TABLESIZE (cmd_info); i++) {
        if (strcasecmp (info->cmd, cmd_info[i].short_name) == 0
                || strcasecmp (info->cmd, cmd_info[i].long_name) == 0) {

            cmd = cmd_info[i].cmd;
            break;
        }
    }

    switch (cmd) {
        case CMD_HELP:
            on_cmd_help (conn);
            break;

        case CMD_EXIT:
            on_cmd_exit (conn);
            return;

        case CMD_CALL:
        case CMD_SUBSCRIBE:
        case CMD_UNSUBSCRIBE:
        case CMD_LIST_ENDPOINTS:
        case CMD_LIST_METHODS:
        case CMD_LIST_BUBBLES:
        default:
            break;
    }

    print_prompt (conn);
}

static void on_append_char (hibus_conn *conn, int ch)
{
    struct run_info *info = hibus_conn_get_user_data (conn);

    if (info->curr_edit_buff) {
        int pos = strlen (info->curr_edit_buff);
        if (pos < LEN_COMMAND) {
            info->curr_edit_buff [pos++] = ch;
            info->curr_edit_buff [pos] = '\0';
            putc (ch, stderr);
        }
    }
}

static void on_delete_char (hibus_conn *conn)
{
    int pos;
    struct run_info *info = hibus_conn_get_user_data (conn);

    assert (info);
    if (info->curr_edit_buff) {
        pos = strlen (info->curr_edit_buff);
        if (pos > 0) {
            info->curr_edit_buff [--pos] = '\0';
            fputs ("\x1B[1D\x1B[1X", stderr);
        }
    }
}

static void handle_tty_input (hibus_conn *conn)
{
    struct run_info *info = hibus_conn_get_user_data (conn);
    ssize_t n;
    char buff [256];

    assert (info);
    while ((n = read (info->ttyfd, buff, 256)) > 0) {
        ssize_t i;

        buff [n] = '\0';
        for (i = 0; i < n; i++) {
            if (buff [i] == '\r') {
                // confirm user's input
                // fputs ("CR", stderr);
                on_confirm_command (conn);
            }
            else if (buff [i] == '\n') {
                // confirm user's input
                // fputs ("NL", stderr);
                on_confirm_command (conn);
            }
            else if (buff [i] == '\t') {
                // confirm user's input
                fputs ("HT", stderr);
            }
            else if (buff [i] == '\b') {
                // backspace
                fputs ("BS", stderr);
            }
            else if (buff [i] == 0x7f) {
                // backspace
                // fputs ("DEL", stderr);
                on_delete_char (conn);
            }
            else if (buff [i] == 0x1B) {
                // an escape sequence.
                if (strncmp (buff + i, "\x1b\x5b\x41", 3) == 0) {
                    fputs ("UP", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1b\x5b\x42", 3) == 0) {
                    fputs ("DOWN", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1b\x5b\x43", 3) == 0) {
                    fputs ("RIGHT", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1b\x5b\x44", 3) == 0) {
                    fputs ("LEFT", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x33\x7E", 4) == 0) {
                    fputs ("Del", stderr);
                    i += 4;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x32\x7E", 4) == 0) {
                    fputs ("Ins", stderr);
                    i += 4;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x48", 3) == 0) {
                    fputs ("Home", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x46", 3) == 0) {
                    fputs ("End", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x35\x7E", 4) == 0) {
                    fputs ("PgUp", stderr);
                    i += 4;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x36\x7E", 4) == 0) {
                    fputs ("PgDn", stderr);
                    i += 4;
                }
                else if (strncmp (buff + i, "\x1B\x4F\x50", 3) == 0) {
                    fputs ("F1", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1B\x4F\x51", 3) == 0) {
                    fputs ("F2", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1B\x4F\x52", 3) == 0) {
                    fputs ("F3", stderr);
                    i += 3;
                }
                else if (strncmp (buff + i, "\x1B\x4F\x53", 3) == 0) {
                    fputs ("F4", stderr);
                    i += 4;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x31\x35\x7E", 5) == 0) {
                    fputs ("F5", stderr);
                    i += 5;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x31\x37\x7E", 5) == 0) {
                    fputs ("F6", stderr);
                    i += 5;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x31\x38\x7E", 5) == 0) {
                    fputs ("F7", stderr);
                    i += 5;
                }
                else if (strncmp (buff + i, "\x1B\x5B\x31\x39\x7E", 5) == 0) {
                    fputs ("F8", stderr);
                    i += 5;
                }
                else {
                    while (buff [i]) {
                        // fprintf (stderr, "\\x%X", buff[i]);
                        i++;
                    }
                }
            }
            else if (buff [i]) {
                on_append_char (conn, buff[i]);
            }
        }
    }
}

int main (int argc, char **argv)
{
    int cnnfd = -1, ttyfd = -1, maxfd;
    hibus_conn* conn;
    fd_set rfds;
    struct timeval tv;

    ulog_open (-1, -1, "hiBusCL");

    the_client.running = true;
    the_client.last_sigint_time = 0;
    if (setup_signals () < 0)
        goto failed;

    if ((ttyfd = setup_tty ()) < 0)
        goto failed;

    cnnfd = hibus_connect_via_unix_socket (HIBUS_US_PATH,
            HIBUS_APP_HIBUS, HIBUS_RUNNER_CMDLINE, &conn);

    if (cnnfd < 0) {
        ULOG_ERR ("Failed to connect to hiBus server: %s\n",
                hibus_get_err_message (cnnfd));
        goto failed;
    }

    ULOG_NOTE ("Connection fd: %d\n", cnnfd);

    the_client.ttyfd = ttyfd;
    hibus_conn_set_user_data (conn, &the_client);

    print_prompt (conn);
    maxfd = cnnfd > ttyfd ? cnnfd : ttyfd;
    do {
        int retval;

        FD_ZERO (&rfds);
        FD_SET (cnnfd, &rfds);
        FD_SET (ttyfd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;
        retval = select (maxfd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            if (errno == EINTR)
                continue;
            else
                break;
        }
        else if (retval) {
            if (FD_ISSET (cnnfd, &rfds)) {
                int err_code = hibus_read_and_dispatch_packet (conn);
                if (err_code) {
                    ULOG_ERR ("Failed to read and dispatch packet: %s",
                            hibus_get_err_message (err_code));
                }

                print_prompt (conn);
            }
            else if (FD_ISSET (ttyfd, &rfds)) {
                handle_tty_input (conn);
            }
        }
        else {
            // ULOG_INFO ("Timeout\n");
        }

        if (time (NULL) > the_client.last_sigint_time + 5) {
            // cancel quit
            the_client.last_sigint_time = 0;
        }

    } while (the_client.running);

    fputs ("\n", stderr);

failed:
    if (ttyfd >= 0)
        restore_tty (ttyfd);

    if (cnnfd >= 0)
        hibus_disconnect (conn);

    ulog_close ();
    return 0;
}

