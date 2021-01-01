/**
 ** cmdline.h: Common definitions for hiBus command line program.
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

#ifndef _HIBUS_CMDLIEN_H
#define _HIBUS_CMDLIEN_H

#include <termio.h>

#define LEN_COMMAND         63
#define LEN_LAST_ARGUMENT   1023
#define TABLESIZE(table)    (sizeof(table)/sizeof(table[0]))

/* original terminal modes */
struct run_info {
    int ttyfd;
    bool running;
    time_t last_sigint_time;

    struct termios startup_termios;

    char builtin_endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];
    char self_endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];

    hibus_json *jo_endpoints;

    // buffers for current command
    char cmd [LEN_COMMAND + 1];
    char endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];
    char method_bubble [HIBUS_LEN_METHOD_NAME + 1];
    char last_arg [LEN_LAST_ARGUMENT + 1];

    char* curr_edit_buff;
    int curr_edit_pos;

    /* fields for drum-game */
    int nr_players;
    char* ball_content;
};

int start_drum_game (hibus_conn* conn, int nr_players, const char *ball_content);

#endif /* _HIBUS_CMDLIEN_H */

