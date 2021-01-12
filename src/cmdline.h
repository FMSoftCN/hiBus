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
#include <hibox/kvlist.h>

#define NR_CMD_ARGS         4

#define LEN_COMMAND         31
#define LEN_NORMAL_ARG      HIBUS_LEN_ENDPOINT_NAME
#define LEN_LAST_ARG        1023
#define LEN_GAME_NAME       31

#define LEN_EDIT_BUFF       1023

#define LEN_HISTORY_BUF     128

#define TABLESIZE(table)    (sizeof(table)/sizeof(table[0]))

/* original terminal modes */
struct run_info {
    int ttyfd;
    bool running;
    time_t last_sigint_time;

    struct termios startup_termios;

    char app_name [HIBUS_LEN_APP_NAME + 1];
    char runner_name [HIBUS_LEN_RUNNER_NAME + 1];
    char builtin_endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];
    char self_endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];

    hibus_json *jo_endpoints;
    struct kvlist ret_value_list;

#if 0
    // buffers for current command
    char cmd [LEN_COMMAND + 1];
    char arg_1st [LEN_NORMAL_ARG + 1];
    char arg_2nd [LEN_NORMAL_ARG + 1];
    char arg_3rd [LEN_NORMAL_ARG + 1];
    char arg_lst [LEN_LAST_ARG + 1];
#endif

    char edit_buff [LEN_EDIT_BUFF + 1];
    int curr_edit_pos;
    bool edited;

    int nr_history_cmds;
    int curr_history_idx;
    char* history_cmds [LEN_HISTORY_BUF];
    char* saved_buff;

    /* fields for drum-game */
    int nr_players;
    char* ball_content;
};

int start_drum_game (hibus_conn* conn, int nr_players, const char *ball_content);

#endif /* _HIBUS_CMDLIEN_H */

