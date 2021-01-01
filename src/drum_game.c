/*
** drum_game.c -- The code for a drum game by using hiBus.
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
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <hibox/ulog.h>
#include <hibox/json.h>

#include "hibus.h"
#include "cmdline.h"

#define PREFIX_PLAYER_RUNNER    "player"
#define LEN_PREFIX              (sizeof (PREFIX_PLAYER_RUNNER) - 1)

struct player_info {
    bool running;
    int number;
    char *ball_content;
};

static char* on_method_get_ball (hibus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *err_code)
{
    char runner_name [HIBUS_LEN_RUNNER_NAME + 1];
    *err_code = 0;

    if (hibus_extract_runner_name (from_endpoint, runner_name) <= 0) {
        *err_code = HIBUS_EC_UNEXPECTED;
        return NULL;
    }

    if (strncasecmp (runner_name, PREFIX_PLAYER_RUNNER, LEN_PREFIX) == 0) {
        int pn = atoi (runner_name + LEN_PREFIX);

        if (pn == 0) {
            /* get the original ball content */
            struct run_info *info = hibus_conn_get_user_data (conn);
            return strdup (info->ball_content);
        }
        else {
            /* get ball content of the current player */
            struct player_info *player = hibus_conn_get_user_data (conn);
            return strdup (player->ball_content);
        }
    }
    else if (strcasecmp (runner_name, HIBUS_RUNNER_CMDLINE) == 0) {
        /* must from the runner `cmdline` */
        struct player_info *player = hibus_conn_get_user_data (conn);
        return strdup (player->ball_content);
    }

    *err_code = HIBUS_EC_UNEXPECTED;
    return NULL;
}

static int get_ball_from_previous_player (hibus_conn* conn, int pn, const char *player_name)
{
    char to_endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];
    int err_code, ret_code;
    char* ret_value;

    if (pn == 0) {
        hibus_assemble_endpoint_name (
                hibus_conn_own_host_name (conn),
                HIBUS_APP_HIBUS, HIBUS_RUNNER_CMDLINE,
                to_endpoint);
    }
    else {
        hibus_assemble_endpoint_name (
                hibus_conn_own_host_name (conn),
                HIBUS_APP_HIBUS, player_name,
                to_endpoint);
    }

    err_code = hibus_call_procedure_and_wait (conn,
            to_endpoint, "getBall",
            player_name,
            HIBUS_DEF_TIME_EXPECTED,
            &ret_code, &ret_value);
    if (err_code == 0 && ret_code == HIBUS_SC_OK) {
        struct player_info *info = hibus_conn_get_user_data (conn);
        struct tm tm;
        time_t curr_time = time (NULL);
        char signature [64], buff [10];

        localtime_r (&curr_time, &tm);
        strftime (buff, sizeof (buff), "%H:%M", &tm);

        strcpy (signature, "\n-- I got this ball at ");
        strcat (signature, buff);

        info->ball_content = malloc (strlen (ret_value) + strlen (signature) + 1);
        if (info->ball_content) {
            strcpy (info->ball_content, ret_value);
            strcat (info->ball_content, signature);
        }
        else
            return -1;
    }
    else
        return -1;

    return 0;
}

static void on_game_over (hibus_conn* conn,
        const char* from_endpoint, const char* from_bubble,
        const char* bubble_data)
{
    struct player_info *info = hibus_conn_get_user_data (conn);

    info->running = false;
}

static int main_of_player (int pn)
{
    char cmdline_endpoint [HIBUS_LEN_ENDPOINT_NAME + 1];
    char player_name [HIBUS_LEN_RUNNER_NAME + 1];
    int cnnfd = -1;
    hibus_conn* conn;
    fd_set rfds;
    struct timeval tv;
    int err_code;
    struct player_info player;

    sprintf (player_name, "%s%d", PREFIX_PLAYER_RUNNER, pn);
    cnnfd = hibus_connect_via_unix_socket (HIBUS_US_PATH,
            HIBUS_APP_HIBUS, player_name, &conn);

    if (cnnfd < 0) {
        goto failed;
    }

    hibus_assemble_endpoint_name (
            hibus_conn_own_host_name (conn),
            HIBUS_APP_HIBUS, HIBUS_RUNNER_CMDLINE,
            cmdline_endpoint);

    player.running = true;
    player.number = pn;
    hibus_conn_set_user_data (conn, &player);

    if (get_ball_from_previous_player (conn, pn, player_name)) {
        goto failed;
    }

    err_code = hibus_register_procedure (conn, "getBall",
            HIBUS_LOCALHOST, HIBUS_APP_HIBUS, on_method_get_ball);
    if (err_code) {
        goto failed;
    }

    err_code = hibus_subscribe_event (conn, cmdline_endpoint, "GameOver",
            on_game_over);
    if (err_code) {
        goto failed;
    }

    err_code = hibus_call_procedure (conn, cmdline_endpoint,
            "notifyReady", player_name,
            HIBUS_DEF_TIME_EXPECTED, 0);
    if (err_code) {
        goto failed;
    }

    do {
        int retval;

        FD_ZERO (&rfds);
        FD_SET (cnnfd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;
        retval = select (cnnfd + 1, &rfds, NULL, NULL, &tv);

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
                }
            }
        }
        else {
        }


    } while (player.running);


failed:
    if (cnnfd >= 0)
        hibus_disconnect (conn);

    return 0;
}


static int fork_a_player (hibus_conn* conn, int pn)
{
    pid_t pid;

    if ((pid = fork())) {
    }
    else {
        /* in the child */
        int fd;

        /* free connection */
        hibus_free_connection (conn);

        /* close the file descriptors for stdio */
        close (0);
        close (1);
        close (2);

        /* redirect 0, 1, and 2 to /dev/null */
        fd = open ("/dev/null", O_RDWR);
        fd = dup (fd);
        fd = dup (fd);

        main_of_player (pn);
    }

    return 0;
}

static void term_drum_game (hibus_conn* conn)
{
    int err_code;
    struct run_info *info = hibus_conn_get_user_data (conn);

    if (info->ball_content)
        free (info->ball_content);

    if ((err_code = hibus_revoke_procedure (conn, "getBall"))) {
        ULOG_ERR ("Failed to revoke procedure `getBall` (%d): %s\n",
                err_code, hibus_get_err_message (err_code));
        return;
    }

    if ((err_code = hibus_revoke_event (conn, "PlayerReady"))) {
        ULOG_ERR ("Failed to revoke event `PlayerReady` (%d): %s\n",
                err_code, hibus_get_err_message (err_code));
        return;
    }

    if ((err_code = hibus_revoke_event (conn, "GameOver"))) {
        ULOG_ERR ("Failed to revoke event `GameOver` (%d): %s\n",
                err_code, hibus_get_err_message (err_code));
        return;
    }
}

static char* on_method_notify_ready (hibus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *err_code)
{
    int my_err_code;
    char runner_name [HIBUS_LEN_RUNNER_NAME + 1];
    struct run_info *info = hibus_conn_get_user_data (conn);

    if (hibus_extract_runner_name (from_endpoint, runner_name) <= 0) {
        *err_code = HIBUS_EC_UNEXPECTED;
        return NULL;
    }

    if (strncasecmp (runner_name, PREFIX_PLAYER_RUNNER, LEN_PREFIX) == 0) {
        int pn = atoi (runner_name + LEN_PREFIX);

        ULOG_INFO ("Player #%d is ready now\n", pn);

        if (pn < info->nr_players) {
            fork_a_player (conn, pn + 1);
        }
        else {
            int ret_code;
            char *ret_value;

            /* all players are ready now */
            my_err_code = hibus_call_procedure_and_wait (conn,
                    from_endpoint, "getBall",
                    HIBUS_RUNNER_CMDLINE,
                    HIBUS_DEF_TIME_EXPECTED,
                    &ret_code, &ret_value);
            if (my_err_code == 0 && ret_code == HIBUS_SC_OK) {
                ULOG_INFO ("The ball content:\n%s\n", ret_value);
            }

            my_err_code = hibus_fire_event (conn, "GameOver", "Ok");
            if (my_err_code) {
                ULOG_ERR ("Failed to fire event `GameOver`\n");
            }

            term_drum_game (conn);
        }

        *err_code = 0;
        return strdup ("Ok");
    }

    *err_code = HIBUS_EC_UNEXPECTED;
    return NULL;
}

int start_drum_game (hibus_conn* conn, int nr_players, const char* ball_content)
{
    int err_code;
    struct run_info *info = hibus_conn_get_user_data (conn);

    if ((err_code = hibus_register_event (conn, "GameOver",
                    HIBUS_LOCALHOST, HIBUS_APP_HIBUS))) {
        ULOG_ERR ("Failed to register event `GameOver` (%d): %s\n",
                err_code, hibus_get_err_message (err_code));
        return -1;
    }

    if ((err_code = hibus_register_procedure (conn, "notifyReady",
            HIBUS_LOCALHOST, HIBUS_APP_HIBUS, on_method_notify_ready))) {
        ULOG_ERR ("Failed to register procedure `notifyReady` (%d): %s\n",
                err_code, hibus_get_err_message (err_code));
        return -1;
    }

    if ((err_code = hibus_register_procedure (conn, "getBall",
            HIBUS_LOCALHOST, HIBUS_APP_HIBUS, on_method_get_ball))) {
        ULOG_ERR ("Failed to register procedure `getBall` (%d): %s\n",
                err_code, hibus_get_err_message (err_code));
        return -1;
    }

    if (nr_players < 2) {
        nr_players = 2;
    }

    info->nr_players = nr_players;
    info->ball_content = strdup (ball_content);

    fork_a_player (conn, 0);
    return 0;
}

