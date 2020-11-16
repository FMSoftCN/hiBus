/*
** libhibus.c -- The code for hiBus library.
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
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/time.h>
#include <hibox/ulog.h>

#include "hibus.h"

struct _hibus_conn {
    char* srv_host_name;
    char* own_host_name;
    char* app_name;
    char* runner_name;

    int fd;
};

int hibus_connect_via_unix_socket (const char* path_to_socket,
        const char* app_name, const char* runner_name, hibus_conn** conn)
{
    return HIBUS_SC_OK;
}

int hibus_connect_via_web_socket (const char* host_name, int port,
        const char* app_name, const char* runner_name, hibus_conn** conn)
{
    return HIBUS_SC_OK;
}

int hibus_disconnect (hibus_conn* conn)
{
    assert (conn);

    free (conn->srv_host_name);
    free (conn->own_host_name);
    free (conn->app_name);
    free (conn->runner_name);
    close (conn->fd);
    free (conn);

    return HIBUS_SC_OK;
}

const char* hibus_conn_srv_host_name (hibus_conn* conn)
{
    return conn->srv_host_name;
}

const char* hibus_conn_own_host_name (hibus_conn* conn)
{
    return conn->own_host_name;
}

const char* hibus_conn_app_name (hibus_conn* conn)
{
    return conn->app_name;
}

const char* hibus_conn_runner_name (hibus_conn* conn)
{
    return conn->runner_name;
}

int hibus_conn_socket_fd (hibus_conn* conn)
{
    return conn->fd;
}

