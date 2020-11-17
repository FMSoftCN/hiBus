/*
** libhibus.c -- The code for hiBus client.
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
#include <hibox/md5.h>

#include "hibus.h"

struct _hibus_conn {
    char* srv_host_name;
    char* own_host_name;
    char* app_name;
    char* runner_name;

    int fd;
};

#define CLI_PATH    "/var/tmp/"
#define CLI_PERM    S_IRWXU

/* returns fd if all OK, -1 on error */
int hibus_connect_via_unix_socket (const char* path_to_socket,
        const char* app_name, const char* runner_name, hibus_conn** conn)
{
    int fd, len;
    struct sockaddr_un unix_addr;
    char md5_digest[17];

    /* create a Unix domain stream socket */
    if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ULOG_ERR ("Failed to call `socket` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        return (-1);
    }

    {
        md5_ctx_t ctx;

        md5_begin (&ctx);
        md5_hash (app_name, strlen (app_name), &ctx);
        md5_hash (runner_name, strlen (runner_name), &ctx);
        md5_end (md5_digest, &ctx);
    }

    /* fill socket address structure w/our address */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    /* On Linux sun_path is 108 bytes in size */
    sprintf (unix_addr.sun_path, "%s%s-%05d", CLI_PATH, md5_digest, getpid());
    len = sizeof(unix_addr.sun_family) + strlen (unix_addr.sun_path);

    ULOG_INFO("The client addres: %s\n", unix_addr.sun_path);

    unlink (unix_addr.sun_path);        /* in case it already exists */
    if (bind (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        ULOG_ERR ("Failed to call `bind` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }
    if (chmod (unix_addr.sun_path, CLI_PERM) < 0) {
        ULOG_ERR ("Failed to call `chmod` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }

    /* fill socket address structure w/server's addr */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy (unix_addr.sun_path, path_to_socket);
    len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path);

    if (connect (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        ULOG_ERR ("Failed to call `connect` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }

    return (fd);

error:
    close (fd);
    return (-1);
}

int hibus_connect_via_web_socket (const char* host_name, int port,
        const char* app_name, const char* runner_name, hibus_conn** conn)
{
    return -HIBUS_SC_NOT_IMPLEMENTED;
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

