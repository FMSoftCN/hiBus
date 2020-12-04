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
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <hibox/ulog.h>

#include "hibus.h"

int main (int argc, char **argv)
{
    int nr_loops = 20;
    int fd;
    hibus_conn* conn;

    ulog_open (-1, -1, "hiBusCL");

    fd = hibus_connect_via_unix_socket (HIBUS_US_PATH,
            HIBUS_APP_HIBUS, HIBUS_RUNNER_CMDLINE, &conn);

    ULOG_NOTE ("fd (%d)\n", fd);

    while (nr_loops--) {
        fd_set rfds;
        struct timeval tv;
        int retval;
        char* packet;
        unsigned int data_len;

        FD_ZERO (&rfds);
        FD_SET (fd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 500 * 1000;
        retval = select (fd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            ULOG_ERR ("Failed to call select(): %s\n", strerror (errno));
            break;
        }
        else if (retval) {
            packet = hibus_read_packet_alloc (conn, &data_len);

            if (packet == NULL) {
                ULOG_ERR ("Failed to read packet\n");
                break;
            }
            else {
                ULOG_INFO ("got a packet (%u long):\n%s\n", data_len, packet);
            }

            free (packet);
        }
        else {
            ULOG_INFO ("Timeout\n");
        }
    }

    hibus_disconnect (conn);

    ulog_close ();

    return 0;
}

