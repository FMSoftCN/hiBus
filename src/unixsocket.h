/**
 ** unixsocket.h: Utilities for Unix Domain Socket.
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

#ifndef _HIBUS_UNIXSOCKET_H
#define _HIBUS_UNIXSOCKET_H

#define TABLESIZE(table)    (sizeof(table)/sizeof(table[0]))

/* A UnixSocket Client */
typedef struct USClient_
{
    int fd;                         /* UNIX socket FD */
    pid_t pid;                      /* client PID */
} USClient;

int us_listen (const char* name);
int us_accept (int listenfd, pid_t *pidptr, uid_t *uidptr);

int us_on_connected (USClient* us_client);
int us_ping_client (const USClient* us_client);
int us_send_event (const USClient* us_client, const struct _remote_event* event);
int us_on_client_data (USClient* us_client);

#endif // for #ifndef _HIBUS_UNIXSOCKET_H
