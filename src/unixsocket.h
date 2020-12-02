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

#include <stdint.h>
#include <unistd.h>

/* A UnixSocket Client */
typedef struct USClient_
{
    int         type;       /* the type of the client */
    int         fd;         /* UNIX socket FD */
    pid_t       pid;        /* client PID */
    uid_t       uid;        /* client UID */

    /* fields for current packet */
    int         t_packet;   /* type of packet */
    int         padding_;
    uint32_t    sz_packet;  /* total size of current packet */
    uint32_t    sz_read;    /* read size of current packet */
    char*       packet;     /* packet data */

    void*       priv_data;  /* private data, used by the higher level */
} USClient;

/* The UnixSocket Server */
typedef struct USServer_
{
    int listener;
    int nr_clients;

    /* Callbacks */
    void (*on_failed) (struct USServer_* server, USClient* client, int ret_code);
    int (*on_accepted) (struct USServer_* server, USClient* client);
    int (*on_packet) (struct USServer_* server, USClient* client,
            const char* body, unsigned int sz_body, int type);
    int (*on_cleanup) (struct USServer_* server, USClient* client);

    const ServerConfig* config;
} USServer;

USServer *us_init (const ServerConfig* config);
void us_stop (USServer *server);

int us_listen (USServer* server);
USClient *us_handle_accept (USServer *server);
int us_handle_reads (USServer *server, USClient* us_client);
int us_client_cleanup (USServer* server, USClient* us_client);

int us_ping_client (USServer* server, USClient* us_client);
int us_send_data (USServer* server, USClient* us_client,
        USOpcode op, const char *data, int sz);

#endif // for #ifndef _HIBUS_UNIXSOCKET_H

