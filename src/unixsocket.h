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

typedef enum USOPCODE
{
  US_OPCODE_CONTINUATION = 0x00,
  US_OPCODE_TEXT = 0x01,
  US_OPCODE_BIN = 0x02,
  US_OPCODE_END = 0x03,
  US_OPCODE_PING = 0x09,
  US_OPCODE_PONG = 0x0A,
  US_OPCODE_CLOSE = 0x08,
} USOpcode;

/* A UnixSocket Client */
typedef struct USClient_
{
    int type;
    int fd;                         /* UNIX socket FD */
    pid_t pid;                      /* client PID */
} USClient;

/* The UnixSocket Server */
typedef struct USServer_
{
    int listener;
    int nr_clients;

    /* Callbacks */
    int (*on_conn) (struct USServer_* server, USClient* client);
    int (*on_data) (struct USServer_* server, USClient* client,
            const char* payload, size_t payload_sz);
    int (*on_close) (struct USServer_* server, USClient* client);

    const ServerConfig* config;
} USServer;

typedef struct USFrameHeader_ {
    int type;
    size_t payload_len;
    unsigned char payload[0];
} USFrameHeader;

USServer *us_init (const ServerConfig* config);
int us_listen (USServer* server);
USClient *us_handle_accept (USServer *server, int listener);
int us_handle_reads (USServer *server, USClient* us_client);
int us_client_cleanup (USServer* server, USClient* us_client);

int us_ping_client (USServer* server, USClient* us_client);
int us_send_data (USServer* server, USClient* us_client,
        USOpcode op, const char *data, int sz);

#endif // for #ifndef _HIBUS_UNIXSOCKET_H

