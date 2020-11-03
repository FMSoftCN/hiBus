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
    int fd;                         /* UNIX socket FD */
    pid_t pid;                      /* client PID */
} USClient;

/* The UnixSocket Server */
typedef struct USServer_
{
    int listener;
} USServer;

typedef struct USFrameHeader_ {
    int type;
    size_t payload_len;
    unsigned char payload[0];
} USFrameHeader;

int us_listen (const char* name);
int us_accept (int listenfd, pid_t *pidptr, uid_t *uidptr);
int us_on_connected (USClient* us_client);
int us_client_cleanup (USClient* us_client);

USClient *us_handle_accept (int listener, USServer * server);
int us_ping_client (const USClient* us_client);
int us_send_data (const USClient* us_client, USOpcode op, const char *data, int sz);
int us_on_client_data (USClient* us_client);

#endif // for #ifndef _HIBUS_UNIXSOCKET_H

