/*
** server.h -- The internal interface for hibus server.
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

#ifndef _HIBUS_SERVER_H_
#define _HIBUS_SERVER_H_

#include <hibox/gslist.h>

#include "hibus.h"

#define MAX_WS_CLIENTS  10

/* A hiBus Client */
typedef struct BusClient_
{
    int     socket_type;
    void*   socket_client;
    char*   host_name;
    char*   app_name;
    char*   runner_name;
} HBClient;

/* Config Options */
typedef struct ServerConfig_
{
  /* Config Options */
  const char *accesslog;
  const char *host;
  const char *origin;
  const char *unixsocket;
  const char *port;
  const char *sslcert;
  const char *sslkey;
  int echomode;
  int max_frm_size;
  int use_ssl;
} ServerConfig;

void srv_set_config_accesslog (const char *accesslog);
void srv_set_config_echomode (int echomode);
void srv_set_config_frame_size (int max_frm_size);
void srv_set_config_host (const char *host);
void srv_set_config_origin (const char *origin);
void srv_set_config_unixsocket (const char *unixsocket);
void srv_set_config_port (const char* port);
void srv_set_config_sslcert (const char *sslcert);
void srv_set_config_sslkey (const char *sslkey);

#endif /* !_HIBUS_SERVER_H_*/

