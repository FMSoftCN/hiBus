/*
** endpoint.h -- The endpoint (event/procedure/subscriber) management.
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

#ifndef _HIBUS_ENDPOINT_H_
#define _HIBUS_ENDPOINT_H_

#include <hibox/avl.h>
#include <hibox/kvlist.h>
#include <hibox/safe_list.h>

#include "hibus.h"
#include "server.h"

BusEndpoint* new_endpoint (BusServer* the_server, int type, void* client);
int del_endpoint (BusServer* the_server, BusEndpoint* endpoint);

int send_challenge_code (BusServer* the_server, BusEndpoint* endpoint);
int handle_json_packet (BusServer* the_server, BusEndpoint* endpoint,
        const char* json, unsigned int len);

typedef hibus_json* (*builtin_method_handler)(BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param);

/* Method information */
typedef struct MethodInfo_
{
    char*               for_host;
    char*               for_app;

    /* only not null for built-in methods */
    builtin_method_handler handler;
} MethodInfo;

/* Bubble information */
typedef struct BubbleInfo_
{
    char* for_host;
    char* for_app;

    /* All subscribers of this bubble */
    struct kvlist subscriber_list;
} BubbleInfo;

int register_procedure (BusEndpoint* from_endpoint, const char* method_name,
        const char* for_host, const char* for_app, builtin_method_handler handler);
int revoke_procedure (BusEndpoint* from_endpoint, const char* method_name);

int register_event (BusEndpoint* from_endpoint, const char* bubble_name,
        const char* for_host, const char* for_app);

int revoke_event (BusEndpoint* from_endpoint, const char* bubble_name);

int subscribe_event (BusEndpoint* from_endpoint, const char* event_name);
int unsubscribe_event (BusEndpoint* from_endpoint, const char* event_name);

typedef struct PendingCall_ {
	struct safe_list list;

    BusEndpoint* from_endpoint;
    const char* method_name;
    const hibus_json* method_param;

    struct timeval queued_time;
} PendingCall;

static inline int
assemble_endpoint_name (BusEndpoint *endpoint, char *buff)
{
    if (endpoint->host_name && endpoint->app_name && endpoint->runner_name) {
        return hibus_assemble_endpoint (endpoint->host_name,
                endpoint->app_name, endpoint->runner_name, buff);
    }

    return 0;
}

#endif /* !_HIBUS_ENDPOINT_H_ */

