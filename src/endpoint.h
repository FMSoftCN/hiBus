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

#include <stdbool.h>

#include <hibox/avl.h>
#include <hibox/kvlist.h>
#include <hibox/safe_list.h>
#include <hibox/list.h>

#include "hibus.h"
#include "server.h"

BusEndpoint* new_endpoint (BusServer* bus_srv, int type, void* client);

/* causes to delete endpoint */
enum {
    CDE_INITIALIZING,
    CDE_EXITING,
    CDE_LOST_CONNECTION,
    CDE_NOT_RESPONDING,
};

int del_endpoint (BusServer* bus_srv, BusEndpoint* endpoint, int cause);

int send_challenge_code (BusServer* bus_srv, BusEndpoint* endpoint);
int handle_json_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const char* json, unsigned int len);

typedef char* (*method_handler) (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code);

typedef struct _pattern_list {
    struct list_head list;
    int nr_patterns;
} pattern_list;

/* Method information */
typedef struct method_info_
{
    pattern_list host_patt_list;
    pattern_list app_patt_list;

    method_handler handler;

    /* All pending calls sent to this endpoint */
    struct safe_list pending_calls;
} method_info;

/* Bubble information */
typedef struct bubble_info_
{
    pattern_list host_patt_list;
    pattern_list app_patt_list;

    /* All subscribers of this bubble */
    struct kvlist subscriber_list;
} bubble_info;

/* allowed pattern: `*, $owner, xxx?, yyy*, !aaa*` */
pattern_list *create_pattern_list (const char* pattern);
void destroy_pattern_list (pattern_list *pl);

bool init_pattern_list (pattern_list *pl, const char* pattern);
void cleanup_pattern_list (pattern_list *pl);

bool match_pattern (pattern_list *pl, const char* string,
        int nr_vars, ...);

int register_procedure (BusEndpoint* endpoint, const char* method_name,
        const char* for_host, const char* for_app, method_handler handler);
int revoke_procedure (BusEndpoint* endpoint, const char* method_name);

int register_event (BusEndpoint* endpoint, const char* bubble_name,
        const char* for_host, const char* for_app);
int revoke_event (BusEndpoint* endpoint, const char* bubble_name);

int subscribe_event (BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint *subscrber);
int unsubscribe_event (BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint *subscrber);

bool init_builtin_endpoint (BusEndpoint* builtin_endpoint);

/* system bubble types */
enum {
    SBT_NEW_ENDPOINT,
    SBT_BROKEN_ENDPOINT,
    SBT_LOST_EVENT_GENERATOR,
};

bool fire_system_event (BusServer* bus_srv, int bubble_type,
        BusEndpoint* cause, BusEndpoint* to, const char* add_msg);

typedef struct pending_call_ {
	struct safe_list list;

    BusEndpoint* from_endpoint;
    const char* method_name;
    const hibus_json* method_param;

    struct timeval queued_time;
} pending_call;

static inline int
assemble_endpoint_name (BusEndpoint *endpoint, char *buff)
{
    if (endpoint->host_name && endpoint->app_name && endpoint->runner_name) {
        return hibus_assemble_endpoint_name (endpoint->host_name,
                endpoint->app_name, endpoint->runner_name, buff);
    }

    return 0;
}

#endif /* !_HIBUS_ENDPOINT_H_ */

