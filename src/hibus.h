/*
** hibus.h -- The code for hiBus library.
**
** Copyright (c) 2020 FMSoft (http://www.fmsoft.cn)
**
** Author: Vincent Wei (https://github.com/VincentWei)
**
** This file is part of hiBus.
**
** hiBus is free software: you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.
**
** hiBus is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** You should have received a copy of the GNU Lesser General Public License
** along with this program.  If not, see http://www.gnu.org/licenses/.
*/

#ifndef _HIBUS_H_
#define _HIBUS_H_

#include <hibox/json.h>

/* Contants */

#define HIBUS_US                        "/var/run/hibus.sock"
#define HIBUS_WS_PORT                   7700
#define HIBUS_WS_PORT_RESERVED          7701

#define HIBUS_LOCALHOST                 "localhost"
#define HIBUS_APP_SELF                  "self"
#define HIBUS_APP_HIBUS                 "cn.fmsoft.hybridos.hibus"
#define HIBUS_RUNNER_BUILITIN           "builtin"

/* Status Codes and Status Messages */
#define HIBUS_SC_OK                     200
#define HIBUS_SM_OK                     "Ok"

#define HIBUS_SC_ACCEPTED               202
#define HIBUS_SM_ACCEPTED               "Accepted"

#define HIBUS_SC_BAD_REQUEST            400
#define HIBUS_SM_BAD_REQUEST            "Bad Request"

#define HIBUS_SC_UNAUTHORIZED           401
#define HIBUS_SM_UNAUTHORIZED           "Unauthorized"

#define HIBUS_SC_FORBIDDEN              403
#define HIBUS_SM_FORBIDDEN              "Forbidden"

#define HIBUS_SC_NOT_FOUND              404
#define HIBUS_SM_NOT_FOUND              "Not Found"

#define HIBUS_SC_METHOD_NOT_ALLOWED     405
#define HIBUS_SM_METHOD_NOT_ALLOWED     "Method Not Allowed"

#define HIBUS_SC_NOT_ACCEPTABLE         406
#define HIBUS_SM_NOT_ACCEPTABLE         "Not Acceptable"

#define HIBUS_SC_CONFILCT               409
#define HIBUS_SM_CONFILCT               "Confilct"

#define HIBUS_SC_LOCKED                 423
#define HIBUS_SM_LOCKED                 "Locked"

#define HIBUS_SC_INTERNAL_SERVER_ERROR  500
#define HIBUS_SM_INTERNAL_SERVER_ERROR  "Internal Server Error"

#define HIBUS_SC_NOT_IMPLEMENTED        501
#define HIBUS_SM_NOT_IMPLEMENTED        "Not Implemented"

#define HIBUS_SC_BAD_GATEWAY            502
#define HIBUS_SM_BAD_GATEWAY            "Bad Gateway"

#define HIBUS_SC_SERVICE_UNAVAILABLE    503
#define HIBUS_SM_SERVICE_UNAVAILABLE    "Service Unavailable"

#define HIBUS_SC_GATEWAY_TIMEOUT        504
#define HIBUS_SM_GATEWAY_TIMEOUT        "Gateway Timeout"

#define HIBUS_SC_INSUFFICIENT_STORAGE   507
#define HIBUS_SM_INSUFFICIENT_STORAGE   "Insufficient Storage"

struct _hibus_conn;
typedef struct _hibus_conn hibus_conn;

typedef struct json_object hibus_json;

#ifdef __cplusplus
extern "C" {
#endif

int hibus_connect_via_unix_socket (const char* path_to_socket, const char* runner_name, hibus_conn** conn);
int hibus_connect_via_web_socket (const char* host_name, int port, const char* runner_name, hibus_conn** conn);
int hibus_disconnect (hibus_conn* conn);

const char* hibus_conn_host_name (hibus_conn* conn);
const char* hibus_conn_app_name (hibus_conn* conn);
const char* hibus_conn_runner_name (hibus_conn* conn);
int hibus_conn_socket_fd (hibus_conn* conn);

#define LEN_HOST_NAME       127
#define LEN_APP_NAME        127
#define LEN_MODULE_NAME     64
#define LEN_METHOD_NAME     64
#define LEN_BUBBLE_NAME     64

int hibus_get_host_name (const char* endpoint, char* buff);
int hibus_get_app_name (const char* endpoint, char* buff);
int hibus_get_runner_name (const char* endpoint, char* buff);

char* hibus_get_host_name_alloc (const char* endpoint);
char* hibus_get_app_name_alloc (const char* endpoint);
char* hibus_get_runner_name_alloc (const char* endpoint);

int hibus_assembly_endpoint (const char* host_name, const char* app_name,
        const char* runner_name, char* buff);

char* hibus_assembly_endpoint_alloc (const char* host_name, const char* app_name,
        const char* runner_name);


typedef hibus_json* (*hibus_method_handler)(hibus_conn* conn,
        const char* from_endpoint, const char* method_name,
        const hibus_json* method_param);

int hibus_register_procedure (hibus_conn* conn, const char* method_name,
        hibus_method_handler method_handler);
int hibus_revoke_procedure (hibus_conn* conn, const char* method_name);

int hibus_register_event (hibus_conn* conn, const char* bubble_name,
        const char* to_host, const char* to_app);
int hibus_revoke_event (hibus_conn* conn, const char* bubble_name);
int hibus_fire_event (hibus_conn* conn,
        const char* bubble_name, const hibus_json* bubble_data);

typedef void (*hibus_event_handler)(hibus_conn* conn,
        const char* from_endpoint, const char* bubble_name,
        const hibus_json* bubble_data);

int hibus_subscribe_event (hibus_conn* conn,
        const char* endpoint, const char* bubble_name,
        hibus_event_handler event_handler);

int hibus_unsubscribe_event (hibus_conn* conn,
        const char* endpoint, const char* bubble_name);

typedef void (*hibus_result_handler)(hibus_conn* conn,
        const char* from_endpoint, const char* method_name,
        int ret_code, const hibus_json* ret_value);

int hibus_call_procedure (hibus_conn* conn, const char* endpoint, const char* method_name,
        const hibus_json* method_praram, time_t ret_time_expected, hibus_result_handler result_handler);

int hibus_call_procedure_and_wait (hibus_conn* conn, const char* endpoint, const char* method_name,
        const hibus_json* method_praram, time_t ret_time_expected, hibus_json** ret_value);

#ifdef __cplusplus
}
#endif

#endif /* !_HIBUS_H_ */

