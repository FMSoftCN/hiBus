/*
** builtin-endpoint.c -- The implemetation of the builtin endpoint.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <hibox/ulog.h>
#include <hibox/sha256.h>
#include <hibox/hmac.h>
#include <hibox/json.h>

#include "hibus.h"
#include "endpoint.h"
#include "unixsocket.h"
#include "websocket.h"

static char *
default_method_handler (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    char buff_in_stack [HIBUS_DEF_PACKET_BUFF_SIZE];
    int n = 0;
    char* packet_buff = buff_in_stack;
    const CallInfo *call_info = from->sta_data;
    size_t len_param = strlen (method_param) * 2 + 1;
    size_t sz_packet_buff = sizeof (buff_in_stack);
    char* escaped_param;

    if (len_param > HIBUS_MIN_PACKET_BUFF_SIZE) {
        sz_packet_buff = HIBUS_MIN_PACKET_BUFF_SIZE + len_param;
        packet_buff = malloc (HIBUS_MIN_PACKET_BUFF_SIZE + len_param);
        if (packet_buff == NULL) {
            *ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
            return NULL;
	    }
    }

    if (method_param)
        escaped_param = hibus_escape_string_for_json (method_param);
    else
        escaped_param = NULL;

    n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"call\","
            "\"callId\":\"%s\","
            "\"resultId\":\"%s\","
            "\"fromEndpoint\":\"@%s/%s/%s\","
            "\"toMethod\":\"%s\","
            "\"timeDiff\":%.9f,"
            "\"parameter\":\"%s\""
            "}",
            call_info->call_id, call_info->result_id,
            from->host_name, from->app_name, from->runner_name,
            method_name,
            call_info->time_diff,
            escaped_param ? escaped_param : "");

    if (escaped_param)
        free (escaped_param);

    if (n >= sz_packet_buff) {
        ULOG_ERR ("The size of buffer for call packet is too small.\n");
        *ret_code = HIBUS_SC_INTERNAL_SERVER_ERROR;
    }
    else {
        if (send_packet_to_endpoint (bus_srv, to, packet_buff, n)) {
            *ret_code = HIBUS_SC_BAD_CALLEE;
        }
        else {
            *ret_code = HIBUS_SC_ACCEPTED;
        }
    }

    if (packet_buff != NULL && packet_buff != buff_in_stack) {
        free (packet_buff);
    }

    return NULL;
}

static char *
builtin_method_echo (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "echo") == 0);

    *ret_code = HIBUS_SC_OK;

    if (method_param) {
        return strdup (method_param);
    }

    return strdup ("ARE YOU JOKING ME?");
}

static char *
builtin_method_register_procedure (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_method_name, *param_for_host, *param_for_app;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "registerProcedure") == 0);

    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "methodName", &jo_tmp) &&
        (param_method_name = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "forHost", &jo_tmp) &&
        (param_for_host = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "forApp", &jo_tmp) &&
        (param_for_app = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = register_procedure (bus_srv, from,
            param_method_name, param_for_host, param_for_app,
            default_method_handler);
    json_object_put (jo);

    return NULL;

failed:
    if (jo)
        json_object_put (jo);

    *ret_code = HIBUS_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_revoke_procedure (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_method_name;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "revokeProcedure") == 0);

    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "methodName", &jo_tmp) &&
        (param_method_name = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = revoke_procedure (bus_srv, from, param_method_name);
    json_object_put (jo);
    return NULL;

failed:
    if (jo)
        json_object_put (jo);
    *ret_code = HIBUS_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_register_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_bubble_name, *param_for_host, *param_for_app;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "registerEvent") == 0);

    ULOG_INFO ("parameter: %s\n", method_param);

    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "bubbleName", &jo_tmp) &&
        (param_bubble_name = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "forHost", &jo_tmp) &&
        (param_for_host = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "forApp", &jo_tmp) &&
        (param_for_app = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = register_event (bus_srv, from,
            param_bubble_name, param_for_host, param_for_app);
    json_object_put (jo);
    return NULL;

failed:
    if (jo)
        json_object_put (jo);

    *ret_code = HIBUS_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_revoke_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_bubble_name;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "revokeEvent") == 0);

    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "bubbleName", &jo_tmp) &&
        (param_bubble_name = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = revoke_event (bus_srv, from, param_bubble_name);
    json_object_put (jo);
    return NULL;

failed:
    if (jo)
        json_object_put (jo);

    *ret_code = HIBUS_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_subscribe_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_endpoint_name, *param_bubble_name;
    BusEndpoint* target_endpoint = NULL;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "subscribeEvent") == 0);

    *ret_code = HIBUS_SC_BAD_REQUEST;

    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "endpointName", &jo_tmp) &&
        (param_endpoint_name = json_object_get_string (jo_tmp))) {
        void *data;
        char normalized_name [HIBUS_LEN_ENDPOINT_NAME + 1];

        hibus_name_tolower_copy (param_endpoint_name, normalized_name,
                HIBUS_LEN_ENDPOINT_NAME);
        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            target_endpoint = *(BusEndpoint **)data;
        }
        else {
            *ret_code = HIBUS_SC_NOT_FOUND;
            goto failed;
        }
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "bubbleName", &jo_tmp) &&
        (param_bubble_name = json_object_get_string (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = subscribe_event (bus_srv, target_endpoint, param_bubble_name, from);
    json_object_put (jo);
    return NULL;

failed:
    if (jo)
        json_object_put (jo);

    return NULL;
}

static char *
builtin_method_unsubscribe_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_endpoint_name, *param_bubble_name;
    BusEndpoint* target_endpoint = NULL;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "unsubscribeEvent") == 0);

    *ret_code = HIBUS_SC_BAD_REQUEST;

    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "endpointName", &jo_tmp) &&
            (param_endpoint_name = json_object_get_string (jo_tmp))) {
        void *data;
        char normalized_name [HIBUS_LEN_ENDPOINT_NAME + 1];

        hibus_name_tolower_copy (param_endpoint_name, normalized_name,
                HIBUS_LEN_ENDPOINT_NAME);
        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            target_endpoint = *(BusEndpoint **)data;
        }
        else {
            ULOG_ERR ("No such endpoint: %s\n", normalized_name);
            *ret_code = HIBUS_SC_NOT_FOUND;
            goto failed;
        }
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "bubbleName", &jo_tmp) &&
            (param_bubble_name = json_object_get_string (jo_tmp))) {
    }
    else {
        *ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    *ret_code = unsubscribe_event (bus_srv, target_endpoint,
            param_bubble_name, from);
    json_object_put (jo);
    return NULL;

failed:
    if (jo)
        json_object_put (jo);

    return NULL;
}

static char *
builtin_method_list_endpoints (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    struct printbuf my_buff, *pb = &my_buff;
    const char *endpoint_name;
    void *data;
    int nr_endpoints;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "listEndpoints") == 0);

	if (printbuf_init (pb)) {
        *ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
		return NULL;
	}

    printbuf_strappend (pb, "[");

    nr_endpoints = 0;
    kvlist_for_each (&bus_srv->endpoint_list, endpoint_name, data) {
        const char *sub_name;
        void *sub_data;
        BusEndpoint* endpoint = *(BusEndpoint **)data;
        int n;

        printbuf_strappend (pb, "{\"endpointName\":");
        sprintbuf (pb, "\"%s\",", endpoint_name);
        sprintbuf (pb, "\"livingSeconds\":%lu,",
                time (NULL) - endpoint->t_created);

        n = 0;
        printbuf_strappend (pb, "\"methods\":[");
        kvlist_for_each (&endpoint->method_list, sub_name, sub_data) {
            sprintbuf (pb, "\"%s\",", sub_name);
            n++;
        }
        if (n > 0)
            printbuf_shrink (pb, 1);
        printbuf_strappend (pb, "],");

        n = 0;
        printbuf_strappend (pb, "\"bubbles\":[");
        kvlist_for_each (&endpoint->bubble_list, sub_name, sub_data) {
            sprintbuf (pb, "\"%s\",", sub_name);
            n++;
        }
        if (n > 0)
            printbuf_shrink (pb, 1);
        printbuf_strappend (pb, "],");

        sprintbuf (pb, "\"memUsed\":%lu,", endpoint->entity.sz_sock_mem);
        sprintbuf (pb, "\"peakMemUsed\":%lu", endpoint->entity.peak_sz_sock_mem);
        printbuf_strappend (pb, "},");
        nr_endpoints++;
    }
    if (nr_endpoints)
        printbuf_shrink (pb, 1);

    printbuf_strappend (pb, "]");

    *ret_code = HIBUS_SC_OK;
    return pb->buf;
}

static char *
builtin_method_list_procedures (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    struct printbuf my_buff, *pb = &my_buff;
    const char *endpoint_name;
    void *data;
    int n;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "listProcedures") == 0);

	if (printbuf_init (pb)) {
        *ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
		return NULL;
	}

    n = 0;
    printbuf_strappend (pb, "[");
    if (hibus_is_valid_endpoint_name (method_param)) {
        char normalized_name [HIBUS_LEN_ENDPOINT_NAME + 1];

        hibus_name_tolower_copy (method_param, normalized_name,
                HIBUS_LEN_ENDPOINT_NAME);

        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            const char *method_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            printbuf_strappend (pb, "{\"endpointName\":");
            sprintbuf (pb, "\"%s\",", normalized_name);

            printbuf_strappend (pb, "\"methods\": [");
            kvlist_for_each (&endpoint->method_list, method_name, sub_data) {
                MethodInfo *method_info = *(MethodInfo **)sub_data;

                if (match_pattern (&method_info->host_patt_list, from->host_name,
                            1, HIBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&method_info->app_patt_list, from->app_name,
                            1, HIBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    printbuf_strappend (pb, "\"");
                    printbuf_memappend (pb, method_name, 0);
                    printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                printbuf_shrink (pb, 1);
            }
            printbuf_strappend (pb, "]}");
        }
    }
    else {
        kvlist_for_each (&bus_srv->endpoint_list, endpoint_name, data) {
            const char *method_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            printbuf_strappend (pb, "{\"endpointName\":");
            sprintbuf (pb, "\"%s\",", endpoint_name);

            printbuf_strappend (pb, "\"methods\": [");
            kvlist_for_each (&endpoint->method_list, method_name, sub_data) {
                MethodInfo *method_info = *(MethodInfo **)sub_data;

                if (match_pattern (&method_info->host_patt_list, from->host_name,
                            1, HIBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&method_info->app_patt_list, from->app_name,
                            1, HIBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    printbuf_strappend (pb, "\"");
                    printbuf_memappend (pb, method_name, 0);
                    printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                printbuf_shrink (pb, 1);
            }
            printbuf_strappend (pb, "]},");

            n++;
        }
    }

    if (n > 0) {
        printbuf_shrink (pb, 1);
    }
    printbuf_strappend (pb, "]");

    *ret_code = HIBUS_SC_OK;
    return pb->buf;
}

static char *
builtin_method_list_events (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    struct printbuf my_buff, *pb = &my_buff;
    const char *endpoint_name;
    void *data;
    int n;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "listEvents") == 0);

	if (printbuf_init (pb)) {
        *ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
		return NULL;
	}

    n = 0;
    printbuf_strappend (pb, "[");
    if (hibus_is_valid_endpoint_name (method_param)) {
        char normalized_name [HIBUS_LEN_ENDPOINT_NAME + 1];

        hibus_name_tolower_copy (method_param, normalized_name,
                HIBUS_LEN_ENDPOINT_NAME);

        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            const char *bubble_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            printbuf_strappend (pb, "{\"endpointName\":");
            sprintbuf (pb, "\"%s\",", normalized_name);

            printbuf_strappend (pb, "\"bubbles\": [");
            kvlist_for_each (&endpoint->bubble_list, bubble_name, sub_data) {
                BubbleInfo *bubble_info = *(BubbleInfo **)sub_data;

                if (match_pattern (&bubble_info->host_patt_list, from->host_name,
                            1, HIBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&bubble_info->app_patt_list, from->app_name,
                            1, HIBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    printbuf_strappend (pb, "\"");
                    printbuf_memappend (pb, bubble_name, 0);
                    printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                printbuf_shrink (pb, 1);
            }
            printbuf_strappend (pb, "]}");
        }
    }
    else {
        kvlist_for_each (&bus_srv->endpoint_list, endpoint_name, data) {
            const char *bubble_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            printbuf_strappend (pb, "{\"endpointName\":");
            sprintbuf (pb, "\"%s\",", endpoint_name);

            printbuf_strappend (pb, "\"bubbles\": [");
            kvlist_for_each (&endpoint->bubble_list, bubble_name, sub_data) {
                BubbleInfo *bubble_info = *(BubbleInfo **)sub_data;

                if (match_pattern (&bubble_info->host_patt_list, from->host_name,
                            1, HIBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&bubble_info->app_patt_list, from->app_name,
                            1, HIBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    printbuf_strappend (pb, "\"");
                    printbuf_memappend (pb, bubble_name, 0);
                    printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                printbuf_shrink (pb, 1);
            }
            printbuf_strappend (pb, "]},");

            n++;
        }
    }

    if (n > 0) {
        printbuf_shrink (pb, 1);
    }
    printbuf_strappend (pb, "]");

    *ret_code = HIBUS_SC_OK;
    return pb->buf;
}

static char *
builtin_method_list_event_subscribers (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    hibus_json *jo = NULL, *jo_tmp;
    const char *param_endpoint_name, *param_bubble_name;
    BusEndpoint *target_endpoint = NULL;
    BubbleInfo *bubble = NULL;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, "listEventSubscribers") == 0);

    struct printbuf my_buff, *pb = &my_buff;

	if (printbuf_init (pb)) {
        *ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
		return NULL;
	}

    *ret_code = HIBUS_SC_BAD_REQUEST;
    jo = hibus_json_object_from_string (method_param, strlen (method_param), 2);
    if (jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "endpointName", &jo_tmp) &&
        (param_endpoint_name = json_object_get_string (jo_tmp))) {
        void *data;
        char normalized_name [HIBUS_LEN_ENDPOINT_NAME + 1];

        hibus_name_tolower_copy (param_endpoint_name, normalized_name,
                HIBUS_LEN_ENDPOINT_NAME);
        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            target_endpoint = *(BusEndpoint **)data;
        }
        else {
            *ret_code = HIBUS_SC_NOT_FOUND;
            goto failed;
        }
    }
    else {
        goto failed;
    }

    if (json_object_object_get_ex (jo, "bubbleName", &jo_tmp) &&
            (param_bubble_name = json_object_get_string (jo_tmp))) {
        void *data;
        char normalized_name [HIBUS_LEN_BUBBLE_NAME + 1];

        hibus_name_toupper_copy (param_bubble_name, normalized_name, HIBUS_LEN_BUBBLE_NAME);

        if ((data = kvlist_get (&target_endpoint->bubble_list, normalized_name))) {
            bubble = *(BubbleInfo **)data;
        }
    }

    if (jo)
        json_object_put (jo);

    if (bubble) {
        const char* name;
        void* data;
        int n;

        printbuf_strappend (pb, "[");

        n = 0;
        kvlist_for_each (&bubble->subscriber_list, name, data) {
            void *sub_data = kvlist_get (&bus_srv->endpoint_list, name);

            if (sub_data) {
                printbuf_strappend (pb, "\"");
                printbuf_memappend (pb, name, 0);
                printbuf_strappend (pb, "\",");
            }

            n++;
        }
        if (n > 0) {
            printbuf_shrink (pb, 1);
        }

        printbuf_strappend (pb, "]");

        *ret_code = HIBUS_SC_OK;
        return pb->buf;
    }
    else {
        *ret_code = HIBUS_SC_NOT_FOUND;
    }

    return NULL;

failed:
    if (jo)
        json_object_put (jo);

    return NULL;
}

bool init_builtin_endpoint (BusServer *bus_srv, BusEndpoint* builtin)
{
    if (register_procedure (bus_srv, builtin, "echo",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_echo) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "registerProcedure",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_register_procedure) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "revokeProcedure",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_revoke_procedure) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "registerEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_register_event) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "revokeEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_revoke_event) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "subscribeEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_subscribe_event) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "unsubscribeEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_unsubscribe_event) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "listEndpoints",
            HIBUS_PATTERN_ANY, HIBUS_APP_HIBUS,
            builtin_method_list_endpoints) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "listProcedures",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_list_procedures) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "listEvents",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_list_events) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, "listEventSubscribers",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_list_event_subscribers) != HIBUS_SC_OK) {
        return false;
    }

    if (register_event (bus_srv, builtin, "NEWENDPOINT",
            HIBUS_PATTERN_ANY, HIBUS_SYS_APPS) != HIBUS_SC_OK) {
        return false;
    }

    if (register_event (bus_srv, builtin, "BROKENENDPOINT",
            HIBUS_PATTERN_ANY, HIBUS_SYS_APPS) != HIBUS_SC_OK) {
        return false;
    }

    ULOG_INFO ("The builtin procedures and events have been registered.\n");

    return true;
}

bool fire_system_event (BusServer* bus_srv, int bubble_type,
        BusEndpoint* cause, BusEndpoint* to, const char* add_msg)
{
    const char* bubble_name;
    int n = 0;
    char packet_buff [HIBUS_DEF_PACKET_BUFF_SIZE];
    char bubble_data [HIBUS_MIN_PACKET_BUFF_SIZE];
    char* escaped_bubble_data = NULL;

    if (bubble_type == SBT_NEW_ENDPOINT) {
        char peer_info [INET6_ADDRSTRLEN] = "";

        if (cause->type == ET_UNIX_SOCKET) {
            USClient* usc = (USClient *)cause->entity.client;
            snprintf (peer_info, sizeof (peer_info), "%d", usc->pid);
        }
        else {
            WSClient* wsc = (WSClient *)cause->entity.client;
            strncpy (peer_info, wsc->remote_ip, sizeof (wsc->remote_ip));
        }

        n = snprintf (bubble_data, sizeof (bubble_data), 
                "{"
                "\"endpointType\":\"%s\","
                "\"endpointName\":\"@%s/%s/%s\","
                "\"peerInfo\":\"%s\","
                "\"totalEndpoints\":%d"
                "}",
                (cause->type == ET_UNIX_SOCKET) ? "unix" : "web",
                cause->host_name, cause->app_name, cause->runner_name,
                peer_info,
                bus_srv->nr_endpoints);
        bubble_name = "NEWENDPOINT";
    }
    else if (bubble_type == SBT_BROKEN_ENDPOINT) {
#if 0
        char peer_info [INET6_ADDRSTRLEN] = "";

        if (cause->type == ET_UNIX_SOCKET) {
            USClient* usc = (USClient *)cause->entity.client;
            snprintf (peer_info, sizeof (peer_info), "%d", usc->pid);
        }
        else {
            WSClient* wsc = (WSClient *)cause->entity.client;
            strncpy (peer_info, wsc->remote_ip, sizeof (wsc->remote_ip));
        }
#else
        const char *peer_info  = "N/A";
#endif

        n = snprintf (bubble_data, sizeof (bubble_data), 
                "{"
                "\"endpointType\":\"%s\","
                "\"endpointName\":\"@%s/%s/%s\","
                "\"peerInfo\":\"%s\","
                "\"brokenReason\":\"%s\","
                "\"totalEndpoints\":%d"
                "}",
                (cause->type == ET_UNIX_SOCKET) ? "unix" : "web",
                cause->host_name, cause->app_name, cause->runner_name,
                peer_info, add_msg,
                bus_srv->nr_endpoints);
        bubble_name = "BROKENENDPOINT";
    }
    else if (bubble_type == SBT_LOST_EVENT_GENERATOR) {
        n = snprintf (bubble_data, sizeof (bubble_data), 
                "{"
                "\"endpointName\":\"@%s/%s/%s\","
                "}",
                cause->host_name, cause->app_name, cause->runner_name);
        bubble_name = "LOSTEVENTGENERATOR";
    }
    else if (bubble_type == SBT_LOST_EVENT_BUBBLE) {
        n = snprintf (bubble_data, sizeof (bubble_data), 
                "{"
                "\"endpointName\":\"@%s/%s/%s\","
                "\"bubbleName\":\"%s\","
                "}",
                cause->host_name, cause->app_name, cause->runner_name,
                add_msg);
        bubble_name = "LOSTEVENTBUBBLE";
    }
    else {
        return false;
    }

    if (n > 0 && n < sizeof (bubble_data)) {
        escaped_bubble_data = hibus_escape_string_for_json (bubble_data);
        if (escaped_bubble_data == NULL)
            return false;
    }
    else {
        return false;
    }

    n = snprintf (packet_buff, sizeof (packet_buff), 
        "{"
        "\"packetType\": \"event\","
        "\"eventId\": \"NOTIFICATION\","
        "\"fromEndpoint\": \"@%s/%s/%s\","
        "\"fromBubble\": \"%s\","
        "\"bubbleData\": \"%s\","
        "\"timeDiff\":0.0"
        "}",
        bus_srv->endpoint_builtin->host_name,
        bus_srv->endpoint_builtin->app_name,
        bus_srv->endpoint_builtin->runner_name,
        bubble_name,
        escaped_bubble_data);

    if (n < sizeof (packet_buff)) {
        if (to) {
            send_packet_to_endpoint (bus_srv, to, packet_buff, n);
        }
        else {
            BubbleInfo *bubble;
            const char* name;
            void *next, *data;

            data = kvlist_get (&bus_srv->endpoint_builtin->bubble_list, bubble_name);
            if (data) {
                bubble = *(BubbleInfo **)data;
            }
            else {
                goto failed;
            }

            kvlist_for_each_safe (&bubble->subscriber_list, name, next, data) {
                void *sub_data;

                sub_data = kvlist_get (&bus_srv->endpoint_list, name);

                // forward event to subscriber.
                if (sub_data) {
                    BusEndpoint* subscriber;

                    subscriber = *(BusEndpoint **)sub_data;
                    send_packet_to_endpoint (bus_srv, subscriber, packet_buff, n);
                }
                else {
                    kvlist_delete (&bubble->subscriber_list, name);
                }
            }
        }
    }
    else {
        ULOG_ERR ("The size of buffer for system event packet is too small.\n");
    }

failed:
    if (escaped_bubble_data)
        free (escaped_bubble_data);

    return true;
}

