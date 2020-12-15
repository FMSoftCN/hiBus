/*
** endpoint.c -- The endpoint (event/procedure/subscriber) management.
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
#include <hibox/md5.h>
#include <hibox/sha256.h>
#include <hibox/hmac.h>
#include <hibox/json.h>

#include "hibus.h"
#include "endpoint.h"
#include "unixsocket.h"
#include "websocket.h"

BusEndpoint* new_endpoint (BusServer* bus_srv, int type, void* client)
{
    struct timespec ts;
    BusEndpoint* endpoint = NULL;

    endpoint = (BusEndpoint *)calloc (sizeof (BusEndpoint), 1);
    if (endpoint == NULL)
        return NULL;

    clock_gettime (CLOCK_REALTIME, &ts);
    endpoint->t_created = ts.tv_sec;
    endpoint->t_living = ts.tv_sec;

    switch (type) {
        case ET_BUILTIN:
            endpoint->type = ET_BUILTIN;
            endpoint->status = ES_READY;
            endpoint->entity.client = NULL;

            endpoint->host_name = strdup (bus_srv->server_name);
            endpoint->app_name = strdup (HIBUS_APP_HIBUS);
            endpoint->runner_name = strdup (HIBUS_RUNNER_BUILITIN);
            break;

        case ET_UNIX_SOCKET:
        case ET_WEB_SOCKET:
            endpoint->type = type;
            endpoint->status = ES_AUTHING;
            endpoint->entity.client = client;

            endpoint->host_name = NULL;
            endpoint->app_name = NULL;
            endpoint->runner_name = NULL;
            if (!store_dangling_endpoint (bus_srv, endpoint)) {
                ULOG_ERR ("Failed to store dangling endpoint\n");
                free (endpoint);
                return NULL;
            }
            break;

        default:
            ULOG_ERR ("Bad endpoint type\n");
            free (endpoint);
            return NULL;
    }

    if (type == ET_UNIX_SOCKET) {
        USClient* usc = (USClient*)client;
        usc->entity = &endpoint->entity;
    }
    else if (type == ET_WEB_SOCKET) {
        WSClient* wsc = (WSClient*)client;
        wsc->entity = &endpoint->entity;
    }

    kvlist_init (&endpoint->method_list, NULL);
    kvlist_init (&endpoint->bubble_list, NULL);

    return endpoint;
}

int del_endpoint (BusServer* bus_srv, BusEndpoint* endpoint, int cause)
{
    char endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];
    const char *method_name, *bubble_name;
    void *data;

    if (assemble_endpoint_name (endpoint, endpoint_name) > 0) {
        ULOG_INFO ("Deleting an endpoint: %s (%p)\n", endpoint_name, endpoint);
        if (cause == CDE_LOST_CONNECTION || cause == CDE_NO_RESPONDING) {
            fire_system_event (bus_srv, SBT_BROKEN_ENDPOINT, endpoint, NULL,
                    (cause == CDE_LOST_CONNECTION) ? "lostConnection" : "noResponding");
        }
    }
    else {
        strcpy (endpoint_name, "@endpoint/not/authenticated");
    }

    kvlist_for_each (&endpoint->method_list, method_name, data) {
        MethodInfo* method;

        method = *(MethodInfo **)data;
        ULOG_INFO ("Revoke procedure: @%s/%s/%s/%s (%p)\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name,
                method_name, method);
        cleanup_pattern_list (&method->host_patt_list);
        cleanup_pattern_list (&method->app_patt_list);
        free (method);
    }
    kvlist_free (&endpoint->method_list);

    kvlist_for_each (&endpoint->bubble_list, bubble_name, data) {
        const char* sub_name;
        void* sub_data;
        BubbleInfo* bubble;

        bubble = *(BubbleInfo **)data;
        ULOG_INFO ("Revoke event: @%s/%s/%s/%s (%p)\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name,
                bubble_name, bubble);
        cleanup_pattern_list (&bubble->host_patt_list);
        cleanup_pattern_list (&bubble->app_patt_list);

        if (endpoint->type != ET_BUILTIN) {
            kvlist_for_each (&bubble->subscriber_list, sub_name, sub_data) {
                BusEndpoint* subscriber;
                sub_data = kvlist_get (&bus_srv->endpoint_list, sub_name);

                if (sub_data) {
                    subscriber = *(BusEndpoint **)sub_data;
                    fire_system_event (bus_srv, SBT_LOST_EVENT_GENERATOR,
                            endpoint, subscriber, bubble_name);
                }
            }
        }
        kvlist_free (&bubble->subscriber_list);

        free (bubble);
    }
    kvlist_free (&endpoint->bubble_list);

    /* not for builtin endpoint */
    if (endpoint->sta_data)
        free (endpoint->sta_data);

    if (endpoint->host_name) free (endpoint->host_name);
    if (endpoint->app_name) free (endpoint->app_name);
    if (endpoint->runner_name) free (endpoint->runner_name);

    free (endpoint);
    ULOG_WARN ("Endpoint (%s) removed\n", endpoint_name);
    return 0;
}

bool store_dangling_endpoint (BusServer* bus_srv, BusEndpoint* endpoint)
{
    if (bus_srv->dangling_endpoints == NULL)
        bus_srv->dangling_endpoints = gslist_create (endpoint);
    else
        bus_srv->dangling_endpoints =
            gslist_insert_append (bus_srv->dangling_endpoints, endpoint);

    if (bus_srv->dangling_endpoints)
        return true;

    return false;
}

bool remove_dangling_endpoint (BusServer* bus_srv, BusEndpoint* endpoint)
{
    gs_list* node = bus_srv->dangling_endpoints;

    while (node) {
        if (node->data == endpoint) {
            gslist_remove_node (&bus_srv->dangling_endpoints, node);
            return true;
        }

        node = node->next;
    }

    return false;
}

bool make_endpoint_ready (BusServer* bus_srv,
        const char* endpoint_name, BusEndpoint* endpoint)
{
    if (remove_dangling_endpoint (bus_srv, endpoint)) {
        if (!kvlist_set (&bus_srv->endpoint_list, endpoint_name, &endpoint)) {
            ULOG_ERR ("Failed to store the endpoint: %s\n", endpoint_name);
            return false;
        }

        bus_srv->nr_endpoints++;
    }
    else {
        ULOG_ERR ("Not found endpoint in dangling list: %s\n", endpoint_name);
        return false;
    }

    return true;
}

static void cleanup_dangling_client (BusServer *bus_srv, BusEndpoint* endpoint)
{
    if (endpoint->type == ET_UNIX_SOCKET) {
        endpoint->entity.client->entity = NULL;
        us_cleanup_client (bus_srv->us_srv, (USClient*)endpoint->entity.client);
    }
    else if (endpoint->type == ET_WEB_SOCKET) {
        endpoint->entity.client->entity = NULL;
        ws_cleanup_client (bus_srv->ws_srv, (WSClient*)endpoint->entity.client);
    }

    ULOG_WARN ("The dangling endpoint (@%s/%s/%s) removed\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name);
}

int check_no_responding_endpoints (BusServer *bus_srv)
{
    int n = 0;
    struct timespec ts;
    const char* name;
    void *next, *data;

    clock_gettime (CLOCK_REALTIME, &ts);

    kvlist_for_each_safe (&bus_srv->endpoint_list, name, next, data) {
        BusEndpoint* endpoint = *(BusEndpoint **)data;

        if (endpoint->type != ET_BUILTIN &&
                ts.tv_sec > endpoint->t_living + HIBUS_MAX_NO_RESPONDING_TIME) {
            kvlist_delete (&bus_srv->endpoint_list, name);
            cleanup_dangling_client (bus_srv, endpoint);
            del_endpoint (bus_srv, endpoint, CDE_NO_RESPONDING);
            n++;
        }
    }

    return n;
}

int check_dangling_endpoints (BusServer *bus_srv)
{
    int n = 0;
    struct timespec ts;
    gs_list* node = bus_srv->dangling_endpoints;

    clock_gettime (CLOCK_REALTIME, &ts);
    while (node) {
        gs_list *next = node->next;
        BusEndpoint* endpoint = (BusEndpoint *)node->data;

        if (ts.tv_sec > endpoint->t_created + HIBUS_MAX_NO_RESPONDING_TIME) {
            gslist_remove_node (&bus_srv->dangling_endpoints, node);
            cleanup_dangling_client (bus_srv, endpoint);
            del_endpoint (bus_srv, endpoint, CDE_NO_RESPONDING);
            n++;
        }

        node = next;
    }

    return n;
}

int send_packet_to_endpoint (BusServer* bus_srv,
        BusEndpoint* endpoint, const char* body, int len_body)
{
    if (endpoint->type == ET_UNIX_SOCKET) {
        return us_send_packet (bus_srv->us_srv, (USClient *)endpoint->entity.client,
                US_OPCODE_TEXT, body, len_body);
    }
    else if (endpoint->type == ET_WEB_SOCKET) {
        return ws_send_packet (bus_srv->ws_srv, (WSClient *)endpoint->entity.client,
                WS_OPCODE_TEXT, body, len_body);
    }

    return -1;
}

int send_challenge_code (BusServer* bus_srv, BusEndpoint* endpoint)
{
    int n, retv;
    char key [32];
    unsigned char ch_code_bin [SHA256_DIGEST_SIZE];
    char *ch_code;
    char buff [HIBUS_DEF_PACKET_BUFF_SIZE];

    if ((endpoint->sta_data = malloc (SHA256_DIGEST_SIZE * 2 + 1)) == NULL) {
        return HIBUS_SC_INSUFFICIENT_STORAGE;
    }
    ch_code = endpoint->sta_data;

    snprintf (key, sizeof (key), "hibus-%ld", random ());

    hmac_sha256 (ch_code_bin,
            (uint8_t*)HIBUS_APP_HIBUS, strlen (HIBUS_APP_HIBUS),
            (uint8_t*)key, strlen (key));
    bin2hex (ch_code_bin, SHA256_DIGEST_SIZE, ch_code);
    ch_code [SHA256_DIGEST_SIZE * 2] = 0;

    ULOG_INFO ("Challenge code for new endpoint: %s\n", ch_code);

    n = snprintf (buff, sizeof (buff), 
            "{"
            "\"packetType\":\"auth\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"challengeCode\":\"%s\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            ch_code);

    if (n >= sizeof (buff)) {
        retv = HIBUS_SC_INTERNAL_SERVER_ERROR;
        // should never reach here
        assert (0);
    }
    else
        retv = send_packet_to_endpoint (bus_srv, endpoint, buff, n);

    if (retv) {
        endpoint->status = ES_CLOSING;
        free (endpoint->sta_data);
        endpoint->sta_data = NULL;
        return HIBUS_SC_IOERR;
    }

    return HIBUS_SC_OK;
}

static int authenticate_endpoint (BusServer* bus_srv, BusEndpoint* endpoint,
        const hibus_json *jo)
{
    hibus_json *jo_tmp;
    const char* prot_name = NULL;
    const char *host_name = NULL, *app_name = NULL, *runner_name = NULL;
    const char *encoded_sig = NULL, *encoding = NULL;
    unsigned char *sig;
    unsigned int sig_len = 0;
    int prot_ver = 0, retv;
    char norm_host_name [HIBUS_LEN_HOST_NAME + 1];
    char norm_app_name [HIBUS_LEN_APP_NAME + 1];
    char norm_runner_name [HIBUS_LEN_RUNNER_NAME + 1];
    char endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];

    if (json_object_object_get_ex (jo, "protocolName", &jo_tmp)) {
        prot_name = json_object_get_string (jo_tmp);
    }

    if (json_object_object_get_ex (jo, "protocolVersion", &jo_tmp)) {
        prot_ver = json_object_get_int (jo_tmp);
    }

    if (json_object_object_get_ex (jo, "hostName", &jo_tmp)) {
        host_name = json_object_get_string (jo_tmp);
    }
    if (json_object_object_get_ex (jo, "appName", &jo_tmp)) {
        app_name = json_object_get_string (jo_tmp);
    }
    if (json_object_object_get_ex (jo, "runnerName", &jo_tmp)) {
        runner_name = json_object_get_string (jo_tmp);
    }
    if (json_object_object_get_ex (jo, "signature", &jo_tmp)) {
        encoded_sig = json_object_get_string (jo_tmp);
    }
    if (json_object_object_get_ex (jo, "encodedIn", &jo_tmp)) {
        encoding = json_object_get_string (jo_tmp);
    }

    if (prot_name == NULL || prot_ver > HIBUS_PROTOCOL_VERSION ||
            host_name == NULL || app_name == NULL || runner_name == NULL ||
            encoded_sig == NULL || encoding == NULL ||
            strcasecmp (prot_name, HIBUS_PROTOCOL_NAME)) {
        ULOG_WARN ("Bad packet data for authentication\n");
        return HIBUS_SC_BAD_REQUEST;
    }

    if (prot_ver < HIBUS_MINIMAL_PROTOCOL_VERSION)
        return HIBUS_SC_UPGRADE_REQUIRED;

    if (!hibus_is_valid_host_name (host_name) ||
            !hibus_is_valid_app_name (app_name) ||
            !hibus_is_valid_token (runner_name, HIBUS_LEN_RUNNER_NAME)) {
        ULOG_WARN ("Bad endpoint name: @%s/%s/%s\n", host_name, app_name, runner_name);
        return HIBUS_SC_NOT_ACCEPTABLE;
    }

    hibus_name_tolower_copy (host_name, norm_host_name, HIBUS_LEN_HOST_NAME);
    hibus_name_tolower_copy (app_name, norm_app_name, HIBUS_LEN_APP_NAME);
    hibus_name_tolower_copy (runner_name, norm_runner_name, HIBUS_LEN_RUNNER_NAME);
    host_name = norm_host_name;
    app_name = norm_app_name;
    runner_name = norm_runner_name;

    assert (endpoint->sta_data);

    if (strcasecmp (encoding, "base64") == 0) {
        sig_len = B64_DECODE_LEN (strlen (encoded_sig));
        sig = malloc (sig_len);
        sig_len = b64_decode (encoded_sig, sig, sig_len);
    }
    else if (strcasecmp (encoding, "hex") == 0) {
        sig = malloc (strlen (encoded_sig) / 2 + 1);
        sig_len = hex2bin (encoded_sig, sig);
    }
    else {
        return HIBUS_SC_BAD_REQUEST;
    }

    if (sig_len <= 0) {
        free (sig);
        return HIBUS_SC_BAD_REQUEST;
    }

    retv = hibus_verify_signature (app_name,
            endpoint->sta_data, strlen (endpoint->sta_data),
            sig, sig_len);
    free (sig);

    if (retv < 0) {
        ULOG_WARN ("No such app installed: %s\n", app_name);
        return HIBUS_SC_NOT_FOUND;
    }
    else if (retv == 0) {
        ULOG_WARN ("Failed to authenticate the app (%s) with challenge code: %s\n",
                app_name, (char *)endpoint->sta_data);
        return HIBUS_SC_UNAUTHORIZED;
    }

    /* make endpoint ready here */
    if (endpoint->type == CT_UNIX_SOCKET) {
        /* override the host name */
        host_name = HIBUS_LOCALHOST;
    }
    else {
        /* TODO: handle hostname for web socket connections here */
        host_name = HIBUS_LOCALHOST;
    }
    
    hibus_assemble_endpoint_name (host_name,
                    app_name, runner_name, endpoint_name);

    ULOG_INFO ("New endpoint: %s (%p)\n", endpoint_name, endpoint);

    if (kvlist_get (&bus_srv->endpoint_list, endpoint_name)) {
        ULOG_WARN ("Duplicated endpoint: %s\n", endpoint_name);
        return HIBUS_SC_CONFLICT;
    }

    if (!make_endpoint_ready (bus_srv, endpoint_name, endpoint)) {
        ULOG_ERR ("Failed to store the endpoint: %s\n", endpoint_name);
        return HIBUS_SC_INSUFFICIENT_STORAGE;
    }

    ULOG_INFO ("New endpoint stored: %s (%p), %d endpoints totally.\n",
            endpoint_name, endpoint, bus_srv->nr_endpoints);

    endpoint->host_name = strdup (host_name);
    endpoint->app_name = strdup (app_name);
    endpoint->runner_name = strdup (runner_name);
    endpoint->status = ES_READY;

    fire_system_event (bus_srv, SBT_NEW_ENDPOINT, endpoint, NULL, NULL);
    return HIBUS_SC_OK;
}

static int handle_auth_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const hibus_json* jo)
{
    if (endpoint->status == ES_AUTHING) {
        char buff [HIBUS_MIN_PACKET_BUFF_SIZE];
        int retv, n;

        assert (endpoint->sta_data);

        if ((retv = authenticate_endpoint (bus_srv, endpoint, jo)) !=
                HIBUS_SC_OK) {

            free (endpoint->sta_data);
            endpoint->sta_data = NULL;

            /* send authFailed packet */
            n = snprintf (buff, sizeof (buff), 
                    "{"
                    "\"packetType\":\"authFailed\","
                    "\"retCode\":%d,"
                    "\"retMsg\":\"%s\","
                    "}",
                    retv, hibus_get_ret_message (retv));

            if (n < sizeof (buff))
                send_packet_to_endpoint (bus_srv, endpoint, buff, n);
            return retv;
        }

        free (endpoint->sta_data);
        endpoint->sta_data = NULL;

        /* send authPassed packet */
        n = snprintf (buff, sizeof (buff), 
                "{"
                "\"packetType\":\"authPassed\","
                "\"serverHostName\":\"%s\","
                "\"reassignedHostName\":\"%s\""
                "}",
                bus_srv->server_name, endpoint->host_name);

        if (n < sizeof (buff))
            send_packet_to_endpoint (bus_srv, endpoint, buff, n);
        return HIBUS_SC_OK;
    }

    return HIBUS_SC_PRECONDITION_FAILED;
}

static int handle_call_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const hibus_json* jo, const struct timespec *ts)
{
    hibus_json *jo_tmp;
    const char *str_tmp;
    char to_endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];
    char to_method_name [HIBUS_LEN_METHOD_NAME + 1];
    BusEndpoint *to_endpoint;
    MethodInfo *to_method;
    const char *call_id;
    int expected_time;
    struct timespec ts_start;
    double time_diff, time_consumed;
    const char *parameter;
    CallInfo call_info;

    char buff_in_stack [HIBUS_MAX_FRAME_PAYLOAD_SIZE];
    int ret_code, sz_packet_buff = sizeof (buff_in_stack), n = 0;
    char result_id [HIBUS_LEN_UNIQUE_ID + 1], *result, *escaped_result = NULL;
    char* packet_buff = NULL;

    if (json_object_object_get_ex (jo, "toEndpoint", &jo_tmp)) {
        if ((str_tmp = json_object_get_string (jo_tmp))) {
            void *data;
            hibus_name_tolower_copy (str_tmp, to_endpoint_name, HIBUS_LEN_ENDPOINT_NAME);
            if ((data = kvlist_get (&bus_srv->endpoint_list, to_endpoint_name))) {
                to_endpoint = *(BusEndpoint **)data;
            }
            else {
                ret_code = HIBUS_SC_NOT_FOUND;
                goto done;
            }
        }
        else {
            ret_code = HIBUS_SC_BAD_REQUEST;
            goto done;
        }
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto done;
    }

    if (json_object_object_get_ex (jo, "toMethod", &jo_tmp)) {
        if ((str_tmp = json_object_get_string (jo_tmp))) {
            void *data;
            hibus_name_tolower_copy (str_tmp, to_method_name, HIBUS_LEN_METHOD_NAME);
            if ((data = kvlist_get (&to_endpoint->method_list, to_method_name))) {
                to_method = *(MethodInfo **)data;
            }
            else {
                ret_code = HIBUS_SC_NOT_FOUND;
                goto done;
            }
        }
        else {
            ret_code = HIBUS_SC_BAD_REQUEST;
            goto done;
        }
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto done;
    }

    if (!match_pattern (&to_method->host_patt_list, endpoint->host_name,
                1, HIBUS_PATTERN_VAR_SELF, to_endpoint->host_name)) {
        ret_code = HIBUS_SC_METHOD_NOT_ALLOWED;
        goto done;
    }

    if (!match_pattern (&to_method->app_patt_list, endpoint->app_name,
                1, HIBUS_PATTERN_VAR_OWNER, to_endpoint->app_name)) {
        ret_code = HIBUS_SC_METHOD_NOT_ALLOWED;
        goto done;
    }

    if (json_object_object_get_ex (jo, "callId", &jo_tmp) &&
            (call_id = json_object_get_string (jo_tmp))) {
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto done;
    }

    if (json_object_object_get_ex (jo, "expectedTime", &jo_tmp)) {
        expected_time = json_object_get_int (jo_tmp);
    }
    else {
        expected_time = -1;
    }

    if (json_object_object_get_ex (jo, "parameter", &jo_tmp) &&
            (parameter = json_object_get_string (jo_tmp))) {
    }
    else {
        parameter = NULL;
    }

    assert (to_method->handler);

    hibus_generate_unique_id (result_id, "result");
    clock_gettime (CLOCK_REALTIME, &ts_start);
    time_diff = hibus_get_elapsed_seconds (ts, &ts_start);

    call_info.call_id = call_id;
    call_info.result_id = result_id;
    call_info.time_diff = time_diff;
    endpoint->sta_data = &call_info;
    result = to_method->handler (bus_srv, endpoint, to_endpoint, to_method_name,
            parameter, &ret_code);
    endpoint->sta_data = NULL;

    time_consumed = hibus_get_elapsed_seconds (&ts_start, NULL);

    if (ret_code == HIBUS_SC_OK && result) {
        escaped_result = hibus_escape_string_for_json (result);
        free (result);

        if (escaped_result == NULL) {
            ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
        }
        else {
            sz_packet_buff = strlen (escaped_result) + HIBUS_MIN_PACKET_BUFF_SIZE;
            if (sz_packet_buff <= sizeof (buff_in_stack)) {
                packet_buff = buff_in_stack;
                sz_packet_buff = sizeof (buff_in_stack);
            }
            else {
                packet_buff = malloc (sz_packet_buff);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof (buff_in_stack);
                    ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
                }
            }
        }
    }
    else {
        escaped_result = NULL;
        packet_buff = buff_in_stack;
    }

done:
    if (ret_code == HIBUS_SC_OK) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"result\","
            "\"resultId\": \"%s\","
            "\"callId\": \"%s\","
            "\"fromEndpoint\": \"@%s/%s/%s\","
            "\"fromMethod\": \"%s\""
            "\"timeDiff\": %f,"
            "\"timeConsumed\": %f,"
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\","
            "\"retValue\": \"%s\""
            "}",
            result_id, call_id,
            to_endpoint->host_name, to_endpoint->app_name, to_endpoint->runner_name,
            to_method_name,
            time_diff, time_consumed,
            ret_code,
            hibus_get_ret_message (ret_code),
            escaped_result ? escaped_result : "");

    }
    else if (ret_code == HIBUS_SC_ACCEPTED) {
        BusWaitingInfo waiting_info;

        waiting_info.ts = *ts;
        waiting_info.expected_time = expected_time;
        hibus_assemble_endpoint_name (endpoint->host_name, endpoint->app_name,
                endpoint->runner_name, waiting_info.endpoint_name);

        if (!kvlist_set (&bus_srv->waiting_endpoints, result_id, &waiting_info)) {
            ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
        }
        else {
            n = snprintf (packet_buff, sz_packet_buff, 
                "{"
                "\"packetType\": \"result\","
                "\"resultId\": \"%s\","
                "\"callId\": \"%s\","
                "\"timeDiff\": %f,"
                "\"timeConsumed\": %f,"
                "\"retCode\": %d,"
                "\"retMsg\": \"%s\""
                "}",
                result_id, call_id,
                time_diff, time_consumed,
                ret_code,
                hibus_get_ret_message (ret_code));
        }
    }

    if (ret_code != HIBUS_SC_OK && ret_code != HIBUS_SC_ACCEPTED) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"causedBy\": \"call\","
            "\"causedId\": \"%s\","
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            call_id,
            ret_code,
            hibus_get_ret_message (ret_code));

    }

    if (n > 0 && n < sz_packet_buff) {
        send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
    }
    else {
        ULOG_ERR ("The size of buffer for packet is too small.\n");
    }

    if (escaped_result)
        free (escaped_result);
    if (packet_buff && packet_buff != buff_in_stack)
        free (packet_buff);

    return HIBUS_SC_OK;
}

static int handle_result_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const hibus_json* jo, const struct timespec *ts)
{
    hibus_json *jo_tmp;
    int real_ret_code;
    const char *call_id, *result_id, *from_method_name;
    double time_diff, time_consumed;
    const char* ret_value;
    void* data;
    BusEndpoint *to_endpoint;

    char buff_in_stack [HIBUS_MAX_FRAME_PAYLOAD_SIZE];
    int ret_code, sz_packet_buff = sizeof (buff_in_stack), n;
    char* escaped_ret_value = NULL, *packet_buff = NULL;

    if (json_object_object_get_ex (jo, "resultId", &jo_tmp) &&
            (result_id = json_object_get_string (jo_tmp))) {
        if (!hibus_is_valid_unique_id (result_id)) {
            ret_code = HIBUS_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    if (json_object_object_get_ex (jo, "callId", &jo_tmp) &&
            (call_id = json_object_get_string (jo_tmp))) {
        if (!hibus_is_valid_unique_id (call_id)) {
            ret_code = HIBUS_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    if (json_object_object_get_ex (jo, "retCode", &jo_tmp) &&
            (real_ret_code = json_object_get_int (jo_tmp))) {
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    if (json_object_object_get_ex (jo, "fromMethod", &jo_tmp) &&
            (from_method_name = json_object_get_string (jo_tmp))) {
        if (hibus_is_valid_method_name (from_method_name)) {
            ret_code = HIBUS_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    data = kvlist_get (&bus_srv->waiting_endpoints, result_id);
    if (data == NULL) {
        ret_code = HIBUS_SC_GONE;
        goto failed;
    }
    else {
        BusWaitingInfo waiting_info;

        memcpy (&waiting_info, data, sizeof (BusWaitingInfo));
        kvlist_delete (&bus_srv->waiting_endpoints, result_id);

        if ((data = kvlist_get (&bus_srv->endpoint_list, waiting_info.endpoint_name)) ==
                NULL) {
            ret_code = HIBUS_SC_NOT_FOUND;
            goto failed;
        }
        else {
            /* NOTE: the endpoint might not the caller */
            to_endpoint = *(BusEndpoint **)data;
        }
    }

    if (json_object_object_get_ex (jo, "timeConsumed", &jo_tmp) &&
            (time_consumed = json_object_get_double (jo_tmp))) {
    }
    else {
        time_consumed = 0.0f;
    }

    if (json_object_object_get_ex (jo, "retValue", &jo_tmp) &&
            (ret_value = json_object_get_string (jo_tmp))) {
    }
    else {
        ret_value = NULL;
    }

    packet_buff = buff_in_stack;
    if (ret_value) {
        escaped_ret_value = hibus_escape_string_for_json (ret_value);

        if (escaped_ret_value == NULL) {
            ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
            goto failed;
        }
        else {
            sz_packet_buff = strlen (escaped_ret_value) + HIBUS_MIN_PACKET_BUFF_SIZE;
            if (sz_packet_buff <= sizeof (buff_in_stack)) {
                packet_buff = buff_in_stack;
                sz_packet_buff = sizeof (buff_in_stack);
            }
            else {
                packet_buff = malloc (sz_packet_buff);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof (buff_in_stack);
                    ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
                    goto failed;
                }
            }
        }
    }
    else {
        escaped_ret_value = NULL;
    }

    time_diff = hibus_get_elapsed_seconds (ts, NULL);
    n = snprintf (packet_buff, sz_packet_buff, 
        "{"
        "\"packetType\":\"result\","
        "\"resultId\":\"%s\","
        "\"callId\":\"%s\","
        "\"fromEndpoint\":\"@%s/%s/%s\","
        "\"fromMethod\":\"%s\","
        "\"timeConsumed\":%f,"
        "\"timeDiff\":%f,"
        "\"retCode\":%d,"
        "\"retMsg\":\"%s\","
        "\"retValue\":\"%s\""
        "}",
        result_id, call_id,
        endpoint->host_name, endpoint->app_name, endpoint->runner_name,
        from_method_name, time_consumed, time_diff,
        real_ret_code, hibus_get_ret_message (real_ret_code),
        escaped_ret_value ? escaped_ret_value : "");

    if (n < sz_packet_buff) {
        send_packet_to_endpoint (bus_srv, to_endpoint, packet_buff, n);
        ret_code = HIBUS_SC_OK;
    }
    else {
        ULOG_ERR ("The size of buffer for result packet is too small.\n");
        ret_code = HIBUS_SC_INTERNAL_SERVER_ERROR;
    }

failed:
    if (ret_code != HIBUS_SC_OK) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"causedBy\":\"result\","
            "\"causedId\":\"%s\","
            "\"retCode\":%d,"
            "\"retMsg\":\"%s\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            result_id,
            ret_code, hibus_get_ret_message (ret_code));

        if (n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            ULOG_ERR ("The size of buffer for error packet is too small.\n");
        }
    }
    else {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"resultSent\","
            "\"resultId\":\"%s\","
            "\"timeDiff\":%.9f"
            "}",
            result_id, time_diff);

        if (n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            ULOG_ERR ("The size of buffer for resultSent packet is too small.\n");
        }
    }

    if (escaped_ret_value)
        free (escaped_ret_value);
    if (packet_buff && packet_buff != buff_in_stack)
        free (packet_buff);

    return HIBUS_SC_OK;
}

static int handle_event_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const hibus_json* jo, const struct timespec *ts)
{
    hibus_json *jo_tmp;
    const char *str_tmp;
    char bubble_name [HIBUS_LEN_BUBBLE_NAME + 1];
    BubbleInfo *bubble;
    const char *event_id;
    const char *bubble_data;

    char buff_in_stack [HIBUS_MAX_FRAME_PAYLOAD_SIZE];
    int ret_code, sz_packet_buff = sizeof (buff_in_stack), n;
    char* escaped_data = NULL, *packet_buff = NULL;
    struct timespec ts_start;
    double time_diff, time_consumed;
    unsigned int nr_succeeded = 0, nr_failed = 0;

    if (json_object_object_get_ex (jo, "bubbleName", &jo_tmp)) {
        if ((str_tmp = json_object_get_string (jo_tmp))) {
            void *data;
            hibus_name_toupper_copy (str_tmp, bubble_name, HIBUS_LEN_BUBBLE_NAME);
            if ((data = kvlist_get (&endpoint->bubble_list, bubble_name))) {
                bubble = *(BubbleInfo **)data;
            }
            else {
                ret_code = HIBUS_SC_NOT_FOUND;
                goto failed;
            }
        }
        else {
            ret_code = HIBUS_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    if (json_object_object_get_ex (jo, "eventId", &jo_tmp) &&
            (event_id = json_object_get_string (jo_tmp))) {
    }
    else {
        ret_code = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    if (json_object_object_get_ex (jo, "bubbleData", &jo_tmp) &&
            (bubble_data = json_object_get_string (jo_tmp))) {
    }
    else {
        bubble_data = NULL;
    }

    packet_buff = buff_in_stack;
    if (bubble_data) {
        escaped_data = hibus_escape_string_for_json (bubble_data);

        if (escaped_data == NULL) {
            ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
            goto failed;
        }
        else {
            sz_packet_buff = strlen (escaped_data) + HIBUS_MIN_PACKET_BUFF_SIZE;
            if (sz_packet_buff <= sizeof (buff_in_stack)) {
                packet_buff = buff_in_stack;
                sz_packet_buff = sizeof (buff_in_stack);
            }
            else {
                packet_buff = malloc (sz_packet_buff);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof (buff_in_stack);
                    ret_code = HIBUS_SC_INSUFFICIENT_STORAGE;
                    goto failed;
                }
            }
        }
    }
    else {
        escaped_data = NULL;
    }

    clock_gettime (CLOCK_REALTIME, &ts_start);
    time_diff = hibus_get_elapsed_seconds (ts, &ts_start);

    n = snprintf (packet_buff, sz_packet_buff, 
        "{"
        "\"packetType\": \"event\","
        "\"eventId\": \"%s\","
        "\"fromEndpoint\": \"@%s/%s/%s\","
        "\"fromBubble\": \"%s\""
        "\"bubbleData\": \"%s\""
        "\"timeDiff\":",
        event_id,
        endpoint->host_name, endpoint->app_name, endpoint->runner_name,
        bubble_name,
        escaped_data ? escaped_data : "");

    if (n < sz_packet_buff) {
        const char* name;
        void *next, *data;
        size_t org_len = strlen (packet_buff);

        kvlist_for_each_safe (&bubble->subscriber_list, name, next, data) {
            void *sub_data;

            sub_data = kvlist_get (&bus_srv->endpoint_list, name);

            // forward event to subscriber.
            if (sub_data) {
                double my_time_diff;
                char str_time_diff [64];
                BusEndpoint* subscriber;

                subscriber = *(BusEndpoint **)sub_data;

                my_time_diff = hibus_get_elapsed_seconds (ts, NULL);
                snprintf (str_time_diff, sizeof (str_time_diff), "%f}", my_time_diff);
                packet_buff [org_len] = '\0';
                if (sz_packet_buff > org_len + strlen (str_time_diff)) {
                    strcat (packet_buff, str_time_diff);
                    send_packet_to_endpoint (bus_srv, subscriber, packet_buff, n);
                }
                else {
                    ULOG_ERR ("The size of buffer for event packet is too small.\n");
                    ret_code = HIBUS_SC_INTERNAL_SERVER_ERROR;
                    break;
                }
                nr_succeeded++;
            }
            else {
                kvlist_delete (&bubble->subscriber_list, name);
                nr_failed++;
            }
        }

        ret_code = HIBUS_SC_OK;
    }
    else {
        ULOG_ERR ("The size of buffer for event packet is too small.\n");
        ret_code = HIBUS_SC_INTERNAL_SERVER_ERROR;
    }

failed:
    if (ret_code != HIBUS_SC_OK) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"causedBy\": \"event\","
            "\"causedId\": \"%s\","
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            event_id,
            ret_code,
            hibus_get_ret_message (ret_code));

        if (n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            ULOG_ERR ("The size of buffer for error packet is too small.\n");
        }
    }
    else {
        time_consumed = hibus_get_elapsed_seconds (&ts_start, NULL);

        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"eventSent\","
            "\"eventId\":\"%s\","
            "\"nrSucceeded\":%u,"
            "\"nrFailed\":%u,"
            "\"timeDiff\":%.9f,"
            "\"timeConsumed\":%.9f"
            "}",
            event_id,
            nr_succeeded, nr_failed,
            time_diff, time_consumed);

        if (n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            ULOG_ERR ("The size of buffer for eventSent packet is too small.\n");
        }
    }

    if (escaped_data)
        free (escaped_data);
    if (packet_buff && packet_buff != buff_in_stack)
        free (packet_buff);

    return HIBUS_SC_OK;
}

int handle_json_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const struct timespec *ts, const char* json, unsigned int len)
{
    int retv = HIBUS_SC_OK;
    hibus_json *jo = NULL, *jo_tmp;

    ULOG_INFO ("Handling packet: \n%s\n", json);

    jo = hibus_json_object_from_string (json, len, 2);
    if (jo == NULL) {
        retv = HIBUS_SC_UNPROCESSABLE_PACKET;
        goto done;
    }

    if (json_object_object_get_ex (jo, "packetType", &jo_tmp)) {
        const char *pack_type;
        pack_type = json_object_get_string (jo_tmp);

        if (strcasecmp (pack_type, "auth") == 0) {
            retv = handle_auth_packet (bus_srv, endpoint, jo);
        }
        else if (strcasecmp (pack_type, "call") == 0) {
            retv = handle_call_packet (bus_srv, endpoint, jo, ts);
        }
        else if (strcasecmp (pack_type, "result") == 0) {
            retv = handle_result_packet (bus_srv, endpoint, jo, ts);
        }
        else if (strcasecmp (pack_type, "event") == 0) {
            retv = handle_event_packet (bus_srv, endpoint, jo, ts);
        }
        else {
            retv = HIBUS_SC_BAD_REQUEST;
        }
    }
    else {
        retv = HIBUS_SC_BAD_REQUEST;
    }

done:
    if (jo)
        json_object_put (jo);

    return retv;
}

int register_procedure (BusServer *bus_srv, BusEndpoint* endpoint, const char* method_name,
        const char* for_host, const char* for_app, method_handler handler)
{
    int retv = HIBUS_SC_OK;
    MethodInfo *info;
    char normalized_name [HIBUS_LEN_METHOD_NAME + 1];

    if (!hibus_is_valid_method_name (method_name))
        return HIBUS_SC_BAD_REQUEST;

    hibus_name_tolower_copy (method_name, normalized_name, 0);

    if (kvlist_get (&endpoint->method_list, normalized_name)) {
        return HIBUS_SC_CONFLICT;
    }

    if ((info = calloc (1, sizeof (MethodInfo))) == NULL)
        return HIBUS_SC_INSUFFICIENT_STORAGE;

    if (!init_pattern_list (&info->host_patt_list, for_host)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->host_patt_list.nr_patterns == 0) {
        retv = HIBUS_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    if (!init_pattern_list (&info->app_patt_list, for_app)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->app_patt_list.nr_patterns == 0) {
        retv = HIBUS_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    info->handler = handler;

    if (!kvlist_set (&endpoint->method_list, normalized_name, &info)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    ULOG_INFO ("New procedure registered: @%s/%s/%s/%s (%p)\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            normalized_name, info);
    return HIBUS_SC_OK;

failed:
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    free (info);
    return retv;
}

int revoke_procedure (BusServer *bus_srv, BusEndpoint* endpoint, const char* method_name)
{
    void *data;
    MethodInfo *info;
    char normalized_name [HIBUS_LEN_METHOD_NAME + 1];

    if (!hibus_is_valid_method_name (method_name))
        return HIBUS_SC_BAD_REQUEST;

    hibus_name_tolower_copy (method_name, normalized_name, 0);

    if ((data = kvlist_get (&endpoint->method_list, normalized_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    info = *(MethodInfo **)data;
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    /* TODO: cancel pending calls */
    free (info);

    kvlist_delete (&endpoint->method_list, normalized_name);
    return HIBUS_SC_OK;
}

int register_event (BusServer *bus_srv, BusEndpoint* endpoint, const char* bubble_name,
        const char* for_host, const char* for_app)
{
    int retv = HIBUS_SC_OK;
    BubbleInfo *info;
    char normalized_name [HIBUS_LEN_BUBBLE_NAME + 1];

    if (!hibus_is_valid_bubble_name (bubble_name))
        return HIBUS_SC_BAD_REQUEST;

    hibus_name_toupper_copy (bubble_name, normalized_name, 0);

    if (kvlist_get (&endpoint->bubble_list, normalized_name)) {
        return HIBUS_SC_CONFLICT;
    }

    if ((info = calloc (1, sizeof (BubbleInfo))) == NULL)
        return HIBUS_SC_INSUFFICIENT_STORAGE;

    if (!init_pattern_list (&info->host_patt_list, for_host)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->host_patt_list.nr_patterns == 0) {
        retv = HIBUS_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    if (!init_pattern_list (&info->app_patt_list, for_app)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->app_patt_list.nr_patterns == 0) {
        retv = HIBUS_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    kvlist_init (&info->subscriber_list, NULL);

    if (!kvlist_set (&endpoint->bubble_list, normalized_name, &info)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    ULOG_INFO ("New event registered: @%s/%s/%s/%s (%p)\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            normalized_name, info);
    return HIBUS_SC_OK;

failed:
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    free (info);
    return retv;
}

int revoke_event (BusServer *bus_srv, BusEndpoint *endpoint, const char* bubble_name)
{
    const char* name;
    void *data;
    BubbleInfo *bubble;
    char normalized_name [HIBUS_LEN_BUBBLE_NAME + 1];

    if (!hibus_is_valid_bubble_name (bubble_name))
        return HIBUS_SC_BAD_REQUEST;

    hibus_name_toupper_copy (bubble_name, normalized_name, 0);

    if ((data = kvlist_get (&endpoint->bubble_list, normalized_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    bubble = *(BubbleInfo **)data;
    cleanup_pattern_list (&bubble->host_patt_list);
    cleanup_pattern_list (&bubble->app_patt_list);

    /* notify subscribers */
    kvlist_for_each (&bubble->subscriber_list, name, data) {
        void *sub_data;
        BusEndpoint* subscriber;
        sub_data = kvlist_get (&bus_srv->endpoint_list, name);

        if (sub_data) {
            subscriber = *(BusEndpoint **)sub_data;
            fire_system_event (bus_srv, SBT_LOST_EVENT_BUBBLE,
                    endpoint, subscriber, bubble_name);
        }
    }

    kvlist_free (&bubble->subscriber_list);
    free (bubble);

    kvlist_delete (&endpoint->bubble_list, normalized_name);
    return HIBUS_SC_OK;
}

int subscribe_event (BusServer *bus_srv, BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint* subscriber)
{
    void *data;
    BubbleInfo *info;
    char endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];
    char normalized_name [HIBUS_LEN_BUBBLE_NAME + 1];

    if (!hibus_is_valid_bubble_name (bubble_name))
        return HIBUS_SC_BAD_REQUEST;

    hibus_name_toupper_copy (bubble_name, normalized_name, 0);

    if ((data = kvlist_get (&endpoint->bubble_list, normalized_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    assemble_endpoint_name (subscriber, endpoint_name);

    info = *(BubbleInfo **)data;
    if (kvlist_get (&info->subscriber_list, endpoint_name))
        return HIBUS_SC_CONFLICT;

    if (!kvlist_set (&info->subscriber_list, endpoint_name, &subscriber))
        return HIBUS_SC_INSUFFICIENT_STORAGE;

    return HIBUS_SC_OK;
}

int unsubscribe_event (BusServer *bus_srv, BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint* subscriber)
{
    void *data;
    BubbleInfo *info;
    char endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];
    char normalized_name [HIBUS_LEN_BUBBLE_NAME + 1];

    if (!hibus_is_valid_bubble_name (bubble_name))
        return HIBUS_SC_BAD_REQUEST;

    hibus_name_toupper_copy (bubble_name, normalized_name, 0);

    if ((data = kvlist_get (&endpoint->bubble_list, normalized_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    assemble_endpoint_name (subscriber, endpoint_name);

    info = *(BubbleInfo **)data;
    if (kvlist_get (&info->subscriber_list, endpoint_name))
        return HIBUS_SC_NOT_FOUND;

    kvlist_delete (&info->subscriber_list, endpoint_name);
    return HIBUS_SC_OK;
}

