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
#include <hibox/sha256.h>
#include <hibox/hmac.h>
#include <hibox/json.h>

#include "hibus.h"
#include "endpoint.h"
#include "unixsocket.h"
#include "websocket.h"

BusEndpoint* new_endpoint (BusServer* the_server, int type, void* client)
{
    BusEndpoint* endpoint = NULL;

    endpoint = (BusEndpoint *)calloc (sizeof (BusEndpoint), 1);
    if (endpoint == NULL)
        return NULL;

    switch (type) {
        case ET_BUILTIN:
            endpoint->type = ET_BUILTIN;
            endpoint->status = ES_READY;
            endpoint->usc = NULL;

            endpoint->host_name = strdup (the_server->server_name);
            endpoint->app_name = strdup (HIBUS_APP_HIBUS);
            endpoint->runner_name = strdup (HIBUS_RUNNER_BUILITIN);
            break;

        case ET_UNIX_SOCKET:
        case ET_WEB_SOCKET:
            endpoint->type = type;
            endpoint->status = ES_AUTHING;
            endpoint->usc = client;

            endpoint->host_name = NULL;
            endpoint->app_name = NULL;
            endpoint->runner_name = NULL;
            break;

        default:
            free (endpoint);
            return NULL;
    }

    if (type == ET_UNIX_SOCKET) {
        USClient* usc = (USClient*)client;
        usc->priv_data = endpoint;
    }
    else if (type == ET_WEB_SOCKET) {
        WSClient* wsc = (WSClient*)client;
        wsc->priv_data = endpoint;
    }

    kvlist_init (&endpoint->method_list, NULL);
    kvlist_init (&endpoint->bubble_list, NULL);
    INIT_SAFE_LIST (&endpoint->pending_calling);

    return endpoint;
}

int del_endpoint (BusServer* the_server, BusEndpoint* endpoint)
{
    char endpoint_name [LEN_ENDPOINT_NAME + 1];
    const char *name;
    void *data;

    if (assemble_endpoint_name (endpoint, endpoint_name) > 0) {
        ULOG_INFO ("Deleting an endpoint: %s (%p)\n", endpoint_name, endpoint);
    }
    else {
        strcpy (endpoint_name, "@unknown/unknown/unknown");
    }

    kvlist_for_each (&endpoint->method_list, name, data) {
        method_info* method;

        method = *(method_info **)data;
        ULOG_INFO ("Revoke procedure: @%s/%s/%s/%s (%p)\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name,
                name, method);
        cleanup_pattern_list (&method->host_patt_list);
        cleanup_pattern_list (&method->app_patt_list);
        free (method);
    }
    kvlist_free (&endpoint->method_list);

    kvlist_for_each (&endpoint->bubble_list, name, data) {
        bubble_info* bubble;

        bubble = *(bubble_info **)data;
        ULOG_INFO ("Revoke event: @%s/%s/%s/%s (%p)\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name,
                name, bubble);
        cleanup_pattern_list (&bubble->host_patt_list);
        cleanup_pattern_list (&bubble->app_patt_list);
        free (bubble);
    }
    kvlist_free (&endpoint->bubble_list);

    if (endpoint->sta_data) free (endpoint->sta_data);
    if (endpoint->host_name) free (endpoint->host_name);
    if (endpoint->app_name) free (endpoint->app_name);
    if (endpoint->runner_name) free (endpoint->runner_name);

    free (endpoint);
    ULOG_WARN ("Endpoint (%s) removed\n", endpoint_name);
    return 0;
}

inline static int send_packet_to_endpoint (BusServer* the_server,
        BusEndpoint* endpoint, const char* body)
{
    if (endpoint->type == ET_UNIX_SOCKET) {
        return us_send_data (the_server->us_srv, endpoint->usc,
                US_OPCODE_TEXT, body, strlen (body));
    }
    else if (endpoint->type == ET_WEB_SOCKET) {
        return ws_send_data (the_server->ws_srv, endpoint->wsc,
                WS_OPCODE_TEXT, body, strlen (body));
    }

    return -1;
}

int send_challenge_code (BusServer* the_server, BusEndpoint* endpoint)
{
    int retv;
    char key [32];
    unsigned char ch_code_bin [SHA256_DIGEST_SIZE];
    char *ch_code;
    char buff [1024];

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

    retv = snprintf (buff, sizeof (buff), 
            "{"
            "\"packetType\":\"auth\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"challengeCode\":\"%s\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            ch_code);

    if (retv >= sizeof (buff)) {
        // should never reach here
        assert (0);
    }
    else
        retv = send_packet_to_endpoint (the_server, endpoint, buff);

    if (retv) {
        endpoint->status = ES_CLOSING;
        free (endpoint->sta_data);
        endpoint->sta_data = NULL;
        return HIBUS_SC_IOERR;
    }

    return HIBUS_SC_OK;
}

static int authenticate_endpoint (BusServer* the_server, BusEndpoint* endpoint,
        const hibus_json *jo)
{
    hibus_json *jo_tmp;
    const char* prot_name = NULL;
    const char *host_name = NULL, *app_name = NULL, *runner_name = NULL;
    const char *encoded_sig = NULL, *encoding = NULL;
    unsigned char *sig;
    unsigned int sig_len = 0;
    int prot_ver = 0, retv;
    char endpoint_name [LEN_ENDPOINT_NAME + 1];

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
            !hibus_is_valid_token (runner_name, LEN_RUNNER_NAME)) {
        ULOG_WARN ("Bad endpoint name: @%s/%s/%s\n", host_name, app_name, runner_name);
        return HIBUS_SC_NOT_ACCEPTABLE;
    }

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

    ULOG_INFO ("New endpoint: %s\n", endpoint_name);

    if (kvlist_get (&the_server->endpoint_list, endpoint_name)) {
        ULOG_WARN ("Duplicated endpoint: %s\n", endpoint_name);
        return HIBUS_SC_CONFILCT;
    }

    if (!kvlist_set (&the_server->endpoint_list, endpoint_name, &endpoint)) {
        ULOG_ERR ("Failed to store the endpoint: %s\n", endpoint_name);
        return HIBUS_SC_INSUFFICIENT_STORAGE;
    }
    the_server->nr_endpoints++;

    ULOG_INFO ("New endpoint stored: %s (%p), %d endpoints totally.\n",
            endpoint_name, endpoint, the_server->nr_endpoints);

    endpoint->host_name = strdup (host_name);
    endpoint->app_name = strdup (app_name);
    endpoint->runner_name = strdup (runner_name);
    endpoint->status = ES_READY;

    return HIBUS_SC_OK;
}

int handle_json_packet (BusServer* the_server, BusEndpoint* endpoint,
        const char* json, unsigned int len)
{
    int retv = HIBUS_SC_OK;
    hibus_json *jo = NULL, *jo_tmp;

    ULOG_INFO ("Handling packet: \n%s\n", json);

    jo = json_object_from_string (json, len, 2);
    if (jo == NULL) {
        retv = HIBUS_SC_UNPROCESSABLE_PACKET;
        goto failed;
    }

    if (json_object_object_get_ex (jo, "packetType", &jo_tmp)) {
        const char *pack_type;
        pack_type = json_object_get_string (jo_tmp);

        if (strcasecmp (pack_type, "auth") == 0) {
            if (endpoint->status == ES_AUTHING) {
                char buff [512];
                int n;

                assert (endpoint->sta_data);

                if ((retv = authenticate_endpoint (the_server, endpoint, jo)) !=
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
                            retv, hibus_get_error_message (retv));

                    if (n < sizeof (buff))
                        send_packet_to_endpoint (the_server, endpoint, buff);
                    goto failed;
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
                        the_server->server_name, endpoint->host_name);

                if (n < sizeof (buff))
                    send_packet_to_endpoint (the_server, endpoint, buff);
            }
            else {
                retv = HIBUS_SC_PRECONDITION_FAILED;
                goto failed;
            }
        }
    }
    else {
        retv = HIBUS_SC_BAD_REQUEST;
        goto failed;
    }

    return retv;

failed:
    if (jo)
        json_object_put (jo);

    return retv;
}

int register_procedure (BusEndpoint* endpoint, const char* method_name,
        const char* for_host, const char* for_app, method_handler handler)
{
    int retv = HIBUS_SC_OK;
    method_info *info;

    if (kvlist_get (&endpoint->method_list, method_name)) {
        return HIBUS_SC_CONFILCT;
    }

    if ((info = calloc (1, sizeof (method_info))) == NULL)
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

    if (!kvlist_set (&endpoint->method_list, method_name, &info)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    ULOG_INFO ("New procedure registered: @%s/%s/%s/%s (%p)\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            method_name, info);
    return HIBUS_SC_OK;

failed:
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    free (info);
    return retv;
}

int revoke_procedure (BusEndpoint* endpoint, const char* method_name)
{
    void *data;

    if ((data = kvlist_get (&endpoint->method_list, method_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    /* TODO: cancel pending calls
    method_info *info;
    info = *(method_info **)data;
    */

    kvlist_delete (&endpoint->method_list, method_name);
    return HIBUS_SC_OK;
}

int register_event (BusEndpoint* endpoint, const char* bubble_name,
        const char* for_host, const char* for_app)
{
    int retv = HIBUS_SC_OK;
    bubble_info *info;

    if (kvlist_get (&endpoint->bubble_list, bubble_name)) {
        return HIBUS_SC_CONFILCT;
    }

    if ((info = calloc (1, sizeof (bubble_info))) == NULL)
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

    if (!kvlist_set (&endpoint->bubble_list, bubble_name, &info)) {
        retv = HIBUS_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    ULOG_INFO ("New event registered: @%s/%s/%s/%s (%p)\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            bubble_name, info);
    return HIBUS_SC_OK;

failed:
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    free (info);
    return retv;
}

int revoke_event (BusEndpoint* endpoint, const char* bubble_name)
{
    void *data;

    if ((data = kvlist_get (&endpoint->bubble_list, bubble_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    /*
    bubble_info *info;
    info = *(bubble_info **)data;
    */

    kvlist_delete (&endpoint->bubble_list, bubble_name);
    return HIBUS_SC_OK;
}

int subscribe_event (BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint* subscriber)
{
    void *data;
    bubble_info *info;
    char endpoint_name [LEN_ENDPOINT_NAME + 1];

    if ((data = kvlist_get (&endpoint->bubble_list, bubble_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    assemble_endpoint_name (subscriber, endpoint_name);

    info = *(bubble_info **)data;
    if (kvlist_get (&info->subscriber_list, endpoint_name))
        return HIBUS_SC_CONFILCT;

    if (!kvlist_set (&info->subscriber_list, endpoint_name, &subscriber))
        return HIBUS_SC_INSUFFICIENT_STORAGE;

    return HIBUS_SC_OK;
}

int unsubscribe_event (BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint* subscriber)
{
    void *data;
    bubble_info *info;
    char endpoint_name [LEN_ENDPOINT_NAME + 1];

    if ((data = kvlist_get (&endpoint->bubble_list, bubble_name)) == NULL) {
        return HIBUS_SC_NOT_FOUND;
    }

    assemble_endpoint_name (subscriber, endpoint_name);

    info = *(bubble_info **)data;
    if (kvlist_get (&info->subscriber_list, endpoint_name))
        return HIBUS_SC_NOT_FOUND;

    kvlist_delete (&info->subscriber_list, endpoint_name);
    return HIBUS_SC_OK;
}

