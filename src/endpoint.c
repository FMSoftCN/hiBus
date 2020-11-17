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

#include "endpoint.h"
#include "unixsocket.h"
#include "websocket.h"

static int get_len_string (struct kvlist *kv, const void *data)
{
    return strlen (data);
}

BusEndpoint* new_endpoint (BusServer* the_server, int type, void* client)
{
    BusEndpoint* endpoint = NULL;

    endpoint = (BusEndpoint *)calloc (sizeof (BusEndpoint), 1);
    if (endpoint == NULL)
        return NULL;

    endpoint->type = type;
    endpoint->status = ES_AUTHING;
    endpoint->usc = client;

    endpoint->host_name = NULL;
    endpoint->app_name = NULL;
    endpoint->runner_name = NULL;

    kvlist_init (&endpoint->method_list, get_len_string);
    kvlist_init (&endpoint->bubble_list, get_len_string);
    INIT_SAFE_LIST (&endpoint->pending_calling);

    if (type == ET_UNIX_SOCKET) {
        USClient* usc = (USClient*)client;
        usc->priv_data = endpoint;
    }
    else if (type == ET_WEB_SOCKET) {
        WSClient* wsc = (WSClient*)client;
        wsc->priv_data = endpoint;
    }
    else {
        assert (0);
    }

    return endpoint;
}

int del_endpoint (BusServer* the_server, BusEndpoint* endpoint)
{
    if (endpoint->host_name == NULL)
        goto free;

    // remove from avl list.

free:
    free (endpoint);
    return 0;
}

int send_challenge_code (BusServer* the_server, BusEndpoint* endpoint)
{
    char ch_code[SHA256_DIGEST_SIZE + 1];
    char key[32];

    snprintf (key, sizeof (key), "hibus-%ld", random ());

    hmac_sha256 ((uint8_t*)ch_code,
            (uint8_t*)HIBUS_APP_HIBUS, strlen (HIBUS_APP_HIBUS),
            (uint8_t*)key, strlen (key));
    ch_code [SHA256_DIGEST_SIZE] = 0;

    ULOG_INFO ("Challenge code for new endpoint: %s\n", ch_code);

    return HIBUS_SC_OK;
}

int check_auth_info (BusServer* the_server, BusEndpoint* endpoint)
{
    return HIBUS_SC_OK;
}

int register_procedure (BusEndpoint* endpoint, const char* method_name,
        const char* for_host, const char* for_app, builtin_method_handler handler)
{
    return HIBUS_SC_OK;
}

int revoke_procedure (BusEndpoint* endpoint, const char* method_name)
{
    return HIBUS_SC_OK;
}

int register_event (BusEndpoint* endpoint, const char* bubble_name,
        const char* for_host, const char* for_app)
{
    return HIBUS_SC_OK;
}

int revoke_event (BusEndpoint* endpoint, const char* bubble_name)
{
    return HIBUS_SC_OK;
}

int subscribe_event (BusEndpoint* endpoint, const char* event_name)
{
    return HIBUS_SC_OK;
}

int unsubscribe_event (BusEndpoint* endpoint, const char* event_name)
{
    return HIBUS_SC_OK;
}

