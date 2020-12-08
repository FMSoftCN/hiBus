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

static char *
builtin_method_echo (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    if (method_param) {
        return strdup (method_param);
    }

    return strdup ("ARE YOU JOKING ME?");
}

static char *
builtin_method_register_procedure (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_revoke_procedure (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_register_event (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_revoke_event (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_subscribe_event (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_unsubscribe_event (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_list_procedures (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_list_events (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

static char *
builtin_method_list_event_subscribers (BusEndpoint* from_endpoint,
        const char* method_name, const char* method_param, int* ret_code)
{
    return NULL;
}

bool init_builtin_endpoint (BusEndpoint* builtin)
{
    if (register_procedure (builtin, "echo",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_echo) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (builtin, "registerProcedure",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_register_procedure) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (builtin, "revokeProcedure",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_OWNER,
            builtin_method_revoke_procedure) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (builtin, "registerEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_register_event) != HIBUS_SC_OK) {
        return false;
    }
    if (register_procedure (builtin, "revokeEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_OWNER,
            builtin_method_revoke_event) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (builtin, "subscribeEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_ANY,
            builtin_method_subscribe_event) != HIBUS_SC_OK) {
        return false;
    }
    if (register_procedure (builtin, "unsubscribeEvent",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_OWNER,
            builtin_method_unsubscribe_event) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (builtin, "listProcedures",
            HIBUS_PATTERN_ANY, HIBUS_APP_HIBUS,
            builtin_method_list_procedures) != HIBUS_SC_OK) {
        return false;
    }
    if (register_procedure (builtin, "listEvents",
            HIBUS_PATTERN_ANY, HIBUS_APP_HIBUS,
            builtin_method_list_events) != HIBUS_SC_OK) {
        return false;
    }

    if (register_procedure (builtin, "listEventSubscribers",
            HIBUS_PATTERN_ANY, HIBUS_PATTERN_OWNER ", ;" HIBUS_APP_HIBUS,
            builtin_method_list_event_subscribers) != HIBUS_SC_OK) {
        return false;
    }

    if (register_event (builtin, "newEndpoint",
            HIBUS_PATTERN_ANY, HIBUS_SYS_APPS) != HIBUS_SC_OK) {
        return false;
    }
    if (register_event (builtin, "brokenEndpoint",
            HIBUS_PATTERN_ANY, HIBUS_SYS_APPS) != HIBUS_SC_OK) {
        return false;
    }

    ULOG_INFO ("The builtin procedures and events have been registered.\n");

    return true;
}

bool fire_system_event (BusServer* bus_srv, int bubble_type,
        BusEndpoint* cause, BusEndpoint* to, const char* add_msg)
{
    return true;
}

