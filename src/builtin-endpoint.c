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

static hibus_json *
builtin_method_register_procedure (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_revoke_procedure (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_register_event (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_revoke_event (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_subscribe_event (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_unsubscribe_event (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_list_procedures (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_list_events (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

static hibus_json *
builtin_method_list_event_subscribers (BusEndpoint* from_endpoint,
        const char* method_name, const hibus_json* method_param)
{
    return NULL;
}

bool init_builtin_endpoint (BusEndpoint* builtin)
{
    register_procedure (builtin, "registerProcedure",
            HIBUS_HOST_ANY, HIBUS_APP_ANY,
            builtin_method_register_procedure);
    register_procedure (builtin, "revokeProcedure",
            HIBUS_HOST_ANY, HIBUS_APP_SELF,
            builtin_method_revoke_procedure);

    register_procedure (builtin, "registerEvent",
            HIBUS_HOST_ANY, HIBUS_APP_ANY,
            builtin_method_register_event);
    register_procedure (builtin, "revokeEvent",
            HIBUS_HOST_ANY, HIBUS_APP_SELF,
            builtin_method_revoke_event);

    register_procedure (builtin, "subscribeEvent",
            HIBUS_HOST_ANY, HIBUS_APP_ANY,
            builtin_method_subscribe_event);
    register_procedure (builtin, "unsubscribeEvent",
            HIBUS_HOST_ANY, HIBUS_APP_SELF,
            builtin_method_unsubscribe_event);

    register_procedure (builtin, "listProcedures",
            HIBUS_HOST_ANY, HIBUS_APP_HIBUS,
            builtin_method_list_procedures);
    register_procedure (builtin, "listEvents",
            HIBUS_HOST_ANY, HIBUS_APP_HIBUS,
            builtin_method_list_events);

    register_procedure (builtin, "listEventSubscribers",
            HIBUS_HOST_ANY, HIBUS_APP_SELF,
            builtin_method_list_event_subscribers);

    return true;
}

