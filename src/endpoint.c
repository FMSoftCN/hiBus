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

#include "endpoint.h"

extern BusServer the_server;

int new_endpoint (int type, void* client,
        const char* host_name, const char* app_name, const char* runner_name)
{
    return 0;
}

int del_endpoint (BusEndpoint* endpoint)
{
    return 0;
}

int auth_endpoint (BusEndpoint* endpoint)
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

