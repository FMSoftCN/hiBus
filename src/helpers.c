/*
** helpers.c -- The helpers for hiBus.
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

#include "hibus.h"

/* Error Codes and Error Messages */
#define UNKNOWN_ERR_CODE    "Unknown Error Code"

static struct  {
    int err_code;
    const char* err_msg;
} err_code_2_messages[] = {
    { HIBUS_SC_OK,                  /* 200 */
        "Ok" },
    { HIBUS_SC_ACCEPTED,            /* 202 */
        "Accepted" },
    { HIBUS_SC_BAD_REQUEST,         /* 400 */
        "Bad Request" },
    { HIBUS_SC_UNAUTHORIZED,        /* 401 */
        "Unauthorized" },
    { HIBUS_SC_FORBIDDEN,           /* 403 */
        "Forbidden" },
    { HIBUS_SC_NOT_FOUND,           /* 404 */
        "Not Found" },
    { HIBUS_SC_METHOD_NOT_ALLOWED,  /* 405 */
        "Method Not Allowed" },
    { HIBUS_SC_NOT_ACCEPTABLE,      /* 406 */
        "Not Acceptable" },
    { HIBUS_SC_CONFILCT,            /* 409 */
        "Confilct" },
    { HIBUS_SC_LOCKED,              /* 423 */
        "Locked" },
    { HIBUS_SC_INTERNAL_SERVER_ERROR,   /* 500 */
        "Internal Server Error" },
    { HIBUS_SC_NOT_IMPLEMENTED,     /* 501 */
        "Not Implemented" },
    { HIBUS_SC_BAD_GATEWAY,         /* 502 */
        "Bad Gateway" },
    { HIBUS_SC_SERVICE_UNAVAILABLE, /* 503 */
        "Service Unavailable" },
    { HIBUS_SC_GATEWAY_TIMEOUT,     /* 504 */
        "Gateway Timeout" },
    { HIBUS_SC_INSUFFICIENT_STORAGE,    /* 507 */
        "Insufficient Storage" },
};

#define TABLESIZE(table)    (sizeof(table)/sizeof(table[0]))

const char* hibus_get_error_message (int err_code)
{
    unsigned int lower = 0;
    unsigned int upper = TABLESIZE (err_code_2_messages) - 1;
    int mid = TABLESIZE (err_code_2_messages) / 2;

    if (err_code < err_code_2_messages[lower].err_code ||
            err_code > err_code_2_messages[upper].err_code)
        return UNKNOWN_ERR_CODE;

    do {
        if (err_code < err_code_2_messages[mid].err_code)
            upper = mid - 1;
        else if (err_code > err_code_2_messages[mid].err_code)
            lower = mid + 1;
        else
            return err_code_2_messages [mid].err_msg;

        mid = (lower + upper) / 2;

    } while (lower <= upper);

    return UNKNOWN_ERR_CODE;
}

