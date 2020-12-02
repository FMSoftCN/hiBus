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

#include <string.h>

#include <hibox/ulog.h>

#include "hibus.h"

/* Error Codes and Error Messages */
#define UNKNOWN_ERR_CODE    "Unknown Error Code"

static struct  {
    int err_code;
    const char* err_msg;
} err_code_2_messages[] = {
    { HIBUS_SC_IOERR,               /* 1 */
        "I/O Error" },
    { HIBUS_SC_OK,                  /* 200 */
        "Ok" },
    { HIBUS_SC_CREATED,             /* 201 */
        "Created" },
    { HIBUS_SC_ACCEPTED,            /* 202 */
        "Accepted" },
    { HIBUS_SC_NO_CONTENT,          /* 204 */
        "No Content" },
    { HIBUS_SC_RESET_CONTENT,       /* 205 */
        "Reset Content" },
    { HIBUS_SC_PARTIAL_CONTENT,     /* 206 */
        "Partial Content" },
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
    { HIBUS_SC_GONE,                /* 410 */
        "Gone" },
    { HIBUS_SC_PRECONDITION_FAILED, /* 412 */
        "Precondition Failed" },
    { HIBUS_SC_PACKET_TOO_LARGE,    /* 413 */
        "Packet Too Large" },
    { HIBUS_SC_EXPECTATION_FAILED,  /* 417 */
        "Expectation Failed" },
    { HIBUS_SC_IM_A_TEAPOT,         /* 418 */
        "I'm a teapot" },
    { HIBUS_SC_UNPROCESSABLE_PACKET,    /* 422 */
        "Unprocessable Packet" },
    { HIBUS_SC_LOCKED,              /* 423 */
        "Locked" },
    { HIBUS_SC_FAILED_DEPENDENCY,   /* 424 */
        "Failed Dependency" },
    { HIBUS_SC_FAILED_DEPENDENCY,   /* 425 */
        "Failed Dependency" },
    { HIBUS_SC_UPGRADE_REQUIRED,    /* 426 */
        "Upgrade Required" },
    { HIBUS_SC_RETRY_WITH,          /* 449 */
        "Retry With" },
    { HIBUS_SC_UNAVAILABLE_FOR_LEGAL_REASONS,   /* 451 */
        "Unavailable For Legal Reasons" },
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

hibus_json *json_object_from_string (const char* json, int len, int in_depth)
{
	struct printbuf *pb;
	struct json_object *obj = NULL;
	json_tokener *tok;

	if (!(pb = printbuf_new())) {
        ULOG_ERR ("Failed to allocate buffer for parse JSON.\n");
		return NULL;
	}

	if (in_depth < 0)
        in_depth = JSON_TOKENER_DEFAULT_DEPTH;

	tok = json_tokener_new_ex (in_depth);
	if (!tok) {
        ULOG_ERR ("Failed to create a new JSON tokener.\n");
		printbuf_free (pb);
		goto error;
	}

	printbuf_memappend (pb, json, len);
	obj = json_tokener_parse_ex (tok, pb->buf, printbuf_length (pb));
	if (obj == NULL) {
        ULOG_ERR ("Failed to parse JSON: %s\n",
                json_tokener_error_desc (json_tokener_get_error (tok)));
    }

	json_tokener_free(tok);

error:
	printbuf_free(pb);
	return obj;
}

int hibus_is_valid_token (const char* token, int max_len)
{
    int i;

    if (!isalpha (token [0]))
        return 0;

    i = 1;
    while (token [i]) {

        if (i > max_len)
            return 0;

        if (!isalnum (token [i]) && token [i] != '_')
            return 0;

        i++;
    }

    return 1;
}

/* @<host_name>/<app_name>/<runner_name> */
int hibus_extract_host_name (const char* endpoint, char* host_name)
{
    int len;
    char* slash;

    if (endpoint [0] != '@' || (slash = strchr (endpoint, '/')) == NULL)
        return 0;

    endpoint++;
    len = (uintptr_t)slash - (uintptr_t)endpoint;
    if (len <= 0 || len > LEN_APP_NAME)
        return 0;

    strncpy (host_name, endpoint, len);
    ULOG_INFO ("Extracted host name: %s\n", host_name);

    return len;
}

char* hibus_extract_host_name_alloc (const char* endpoint)
{
    char* host_name;
    if ((host_name = malloc (LEN_HOST_NAME + 1)) == NULL)
        return NULL;

    if (hibus_extract_host_name (endpoint, host_name) > 0)
        return host_name;

    free (host_name);
    return NULL;
}

/* @<host_name>/<app_name>/<runner_name> */
int hibus_extract_app_name (const char* endpoint, char* app_name)
{
    int len;
    char *first_slash, *second_slash;

    if (endpoint [0] != '@' || (first_slash = strchr (endpoint, '/')) == 0 ||
            (second_slash = strrchr (endpoint, '/')) == 0 ||
            first_slash == second_slash)
        return 0;

    first_slash++;
    len = (uintptr_t)second_slash - (uintptr_t)first_slash;
    if (len <= 0 || len > LEN_APP_NAME)
        return 0;

    strncpy (app_name, first_slash, len);
    ULOG_INFO ("Extracted app name: %s\n", app_name);

    return len;
}

char* hibus_extract_app_name_alloc (const char* endpoint)
{
    char* app_name;

    if ((app_name = malloc (LEN_APP_NAME + 1)) == NULL)
        return NULL;

    if (hibus_extract_app_name (endpoint, app_name) > 0)
        return app_name;

    free (app_name);
    return NULL;
}

int hibus_extract_runner_name (const char* endpoint, char* runner_name)
{
    int len;
    char *second_slash;

    if (endpoint [0] != '@' ||
            (second_slash = strrchr (endpoint, '/')) == 0)
        return 0;

    second_slash++;
    len = strlen (second_slash);
    if (len > LEN_RUNNER_NAME)
        return 0;

    strcpy (runner_name, second_slash);
    ULOG_INFO ("Extracted runner name: %s\n", runner_name);

    return len;
}

char* hibus_extract_runner_name_alloc (const char* endpoint)
{
    char* runner_name;

    if ((runner_name = malloc (LEN_RUNNER_NAME + 1)) == NULL)
        return NULL;

    if (hibus_extract_runner_name (endpoint, runner_name) > 0)
        return runner_name;

    free (runner_name);
    return NULL;
}

int hibus_assembly_endpoint (const char* host_name, const char* app_name,
        const char* runner_name, char* buff)
{
    int host_len, app_len, runner_len;

    if ((host_len = strlen (host_name)) > LEN_HOST_NAME)
        return 0;

    if ((app_len = strlen (app_name)) > LEN_APP_NAME)
        return 0;

    if ((runner_len = strlen (runner_name)) > LEN_RUNNER_NAME)
        return 0;

    buff [0] = '@';
    buff [1] = '\0';
    strcat (buff, host_name);
    buff [host_len + 1] = '/';

    strcat (buff, app_name);
    buff [host_len + app_len + 2] = '/';

    strcat (buff, runner_name);
    ULOG_INFO ("Assemblied endpoint: %s\n", buff);

    return host_len + app_len + runner_len + 3;
}

char* hibus_assembly_endpoint_alloc (const char* host_name, const char* app_name,
        const char* runner_name)
{
    char* endpoint;
    int host_len, app_len, runner_len;

    if ((host_len = strlen (host_name)) > LEN_HOST_NAME)
        return NULL;

    if ((app_len = strlen (app_name)) > LEN_APP_NAME)
        return NULL;

    if ((runner_len = strlen (runner_name)) > LEN_RUNNER_NAME)
        return NULL;

    if ((endpoint = malloc (host_len + app_len + runner_len + 4)) == NULL)
        return NULL;

    endpoint [0] = '@';
    endpoint [1] = '\0';
    strcat (endpoint, host_name);
    endpoint [host_len + 1] = '/';

    strcat (endpoint, app_name);
    endpoint [host_len + app_len + 2] = '/';

    strcat (endpoint, runner_name);
    ULOG_INFO ("Assemblied endpoint: %s\n", endpoint);

    return endpoint;
}

int hibus_is_valid_host_name (const char* host_name)
{
    return 1;
}

/* cn.fmsoft.hybridos.aaa */
int hibus_is_valid_app_name (const char* app_name)
{
    int len, max_len = LEN_APP_NAME;
    const char *start;
    char *end;

    start = app_name;
    while (*start) {
        char saved;
        end = strchr (start, '.');
        if (end == NULL) {
            saved = 0;
            end += strlen (start);
        }
        else {
            saved = '.';
            *end = 0;
        }

        if (end == start)
            return 0;

        if ((len = hibus_is_valid_token (start, max_len)) <= 0)
            return 0;

        max_len -= len;
        if (saved) {
            start = end + 1;
            *end = saved;
            max_len--;
        }
        else {
            break;
        }
    }

    return 1;
}

