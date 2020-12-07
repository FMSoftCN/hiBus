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

#ifndef _HIBUS_H_
#define _HIBUS_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>

#include <hibox/json.h>

/* Contants */
#define HIBUS_PROTOCOL_NAME             "HIBUS"
#define HIBUS_PROTOCOL_VERSION          90
#define HIBUS_MINIMAL_PROTOCOL_VERSION  90

#define HIBUS_US_PATH                   "/var/tmp/hibus.sock"
#define HIBUS_WS_PORT                   "7700"
#define HIBUS_WS_PORT_RESERVED          "7701"

#define HIBUS_LOCALHOST                 "localhost"
#define HIBUS_APP_SELF                  "self"
#define HIBUS_APP_HIBUS                 "cn.fmsoft.hybridos.hibus"
#define HIBUS_RUNNER_BUILITIN           "builtin"
#define HIBUS_RUNNER_CMDLINE            "cmdline"

#define HIBUS_NOT_AVAILABLE             "<N/A>"

#define HIBUS_PUBLIC_PEM_KEY_FILE       "/etc/public-keys/public-%s.pem"
#define HIBUS_PRIVATE_PEM_KEY_FILE      "/app/%s/private/private-%s.pem"
#define HIBUS_PRIVATE_HMAC_KEY_FILE     "/app/%s/private/hmac-%s.key"
#define HIBUS_LEN_PRIVATE_HMAC_KEY      64

/* Status Codes */
#define HIBUS_SC_IOERR                  1
#define HIBUS_SC_OK                     200
#define HIBUS_SC_CREATED                201
#define HIBUS_SC_ACCEPTED               202
#define HIBUS_SC_NO_CONTENT             204 
#define HIBUS_SC_RESET_CONTENT          205
#define HIBUS_SC_PARTIAL_CONTENT        206
#define HIBUS_SC_BAD_REQUEST            400
#define HIBUS_SC_UNAUTHORIZED           401
#define HIBUS_SC_FORBIDDEN              403
#define HIBUS_SC_NOT_FOUND              404
#define HIBUS_SC_METHOD_NOT_ALLOWED     405
#define HIBUS_SC_NOT_ACCEPTABLE         406
#define HIBUS_SC_CONFILCT               409
#define HIBUS_SC_GONE                   410
#define HIBUS_SC_PRECONDITION_FAILED    412
#define HIBUS_SC_PACKET_TOO_LARGE       413
#define HIBUS_SC_EXPECTATION_FAILED     417
#define HIBUS_SC_IM_A_TEAPOT            418 
#define HIBUS_SC_UNPROCESSABLE_PACKET   422
#define HIBUS_SC_LOCKED                 423
#define HIBUS_SC_FAILED_DEPENDENCY      424
#define HIBUS_SC_TOO_EARLY              425
#define HIBUS_SC_UPGRADE_REQUIRED       426
#define HIBUS_SC_RETRY_WITH             449
#define HIBUS_SC_UNAVAILABLE_FOR_LEGAL_REASONS             451
#define HIBUS_SC_INTERNAL_SERVER_ERROR  500
#define HIBUS_SC_NOT_IMPLEMENTED        501
#define HIBUS_SC_BAD_GATEWAY            502
#define HIBUS_SC_SERVICE_UNAVAILABLE    503
#define HIBUS_SC_GATEWAY_TIMEOUT        504
#define HIBUS_SC_INSUFFICIENT_STORAGE   507

#define HIBUS_EC_IO         (-1)
#define HIBUS_EC_CLOSED     (-2)
#define HIBUS_EC_NOMEM      (-3)
#define HIBUS_EC_TOO_LARGE  (-4)
#define HIBUS_EC_PROTOCOL   (-5)
#define HIBUS_EC_UPPER      (-6)

#define LEN_HOST_NAME       127
#define LEN_APP_NAME        127
#define LEN_RUNNER_NAME     63
#define LEN_METHOD_NAME     63
#define LEN_BUBBLE_NAME     63
#define LEN_ENDPOINT_NAME   (LEN_HOST_NAME + LEN_APP_NAME + LEN_RUNNER_NAME + 3)

/* the maximal size of a payload in a frame */
#define MAX_PAYLOAD_SIZE    4096    /* 4 KiB max frame payload size */
#define MAX_FRAME_SIZE      MAX_PAYLOAD_SIZE

/* the maximal size of a packet which will be held in memory */
#define MAX_INMEM_PACKET_SIZE   40960

typedef enum USOpcode_ {
    US_OPCODE_CONTINUATION = 0x00,
    US_OPCODE_TEXT = 0x01,
    US_OPCODE_BIN = 0x02,
    US_OPCODE_END = 0x03,
    US_OPCODE_CLOSE = 0x08,
    US_OPCODE_PING = 0x09,
    US_OPCODE_PONG = 0x0A,
} USOpcode;

typedef struct USFrameHeader_ {
    int op;
    unsigned int fragmented;
    unsigned int sz_payload;
    unsigned char payload[0];
} USFrameHeader;

/* connection types */
enum {
    CT_UNIX_SOCKET = 1,
    CT_WEB_SOCKET,
};

/* packet body types */
enum {
    PT_TEXT = 0,
    PT_BINARY,
};

/* JSON packet type */
enum {
    JPT_BAD_JSON = -1,
    JPT_UNKNOWN = 0,
    JPT_ERROR,
    JPT_AUTH,
    JPT_AUTH_PASSED,
    JPT_AUTH_FAILED,
    JPT_CALL,
    JPT_RESULT,
    JPT_EVENT,
};

struct _hibus_conn;
typedef struct _hibus_conn hibus_conn;

typedef struct json_object hibus_json;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * helper functions - implemented in helpers.c, for both server and clients.
 */
const char* hibus_get_error_message (int err_code);

hibus_json *json_object_from_string (const char* json, int len, int in_depth);

bool hibus_is_valid_token (const char* token, int max_len);
bool hibus_is_valid_host_name (const char* host_name);
bool hibus_is_valid_app_name (const char* app_name);

int hibus_extract_host_name (const char* endpoint, char* buff);
int hibus_extract_app_name (const char* endpoint, char* buff);
int hibus_extract_runner_name (const char* endpoint, char* buff);

char* hibus_extract_host_name_alloc (const char* endpoint);
char* hibus_extract_app_name_alloc (const char* endpoint);
char* hibus_extract_runner_name_alloc (const char* endpoint);

/* return the length of the endpoint name if success, <= 0 otherwise */
int hibus_assemble_endpoint_name (const char *host_name, const char *app_name,
        const char *runner_name, char *buff);
char* hibus_assemble_endpoint_name_alloc (const char* host_name, const char* app_name,
        const char* runner_name);

unsigned char *hibus_sign_data (const char *app_name,
        const unsigned char* data, unsigned int data_len,
        unsigned int *sig_len);

/* return > 0 if verified, = 0 if failes, < 0 when no such app. */
int hibus_verify_signature (const char* app_name,
        const unsigned char* data, unsigned int data_len,
        const unsigned char* sig, unsigned int sig_len);

/* parse the JSON packet and return the packet type and the JSON object */
int hibus_json_packet_to_object (const char* json, unsigned int json_len,
        hibus_json **jo);

/*
 * connection functions - implemented in libhibus.c, only for clients.
 */
int hibus_connect_via_unix_socket (const char* path_to_socket,
        const char* app_name, const char* runner_name, hibus_conn** conn);
int hibus_connect_via_web_socket (const char* host_name, int port,
        const char* app_name, const char* runner_name, hibus_conn** conn);
int hibus_disconnect (hibus_conn* conn);

const char* hibus_conn_srv_host_name (hibus_conn* conn);
const char* hibus_conn_own_host_name (hibus_conn* conn);
const char* hibus_conn_app_name (hibus_conn* conn);
const char* hibus_conn_runner_name (hibus_conn* conn);
int hibus_conn_endpoint_name (hibus_conn* conn, char *buff);
char *hibus_conn_endpoint_name_alloc (hibus_conn* conn);

int hibus_conn_socket_fd (hibus_conn* conn);
int hibus_conn_socket_type (hibus_conn* conn);

int hibus_read_packet (hibus_conn* conn, void* packet_buf, unsigned int *packet_len);
void* hibus_read_packet_alloc (hibus_conn* conn, unsigned int *packet_len);

int hibus_send_text_packet (hibus_conn* conn, const char* text, unsigned int txt_len);

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

int hibus_call_procedure (hibus_conn* conn,
        const char* endpoint, const char* method_name,
        const hibus_json* method_praram,
        time_t ret_time_expected, hibus_result_handler result_handler);

int hibus_call_procedure_and_wait (hibus_conn* conn, const char* endpoint,
        const char* method_name, const hibus_json* method_praram,
        time_t ret_time_expected, hibus_json** ret_value);

#ifdef __cplusplus
}
#endif

static inline int
hibus_is_valid_runner_name (const char* runner_name)
{
    return hibus_is_valid_token (runner_name, LEN_RUNNER_NAME);
}

static inline int
hibus_is_valid_method_name (const char* method_name)
{
    return hibus_is_valid_token (method_name, LEN_METHOD_NAME);
}

static inline int
hibus_is_valid_bubble_name (const char* bubble_name)
{
    return hibus_is_valid_token (bubble_name, LEN_BUBBLE_NAME);
}

static inline int
hibus_name_tolower (char* name)
{
    int i = 0;

    while (name [i]) {
        name [i] = tolower (name[i]);
        i++;
    }

    return i;
}

static inline int
hibus_name_toupper (char* name)
{
    int i = 0;

    while (name [i]) {
        name [i] = toupper (name[i]);
        i++;
    }

    return i;
}

#endif /* !_HIBUS_H_ */

