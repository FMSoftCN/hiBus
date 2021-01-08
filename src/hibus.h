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
#include <time.h>

#include <hibox/json.h>

/* Constants */
#define HIBUS_PROTOCOL_NAME             "HIBUS"
#define HIBUS_PROTOCOL_VERSION          90
#define HIBUS_MINIMAL_PROTOCOL_VERSION  90

#define HIBUS_US_PATH                   "/var/tmp/hibus.sock"
#define HIBUS_WS_PORT                   "7700"
#define HIBUS_WS_PORT_RESERVED          "7701"

#define HIBUS_PATTERN_VAR_SELF          "self"
#define HIBUS_PATTERN_VAR_OWNER         "owner"

#define HIBUS_PATTERN_ANY               "*"
#define HIBUS_PATTERN_SELF              "$self"
#define HIBUS_PATTERN_OWNER             "$owner"

#define HIBUS_LOCALHOST                 "localhost"
#define HIBUS_APP_HIBUS                 "cn.fmsoft.hybridos.hibus"
#define HIBUS_SYS_APPS                  "cn.fmsoft.hybridos.*"
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
#define HIBUS_SC_CONFLICT               409
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
#define HIBUS_SC_BAD_CALLEE             502
#define HIBUS_SC_SERVICE_UNAVAILABLE    503
#define HIBUS_SC_CALLEE_TIMEOUT         504
#define HIBUS_SC_INSUFFICIENT_STORAGE   507

#define HIBUS_EC_IO                     (-1)
#define HIBUS_EC_CLOSED                 (-2)
#define HIBUS_EC_NOMEM                  (-3)
#define HIBUS_EC_TOO_LARGE              (-4)
#define HIBUS_EC_PROTOCOL               (-5)
#define HIBUS_EC_UPPER                  (-6)
#define HIBUS_EC_NOT_IMPLEMENTED        (-7)
#define HIBUS_EC_INVALID_VALUE          (-8)
#define HIBUS_EC_DUPLICATED             (-9)
#define HIBUS_EC_TOO_SMALL_BUFF         (-10)
#define HIBUS_EC_BAD_SYSTEM_CALL        (-11)
#define HIBUS_EC_AUTH_FAILED            (-12)
#define HIBUS_EC_SERVER_ERROR           (-13)
#define HIBUS_EC_TIMEOUT                (-14)
#define HIBUS_EC_UNKNOWN_EVENT          (-15)
#define HIBUS_EC_UNKNOWN_RESULT         (-16)
#define HIBUS_EC_UNKNOWN_METHOD         (-17)
#define HIBUS_EC_UNEXPECTED             (-18)
#define HIBUS_EC_SERVER_REFUSED         (-19)
#define HIBUS_EC_BAD_PACKET             (-20)
#define HIBUS_EC_BAD_CONNECTION         (-21)
#define HIBUS_EC_CANT_LOAD              (-22)
#define HIBUS_EC_BAD_KEY                (-23)

#define HIBUS_LEN_HOST_NAME             127
#define HIBUS_LEN_APP_NAME              127
#define HIBUS_LEN_RUNNER_NAME           63
#define HIBUS_LEN_METHOD_NAME           63
#define HIBUS_LEN_BUBBLE_NAME           63
#define HIBUS_LEN_ENDPOINT_NAME         \
    (HIBUS_LEN_HOST_NAME + HIBUS_LEN_APP_NAME + HIBUS_LEN_RUNNER_NAME + 3)
#define HIBUS_LEN_UNIQUE_ID             63

#define HIBUS_MIN_PACKET_BUFF_SIZE      512
#define HIBUS_DEF_PACKET_BUFF_SIZE      1024
#define HIBUS_DEF_TIME_EXPECTED         5   /* 5 seconds */

/* the maximal size of a payload in a frame (4KiB) */
#define HIBUS_MAX_FRAME_PAYLOAD_SIZE    4096

/* the maximal size of a payload which will be held in memory (40KiB) */
#define HIBUS_MAX_INMEM_PAYLOAD_SIZE    40960

/* the maximal no responding time (90 seconds) */
#define HIBUS_MAX_NO_RESPONDING_TIME    90

/* Connection types */
enum {
    CT_UNIX_SOCKET = 1,
    CT_WEB_SOCKET,
};

/* The frame operation codes for UnixSocket */
typedef enum USOpcode_ {
    US_OPCODE_CONTINUATION = 0x00,
    US_OPCODE_TEXT = 0x01,
    US_OPCODE_BIN = 0x02,
    US_OPCODE_END = 0x03,
    US_OPCODE_CLOSE = 0x08,
    US_OPCODE_PING = 0x09,
    US_OPCODE_PONG = 0x0A,
} USOpcode;

/* The frame header for UnixSocket */
typedef struct USFrameHeader_ {
    int op;
    unsigned int fragmented;
    unsigned int sz_payload;
    unsigned char payload[0];
} USFrameHeader;

/* packet body types */
enum {
    PT_TEXT = 0,
    PT_BINARY,
};

/* JSON packet types */
enum {
    JPT_BAD_JSON = -1,
    JPT_UNKNOWN = 0,
    JPT_ERROR,
    JPT_AUTH,
    JPT_AUTH_PASSED,
    JPT_AUTH_FAILED,
    JPT_CALL,
    JPT_RESULT,
    JPT_RESULT_SENT,
    JPT_EVENT,
    JPT_EVENT_SENT,
};

struct _hibus_conn;
typedef struct _hibus_conn hibus_conn;

typedef struct json_object hibus_json;

struct _hibus_pattern_list;
typedef struct _hibus_pattern_list hibus_pattern_list;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * helper functions - implemented in helpers.c, for both server and clients.
 */

/**
 * hibus_get_ret_message:
 * @ret_code: the return code.
 *
 * Returns the pointer to the message string of the specific return code.
 *
 * Returns: a pointer to the message string.
 *
 * Since: 1.0
 */
const char* hibus_get_ret_message (int ret_code);

/**
 * hibus_get_err_message:
 * @err_code: the error code.
 *
 * Returns the pointer to the message string of the specific error code.
 *
 * Returns: a pointer to the message string.
 *
 * Since: 1.0
 */
const char* hibus_get_err_message (int err_code);

/**
 * hibus_errcode_to_retcode:
 * @err_code: the internal error code of hiBus.
 *
 * Returns the return code of the hiBus protocol according to
 * the internal error code.
 *
 * Returns: the return code of hiBus protocol.
 *
 * Since: 1.0
 */
int hibus_errcode_to_retcode (int err_code);

/**
 * hibus_json_object_from_string:
 * @json: the pointer to the JSON string.
 * @len: the length of the JSON string. If it is equal to or less then 0,
 *      the function will get the whole length of the string by calling
 *      strlen().
 * @depth: the maximal nesting depth for the JSON tokenzer.
 *
 * Parses a JSON string and returns a JSON object.
 *
 * Returns: A valid JSON object if success, NULL otherwise.
 *
 * Note that the caller should release the JSON object by calling
 * json_object_put().
 *
 * Since: 1.0
 */
hibus_json *hibus_json_object_from_string (const char* json, int len, int depth);

/**
 * hibus_is_valid_token:
 * @token: the pointer to the token string.
 * @max_len: The maximal possible length of the token string.
 *
 * Checks whether a token string is valid. According to hiBus protocal,
 * the runner name, method name, bubble name should be a valid token.
 *
 * Note that a string with a length longer than @max_len will
 * be considered as an invalid token.
 *
 * Returns: true for a valid token, otherwise false.
 *
 * Since: 1.0
 */
bool hibus_is_valid_token (const char* token, int max_len);

/**
 * hibus_is_valid_wildcard_pattern_list:
 * @pattern_list: the pointer to the wildcard pattern list such as
 * "*, com.example.?; $self, !com.foo.bar.*".
 *
 * Checks whether a wildcard pattern list string is valid. According to
 * hiBus protocal, you can use wildcard pattern list to define
 * the access control list of a method or event.
 *
 * Returns: true for a valid wildcard pattern list, otherwise false.
 *
 * Since: 1.0
 */
bool hibus_is_valid_wildcard_pattern_list (const char* pattern_list);

/**
 * hibus_is_valid_host_name:
 * @host_name: the pointer to a string contains a host name.
 *
 * Checks whether a host name is valid.
 *
 * Returns: true for a valid host name, otherwise false.
 *
 * Since: 1.0
 */
bool hibus_is_valid_host_name (const char* host_name);

/**
 * hibus_is_valid_app_name:
 * @app_name: the pointer to a string contains an app name.
 *
 * Checks whether an app name is valid.
 *
 * Returns: true for a valid app name, otherwise false.
 *
 * Since: 1.0
 */
bool hibus_is_valid_app_name (const char* app_name);

/**
 * hibus_is_valid_endpoint_name:
 * @endpoint_name: the pointer to a string contains an endpoint name.
 *
 * Checks whether an enpoint name is valid. According to hiBus
 * protocol, a valid endpoint name should having the following pattern:
 *
 *  @<host_name>/<app_name>/<runner_name>
 *
 * Returns: true for a valid endpoint name, otherwise false.
 *
 * Since: 1.0
 */
bool hibus_is_valid_endpoint_name (const char* endpoint_name);

/**
 * hibus_extract_host_name:
 * @endpoint: the pointer to a string contains an endpoint name.
 * @buff: the buffer used to return the host name in the endpoint name.
 *
 * Extracts the part of host name from an endpoint name.
 *
 * Note that the buffer should be large enough to contain a host name.
 * See @HIBUS_LEN_HOST_NAME.
 *
 * Returns: the length of the host name; <= 0 means @endpoint contains
 * an invalid endpoint name.
 *
 * Since: 1.0
 */
int hibus_extract_host_name (const char* endpoint, char* buff);

/**
 * hibus_extract_app_name:
 * @endpoint: the pointer to a string contains an endpoint name.
 * @buff: the buffer used to return the sub-string of app name in
 * the endpoint name.
 *
 * Extracts the part of app name from an endpoint name.
 *
 * Returns: the length of the app name; <= 0 means @endpoint contains
 * an invalid endpoint name.
 *
 * Since: 1.0
 */
int hibus_extract_app_name (const char* endpoint, char* buff);

/**
 * hibus_extract_runner_name:
 * @endpoint: the pointer to a string contains an endpoint name.
 * @buff: the buffer used to return the sub-string of runner name in
 * the endpoint name.
 *
 * Extracts the part of runner name from an endpoint name.
 *
 * Returns: the length of the runner name; <= 0 means @endpoint contains
 * an invalid endpoint name.
 *
 * Since: 1.0
 */
int hibus_extract_runner_name (const char* endpoint, char* buff);

/**
 * hibus_extract_host_name_alloc:
 * @endpoint: the pointer to a string contains an endpoint name.
 *
 * Extracts the part of host name from an endpoint name,
 * allocates a new buffer, copies the host name to the buffer,
 * and returns the pointer to the buffer.
 * 
 * Note that the caller is responsible for releasing the buffer.
 *
 * Returns: the pointer to the new buffer contains the host name if success;
 * NULL for an invalid endpoint name.
 *
 * Since: 1.0
 */
char* hibus_extract_host_name_alloc (const char* endpoint);

/**
 * hibus_extract_app_name_alloc:
 * @endpoint: the pointer to a string contains an endpoint name.
 *
 * Extracts the part of app name from an endpoint name,
 * allocates a new buffer, copies the app name to the buffer,
 * and returns the pointer to the buffer.
 * 
 * Note that the caller is responsible for releasing the buffer.
 *
 * Returns: the pointer to the new buffer contains the app name if success;
 * NULL for an invalid endpoint name.
 *
 * Since: 1.0
 */
char* hibus_extract_app_name_alloc (const char* endpoint);

/**
 * hibus_extract_runner_name_alloc:
 * @endpoint: the pointer to a string contains an endpoint name.
 *
 * Extracts the part of runner name from an endpoint name,
 * allocates a new buffer, copies the runner name to the buffer,
 * and returns the pointer to the buffer.
 * 
 * Note that the caller is responsible for releasing the buffer.
 *
 * Returns: the pointer to the new buffer contains the runner name if success;
 * NULL for an invalid endpoint name.
 *
 * Since: 1.0
 */
char* hibus_extract_runner_name_alloc (const char* endpoint);

/**
 * hibus_assemble_endpoint_name:
 * @host_name: the pointer to a string contains the host name.
 * @app_name: the pointer to a string contains the app name.
 * @runner_name: the pointer to a string contains the runner name.
 * @buff: the buffer used to return the endpoint name string.
 *
 * Assembles an endpoint name from a host name, app name, and
 * runner name.
 * 
 * Note that the caller should prepare the buffer (@buff) to
 * return the assembled endpoint name.
 *
 * Returns: the lenght of the endpoint name if succes; <= 0
 * if one of the host name, the app name, and the runner name
 * is invalid.
 *
 * Since: 1.0
 */
int hibus_assemble_endpoint_name (const char *host_name, const char *app_name,
        const char *runner_name, char *buff);

/**
 * hibus_assemble_endpoint_name_alloc:
 * @host_name: the pointer to a string contains the host name.
 * @app_name: the pointer to a string contains the app name.
 * @runner_name: the pointer to a string contains the runner name.
 *
 * Assembles an endpoint name from a host name, app name, and
 * runner name, and returns it in a new allocated buffer.
 * 
 * Note that the caller is responsible for releasing the buffer.
 *
 * Returns: the pointer to the new buffer contains the endpoint name
 * if success; NULL otherwise.
 *
 * Since: 1.0
 */
char* hibus_assemble_endpoint_name_alloc (const char* host_name,
        const char* app_name, const char* runner_name);

/**
 * hibus_sign_data:
 * @app_name: the pointer to a string contains the app name.
 * @data: the pointer to the data will be signed.
 * @data_len: the length of the data in bytes.
 * @sig: the pointer to a buffer for returning
 *      the pointer to the newly allocated signature if success.
 * @sig_len: the pointer to an unsigned integer for returning the length
 *      of the signature.
 *
 * Signs the specified data with the private key of a specific app
 * and returns the signature.
 * 
 * Note that the caller is responsible for releasing the buffer of
 * the signature.
 *
 * Returns: zero if success; an error code (<0) otherwise.
 *
 * Since: 1.0
 */
int hibus_sign_data (const char *app_name,
        const unsigned char* data, unsigned int data_len,
        unsigned char **sig, unsigned int *sig_len);

/**
 * hibus_verify_signature:
 * @app_name: the pointer to a string contains the app name.
 * @data: the pointer to the data will be verified.
 * @data_len: the length of the data in bytes.
 * @sig: the pointer to the signature.
 * @sig_len: the length of the signature.
 *
 * Signs the specified data with the private key of a specific app
 * and returns the signature.
 * 
 * Note that the caller is responsible for releasing the buffer of
 * the signature.
 *
 * Returns: 1 if verified, 0 if cannot verify the signature; an error code
 * which is less than 0 means something wrong.
 *
 * Since: 1.0
 */
int hibus_verify_signature (const char* app_name,
        const unsigned char* data, unsigned int data_len,
        const unsigned char* sig, unsigned int sig_len);

/**
 * hibus_json_packet_to_object:
 * @json: the string contains the JSON text.
 * @json_len: the length of the JSON text.
 * @jo: a pointer to hibus_json* for returning the json object.
 *
 * Parses a text packet in JSON format, returns the packet type and
 * a hibus_json object.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that the caller is responsible for releasing the json object.
 *
 * Since: 1.0
 */
int hibus_json_packet_to_object (const char* json, unsigned int json_len,
        hibus_json **jo);

/**
 * hibus_generate_unique_id:
 * @id_buff: the buffer to save the identifier.
 * @prefix: the prefix used for the identifier.
 *
 * Generates a unique id; the size of @id_buff should be at least 64 long.
 *
 * Returns: none.
 *
 * Since: 1.0
 */
void hibus_generate_unique_id (char* id_buff, const char* prefix);

/**
 * hibus_generate_md5_id:
 * @id_buff: the buffer to save the identifier.
 * @prefix: the prefix used for the identifier.
 *
 * Generates a unique id by using MD5 digest algorithm.
 * The size of @id_buff should be at least 33 bytes long.
 *
 * Returns: none.
 *
 * Since: 1.0
 */
void hibus_generate_md5_id (char* id_buff, const char* prefix);

/**
 * hibus_is_valid_unique_id:
 * @id: the unique identifier.
 *
 * Checks whether a unique id is valid.
 *
 * Returns: none.
 *
 * Since: 1.0
 */
bool hibus_is_valid_unique_id (const char* id);

/**
 * hibus_is_valid_md5_id:
 * @id: the unique identifier.
 *
 * Checks whether a unique identifier is valid.
 *
 * Returns: none.
 *
 * Since: 1.0
 */
bool hibus_is_valid_md5_id (const char* id);

/**
 * hibus_get_elapsed_seconds:
 * @ts1: the earlier time.
 * @ts2 (nullable): the later time.
 *
 * Calculates the elapsed seconds between two times.
 * If @ts2 is NULL, the function uses the current time.
 *
 * Returns: the elapsed time in seconds (a double).
 *
 * Since: 1.0
 */
double hibus_get_elapsed_seconds (const struct timespec *ts1, const struct timespec *ts2);

/**
 * hibus_escape_string_for_json:
 * @str: the string to escape.
 *
 * Escapes a string for JSON.
 *
 * Returns: A newly allocated string which contains the escaped string.
 *
 * Note that the caller is responsible for releasing the escaped string.
 *
 * Since: 1.0
 */
char* hibus_escape_string_for_json (const char* str);

/*
 * connection functions - implemented in libhibus.c, only for clients.
 */

/**
 * hibus_connect_via_unix_socket:
 * @path_to_socket: the path to the unix socket.
 * @app_name: the app name.
 * @runner_name: the runner name.
 * @conn: the pointer to a hibus_conn* to return the hiBus connection.
 *
 * Connects to a hiBus server via WebSocket.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_connect_via_unix_socket (const char* path_to_socket,
        const char* app_name, const char* runner_name, hibus_conn** conn);

/**
 * hibus_connect_via_web_socket:
 * @srv_host_name: the host name of the server.
 * @port: the port.
 * @app_name: the app name.
 * @runner_name: the runner name.
 * @conn: the pointer to a hibus_conn* to return the hiBus connection.
 *
 * Connects to a hiBus server via WebSocket.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that this function is not implemented so far.
 */
int hibus_connect_via_web_socket (const char* srv_host_name, int port,
        const char* app_name, const char* runner_name, hibus_conn** conn);

/**
 * hibus_disconnect:
 * @conn: the pointer to the hiBus connection.
 *
 * Disconnects the hiBus connection.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_disconnect (hibus_conn* conn);

/**
 * hibus_free_connection:
 * @conn: the pointer to the hiBus connection.
 *
 * Frees the space used by the connection, including the connection itself.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_free_connection (hibus_conn* conn);

/**
 * hibus_error_handler:
 * The prototype of an error handler.
 *
 * @conn: the pointer to the hiBus connection.
 * @jo: the json object contains the error information.
 *
 * Since: 1.0
 */
typedef void (*hibus_error_handler)(hibus_conn* conn, const hibus_json *jo);

/**
 * hibus_conn_get_error_handler:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the current error handler of the hiBus connection.
 *
 * Since: 1.0
 */
hibus_error_handler hibus_conn_get_error_handler (hibus_conn* conn);

/**
 * hibus_conn_set_error_handler:
 * @conn: the pointer to the hiBus connection.
 * @error_handler: the new error handler.
 *
 * Sets the error handler of the hiBus connection, and returns the old one.
 *
 * Since: 1.0
 */
hibus_error_handler hibus_conn_set_error_handler (hibus_conn* conn,
        hibus_error_handler error_handler);

/**
 * hibus_conn_get_user_data:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the current user data (a pointer) bound with the hiBus connection.
 *
 * Since: 1.0
 */
void *hibus_conn_get_user_data (hibus_conn* conn);

/**
 * hibus_conn_set_user_data:
 * @conn: the pointer to the hiBus connection.
 * @user_data: the new user data (a pointer).
 *
 * Sets the user data of the hiBus connection, and returns the old one.
 *
 * Since: 1.0
 */
void *hibus_conn_set_user_data (hibus_conn* conn, void* user_data);

/**
 * hibus_conn_get_last_ret_code:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the last return code of hiBus result or error packet.
 *
 * Since: 1.0
 */
int hibus_conn_get_last_ret_code (hibus_conn* conn);

/**
 * hibus_conn_srv_host_name:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the host name of the hiBus server.
 *
 * Since: 1.0
 */
const char* hibus_conn_srv_host_name (hibus_conn* conn);

/**
 * hibus_conn_own_host_name:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the host name of the current hiBus client.
 *
 * Since: 1.0
 */
const char* hibus_conn_own_host_name (hibus_conn* conn);

/**
 * hibus_conn_app_name:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the app name of the current hiBus client.
 *
 * Since: 1.0
 */
const char* hibus_conn_app_name (hibus_conn* conn);

/**
 * hibus_conn_runner_name:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the runner name of the current hiBus client.
 *
 * Since: 1.0
 */
const char* hibus_conn_runner_name (hibus_conn* conn);

/**
 * hibus_conn_endpoint_name:
 * @conn: the pointer to the hiBus connection.
 * @buff: the pointer to a buffer to contain the endpoint name.
 *
 * Gets the endpoint name of the hiBus connection and
 * returns the length of the endpoint name.
 *
 * Returns: the length of the endpoint name; <= 0 means error.
 *
 * Note that the buffer should be long enough, see @HIBUS_LEN_ENDPOINT_NAME.
 *
 * Since: 1.0
 */
int hibus_conn_endpoint_name (hibus_conn* conn, char *buff);

/**
 * hibus_conn_endpoint_name_alloc:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns a copy of the endpoint name of the hiBus connection.
 *
 * Returns: a pointer to the string contains the endpoint name;
 *  NULL for error.
 *
 * Note that the caller is responsible for releasing the buffer.
 *
 * Since: 1.0
 */
char *hibus_conn_endpoint_name_alloc (hibus_conn* conn);

/**
 * hibus_conn_socket_fd:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the file descriptor of the hiBus connection socket.
 *
 * Returns: the file descriptor.
 *
 * Since: 1.0
 */
int hibus_conn_socket_fd (hibus_conn* conn);

/**
 * hibus_conn_socket_type:
 * @conn: the pointer to the hiBus connection.
 *
 * Returns the socket type of the hiBus connection.
 *
 * Returns: @CT_UNIX_SOCKET for UnixSocket, and @CT_WEB_SOCKET for WebSocket.
 *
 * Since: 1.0
 */
int hibus_conn_socket_type (hibus_conn* conn);

/**
 * hibus_read_packet:
 * @conn: the pointer to the hiBus connection.
 * @packet_buf: the pointer to a buffer for saving the contents of the packet.
 * @packet_len: the pointer to a unsigned integer for returning
 *      the length of the packet.
 *
 * Reads a packet and saves the contents of the packet and returns
 * the length of the packet.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that you use this function only if you know the length of
 * the next packet, and have a long enough buffer to save the
 * contents of the packet.
 *
 * Since: 1.0
 */
int hibus_read_packet (hibus_conn* conn, void* packet_buf, unsigned int *packet_len);

/**
 * hibus_read_packet_alloc:
 * @conn: the pointer to the hiBus connection.
 * @packet: the pointer to a pointer to a buffer for returning
 *      the contents of the packet.
 * @packet_len: the pointer to a unsigned integer for returning
 *      the length of the packet.
 *
 * Reads a packet and allocates a buffer for the contents of the packet
 * and returns the contents and the length.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that the caller is responsible for releasing the buffer.
 *
 * Since: 1.0
 */
int hibus_read_packet_alloc (hibus_conn* conn, void **packet, unsigned int *packet_len);

/**
 * hibus_send_text_packet:
 * @conn: the pointer to the hiBus connection.
 * @text: the pointer to the text to send.
 * @txt_len: the length to send.
 *
 * Sends a text packet to the hiBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_send_text_packet (hibus_conn* conn, const char* text, unsigned int txt_len);

/**
 * hibus_ping_server:
 * @conn: the pointer to the hiBus connection.
 *
 * Pings the hiBus server. The client should ping the server
 * about every 30 seconds to tell the server "I am alive".
 * According to the hiBus protocol, the server may consider
 * a client died if there was no any data from the client
 * for 90 seconds.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_ping_server (hibus_conn* conn);

/**
 * hibus_method_handler:
 * The prototype of a method handler.
 *
 * @conn: the pointer to the hiBus connection.
 * @from_endpoint: the endpoint name emited the call.
 * @to_method: the method name of the call.
 * @method_param: the method parameter (a string).
 * @err_code: the pointer to an integer for the error code.
 *
 * Returns: the return value (a string) if @err_code contains 0.
 *
 * Since: 1.0
 */
typedef char* (*hibus_method_handler)(hibus_conn* conn,
        const char* from_endpoint, const char* to_method,
        const char* method_param, int *err_code);

/**
 * hibus_register_procedure:
 * @conn: the pointer to the hiBus connection.
 * @method_name: the method name of the procedure.
 * @for_host: the pattern list for allowed hosts.
 * @for_app: the pattern list for allowed apps.
 * @method_handler: the local method handler for this procedure.
 *
 * Registers an procedure to the hiBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_register_procedure (hibus_conn* conn, const char* method_name,
        const char* for_host, const char* for_app,
        hibus_method_handler method_handler);

/**
 * hibus_revoke_procedure:
 * @conn: the pointer to the hiBus connection.
 * @method_name: the method name of the procedure.
 *
 * Revokes an procedure from the hiBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_revoke_procedure (hibus_conn* conn, const char* method_name);

/**
 * hibus_register_event:
 * @conn: the pointer to the hiBus connection.
 * @bubble_name: the bubble name of the event.
 * @for_host: the pattern list for allowed hosts.
 * @for_app: the pattern list for allowed apps.
 *
 * Registers an event to the hiBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_register_event (hibus_conn* conn, const char* bubble_name,
        const char* for_host, const char* for_app);

/**
 * hibus_revoke_event:
 * @conn: the pointer to the hiBus connection.
 * @bubble_name: the bubble name of the event.
 *
 * Revokes an event from the hiBus server.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_revoke_event (hibus_conn* conn, const char* bubble_name);

/**
 * hibus_fire_event:
 * @conn: the pointer to the hiBus connection.
 * @bubble_name: the bubble name of the event.
 * @bubble_data: the bubble data (a string) of the event.
 *
 * Fires an event for the specified bubble name.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_fire_event (hibus_conn* conn,
        const char* bubble_name, const char* bubble_data);

/**
 * hibus_event_handler:
 * The prototype of an event handler.
 *
 * @conn: the pointer to the hiBus connection.
 * @from_endpoint: the endpoint name of the event.
 * @from_bubble: the bubble name of the event.
 * @bubble_data: the bubble data (a string) of the event.
 *
 * Since: 1.0
 */
typedef void (*hibus_event_handler)(hibus_conn* conn,
        const char* from_endpoint, const char* from_bubble,
        const char* bubble_data);

/**
 * hibus_subscribe_event:
 * @conn: the pointer to the hiBus connection.
 * @endpoint: the endpoint name of the event.
 * @bubble_name: the bubble name of the event.
 * @event_handler: the event handler.
 *
 * This function subscribes the specified event. When
 * there is an event, @event_handler will be called with
 * the bubble data.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_subscribe_event (hibus_conn* conn,
        const char* endpoint, const char* bubble_name,
        hibus_event_handler event_handler);

/**
 * hibus_unsubscribe_event:
 * @conn: the pointer to the hiBus connection.
 * @endpoint: the endpoint name of the event.
 * @bubble_name: the bubble name of the event.
 *
 * This function unsubscribes the specified event.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_unsubscribe_event (hibus_conn* conn,
        const char* endpoint, const char* bubble_name);

/**
 * hibus_result_handler:
 * The prototype of an result handler.
 *
 * @conn: the pointer to the hiBus connection.
 * @from_endpoint: the endpoint name of the result.
 * @from_method: the method name of the result.
 * @ret_code: the return code of the result.
 * @ret_value: the return value (a string) of the result.
 *
 * Returns: 0 for finished the handle of the result; otherwise -1.
 *
 * Since: 1.0
 */
typedef int (*hibus_result_handler)(hibus_conn* conn,
        const char* from_endpoint, const char* from_method,
        int ret_code, const char* ret_value);

/**
 * hibus_call_procedure:
 * @conn: the pointer to the hiBus connection.
 * @endpoint: the endpoint name of the procedure.
 * @method_name: the method of the procedure.
 * @method_param: the parameter of the method.
 * @time_expected: the expected return time in seconds.
 * @result_handler: the result handler.
 *
 * This function emits a call to a remote procedure and
 * returns immediately. The result handler will be called
 * in subsequent calls of @hibus_read_and_dispatch_packet().
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_call_procedure (hibus_conn* conn,
        const char* from_endpoint, const char* from_method,
        const char* method_param,
        int time_expected, hibus_result_handler result_handler);

/**
 * hibus_call_procedure_and_wait:
 * @conn: the pointer to the hiBus connection.
 * @endpoint: the endpoint name of the procedure.
 * @method_name: the method of the procedure.
 * @method_param: the parameter of the method.
 * @time_expected: the expected return time in seconds.
 * @ret_code: the pointer to an integer to return the return code
 *      of the result.
 * @ret_value: the pointer to a pointer to return the value (a string)
 *      of the result.
 *
 * This function calls a remote procedure and wait for the result.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_call_procedure_and_wait (hibus_conn* conn, const char* endpoint,
        const char* method_name, const char* method_param,
        int time_expected, int *ret_code, char** ret_value);

/**
 * hibus_read_and_dispatch_packet:
 * @conn: the pointer to the hiBus connection.
 *
 * This function read a hiBus packet and dispatches the packet to
 * a event handler, method handler, or result handler.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Since: 1.0
 */
int hibus_read_and_dispatch_packet (hibus_conn* conn);

/**
 * hibus_wait_and_dispatch_packet:
 * @conn: the pointer to the hiBus connection.
 * @timeout_ms (not nullable): the timeout value in milliseconds.
 *
 * This function waits for a hiBus packet by calling select()
 * and dispatches the packet to event handlers, method handlers,
 * or result handlers.
 *
 * Returns: the error code; zero means everything is ok.
 *
 * Note that if you need watching multiple file descriptors, you'd
 * better user @hibus_read_and_dispatch_packet.
 *
 * Since: 1.0
 */
int hibus_wait_and_dispatch_packet (hibus_conn* conn, int timeout_ms);

#ifdef __cplusplus
}
#endif

/**
 * hibus_is_valid_runner_name:
 * @runner_name: the pointer to the runner name string.
 *
 * Checks whether a runner name is valid. According to hiBus protocal,
 * the runner name should be a valid token and not longer than
 * @HIBUS_LEN_RUNNER_NAME.
 *
 * Note that a string with a length longer than @HIBUS_LEN_RUNNER_NAME will
 * be considered as an invalid runner name.
 *
 * Returns: true for a valid token, otherwise false.
 *
 * Since: 1.0
 */
static inline bool
hibus_is_valid_runner_name (const char* runner_name)
{
    return hibus_is_valid_token (runner_name, HIBUS_LEN_RUNNER_NAME);
}

/**
 * hibus_is_valid_method_name:
 * @method_name: the pointer to the method name string.
 *
 * Checks whether a method name is valid. According to hiBus protocal,
 * the method name should be a valid token and not longer than
 * @HIBUS_LEN_METHOD_NAME.
 *
 * Note that a string with a length longer than @HIBUS_LEN_METHOD_NAME will
 * be considered as an invalid method name.
 *
 * Returns: true for a valid token, otherwise false.
 *
 * Since: 1.0
 */
static inline bool
hibus_is_valid_method_name (const char* method_name)
{
    return hibus_is_valid_token (method_name, HIBUS_LEN_METHOD_NAME);
}

/**
 * hibus_is_valid_bubble_name:
 * @bubble_name: the pointer to the bubble name string.
 *
 * Checks whether a bubble name is valid. According to hiBus protocal,
 * the bubble name should be a valid token and not longer than
 * @HIBUS_LEN_BUBBLE_NAME.
 *
 * Note that a string with a length longer than @HIBUS_LEN_BUBBLE_NAME will
 * be considered as an invalid bubble name.
 *
 * Returns: true for a valid token, otherwise false.
 *
 * Since: 1.0
 */
static inline bool
hibus_is_valid_bubble_name (const char* bubble_name)
{
    return hibus_is_valid_token (bubble_name, HIBUS_LEN_BUBBLE_NAME);
}

/**
 * hibus_name_tolower:
 * @name (not nullable): the pointer to a name string.
 *
 * Converts a name string lowercase in place.
 *
 * Returns: the length of the name string.
 *
 * Since: 1.0
 */
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

/**
 * hibus_name_toupper:
 * @name (not nullable): the pointer to a name string.
 *
 * Converts a name string uppercase in place.
 *
 * Returns: the length of the name string.
 *
 * Since: 1.0
 */
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

/**
 * hibus_name_tolower_copy:
 * @name (not nullable): the pointer to a name string.
 * @buff (not nullable): the buffer used to return the converted name string.
 * @max_len: The maximal length of the name string to convert.
 *
 * Converts a name string lowercase and copies the letters to
 * the specified buffer.
 *
 * Note that if @max_len <= 0, the argument will be ignored.
 *
 * Returns: the total number of letters converted.
 *
 * Since: 1.0
 */
static inline int
hibus_name_tolower_copy (const char* name, char* buff, int max_len)
{
    int n = 0;

    while (*name) {
        buff [n] = tolower (*name);
        name++;
        n++;

        if (max_len > 0 && n == max_len)
            break;
    }

    buff [n] = '\0';
    return n;
}

/**
 * hibus_name_toupper_copy:
 * @name (not nullable): the pointer to a name string.
 * @buff (not nullable): the buffer used to return the converted name string.
 * @max_len: The maximal length of the name string to convert.
 *
 * Converts a name string uppercase and copies the letters to
 * the specified buffer.
 *
 * Note that if @max_len <= 0, the argument will be ignored.
 *
 * Returns: the total number of letters converted.
 *
 * Since: 1.0
 */
static inline int
hibus_name_toupper_copy (const char* name, char* buff, int max_len)
{
    int n = 0;

    while (*name) {
        buff [n] = toupper (*name);
        name++;
        n++;

        if (max_len > 0 && n == max_len)
            break;
    }

    buff [n] = '\0';
    return n;
}

#endif /* !_HIBUS_H_ */

