/*
** libhibus.c -- The code for hiBus client.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/time.h>

#include <hibox/utils.h>
#include <hibox/ulog.h>
#include <hibox/md5.h>
#include <hibox/json.h>

#include "hibus.h"

struct _hibus_conn {
    int type;
    int fd;

    char* srv_host_name;
    char* own_host_name;
    char* app_name;
    char* runner_name;
};

int hibus_conn_endpoint_name (hibus_conn* conn, char *buff)
{
    if (conn->own_host_name && conn->app_name && conn->runner_name) {
        return hibus_assemble_endpoint_name (conn->own_host_name,
                conn->app_name, conn->runner_name, buff);
    }

    return 0;
}

char *hibus_conn_endpoint_name_alloc (hibus_conn* conn)
{
    if (conn->own_host_name && conn->app_name && conn->runner_name) {
        return hibus_assemble_endpoint_name_alloc (conn->own_host_name,
                conn->app_name, conn->runner_name);
    }

    return NULL;
}

/* return NULL for error */
static char* read_text_payload_from_us (int fd, int* len)
{
    ssize_t n = 0;
    USFrameHeader header;
    char *payload = NULL;

    n = read (fd, &header, sizeof (USFrameHeader));
    if (n > 0) {
        if (header.op == US_OPCODE_TEXT &&
                header.sz_payload > 0) {
            payload = malloc (header.sz_payload + 1);
        }
        else {
            ULOG_WARN ("Bad payload type (%d) and length (%d)\n",
                    header.op, header.sz_payload);
            return NULL;  /* must not the challenge code */
        }
    }

    if (payload == NULL) {
        ULOG_ERR ("Failed to allocate memory for payload.\n");
        return NULL;
    }
    else {
        n = read (fd, payload, header.sz_payload);
        if (n < header.sz_payload) {
            ULOG_ERR ("Failed to read payload.\n");
            goto failed;
        }

        payload [header.sz_payload] = 0;
        if (len)
            *len = header.sz_payload;
    }

    ULOG_INFO ("Got payload: \n%s\n", payload);

    return payload;

failed:
    free (payload);
    return NULL;
}

/* return zero for success */
static char *get_challenge_code (hibus_conn *conn)
{
    char* payload;
    int len;
    hibus_json *jo = NULL, *jo_tmp;
    const char *ch_code = NULL;

    payload = read_text_payload_from_us (conn->fd, &len);
    if (payload == NULL) {
        goto failed;
    }

    jo = json_object_from_string (payload, len, 2);
    if (jo == NULL) {
        goto failed;
    }

    free (payload);
    payload = NULL;

    if (json_object_object_get_ex (jo, "packetType", &jo_tmp)) {
        const char *pack_type;
        pack_type = json_object_get_string (jo_tmp);
        ULOG_INFO ("packetType: %s\n", pack_type);

        if (strcasecmp (pack_type, "error") == 0) {
            const char* prot_name = HIBUS_NOT_AVAILABLE;
            int prot_ver = 0, ret_code;
            const char *ret_msg = HIBUS_NOT_AVAILABLE, *extra_msg = HIBUS_NOT_AVAILABLE;

            ULOG_WARN ("Refued by server:\n");
            if (json_object_object_get_ex (jo, "protocolName", &jo_tmp)) {
                prot_name = json_object_get_string (jo_tmp);
            }

            if (json_object_object_get_ex (jo, "protocolVersion", &jo_tmp)) {
                prot_ver = json_object_get_int (jo_tmp);
            }
            ULOG_WARN ("  Protocol: %s/%d\n", prot_name, prot_ver);

            if (json_object_object_get_ex (jo, "retCode", &jo_tmp)) {
                ret_code = json_object_get_int (jo_tmp);
            }
            if (json_object_object_get_ex (jo, "retMsg", &jo_tmp)) {
                ret_msg = json_object_get_string (jo_tmp);
            }
            if (json_object_object_get_ex (jo, "extraMsg", &jo_tmp)) {
                extra_msg = json_object_get_string (jo_tmp);
            }
            ULOG_WARN ("  Error Info: %d (%s): %s\n", ret_code, ret_msg, extra_msg);

            goto failed;
        }
        else if (strcasecmp (pack_type, "auth") == 0) {
            const char *prot_name = HIBUS_NOT_AVAILABLE;
            int prot_ver = 0;

            if (json_object_object_get_ex (jo, "challengeCode", &jo_tmp)) {
                ch_code = json_object_get_string (jo_tmp);
                ULOG_INFO ("challengeCode: %s\n", ch_code);
            }

            if (json_object_object_get_ex (jo, "protocolName", &jo_tmp)) {
                prot_name = json_object_get_string (jo_tmp);
            }
            if (json_object_object_get_ex (jo, "protocolVersion", &jo_tmp)) {
                prot_ver = json_object_get_int (jo_tmp);
            }

            ULOG_INFO ("Protocol :%s/%d\n", prot_name, prot_ver);

            if (ch_code == NULL) {
                ULOG_WARN ("Null challenge code\n");
                goto failed;
            }
            else if (strcasecmp (prot_name, HIBUS_PROTOCOL_NAME) ||
                    prot_ver < HIBUS_PROTOCOL_VERSION) {
                ULOG_WARN ("Protocol not matched: %s/%d\n", prot_name, prot_ver);
                goto failed;
            }

        }
    }
    else {
        ULOG_WARN ("No packetType field\n");
        goto failed;
    }

    assert (ch_code);
    json_object_put (jo);
    return strdup (ch_code);

failed:
    if (jo)
        json_object_put (jo);
    if (payload)
        free (payload);

    return NULL;
}

static int send_auth_info (hibus_conn *conn, const char* ch_code)
{
    int retv;
    unsigned char* sig;
    unsigned int sig_len;
    char* enc_sig = NULL;
    unsigned int enc_sig_len;
    char buff [1024];

    sig = hibus_sign_data (conn->app_name,
            (const unsigned char *)ch_code, strlen (ch_code), &sig_len);
    if (sig == NULL || sig_len <= 0) {
        return -1;
    }

    enc_sig_len = B64_ENCODE_LEN (sig_len);
    enc_sig = malloc (enc_sig_len);
    if (enc_sig == NULL) {
        goto failed;
    }

    // When encode the signature in base64 or exadecimal notation,
    // there will be no any '"' and '\' charecters.
    b64_encode (sig, sig_len, enc_sig, enc_sig_len);

    free (sig);
    sig = NULL;

    retv = snprintf (buff, 1024, 
            "{"
            "\"packetType\":\"auth\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"hostName\":\"%s\","
            "\"appName\":\"%s\","
            "\"runnerName\":\"%s\","
            "\"signature\":\"%s\","
            "\"encodedIn\":\"base64\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            conn->own_host_name, conn->app_name, conn->runner_name, enc_sig);

    if (retv >= sizeof (buff)) {
        ULOG_ERR ("Too small buffer for signature (%s) in send_auth_info.\n", enc_sig);
        goto failed;
    }

    ULOG_INFO ("auth packate: \n%s\n", buff);
    if (hibus_send_text_packet (conn, buff, retv)) {
        ULOG_ERR ("Failed to send text packet to hiBus server in send_auth_info.\n");
        goto failed;
    }

    free (enc_sig);
    return 0;

failed:
    if (sig)
        free (sig);
    if (enc_sig)
        free (enc_sig);
    return -1;
}

#define CLI_PATH    "/var/tmp/"
#define CLI_PERM    S_IRWXU

/* returns fd if all OK, -1 on error */
int hibus_connect_via_unix_socket (const char* path_to_socket,
        const char* app_name, const char* runner_name, hibus_conn** conn)
{
    int fd, len;
    struct sockaddr_un unix_addr;
    char peer_name [33];
    char *ch_code = NULL;

    if ((*conn = calloc (1, sizeof (hibus_conn))) == NULL) {
        ULOG_ERR ("Failed to callocate space for connection: %s\n",
                strerror (errno));
        return -1;
    }

    /* create a Unix domain stream socket */
    if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ULOG_ERR ("Failed to call `socket` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        return -1;
    }

    {
        md5_ctx_t ctx;
        unsigned char md5_digest[16];

        md5_begin (&ctx);
        md5_hash (app_name, strlen (app_name), &ctx);
        md5_hash ("/", 1, &ctx);
        md5_hash (runner_name, strlen (runner_name), &ctx);
        md5_end (md5_digest, &ctx);
        bin2hex (md5_digest, 16, peer_name);
    }

    /* fill socket address structure w/our address */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    /* On Linux sun_path is 108 bytes in size */
    sprintf (unix_addr.sun_path, "%s%s-%05d", CLI_PATH, peer_name, getpid());
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path);

    ULOG_INFO ("The client addres: %s\n", unix_addr.sun_path);

    unlink (unix_addr.sun_path);        /* in case it already exists */
    if (bind (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        ULOG_ERR ("Failed to call `bind` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }
    if (chmod (unix_addr.sun_path, CLI_PERM) < 0) {
        ULOG_ERR ("Failed to call `chmod` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }

    /* fill socket address structure w/server's addr */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy (unix_addr.sun_path, path_to_socket);
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path);

    if (connect (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        ULOG_ERR ("Failed to call `connect` in hibus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }

    (*conn)->type = CT_UNIX_SOCKET;
    (*conn)->fd = fd;
    (*conn)->srv_host_name = NULL;
    (*conn)->own_host_name = strdup (HIBUS_LOCALHOST);
    (*conn)->app_name = strdup (app_name);
    (*conn)->runner_name = strdup (runner_name);

    /* try to read challenge code */
    if ((ch_code = get_challenge_code (*conn)) == NULL)
        goto error;

    if (send_auth_info (*conn, ch_code)) {
        goto error;
    }

    free (ch_code);
    return fd;

error:
    close (fd);

    if (ch_code)
        free (ch_code);
    if ((*conn)->own_host_name)
       free ((*conn)->own_host_name);
    if ((*conn)->app_name)
       free ((*conn)->app_name);
    if ((*conn)->runner_name)
       free ((*conn)->runner_name);
    free (*conn);
    *conn = NULL;

    return -1;
}

int hibus_connect_via_web_socket (const char* host_name, int port,
        const char* app_name, const char* runner_name, hibus_conn** conn)
{
    return -HIBUS_SC_NOT_IMPLEMENTED;
}

int hibus_disconnect (hibus_conn* conn)
{
    assert (conn);

    free (conn->srv_host_name);
    free (conn->own_host_name);
    free (conn->app_name);
    free (conn->runner_name);
    close (conn->fd);
    free (conn);

    return HIBUS_SC_OK;
}

const char* hibus_conn_srv_host_name (hibus_conn* conn)
{
    return conn->srv_host_name;
}

const char* hibus_conn_own_host_name (hibus_conn* conn)
{
    return conn->own_host_name;
}

const char* hibus_conn_app_name (hibus_conn* conn)
{
    return conn->app_name;
}

const char* hibus_conn_runner_name (hibus_conn* conn)
{
    return conn->runner_name;
}

int hibus_conn_socket_fd (hibus_conn* conn)
{
    return conn->fd;
}

int hibus_conn_socket_type (hibus_conn* conn)
{
    return conn->type;
}

int hibus_read_packet (hibus_conn* conn, void* packet_buf, unsigned int *packet_len)
{
    unsigned int offset;
    if (conn->type == CT_UNIX_SOCKET) {
        while (1) {
            ssize_t n = 0;
            USFrameHeader header;

            n = read (conn->fd, &header, sizeof (USFrameHeader));
            if (n < sizeof (USFrameHeader)) {
                ULOG_ERR ("Failed to read frame header from Unix socket\n");
                return -1;
            }

            if (header.op == US_OPCODE_PONG) {
                // TODO
                continue;
            }
            else if (header.op == US_OPCODE_PING) {
                header.op = US_OPCODE_PONG;
                header.sz_payload = 0;
                n = write (conn->fd, &header, sizeof (USFrameHeader));
                continue;
            }
            else if (header.op == US_OPCODE_CLOSE) {
                ULOG_WARN ("Peer closed\n");
                return -1;
            }
            else if (header.op == US_OPCODE_TEXT ||
                    header.op == US_OPCODE_BIN) {

                int is_text;
                if (header.op == US_OPCODE_TEXT) {
                    is_text = 1;
                }
                else {
                    is_text = 0;
                }

                if (read (conn->fd, packet_buf, header.sz_payload)
                        < header.sz_payload) {
                    ULOG_ERR ("Failed to read packet from Unix socket\n");
                    return -1;
                }

                offset = header.sz_payload;
                while (header.fragmented) {
                    n = read (conn->fd, &header, sizeof (USFrameHeader));
                    if (n < sizeof (USFrameHeader)) {
                        ULOG_ERR ("Failed to read frame header from Unix socket\n");
                        return -1;
                    }

                    if (header.op == US_OPCODE_END) {
                        break;
                    }
                    else if (header.op != US_OPCODE_CONTINUATION ) {
                        ULOG_ERR ("Not a continuation frame\n");
                        return -1;
                    }

                    if (read (conn->fd, packet_buf + offset, header.sz_payload)
                            < header.sz_payload) {
                        ULOG_ERR ("Failed to read packet from Unix socket\n");
                        return -1;
                    }

                    offset += header.sz_payload;
                }

                if (is_text) {
                    ((char *)packet_buf) [offset] = '\0';
                    *packet_len = offset + 1;
                }
                else {
                    *packet_len = offset;
                }

                return 0;
            }
            else {
                ULOG_ERR ("Bad packet op code: %d\n", header.op);
                return -1;
            }
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        return -2;
    }
    else
        return -3;

    return 0;
}

void* hibus_read_packet_alloc (hibus_conn* conn, unsigned int *packet_len)
{
    void* packet_buf = NULL;
    unsigned int offset;

    if (conn->type == CT_UNIX_SOCKET) {

        while (1) {
            ssize_t n = 0;
            USFrameHeader header;

            n = read (conn->fd, &header, sizeof (USFrameHeader));
            if (n < sizeof (USFrameHeader)) {
                ULOG_ERR ("Failed to read frame header from Unix socket\n");
                break;
            }

            if (header.op == US_OPCODE_PONG) {
                // TODO
                continue;
            }
            else if (header.op == US_OPCODE_PING) {
                header.op = US_OPCODE_PONG;
                header.sz_payload = 0;
                n = write (conn->fd, &header, sizeof (USFrameHeader));
                continue;
            }
            else if (header.op == US_OPCODE_CLOSE) {
                ULOG_WARN ("Peer closed\n");
                return NULL;
            }
            else if (header.op == US_OPCODE_TEXT ||
                    header.op == US_OPCODE_BIN) {

                int is_text;
                if (header.op == US_OPCODE_TEXT) {
                    is_text = 1;
                }
                else {
                    is_text = 0;
                }

                if ((packet_buf = malloc (header.sz_payload + 1)) == NULL) {
                    return NULL;
                }

                if (read (conn->fd, packet_buf, header.sz_payload)
                        < header.sz_payload) {
                    ULOG_ERR ("Failed to read packet from Unix socket\n");
                    free (packet_buf);
                    return NULL;
                }

                offset = header.sz_payload;
                while (header.fragmented) {
                    n = read (conn->fd, &header, sizeof (USFrameHeader));
                    if (n < sizeof (USFrameHeader)) {
                        ULOG_ERR ("Failed to read frame header from Unix socket\n");
                        free (packet_buf);
                        return NULL;
                    }

                    if (header.op == US_OPCODE_END) {
                        break;
                    }
                    else if (header.op != US_OPCODE_CONTINUATION ) {
                        ULOG_ERR ("Not a continuation frame\n");
                        free (packet_buf);
                        return NULL;
                    }

                    if ((packet_buf = realloc (packet_buf, offset + header.sz_payload + 1))
                            == NULL) {
                        // free?
                        return NULL;
                    }

                    if (read (conn->fd, packet_buf + offset, header.sz_payload)
                            < header.sz_payload) {
                        ULOG_ERR ("Failed to read packet from Unix socket\n");
                        free (packet_buf);
                        return NULL;
                    }

                    offset += header.sz_payload;
                }

                if (is_text) {
                    ((char *)packet_buf) [offset] = '\0';
                    *packet_len = offset + 1;
                }
                else {
                    *packet_len = offset;
                }
                return packet_buf;
            }
            else {
                ULOG_ERR ("Bad packet op code: %d\n", header.op);
                return NULL;
            }
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        return NULL;
    }
    else {
        assert (0);
        return NULL;
    }

    return packet_buf;
}

/* TODO: fragment if the text is too long */
int hibus_send_text_packet (hibus_conn* conn, const char* text, unsigned int len)
{
    if (conn->type == CT_UNIX_SOCKET) {
        ssize_t n = 0;
        USFrameHeader header;

        header.op = US_OPCODE_TEXT;
        header.fragmented = 0;
        header.sz_payload = len;
        n = write (conn->fd, &header, sizeof (USFrameHeader));
        n += write (conn->fd, text, len);
        if (n != (sizeof (USFrameHeader) + len)) {
            ULOG_ERR ("Error when wirting to Unix Socket: %s\n", strerror (errno));
            return -1;
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        return -2;
    }
    else
        return -3;

    return 0;
}

int hibus_ping_server (hibus_conn* conn)
{
    if (conn->type == CT_UNIX_SOCKET) {
        ssize_t n = 0;
        USFrameHeader header;

        header.op = US_OPCODE_PING;
        header.fragmented = 0;
        header.sz_payload = 0;
        n = write (conn->fd, &header, sizeof (USFrameHeader));
        if (n < sizeof (USFrameHeader)) {
            ULOG_ERR ("Error when wirting to Unix Socket: %s\n", strerror (errno));
            return -1;
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        return -2;
    }
    else
        return -3;

    return 0;
}

