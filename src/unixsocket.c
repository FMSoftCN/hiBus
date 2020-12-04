/*
** unixsocket.c: Utilities for UNIX socket server.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/time.h>

#include <hibox/ulog.h>

#include "hibus.h"
#include "server.h"
#include "unixsocket.h"

USServer *us_init (const ServerConfig* config)
{
    USServer *server = calloc (1, sizeof (USServer));

    server->listener = -1;
    server->config = config;
    return server;
}

void us_stop (USServer * server)
{
    close (server->listener);
    free (server);
}

/* returns fd if all OK, -1 on error */
int us_listen (USServer* server)
{
    int    fd, len;
    struct sockaddr_un unix_addr;

    /* create a Unix domain stream socket */
    if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ULOG_ERR ("Error duing calling `socket` in us_listen: %s\n", strerror (errno));
        return (-1);
    }

    fcntl (fd, F_SETFD, FD_CLOEXEC);

    /* in case it already exists */
    unlink (server->config->unixsocket);

    /* fill in socket address structure */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy (unix_addr.sun_path, server->config->unixsocket);
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path);

    /* bind the name to the descriptor */
    if (bind (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        ULOG_ERR ("Error duing calling `bind` in us_listen: %s\n", strerror (errno));
        goto error;
    }
    if (chmod (server->config->unixsocket, 0666) < 0) {
        ULOG_ERR ("Error duing calling `chmod` in us_listen: %s\n", strerror (errno));
        goto error;
    }

    /* tell kernel we're a server */
    if (listen (fd, server->config->backlog) < 0) {
        ULOG_ERR ("Error duing calling `listen` in us_listen: %s\n", strerror (errno));
        goto error;
    }

    server->listener = fd;
    return (fd);

error:
    close (fd);
    return (-1);
}

#define    STALE    30    /* client's name can't be older than this (sec) */

/* Wait for a client connection to arrive, and accept it.
 * We also obtain the client's pid from the pathname
 * that it must bind before calling us.
 */
/* returns new fd if all OK, < 0 on error */
static int us_accept (int listenfd, pid_t *pidptr, uid_t *uidptr)
{
    int                clifd;
    socklen_t          len;
    time_t             staletime;
    struct sockaddr_un unix_addr;
    struct stat        statbuf;
    const char*        pid_str;

    len = sizeof (unix_addr);
    if ((clifd = accept (listenfd, (struct sockaddr *) &unix_addr, &len)) < 0)
        return (-1);        /* often errno=EINTR, if signal caught */

    fcntl (clifd, F_SETFD, FD_CLOEXEC);

    /* obtain the client's uid from its calling address */
    len -= sizeof(unix_addr.sun_family);
    if (len <= 0) {
        ULOG_ERR ("Bad peer address in us_accept: %s\n", unix_addr.sun_path);
        goto error;
    }

    unix_addr.sun_path[len] = 0;            /* null terminate */
    ULOG_NOTE ("The peer address in us_accept: %s\n", unix_addr.sun_path);
    if (stat (unix_addr.sun_path, &statbuf) < 0) {
        ULOG_ERR ("Failed `stat` in us_accept: %s\n", strerror (errno));
        goto error;
    }
#ifdef S_ISSOCK    /* not defined for SVR4 */
    if (S_ISSOCK(statbuf.st_mode) == 0) {
        ULOG_ERR ("Not a socket: %s\n", unix_addr.sun_path);
        goto error;
    }
#endif
    if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) ||
            (statbuf.st_mode & S_IRWXU) != S_IRWXU) {
        ULOG_ERR ("Bad RW mode (rwx------): %s\n", unix_addr.sun_path);
        goto error;
    }

    staletime = time(NULL) - STALE;
    if (statbuf.st_atime < staletime ||
            statbuf.st_ctime < staletime ||
            statbuf.st_mtime < staletime) {
        ULOG_ERR ("i-node is too old: %s\n", unix_addr.sun_path);
        goto error;
    }

    if (uidptr != NULL)
        *uidptr = statbuf.st_uid;    /* return uid of caller */

    /* get pid of client from sun_path */
    pid_str = strrchr (unix_addr.sun_path, '-');
    pid_str++;

    *pidptr = atoi (pid_str);
    ULOG_INFO ("Got pid from peer address: %d\n", *pidptr);
    
    unlink (unix_addr.sun_path);        /* we're done with pathname now */
    return (clifd);

error:
    close (clifd);
    return -1;
}

/* Set the given file descriptor as NON BLOCKING. */
inline static int
set_nonblocking (int sock)
{
    if (fcntl (sock, F_SETFL, fcntl (sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
        ULOG_ERR ("Unable to set socket as non-blocking: %s.",
                strerror (errno));
        return -1;
    }

    return 0;
}

/* Handle a new UNIX socket connection. */
USClient *
us_handle_accept (USServer* server)
{
    USClient *usc = NULL;
    pid_t pid;
    uid_t uid;
    int newfd = -1;

    usc = (USClient *)calloc (sizeof (USClient), 1);
    if (usc == NULL) {
        ULOG_ERR ("Failed to callocate memory for Unix socket client\n");
        return NULL;
    }

    newfd = us_accept (server->listener, &pid, &uid);
    if (newfd < 0) {
        ULOG_ERR ("Failed to accept Unix socket: %d\n", newfd);
        goto failed;
    }

    if (set_nonblocking (newfd)) {
        goto cleanup;
    }

    usc->type = ET_UNIX_SOCKET;
    usc->fd = newfd;
    usc->pid = pid;
    usc->uid = uid;
    server->nr_clients++;

    if (server->nr_clients > MAX_CLIENTS_EACH) {
        ULOG_WARN ("Too many clients (maximal clients allowed: %d)\n", MAX_CLIENTS_EACH);
        server->on_failed (server, usc, HIBUS_SC_SERVICE_UNAVAILABLE);
        goto cleanup;
    }

    if (server->on_accepted) {
        int ret_code;
        ret_code = server->on_accepted (server, usc);
        if (ret_code != HIBUS_SC_OK) {
            ULOG_WARN ("Internal error after accepted this client (%d): %d\n",
                    newfd, ret_code);

            server->on_failed (server, usc, ret_code);
            goto cleanup;
        }
    }

    ULOG_NOTE ("Accepted a client via Unix socket: fd (%d), pid (%d), uid (%d)\n",
            newfd, pid, uid);
    return usc;

cleanup:
    us_client_cleanup (server, usc);
    return NULL;

failed:
    free (usc);
    return NULL;
}

int us_handle_reads (USServer* server, USClient* usc)
{
    int err_code = 0, sta_code = 0;
    ssize_t n = 0;
    USFrameHeader header;

    n = read (usc->fd, &header, sizeof (USFrameHeader));
    if (n < sizeof (USFrameHeader)) {
        ULOG_ERR ("Failed to read frame header from Unix socket: %s\n",
                strerror (errno));
        err_code = HIBUS_EC_IO;
        sta_code = HIBUS_SC_EXPECTATION_FAILED;
        goto done;
    }

    switch (header.op) {
    case US_OPCODE_PING:
        header.op = US_OPCODE_PONG;
        header.fragmented = 0;
        header.sz_payload = 0;
        n = write (usc->fd, &header, sizeof (USFrameHeader));
        if (n != (sizeof (USFrameHeader))) {
            ULOG_ERR ("Error when wirting socket: %s\n", strerror (errno));
            err_code = HIBUS_EC_IO;
            sta_code = HIBUS_SC_IOERR;
        }
        break;

    case US_OPCODE_CLOSE:
        ULOG_WARN ("Peer closed\n");
        err_code = HIBUS_EC_CLOSED;
        sta_code = 0;
        break;

    case US_OPCODE_TEXT:
    case US_OPCODE_BIN: {
        if (header.fragmented > 0 && header.fragmented > header.sz_payload) {
            usc->sz_packet = header.fragmented;
        }
        else {
            usc->sz_packet = header.sz_payload;
        }

        if (usc->sz_packet > MAX_SIZE_INMEM_PACKET) {
            err_code = HIBUS_EC_PROTOCOL;
            sta_code = HIBUS_SC_PACKET_TOO_LARGE;
            break;
        }

        if (header.op == US_OPCODE_TEXT)
            usc->t_packet = PT_TEXT;
        else
            usc->t_packet = PT_BINARY;

        /* always reserve a space for null character */
        usc->packet = malloc (usc->sz_packet + 1);
        if (usc->packet == NULL) {
            ULOG_ERR ("Failed to allocate memory for packet (size: %u)\n", usc->sz_packet);
            err_code = HIBUS_EC_NOMEM;
            sta_code = HIBUS_SC_INSUFFICIENT_STORAGE;
            break;
        }

        if ((n = read (usc->fd, usc->packet, header.sz_payload))
                < header.sz_payload) {
            ULOG_ERR ("Failed to read packet from Unix socket: %s\n",
                    strerror (errno));
            err_code = HIBUS_EC_IO;
            sta_code = HIBUS_SC_EXPECTATION_FAILED;
            break;
        }
        usc->sz_read = header.sz_payload;

        if (header.fragmented == 0) {
            goto got_packet;
        }

        break;
    }

    case US_OPCODE_CONTINUATION:
    case US_OPCODE_END:
        if (usc->packet == NULL ||
                (usc->sz_read + header.sz_payload) > usc->sz_packet) {
            err_code = HIBUS_EC_PROTOCOL;
            sta_code = HIBUS_SC_EXPECTATION_FAILED;
            break;
        }

        if ((n = read (usc->fd, usc->packet + usc->sz_read, header.sz_payload))
                < header.sz_payload) {
            ULOG_ERR ("Failed to read packet from Unix socket: %s\n",
                    strerror (errno));
            err_code = HIBUS_EC_IO;
            sta_code = HIBUS_SC_EXPECTATION_FAILED;
            break;
        }

        usc->sz_read += header.sz_payload;
        if (header.op == US_OPCODE_END) {
            goto got_packet;
        }

        break;

    case US_OPCODE_PONG: {
        BusEndpoint *endpoint = usc->priv_data;

        assert (endpoint);

        ULOG_INFO ("Got a PONG frame from endpoint @%s/%s/%s\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name);
        break;
    }

    default:
        ULOG_ERR ("Unknown frame opcode: %d\n", header.op);
        err_code = HIBUS_EC_PROTOCOL;
        sta_code = HIBUS_SC_EXPECTATION_FAILED;
        break;
    }

done:
    if (err_code) {
        /* read and discard all payload
        char buff [1024];
        while (read (usc->fd, buff, sizeof (buff)) == sizeof (buff));
        */

        if (sta_code) {
            server->on_failed (server, usc, sta_code);
        }

        us_client_cleanup (server, usc);
    }

    return err_code;

got_packet:
    usc->packet [usc->sz_read] = '\0';
    sta_code = server->on_packet (server, usc, usc->packet,
            (usc->t_packet == PT_TEXT) ? (usc->sz_read + 1) : usc->sz_read,
            usc->t_packet);
    free (usc->packet);
    usc->packet = NULL;
    usc->sz_packet = 0;
    usc->sz_read = 0;

    if (sta_code != HIBUS_SC_OK) {
        ULOG_WARN ("Internal error after got a packet: %d\n", sta_code);

        server->on_failed (server, usc, sta_code);
        err_code = HIBUS_EC_UPPER;

        us_client_cleanup (server, usc);
    }

    return err_code;
}

/* return zero on success; none-zero on error */
int us_ping_client (USServer* server, USClient* us_client)
{
    ssize_t n = 0;
    USFrameHeader header;

    header.op = US_OPCODE_PING;
    header.fragmented = 0;
    header.sz_payload = 0;
    n = write (us_client->fd, &header, sizeof (USFrameHeader));
    if (n != sizeof (USFrameHeader)) {
        return 1;
    }

    return 0;
}

/* return zero on success; none-zero on error
 * TODO: handle fragments */
int us_send_data (USServer* server, USClient* us_client,
        USOpcode op, const char* data, int sz)
{
    ssize_t n = 0;
    USFrameHeader header;

    header.op = op;
    header.fragmented = 0;
    header.sz_payload = sz;
    n = write (us_client->fd, &header, sizeof (USFrameHeader));
    n += write (us_client->fd, data, sz);
    if (n != (sizeof (USFrameHeader) + sz)) {
        ULOG_ERR ("Error when wirting socket: %ld\n", n);
        return 1;
    }

    return 0;
}

int us_client_cleanup (USServer* server, USClient* us_client)
{
    server->on_close (server, us_client);

    if (us_client->fd >= 0)
        close (us_client->fd);
    us_client->fd = -1;

    server->nr_clients--;

    assert (server->nr_clients >= 0);
    free (us_client);

    return 0;
}

