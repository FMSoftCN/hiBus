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
    if ( (clifd = accept (listenfd, (struct sockaddr *) &unix_addr, &len)) < 0)
        return (-1);        /* often errno=EINTR, if signal caught */

    fcntl (clifd, F_SETFD, FD_CLOEXEC);

    /* obtain the client's uid from its calling address */
    len -= /* th sizeof(unix_addr.sun_len) - */ sizeof(unix_addr.sun_family);
                    /* len of pathname */
    unix_addr.sun_path[len] = 0;            /* null terminate */
    if (stat(unix_addr.sun_path, &statbuf) < 0)
        return(-2);
#ifdef S_ISSOCK    /* not defined for SVR4 */
    if (S_ISSOCK(statbuf.st_mode) == 0)
        return(-3);        /* not a socket */
#endif
    if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) ||
        (statbuf.st_mode & S_IRWXU) != S_IRWXU)
          return(-4);    /* is not rwx------ */

    staletime = time(NULL) - STALE;
    if (statbuf.st_atime < staletime ||
        statbuf.st_ctime < staletime ||
        statbuf.st_mtime < staletime)
          return(-5);    /* i-node is too old */

    if (uidptr != NULL)
        *uidptr = statbuf.st_uid;    /* return uid of caller */

    /* get pid of client from sun_path */
    pid_str = strrchr (unix_addr.sun_path, 'P');
    pid_str++;

    *pidptr = atoi (pid_str);
    
    unlink (unix_addr.sun_path);        /* we're done with pathname now */
    return (clifd);
}

/* Handle a new UNIX socket connection. */
USClient *
us_handle_accept (USServer* server)
{
    USClient *usc = NULL;
    pid_t pid_buddy;
    int newfd = -1;

    usc = (USClient *)calloc (sizeof (USClient), 1);
    if (usc == NULL) {
        ULOG_ERR ("Failed to callocate memory for Unix socket client\n");
        return NULL;
    }

    newfd = us_accept (server->listener, &pid_buddy, NULL);
    if (newfd < 0) {
        ULOG_ERR ("Failed to accept Unix socket: %d\n", newfd);
        goto failed;
    }

    usc->type = ET_UNIX_SOCKET;
    usc->fd = newfd;
    usc->pid = pid_buddy;
    server->nr_clients++;

    if (server->nr_clients > MAX_CLIENTS_EACH) {
        ULOG_WARN ("Too many clients (maximal clients allowed: %d)\n", MAX_CLIENTS_EACH);
        if (server->on_failed) {
            server->on_failed (server, usc, HIBUS_SC_SERVICE_UNAVAILABLE);
        }
        goto close;
    }

    if (server->on_accepted) {
        int ret_code;
        ret_code = server->on_accepted (server, usc);
        if (ret_code != HIBUS_SC_OK) {
            ULOG_WARN ("Internal error after accepted this client (%d): %d\n",
                    newfd, ret_code);

            if (server->on_failed) {
                server->on_failed (server, usc, ret_code);
            }

            goto close;
        }
    }

    ULOG_NOTE ("Accepted a client via Unix socket: %d\n", pid_buddy);
    return usc;

close:
    us_client_cleanup (server, usc);

failed:
    free (usc);
    return NULL;
}

int us_handle_reads (USServer* server, USClient* usc)
{
    int retval = 0;

    return retval;
}

/* return zero on success; none-zero on error */
int us_ping_client (USServer* server, USClient* us_client)
{
    ssize_t n = 0;
    USFrameHeader header;

    header.type = US_OPCODE_PING;
    header.payload_len = 0;
    n = write (us_client->fd, &header, sizeof (USFrameHeader));
    if (n != sizeof (USFrameHeader)) {
        return 1;
    }

    return 0;
}

/* return zero on success; none-zero on error */
int us_send_data (USServer* server, USClient* us_client,
        USOpcode op, const char* data, int sz)
{
    ssize_t n = 0;
    USFrameHeader header;

    header.type = op;
    header.payload_len = sz;
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
    if (us_client->fd >= 0)
        close (us_client->fd);
    us_client->fd = -1;

    server->nr_clients--;

    assert (server->nr_clients >= 0);
    return 0;
}

