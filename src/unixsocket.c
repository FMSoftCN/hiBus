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
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/time.h>

#include "unixsocket.h"

/* returns fd if all OK, -1 on error */
int us_listen (const char *name)
{
    int    fd, len;
    struct sockaddr_un unix_addr;

    /* create a Unix domain stream socket */
    if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
        return (-1);

    fcntl (fd, F_SETFD, FD_CLOEXEC);

    /* in case it already exists */
    unlink (name);

    /* fill in socket address structure */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy (unix_addr.sun_path, name);
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path);

    /* bind the name to the descriptor */
    if (bind (fd, (struct sockaddr *) &unix_addr, len) < 0)
        goto error;
    if (chmod (name, 0666) < 0)
        goto error;

    /* tell kernel we're a server */
    if (listen (fd, 5) < 0)
        goto error;

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
int us_accept (int listenfd, pid_t *pidptr, uid_t *uidptr)
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

int us_on_connected (USClient* us_client)
{
    ssize_t n = 0;
    int retval;
    struct _frame_header header;

    us_client->shadow_fb = NULL;

    /* read info of virtual frame buffer */
    n = read (us_client->fd, &header, sizeof (struct _frame_header));
    if (n < sizeof (struct _frame_header) || header.type != FT_VFBINFO) {
        retval = 1;
        goto error;
    }

    n = read (us_client->fd, &us_client->vfb_info, sizeof (struct _vfb_info));
    if (n < header.payload_len) {
        retval = 2;
        goto error;
    }

    if (us_client->vfb_info.type == USVFB_TRUE_RGB565) {
        us_client->bytes_per_pixel = 3;
        us_client->row_pitch = us_client->vfb_info.width * 3;
    }
    else if (us_client->vfb_info.type == USVFB_TRUE_RGB0888) {
        us_client->bytes_per_pixel = 3;
        us_client->row_pitch = us_client->vfb_info.width * 3;
    }
    else {
        /* not support pixel type */
        retval = 3;
        goto error;
    }

    /* create shadow frame buffer */
    us_client->shadow_fb = malloc (us_client->row_pitch * us_client->vfb_info.height);
    if (us_client->shadow_fb == NULL) {
        retval = 4;
        goto error;
    }

    gettimeofday (&us_client->last_flush_time, NULL);
    return 0;

error:
    LOG (("us_on_connected: failed (%d)\n", retval));

    if (us_client->shadow_fb) {
        free (us_client->shadow_fb);
    }

    return retval;
}

/* return zero on success; none-zero on error */
int us_ping_client (const USClient* us_client)
{
    ssize_t n = 0;
    struct _frame_header header;

    header.type = FT_PING;
    header.payload_len = 0;
    n = write (us_client->fd, &header, sizeof (struct _frame_header));
    if (n != sizeof (struct _frame_header)) {
        return 1;
    }

    return 0;
}

/* return zero on success; none-zero on error */
int us_send_event (const USClient* us_client, const struct _remote_event* event)
{
    ssize_t n = 0;
    struct _frame_header header;

    header.type = FT_EVENT;
    header.payload_len = sizeof (struct _remote_event);
    n = write (us_client->fd, &header, sizeof (struct _frame_header));
    n += write (us_client->fd, event, sizeof (struct _remote_event));
    if (n != (sizeof (struct _frame_header) + sizeof (struct _remote_event))) {
        LOG (("us_send_event: error when wirtting socket: %ld\n", n));
        return 1;
    }

    return 0;
}

int us_client_cleanup (USClient* us_client)
{
    if (us_client->shadow_fb) {
        free (us_client->shadow_fb);
        us_client->shadow_fb = NULL;
    }

    if (us_client->fd >= 0)
        close (us_client->fd);
    us_client->fd = -1;

    return 0;
}

