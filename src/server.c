/*
** hibusd.c -- The code for hiBus daemon.
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
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <hibox/ulog.h>

#include "hibus.h"
#include "server.h"
#include "websocket.h"
#include "unixsocket.h"

BusServer the_server;

static ServerConfig srvcfg = { 0 };
static WSServer *ws_srv = NULL;
// static USServer *us_srv = NULL;

/* Set the origin so the server can force connections to have the
 * given HTTP origin. */
static inline void
srv_set_config_origin (const char *origin)
{
    srvcfg.origin = origin;
}

/* Set the the maximum websocket frame size. */
static inline void
srv_set_config_frame_size (int max_frm_size)
{
    srvcfg.max_frm_size = max_frm_size;
}

/* Set specific name for the UNIX socket. */
static inline void
srv_set_config_unixsocket (const char *unixsocket)
{
    srvcfg.unixsocket = unixsocket;
}

/* Set a path and a file for the access log. */
static inline void
srv_set_config_accesslog (const char *accesslog)
{
    srvcfg.accesslog = accesslog;

#if 0
  if (access_log_open (srvcfg.accesslog) == 1)
    ULOG_ERR ("Unable to open access log: %s.", strerror (errno));
#endif
}

/* Set the server host bind address. */
static inline void
srv_set_config_host (const char *host)
{
    srvcfg.host = host;
}

/* Set the server port bind address. */
static inline void
srv_set_config_port (const char *port)
{
    srvcfg.port = port;
}

/* Set specific name for the SSL certificate. */
static inline void
srv_set_config_sslcert (const char *sslcert)
{
    srvcfg.sslcert = sslcert;
}

/* Set specific name for the SSL key. */
static inline void
srv_set_config_sslkey (const char *sslkey)
{
    srvcfg.sslkey = sslkey;
}

/* *INDENT-OFF* */
static char short_options[] = "dp:Vh";
static struct option long_opts[] = {
    {"port"           , required_argument , 0 , 'p' } ,
    {"addr"           , required_argument , 0 ,  0  } ,
    {"max-frame-size" , required_argument , 0 ,  0  } ,
    {"origin"         , required_argument , 0 ,  0  } ,
#if HAVE_LIBSSL
    {"ssl-cert"       , required_argument , 0 ,  0  } ,
    {"ssl-key"        , required_argument , 0 ,  0  } ,
#endif
    {"access-log"     , required_argument , 0 ,  0  } ,
    {"version"        , no_argument       , 0 , 'V' } ,
    {"help"           , no_argument       , 0 , 'h' } ,
    {0, 0, 0, 0}
};

/* Command line help. */
static void
cmd_help (void)
{
    printf ("\nhibusd - %s\n\n", HIBUS_VERSION);

    printf (
            "Usage: "
            "wdserver [ options ... ] -p [--addr][--origin][...]\n"
            "The following options can also be supplied to the command:\n\n"
            ""
            "  -d                       - Run as a daemon.\n"
            "  -p --port=<port>         - Specifies the port to bind.\n"
            "  -h --help                - This help.\n"
            "  -V --version             - Display version information and exit.\n"
            "  --access-log=<path/file> - Specifies the path/file for the access log.\n"
            "  --addr=<addr>            - Specify an IP address to bind to.\n"
            "  --max-frame-size=<bytes> - Maximum size of a websocket frame. This\n"
            "                             includes received frames from the client\n"
            "                             and messages through the named pipe.\n"
            "  --origin=<origin>        - Ensure clients send the specified origin\n"
            "                             header upon the WebSocket handshake.\n"
            "  --ssl-cert=<cert.crt>    - Path to SSL certificate.\n"
            "  --ssl-key=<priv.key>     - Path to SSL private key.\n"
            "\n"
            "See the man page for more information `man wdserver`.\n\n"
            "For more details visit: http://www.minigui.com\n"
            "wdserver Copyright (C) 2018 by FMSoft\n"
            "\n"
            "wdserver is derived from gwsocket\n"
            "gwsocket Copyright (C) 2016 by Gerardo Orellana"
            "\n\n"
            );
}
/* *INDENT-ON* */

static void
handle_signal_action (int sig_number)
{
    if (sig_number == SIGINT) {
        printf ("SIGINT caught!\n");
        /* if it fails to write, force stop */
        ws_stop (ws_srv);
        _exit (1);
    }
    else if (sig_number == SIGPIPE) {
        printf ("SIGPIPE caught!\n");
    }
}

static int
setup_signals (void)
{
    struct sigaction sa;
    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = handle_signal_action;
    if (sigaction (SIGINT, &sa, 0) != 0) {
        perror ("sigaction()");
        return -1;
    }
    if (sigaction (SIGPIPE, &sa, 0) != 0) {
        perror ("sigaction()");
        return -1;
    }
    if (sigaction (SIGCHLD, &sa, 0) != 0) {
        perror ("sigaction()");
        return -1;
    }
    return 0;
}

static void
parse_long_opt (const char *name, const char *oarg)
{
    if (!strcmp ("max-frame-size", name))
        srv_set_config_frame_size (atoi (oarg));
    if (!strcmp ("origin", name))
        srv_set_config_origin (oarg);
    if (!strcmp ("unixsocket", name))
        srv_set_config_unixsocket (oarg);
    else
        srv_set_config_unixsocket (HIBUS_US_PATH);
    if (!strcmp ("access-log", name))
        srv_set_config_accesslog (oarg);
#if HAVE_LIBSSL
    if (!strcmp ("ssl-cert", name))
        srv_set_config_sslcert (oarg);
    if (!strcmp ("ssl-key", name))
        srv_set_config_sslkey (oarg);
#endif
}

/* Read the user's supplied command line options. */
static int
read_option_args (int argc, char **argv)
{
  int daemon = 0;
  int o, idx = 0;

  while ((o = getopt_long (argc, argv, short_options, long_opts, &idx)) >= 0) {
    if (-1 == o || EOF == o)
      break;
    switch (o) {
    case 'd':
      daemon = 1;
      break;
    case 'p':
      srv_set_config_port (optarg);
      break;
    case 'h':
      cmd_help ();
      exit (EXIT_SUCCESS);
      return -1;
    case 'V':
      fprintf (stdout, "hibusd %s\n", HIBUS_VERSION);
      exit (EXIT_SUCCESS);
      return -1;
    case 0:
      parse_long_opt (long_opts[idx].name, optarg);
      break;
    case '?':
      cmd_help ();
      exit (EXIT_SUCCESS);
      return -1;
    default:
      return -1;
    }
  }

  for (idx = optind; idx < argc; idx++)
    cmd_help ();

  return daemon;
}

static int
wd_set_null_stdio (void)
{
    int fd = open ("/dev/null", O_RDWR);
    if (fd < 0)
        return -1;

    if (dup2 (fd, 0) < 0 ||
            dup2 (fd, 1) < 0 ||
            dup2 (fd, 2) < 0) {
        close (fd);
        return -1;
    }

    close (fd);
    return 0;
}

static int
srv_daemon (void)
{
    pid_t pid;

    if (chdir ("/") != 0)
        return -1;

    if (wd_set_null_stdio ())
        return -1;

    pid = fork ();
    if (pid < 0)
        return -1;

    if (pid > 0)
        _exit(0);

    if (setsid () < 0)
        return -1;

    return 0;
}

static int max_file_fd = 0;
static WSEState fdstate;

/* Handle a UnixSocket read. */
static void
handle_us_reads (USClient *us_client, WSClient* ws_client, WSServer* server)
{
    int retval = us_on_client_data (us_client);

    if (retval < 0) {
        ULOG_NOTE ("handle_us_reads: client #%d exited.\n", us_client->pid);
        /* force to close the connection */
        ws_handle_tcp_close (ws_client->fd, ws_client, server);
    }
    else if (retval > 0) {
        ULOG_NOTE ("handle_us_reads: error when handling data from client #%d.\n", us_client->pid);
    }
}

/* Handle a UnixSocket write. */
static void
handle_us_writes (USClient *us_client, WSClient* ws_client, WSServer* server)
{
    ULOG_NOTE ("handle_us_writes: do nothing for client #%d.\n", us_client->pid);
}

/* Set each client to determine if:
 * 1. We want to see if it has data for reading
 * 2. We want to write data to it.
 * If so, set the client's socket descriptor in the descriptor set. */
static void
set_rfds_wfds (int ws_listener, int us_listener, WSServer * server)
{
    GSLList *client_node = server->colist;
    WSClient *client = NULL;

    /* WebSocket server socket, ready for accept() */
    FD_SET (ws_listener, &fdstate.rfds);

    /* UnixSocket server socket, ready for accept() */
    FD_SET (us_listener, &fdstate.rfds);

    while (client_node) {
        int ws_fd, us_fd = 0;

        client = (WSClient*)(client_node->data);
        ws_fd = client->fd;

        /* As long as we are not closing a connection, we assume we always
         * check a client for reading */
        if (!server->closing) {
            FD_SET (ws_fd, &fdstate.rfds);
            if (ws_fd > max_file_fd)
                max_file_fd = ws_fd;

            if (us_fd > 0) {
                FD_SET (us_fd, &fdstate.rfds);
                if (us_fd > max_file_fd)
                    max_file_fd = us_fd;
            }
        }

        /* Only if we have data to send to the WebSocket client */
        if (client->status & WS_SENDING) {
            FD_SET (ws_fd, &fdstate.wfds);
            if (ws_fd > max_file_fd)
                max_file_fd = ws_fd;
        }

        client_node = client_node->next;
    }
}

/* Check and handle fds. */
static void
check_rfds_wfds (int ws_listener, int us_listener, WSServer * server)
{
    GSLList *client_node = server->colist;
    WSClient *ws_client = NULL;
    USClient *us_client = NULL;

    /* handle new WebSocket connections */
    if (FD_ISSET (ws_listener, &fdstate.rfds))
        ws_handle_accept (ws_listener, server);
    /* handle new UnixSocket connections */
    else if (FD_ISSET (us_listener, &fdstate.rfds))
        us_handle_accept (us_listener, NULL);

    while (client_node) {
        int ws_fd;
        int retval = 0;

        ws_client = (WSClient*)(client_node->data);
        us_client = (USClient*)(client_node->data);
        ws_fd = ws_client->fd;

#if 0
        /* check died buddy */
        {
            int free_client = 0;
            if (ws_client->status_buddy == WS_BUDDY_LAUNCHED
                    && (time (NULL) - ws_client->launched_time_buddy) > 10) {
                free_client = 1;
            }
            else if (ws_client->status_buddy == WS_BUDDY_EXITED) {
                free_client = 1;
            }

            if (free_client) {
                ws_handle_tcp_close (ws_fd, ws_client, server);
                printf ("check_rfds_wfds: force to close client #%d\n", ws_fd);
                if (FD_ISSET (ws_fd, &fdstate.rfds))
                    FD_CLR (ws_fd, &fdstate.rfds);
                if (FD_ISSET (ws_fd, &fdstate.wfds))
                    FD_CLR (ws_fd, &fdstate.wfds);
            }
        }
#endif

        /* handle reading data from a WebSocket client */
        if (FD_ISSET (ws_fd, &fdstate.rfds))
            retval = ws_handle_reads (ws_fd, server);
        /* handle sending data to a WebSocket client */
        else if (FD_ISSET (ws_fd, &fdstate.wfds))
            retval = ws_handle_writes (ws_fd, server);

        if (retval >= 0) {

            /* handle reading data from a UnixSocket client */
            if (FD_ISSET (us_client->fd, &fdstate.rfds))
                handle_us_reads (us_client, ws_client, server);
            /* handle sending data to a UnixSocket client */
            else if (FD_ISSET (us_client->fd, &fdstate.wfds))
                handle_us_writes (us_client, ws_client, server);
        }

        client_node = client_node->next;
    }
}

/* Start the websocket server and start to monitor multiple file
 * descriptors until we have something to read or write. */
static void ws_start (WSServer * server)
{
    int ws_listener = 0, us_listener = 0, retval;

#ifdef HAVE_LIBSSL
    if (srvcfg.sslcert && srvcfg.sslkey) {
        ULOG_NOTE ("==Using TLS/SSL==\n");
        srvcfg.use_ssl = 1;
        if (initialize_ssl_ctx (server)) {
            ULOG_NOTE ("Unable to initialize_ssl_ctx\n");
            return;
        }
    }
#endif

    memset (&fdstate, 0, sizeof fdstate);
    if ((us_listener = us_listen (srvcfg.unixsocket)) < 0) {
        ULOG_ERR ("Unable to create Unix socket (%s): %s.",  srvcfg.unixsocket, strerror (errno));
        goto error;
    }

    if ((ws_listener = ws_socket (server)) < 0) {
        ULOG_ERR ("Unable to create Web socket (%s): %s.",  srvcfg.unixsocket, strerror (errno));
        goto error;
    }

    while (1) {
        struct timeval timeout = {0, 10000};   /* 10 ms */
        max_file_fd = MAX (ws_listener, us_listener);

        /* Clear out the fd sets for this iteration. */
        FD_ZERO (&fdstate.rfds);
        FD_ZERO (&fdstate.wfds);

        set_rfds_wfds (ws_listener, us_listener, server);
        max_file_fd += 1;

        /* yep, wait patiently */
        /* should it be using epoll/kqueue? will see... */
        retval = select (max_file_fd, &fdstate.rfds, &fdstate.wfds, NULL, &timeout);
        if (retval == 0) {
            //check_dirty_pixels (server);
        }
        else if (retval > 0) {
            check_rfds_wfds (ws_listener, us_listener, server);
        }
        else {
            switch (errno) {
                case EINTR:
                    break;
                default:
                    ULOG_ERR ("Unable to select: %s.", strerror (errno));
                    goto error;
            }
        }
    }

error:
    return;
}

int
main (int argc, char **argv)
{
    int retval;

    srv_set_config_host ("localhost");
    srv_set_config_port (HIBUS_WS_PORT);
    srv_set_config_unixsocket (HIBUS_US_PATH);

    retval = read_option_args (argc, argv);
    if (retval >= 0) {
        if (retval && srv_daemon ()) {
            perror ("Error during srv_daemon");
            exit (EXIT_FAILURE);
        }

        setup_signals ();

        if ((ws_srv = ws_init (&srvcfg)) == NULL) {
            perror ("Error during ws_init");
            exit (EXIT_FAILURE);
        }

        ws_start (ws_srv);
        ws_stop (ws_srv);
    }

    return EXIT_SUCCESS;
}

