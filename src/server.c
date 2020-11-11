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
#include <sys/epoll.h>
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
// static USServer *us_srv = NULL;

static inline void
srv_set_config_websocket (int websocket)
{
    srvcfg.websocket = websocket;
}

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

/* Set the the backlog. */
static inline void
srv_set_config_backlog (int backlog)
{
    srvcfg.backlog = backlog;
}

/* Set specific name for the UNIX socket. */
static inline void
srv_set_config_unixsocket (const char *unixsocket)
{
    srvcfg.unixsocket = unixsocket;
}

/* Set a path and a file for the access log. */
static inline void
srv_set_config_accesslog (int accesslog)
{
    srvcfg.accesslog = accesslog;
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
static char short_options[] = "dwbp:Vh";
static struct option long_opts[] = {
    {"without-websocket", no_argument     , 0 , 'w' } ,
    {"port"           , required_argument , 0 , 'p' } ,
    {"addr"           , required_argument , 0 ,  0  } ,
    {"max-frame-size" , required_argument , 0 ,  0  } ,
    {"origin"         , required_argument , 0 ,  0  } ,
    {"backlog"        , required_argument , 0 , 'b' } ,
#if HAVE_LIBSSL
    {"ssl-cert"       , required_argument , 0 ,  0  } ,
    {"ssl-key"        , required_argument , 0 ,  0  } ,
#endif
    {"with-access-log", no_argument       , 0 , 'a' } ,
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
            "hibusd [ options ... ] [--unixsocket] [-p <port>] [--addr] [--origin] ...\n"
            "The following options can also be supplied to the command:\n\n"
            ""
            "  -d                       - Run as a daemon.\n"
            "  -a --with-access-log     - Logging the verbose socket access info.\n"
            "  -w --without-websocket   - Disable WebSocket.\n"
            "  --unixsocket=<path>      - Specify the path of the Unix socket.\n"
            "  --origin=<origin>        - Ensure clients send the specified origin\n"
            "                             header upon the WebSocket handshake.\n"
            "  --addr=<addr>            - Specify an IP address to bind to.\n"
            "  -p --port=<port>         - Specify the port to bind.\n"
            "  -b --backlog=<number>    - The maximum length to which the queue of \n"
            "                             pending connections.\n"
            "  --max-frame-size=<bytes> - Maximum size of a socket frame.\n"
            "  --ssl-cert=<cert.crt>    - Path to SSL certificate.\n"
            "  --ssl-key=<priv.key>     - Path to SSL private key.\n"
            "  -h --help                - This help.\n"
            "  -V --version             - Display version information and exit.\n"
            "\n"
            "hibusd Copyright (C) 2020 FMSoft <https://www.fmsoft.cn>\n"
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
        ws_stop (the_server.ws_srv);
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

    if (!strcmp ("backlog", name))
        srv_set_config_backlog (atoi (oarg));

    if (!strcmp ("origin", name))
        srv_set_config_origin (oarg);

    if (!strcmp ("unixsocket", name))
        srv_set_config_unixsocket (oarg);

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
            case 'w':
                srv_set_config_websocket (0);
                break;
            case 'a':
                srv_set_config_accesslog (1);
                break;
            case 'p':
                srv_set_config_port (optarg);
                break;
            case 'h':
                cmd_help ();
                return -1;
            case 'V':
                fprintf (stdout, "hibusd %s\n", HIBUS_VERSION);
                return -1;
            case 0:
                parse_long_opt (long_opts[idx].name, optarg);
                break;
            case '?':
                cmd_help ();
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

#if 1 // epoll version

/* max events for epoll */
#define MAX_EVENTS          10
#define PTR_FOR_US_LISTENER ((void *)1)
#define PTR_FOR_WS_LISTENER ((void *)2)

static void server_start (void)
{
    int us_listener = -1, ws_listener = -1;
    struct epoll_event ev, events[MAX_EVENTS];
    int epollfd;

    // create unix socket
    if ((us_listener = us_listen (the_server.us_srv)) < 0) {
        ULOG_ERR ("Unable to create Unix socket (%s, %s): %s.",
                srvcfg.host, srvcfg.port, strerror (errno));
        goto error;
    }

    // create web socket listener if enabled
    if (the_server.ws_srv) {
#ifdef HAVE_LIBSSL
        if (srvcfg.sslcert && srvcfg.sslkey) {
            ULOG_NOTE ("==Using TLS/SSL==\n");
            srvcfg.use_ssl = 1;
            if (ws_initialize_ssl_ctx (the_server.ws_srv)) {
                ULOG_ERR ("Unable to initialize_ssl_ctx\n");
                goto error;
            }
        }
#endif

        if ((ws_listener = ws_listen (the_server.ws_srv)) < 0) {
            ULOG_ERR ("Unable to create Web socket (%s): %s.",
                    srvcfg.unixsocket, strerror (errno));
            goto error;
        }
    }

    epollfd = epoll_create1 (EPOLL_CLOEXEC);
    if (epollfd == -1) {
        ULOG_ERR ("Failed to call epoll_create1: %s.", strerror (errno));
        goto error;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = PTR_FOR_US_LISTENER;
    if (epoll_ctl (epollfd, EPOLL_CTL_ADD, us_listener, &ev) == -1) {
        ULOG_ERR ("Failed to call epoll_ctl with us_listener (%d): %s.",
                us_listener, strerror (errno));
        goto error;
    }

    if (ws_listener >= 0) {
        ev.events = EPOLLIN;
        ev.data.ptr = PTR_FOR_WS_LISTENER;
        if (epoll_ctl (epollfd, EPOLL_CTL_ADD, ws_listener, &ev) == -1) {
            ULOG_ERR ("Failed to call epoll_ctl with ws_listener (%d): %s.",
                    ws_listener, strerror (errno));
            goto error;
        }
    }

    while (1) {
        int nfds, n;

        nfds = epoll_wait (epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            ULOG_ERR ("failed epoll_wait: %s.",
                    strerror (errno));
            goto error;
        }

        for (n = 0; n < nfds; ++n) {
            if (events[n].data.ptr == PTR_FOR_US_LISTENER) {
                USClient * client = us_handle_accept (the_server.us_srv, &the_server);
                if (client == NULL) {
                    ULOG_NOTE ("refused a client");
                }
                else {
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.ptr = client;
                    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client->fd, &ev) == -1) {
                        ULOG_ERR ("failed epoll_ctl for connected unix socket (%d): %s.",
                                client->fd, strerror (errno));
                        goto error;
                    }
                }
            }
            else if (events[n].data.ptr == PTR_FOR_WS_LISTENER) {
                WSClient * client = ws_handle_accept (the_server.ws_srv, ws_listener);
                if (client == NULL) {
                    ULOG_NOTE ("refuse a client");
                }
                else {
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.ptr = client;
                    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client->fd, &ev) == -1) {
                        ULOG_ERR ("failed epoll_ctl for connected web socket (%d): %s.",
                                client->fd, strerror (errno));
                        goto error;
                    }
                }
            }
            else {
                USClient *usc = (USClient *)events[n].data.ptr;
                if (usc->type == ET_UNIX_SOCKET) {
                    us_handle_reads (the_server.us_srv, usc);
                }
                else if (usc->type == ET_UNIX_SOCKET) {
                    WSClient *wsc = (WSClient *)events[n].data.ptr;
                    ws_handle_reads (the_server.ws_srv, wsc);
                }
                else {
                    ULOG_ERR ("bad socket type: (%d) %s.",
                            usc->type, strerror (errno));
                    goto error;
                }
            }
        }
    }

error:
    return;
}

#else // select version

static int max_file_fd = 0;
static WSEState fdstate;

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

/* Start the server and start to monitor the file
 * descriptors until we have something to read or write. */
static void server_start (void)
{
    int ws_listener = -1, us_listener = -1, retval;

    memset (&fdstate, 0, sizeof fdstate);

    // create unix socket
    if ((us_listener = us_listen (the_server.us_srv)) < 0) {
        ULOG_ERR ("Unable to create Unix socket (%s, %s): %s.",
                srvcfg.host, srvcfg.port, strerror (errno));
        goto error;
    }

    // create web socket listener if enabled
    if (the_server.ws_srv) {
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

        if ((ws_listener = ws_listen (the_server.ws_srv)) < 0) {
            ULOG_ERR ("Unable to create Web socket (%s): %s.",
                    srvcfg.unixsocket, strerror (errno));
            goto error;
        }
    }

    while (1) {
        struct timeval timeout = {0, 10000};   /* 10 ms */
        max_file_fd = MAX (ws_listener, us_listener);

        /* Clear out the fd sets for this iteration. */
        FD_ZERO (&fdstate.rfds);
        FD_ZERO (&fdstate.wfds);

        set_rfds_wfds (ws_listener, us_listener, the_server.ws_srv);
        max_file_fd += 1;

        /* yep, wait patiently */
        /* should it be using epoll/kqueue? will see... */
        retval = select (max_file_fd, &fdstate.rfds, &fdstate.wfds, NULL, &timeout);
        if (retval == 0) {
            //check_dirty_pixels (server);
        }
        else if (retval > 0) {
            check_rfds_wfds (ws_listener, us_listener, the_server.ws_srv);
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

#endif // select version

static void
server_stop (void)
{
}

int
main (int argc, char **argv)
{
    int retval;

    srv_set_config_websocket (1);
    srv_set_config_origin ("localhost");
    srv_set_config_host ("localhost");
    srv_set_config_port (HIBUS_WS_PORT);
    srv_set_config_unixsocket (HIBUS_US_PATH);
    srv_set_config_frame_size (WS_MAX_FRM_SZ);
    srv_set_config_backlog (SOMAXCONN);

    retval = read_option_args (argc, argv);
    if (retval < 0) {
        return EXIT_SUCCESS;
    }
    else if (retval && srv_daemon ()) {
        perror ("Error during srv_daemon");
        return EXIT_FAILURE;
    }

    ulog_open (-1, -1, "hiBusd: ");
    if (srvcfg.accesslog) {
        ulog_threshold (LOG_INFO);
    }
    else {
        ulog_threshold (LOG_NOTICE);
    }

    setup_signals ();

    if ((the_server.us_srv = us_init (&srvcfg)) == NULL) {
        ULOG_ERR ("Error during us_init");
        goto error;
    }

    if (srvcfg.websocket) {
        if ((the_server.ws_srv = ws_init (&srvcfg)) == NULL) {
            ULOG_ERR ("Error during ws_init");
            goto error;
        }
    }
    else {
        the_server.ws_srv = NULL;
        ULOG_NOTE ("Skip web socket");
    }

    server_start ();
    server_stop ();

    return EXIT_SUCCESS;

error:
    ulog_close ();
    return EXIT_FAILURE;
}

#if 0

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

#endif

