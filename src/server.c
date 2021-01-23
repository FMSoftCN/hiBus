/*
** server.c -- The code for hiBus daemon.
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
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <hibox/ulog.h>
#include <hibox/kvlist.h>
#include <hibox/safe_list.h>

#include "hibus.h"
#include "server.h"
#include "websocket.h"
#include "unixsocket.h"
#include "endpoint.h"

static BusServer the_server;

static ServerConfig srvcfg = { 0 };

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
static char short_options[] = "adwbp:Vh";
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
    printf ("hiBusD (%s) - the daemon of data bus system for HybridOS\n\n", HIBUS_VERSION);

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
            "hiBus - the data bus system for HybridOS.\n"
            "\n"
            "Copyright (C) 2020 FMSoft <https://www.fmsoft.cn>\n"
            "\n"
            "hiBus is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License as published by\n"
            "the Free Software Foundation, either version 3 of the License, or\n"
            "(at your option) any later version.\n"
            "\n"
            "hiBus is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
            "GNU General Public License for more details.\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program.  If not, see http://www.gnu.org/licenses/.\n"
            "\n"
            );
}
/* *INDENT-ON* */

static void
handle_signal_action (int sig_number)
{
    if (sig_number == SIGINT) {
        ULOG_WARN ("SIGINT caught!\n");
#if 1
        the_server.running = false;
#else
        /* if it fails to write, force stop */
        us_stop (the_server.us_srv);
        if (the_server.ws_srv)
            ws_stop (the_server.ws_srv);
        _exit (1);
#endif
    }
    else if (sig_number == SIGPIPE) {
        ULOG_WARN ("SIGPIPE caught!\n");
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
                fprintf (stdout, "hiBusD: %s\n", HIBUS_VERSION);
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

    if (optind < argc) {
        cmd_help ();
        return -1;
    }

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

/* callbacks for socket servers */
// Allocate a BusEndpoint structure for a new client and send `auth` packet.
static int
on_accepted (void* sock_srv, SockClient* client)
{
    int ret_code;
    BusEndpoint* endpoint;

    endpoint = new_endpoint (&the_server,
            (client->ct == CT_WEB_SOCKET) ? ET_WEB_SOCKET : ET_UNIX_SOCKET,
            client);

    if (endpoint == NULL)
        return HIBUS_SC_INSUFFICIENT_STORAGE;

    // send challenge code
    ret_code = send_challenge_code (&the_server, endpoint);
    if (ret_code != HIBUS_SC_OK)
        return ret_code;

    return HIBUS_SC_OK;
}

static int
on_packet (void* sock_srv, SockClient* client,
            const char* body, unsigned int sz_body, int type)
{
    assert (client->entity);

    if (type == PT_TEXT) {

        handle_json_packet (&the_server,
                container_of (client->entity, BusEndpoint, entity),
                &client->ts, body, sz_body);
    }
    else {
        /* discard all packet in binary */
        return HIBUS_SC_NOT_ACCEPTABLE;
    }

    return HIBUS_SC_OK;
}

static int
on_close (void* sock_srv, SockClient* client)
{
    if (epoll_ctl (the_server.epollfd, EPOLL_CTL_DEL, client->fd, NULL) == -1) {
        ULOG_ERR ("Failed to call epoll_ctl to delete the client fd (%d): %s\n",
                client->fd, strerror (errno));
        assert (0);
    }

    if (client->entity) {
        BusEndpoint *endpoint = container_of (client->entity, BusEndpoint, entity);
        char endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];

        if (endpoint->status == ES_AUTHING) {
            remove_dangling_endpoint (&the_server, endpoint);
            ULOG_INFO ("An endpoint not authenticated removed: (%p), %d endpoints left.\n",
                    endpoint, the_server.nr_endpoints);
        }
        else {
            assemble_endpoint_name (endpoint, endpoint_name);
            if (kvlist_delete (&the_server.endpoint_list, endpoint_name))
                the_server.nr_endpoints--;

            ULOG_INFO ("An authenticated endpoint removed: %s (%p), %d endpoints left.\n",
                    endpoint_name, endpoint, the_server.nr_endpoints);
        }
        del_endpoint (&the_server, endpoint, CDE_LOST_CONNECTION);

        client->entity = NULL;
    }

    return 0;
}

static void
on_error (void* sock_srv, SockClient* client, int err_code)
{
    int n;
    char buff [HIBUS_MIN_PACKET_BUFF_SIZE];

    n = snprintf (buff, sizeof (buff), 
            "{"
            "\"packetType\":\"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"retCode\":%d,"
            "\"retMsg\":\"%s\""
            "}",
            HIBUS_PROTOCOL_NAME, HIBUS_PROTOCOL_VERSION,
            err_code, hibus_get_ret_message (err_code));

    if (n < 0 || (size_t)n >= sizeof (buff)) {
        // should never reach here
        assert (0);
    }

    if (client->ct == CT_UNIX_SOCKET) {
        us_send_packet (sock_srv, (USClient *)client, US_OPCODE_TEXT, buff, n);
    }
    else {
        ws_send_packet (sock_srv, (WSClient *)client, WS_OPCODE_TEXT, buff, n);
    }
}

/* max events for epoll */
#define MAX_EVENTS          10
#define PTR_FOR_US_LISTENER ((void *)1)
#define PTR_FOR_WS_LISTENER ((void *)2)

static void
run_server (void)
{
    int us_listener = -1, ws_listener = -1;
    struct epoll_event ev, events[MAX_EVENTS];
    time_t t_last = time (NULL);
    time_t t_diff;

    // create unix socket
    if ((us_listener = us_listen (the_server.us_srv)) < 0) {
        ULOG_ERR ("Unable to listen on Unix socket (%s)\n",
                srvcfg.unixsocket);
        goto error;
    }
    ULOG_NOTE ("Listening on Unix Socket (%s)...\n", srvcfg.unixsocket);

    the_server.us_srv->on_accepted = on_accepted;
    the_server.us_srv->on_packet = on_packet;
    the_server.us_srv->on_close = on_close;
    the_server.us_srv->on_error = on_error;

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
#else
        srvcfg.sslcert = srvcfg.sslkey = NULL;
#endif

        if ((ws_listener = ws_listen (the_server.ws_srv)) < 0) {
            ULOG_ERR ("Unable to listen on Web socket (%s, %s)\n",
                    srvcfg.host, srvcfg.port);
            goto error;
        }

        the_server.ws_srv->on_accepted = on_accepted;
        the_server.ws_srv->on_packet = on_packet;
        the_server.ws_srv->on_close = on_close;
        the_server.ws_srv->on_error = on_error;
    }
    ULOG_NOTE ("Listening on Web Socket (%s, %s) %s SSL...\n",
            srvcfg.host, srvcfg.port, srvcfg.sslcert ? "with" : "without");

    the_server.epollfd = epoll_create1 (EPOLL_CLOEXEC);
    if (the_server.epollfd == -1) {
        ULOG_ERR ("Failed to call epoll_create1: %s\n", strerror (errno));
        goto error;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = PTR_FOR_US_LISTENER;
    if (epoll_ctl (the_server.epollfd, EPOLL_CTL_ADD, us_listener, &ev) == -1) {
        ULOG_ERR ("Failed to call epoll_ctl with us_listener (%d): %s\n",
                us_listener, strerror (errno));
        goto error;
    }

    if (ws_listener >= 0) {
        ev.events = EPOLLIN;
        ev.data.ptr = PTR_FOR_WS_LISTENER;
        if (epoll_ctl (the_server.epollfd, EPOLL_CTL_ADD, ws_listener, &ev) == -1) {
            ULOG_ERR ("Failed to call epoll_ctl with ws_listener (%d): %s\n",
                    ws_listener, strerror (errno));
            goto error;
        }
    }

    while (the_server.running) {
        int nfds, n;

        nfds = epoll_wait (the_server.epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            ULOG_ERR ("Failed to call epoll_wait: %s\n",
                    strerror (errno));
            goto error;
        }

        for (n = 0; n < nfds; ++n) {
            if (events[n].data.ptr == PTR_FOR_US_LISTENER) {
                USClient * client = us_handle_accept (the_server.us_srv);
                if (client == NULL) {
                    ULOG_NOTE ("Refused a client\n");
                }
                else {
                    ev.events = EPOLLIN | EPOLLOUT; /* do not use EPOLLET */
                    ev.data.ptr = client;
                    if (epoll_ctl (the_server.epollfd,
                                EPOLL_CTL_ADD, client->fd, &ev) == -1) {
                        ULOG_ERR ("Failed epoll_ctl for connected unix socket (%d): %s\n",
                                client->fd, strerror (errno));
                        goto error;
                    }
                }
            }
            else if (events[n].data.ptr == PTR_FOR_WS_LISTENER) {
                WSClient * client = ws_handle_accept (the_server.ws_srv, ws_listener);
                if (client == NULL) {
                    ULOG_NOTE ("Refused a client\n");
                }
                else {
                    ev.events = EPOLLIN | EPOLLOUT; /* do not use EPOLLET */
                    ev.data.ptr = client;
                    if (epoll_ctl(the_server.epollfd,
                                EPOLL_CTL_ADD, client->fd, &ev) == -1) {
                        ULOG_ERR ("Failed epoll_ctl for connected web socket (%d): %s\n",
                                client->fd, strerror (errno));
                        goto error;
                    }
                }
            }
            else {
                USClient *usc = (USClient *)events[n].data.ptr;
                struct timespec ts;
                int retv = 0;

                clock_gettime (CLOCK_REALTIME, &ts);

                if (usc->ct == CT_UNIX_SOCKET) {
                    BusEndpoint *endpoint = container_of (usc->entity, BusEndpoint, entity);

                    if (endpoint)
                        endpoint->t_living = ts.tv_sec;

                    if (events[n].events & EPOLLIN) {
                        retv = us_handle_reads (the_server.us_srv, usc);
                    }
                    if (retv == 0 && usc->sz_pending > 0 && events[n].events & EPOLLOUT) {
                        us_handle_writes (the_server.us_srv, usc);
                    }
                }
                else if (usc->ct == CT_WEB_SOCKET) {
                    WSClient *wsc = (WSClient *)events[n].data.ptr;
                    BusEndpoint *endpoint;
                   
                    if (wsc->entity) {
                        endpoint = container_of (wsc->entity, BusEndpoint, entity);
                        endpoint->t_living = ts.tv_sec;
                    }

                    if (events[n].events & EPOLLIN) {
                        retv = ws_handle_reads (the_server.ws_srv, wsc);
                    }
                    if (retv == 0 && wsc->sockqueue && wsc->sockqueue->qlen > 0 &&
                            events[n].events & EPOLLOUT) {
                        ws_handle_writes (the_server.ws_srv, wsc);
                    }
                }
                else {
                    ULOG_ERR ("Bad socket type (%d): %s\n",
                            usc->ct, strerror (errno));
                    goto error;
                }
            }
        }

        t_diff = time (NULL) - t_last;
        if (t_diff % 10) {
            check_no_responding_endpoints (&the_server);
        }
        else if (t_diff % 5) {
            check_dangling_endpoints (&the_server);
        }
    }

error:
    return;
}

static int
get_waiting_info_len (struct kvlist *kv, const void *data)
{
    (void) kv;
    (void )data;
    return (int)sizeof (BusWaitingInfo);
}

static int
init_bus_server (void)
{
    BusEndpoint* builtin;
    char endpoint_name [HIBUS_LEN_ENDPOINT_NAME + 1];

    /* TODO for host name */
    the_server.running = true;
    the_server.server_name = strdup (HIBUS_LOCALHOST);
    kvlist_init (&the_server.endpoint_list, NULL);
    kvlist_init (&the_server.waiting_endpoints, get_waiting_info_len);

    builtin = new_endpoint (&the_server, ET_BUILTIN, NULL);
    if (builtin == NULL) {
        return HIBUS_SC_INSUFFICIENT_STORAGE;
    }
    the_server.endpoint_builtin = builtin;

    if (assemble_endpoint_name (builtin, endpoint_name) <= 0) {
        del_endpoint (&the_server, builtin, CDE_INITIALIZING);
        return HIBUS_SC_INTERNAL_SERVER_ERROR;
    }

    if (!init_builtin_endpoint (&the_server, builtin)) {
        del_endpoint (&the_server, builtin, CDE_INITIALIZING);
        return HIBUS_SC_INTERNAL_SERVER_ERROR;
    }

    if (!kvlist_set (&the_server.endpoint_list, endpoint_name, &builtin)) {
        del_endpoint (&the_server, builtin, CDE_INITIALIZING);
        return HIBUS_SC_INTERNAL_SERVER_ERROR;
    }
    the_server.nr_endpoints++;

    ULOG_INFO ("Builtin builtin stored: %s (%p)\n", endpoint_name, builtin);
    return 0;
}

static void
cleanup_bus_server (void)
{
    const char* name;
    void *next, *data;
    BusEndpoint* endpoint;

    kvlist_free (&the_server.waiting_endpoints);

    kvlist_for_each_safe (&the_server.endpoint_list, name, next, data) {
        //memcpy (&endpoint, data, sizeof (BusEndpoint*));
        endpoint = *(BusEndpoint **)data;

        if (endpoint->type != ET_BUILTIN) {
            ULOG_INFO ("Deleting endpoint: %s (%p) in cleanup_bus_server\n", name, endpoint);

            if (endpoint->type == ET_UNIX_SOCKET && endpoint->entity.client) {
                // avoid a duplicated call of del_endpoint
                endpoint->entity.client->entity = NULL;
                us_cleanup_client (the_server.us_srv, (USClient *)endpoint->entity.client);
            }
            else if (endpoint->type == ET_WEB_SOCKET && endpoint->entity.client) {
                // avoid a duplicated call of del_endpoint
                endpoint->entity.client->entity = NULL;
                ws_cleanup_client (the_server.ws_srv, (WSClient *)endpoint->entity.client);
            }

            del_endpoint (&the_server, endpoint, CDE_EXITING);
            kvlist_delete (&the_server.endpoint_list, name);
            the_server.nr_endpoints--;
        }
    }

    ULOG_INFO ("Deleting builtin endpoint in cleanup_bus_server\n");
    del_endpoint (&the_server, the_server.endpoint_builtin, CDE_EXITING);
    the_server.nr_endpoints--;

    kvlist_free (&the_server.endpoint_list);

    if (the_server.dangling_endpoints) {
        gs_list* node = the_server.dangling_endpoints;

        while (node) {
            endpoint = (BusEndpoint *)node->data;
            ULOG_WARN ("Removing dangling endpoint: %p, type (%d), status (%d)\n",
                    endpoint, endpoint->type, endpoint->status);

            if (endpoint->type == ET_UNIX_SOCKET) {
                USClient* usc = (USClient *)endpoint->entity.client;
                us_remove_dangling_client (the_server.us_srv, usc);
            }
            else if (endpoint->type == ET_WEB_SOCKET) {
                WSClient* wsc = (WSClient *)endpoint->entity.client;
                ws_remove_dangling_client (the_server.ws_srv, wsc);
            }
            else {
                ULOG_WARN ("Bad type of dangling endpoint\n");
            }

            del_endpoint (&the_server, endpoint, CDE_EXITING);

            node = node->next;
        }

        gslist_remove_nodes (the_server.dangling_endpoints);
    }

    us_stop (the_server.us_srv);
    if (the_server.ws_srv)
        ws_stop (the_server.ws_srv);

    free (the_server.server_name);

    assert (the_server.nr_endpoints == 0);
}

int
main (int argc, char **argv)
{
    int retval;

    srv_set_config_websocket (1);
    srv_set_config_host ("localhost");
    srv_set_config_port (HIBUS_WS_PORT);
    srv_set_config_unixsocket (HIBUS_US_PATH);
    srv_set_config_frame_size (HIBUS_MAX_FRAME_PAYLOAD_SIZE);
    srv_set_config_backlog (SOMAXCONN);

    retval = read_option_args (argc, argv);
    if (retval < 0) {
        return EXIT_SUCCESS;
    }
    else if (retval && srv_daemon ()) {
        perror ("Error during srv_daemon");
        return EXIT_FAILURE;
    }

    ulog_open (-1, -1, "hiBusD");
    if (srvcfg.accesslog) {
        ulog_threshold (LOG_INFO);
    }
    else {
        ulog_threshold (LOG_NOTICE);
    }

    srandom (time (NULL));

    setup_signals ();

    if ((retval = init_bus_server ())) {
        ULOG_ERR ("Error during init_bus_server: %s\n",
                hibus_get_ret_message (retval));
        goto error;
    }

    if ((the_server.us_srv = us_init (&srvcfg)) == NULL) {
        ULOG_ERR ("Error during us_init\n");
        goto error;
    }

    if (srvcfg.websocket) {
        if ((the_server.ws_srv = ws_init (&srvcfg)) == NULL) {
            ULOG_ERR ("Error during ws_init\n");
            goto error;
        }
    }
    else {
        the_server.ws_srv = NULL;
        ULOG_NOTE ("Skip web socket");
    }

    run_server ();

    cleanup_bus_server ();
    ulog_close ();

    ULOG_NOTE ("Will exit normally.\n");
    return EXIT_SUCCESS;

error:
    ulog_close ();
    return EXIT_FAILURE;
}

