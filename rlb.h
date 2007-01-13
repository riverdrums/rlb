/* rlb.h Jason Armstrong <ja@riverdrums.com> � 2006-2007 RIVERDRUMS
 * $Id$ */

#ifndef _RLB_H_
#define _RLB_H_

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <event.h>

struct client {
  unsigned int id;          /**< Client IP address */
  struct server *server;    /**< Who the client connected to last time */
  time_t last;              /**< Last operation to that server */
};

struct server {
  int status, num, max;     /**< Working / number of connections / max allowed */
  struct addrinfo *ai;      /**< Socket address structure */
  time_t last;              /**< Time of last failed connection */
};

typedef enum { RLB_NONE, RLB_CLIENT, RLB_SERVER } rlb_scope;

struct connection {
  int fd, od, bs;           /**< Socket, other socket, buffer size */
  char *b;                  /**< Data buffer */
  unsigned int nr, nw;      /**< Read and write totals for connection */
  size_t len, pos;          /**< Length and position in buffer of data */
  struct event ev;          /**< Event structure for libevent */
  struct server *server;    /**< RLB_CLIENT only: which server is backend */
  struct client *client;    /**< Pointer to previous connection information */
  struct cfg *cfg;          /**< Pointer to global configuration structure */
  rlb_scope scope;          /**< CLIENT=outside connection SERVER=backend server */
  struct sockaddr sa;       /**< Accepted client address */
  int closed;               /**< Socket is closed, but there is still data to write */
  int connected;            /**< RLB_CLIENT only: whether we are connected to the server */
#ifdef RLB_SO
  struct server *so_server; /**< Pointer to our own defined server to connect to */
  int reconnect;            /**< Reconnect to another server during a connection */
  int nowrite;              /**< Don't write data when this is set */
  void *userdata;           /**< Persistent across a connection */
#endif
};

#ifdef RLB_SO
struct filter {
  void *h;                                      /**< Handle to shared object */
  void *userdata;                               /**< Persistent while rlb is running */
  int  (*fl)(struct connection *, int, void *); /**< Filter               rlb_filter() */
  void (*cl)(struct connection *, void *);      /**< Connection close     rlb_close() */
  void (*gs)(struct connection *, void *);      /**< Custom choose server rlb_get_server() */
  int  (*in)(struct cfg *, void **);            /**< Global init          rlb_init() */
  void (*fr)(struct cfg *, void **);            /**< Global shutdown      rlb_cleanup() */
};
#endif

struct cfg {
  int bufsize, si, cs, num, daemon, fd, check, max; 
  int ci, rr, stubborn, delay;
  struct connection *conn;  /**< Array of 'max' connections */
  struct server *servers;   /**< Array of 'si' servers */
  struct client *clients;   /**< Array of 'ci' clients */
  char *jail, *user;        /**< chroot() jail / Run as 'user' */
  struct timeval to;        /**< Timeout value (seconds) */
  char host[64], port[8];   /**< Listen host and port */
  struct sockaddr oaddr;    /**< Bind to this address on 'connect()' */
  size_t olen;
#ifdef RLB_SO
  void *userdata;           /**< Persistent while rlb is running */
  struct filter *filters;   /**< Array of 'fi' filters */
  int fi, ini, fri, gsi, fli, cli, cf;
#endif
};

#endif
