/* rlb.h Jason Armstrong <ja@riverdrums.com> © 2006 RIVERDRUMS
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
  unsigned int id;        /**< Client IP address */
  struct server * server; /**< Who the client connected to last time */
  time_t last;            /**< Last operation to that server */
};

struct server {
  int weight, status, num, max;
  struct addrinfo *ai;
  time_t last;
};

typedef enum { RLB_NONE, RLB_CLIENT, RLB_SERVER } rlb_scope;

struct connection {
  int fd, od, bs;         /**< Socket, other socket, buffer size */
  char *b;                /**< Buffer */
  unsigned int nr, nw;    /**< Read and write totals for connection */
  size_t len, pos;        /**< Length and position in buffer of data */
  struct event rev, wev;  /**< Events (libevent) */
  struct server *server;  /**< RLB_CLIENT only: which server is backend */
  struct client *client;
  struct cfg *cfg;
  rlb_scope scope;        /**< CLIENT: outside connection SERVER: backend server */
  struct sockaddr sa;     /**< Accepted client address */
#ifdef RLB_SO
  struct server *so_server;
  int reconnect;          /**< Reconnect to another server during a connection */
  int nowrite;
  void *userdata;         /**< Persistent across a connection */
#endif
};

struct cfg {
  int bufsize, si, cs, num, daemon, fd, check, max; 
  int ci, rr, stubborn, delay;
  struct connection *conn;  /**< Array of 'max' connections */
  struct server *servers;   /**< Array of 'si' servers */
  struct client *clients;   /**< Array of 'ci' clients */
  char *jail, *user;        /**< chroot() jail, run as 'user' */
  struct timeval to;        /**< Timeout value (seconds) */
  char host[64], port[8];   /**< Listen host and port */
  struct sockaddr oaddr;    /**< Bind to this address on 'connect()' */
  size_t olen;
#ifdef RLB_SO
  void *h;                                /**< Handle to shared object */
  void *userdata;                         /**< Persistent while process is running */
  int  (*fl)(struct connection *, int);   /**< Filter */
  void (*cl)(struct connection *);        /**< Connection close */
  void (*gs)(struct connection *);        /**< Custom choose server */
  int  (*in)(struct cfg *);               /**< Global init */
  void (*fr)(struct cfg *);               /**< Global shutdown */
#endif
};

#endif
