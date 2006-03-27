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
  unsigned int id;
  int server;
  time_t last;
};

struct server {
  int weight, status, num, max, id;
  struct addrinfo *ai;
  time_t last;
};

typedef enum { RLB_NONE, RLB_CLIENT, RLB_SERVER } rlb_scope;

struct connection {
  int fd, od, bs;         /**< Socket, other socket */
  char *b;                /**< Buffer */
  unsigned int nr, nw;    /**< Read and write totals for connection */
  size_t len, pos;        /**< Length and position in buffer of data */
  struct event rev, wev;  /**< Events (libevent) */
  struct server *server;  /**< RLB_CLIENT only: which server is backend */
  struct client *client;
  struct cfg *cfg;
  rlb_scope scope;
  struct sockaddr sa;     /**< Accepted client address */
#ifdef RLB_SO
  int so_server;
  int nowrite;
  void *userdata;     /**< Persistent across a connection */
#endif
};

struct cfg {
  int bufsize, si, cs, num, daemon, fd, check, max; 
  int ci, rr, stubborn, delay;
  struct connection *conn;
  struct server *servers;
  struct client *clients;
  char *jail, *user;
  struct timeval to;
  char host[64], port[8];
  struct sockaddr oaddr;
  size_t olen;
#ifdef RLB_SO
  void *h;            /**< Handle to shared object */
  void *userdata;     /**< Persistent while process is running */
  int  (*fl)(struct connection *, int);
  void (*cl)(struct connection *);
  void (*gs)(struct cfg *, struct connection *);
  int  (*in)(struct cfg *);
  void (*fr)(struct cfg *);
#endif
};

#endif
