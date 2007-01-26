/* rlb.h Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
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

#define RLB_VERSION    "0.6"
#define RLB_TIMEOUT    30        /**< Socket timeout and dead server check interval */
#define RLB_BUFSIZE    4096      /**< Default buffer size and number of clients to track */

#ifdef RLB_DEBUG
FILE *_rlb_fp = NULL;
# define RLOG(f,...) do { if (_rlb_fp) { struct timeval tv; gettimeofday(&tv, NULL); fprintf(_rlb_fp, "%lu.%06lu [%7s:%d] " f "\n", tv.tv_sec, tv.tv_usec, __FUNCTION__, __LINE__, ##__VA_ARGS__); fflush(_rlb_fp); } } while(0)
# define SCOPE  (c->scope == RLB_CLIENT) ? "CLIENT" : (c->scope == RLB_SERVER) ? "SERVER" : " NONE "
#else
# define RLOG(f,...)
# define SCOPE ""
#endif

typedef enum { RLB_NONE, RLB_CLIENT, RLB_SERVER } rlb_scope;

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

struct buffer {
  char *b;                  /**< Data buffer */
  int bs, taken;            /**< Buffer size / whether it is attached */
  size_t len, pos;          /**< Length and position of data in the buffer */
};

struct connection {
  int fd, od;               /**< Socket, other socket */
  struct buffer *rb, *wb;   /**< Data buffers for read and write */
  unsigned int nr, nw;      /**< Read and write totals for connection */
  struct event ev;          /**< Event structure for libevent */
  struct server *server;    /**< CLIENT: which server is backend SERVER: myself */
  struct client *client;    /**< Pointer to previous connection information */
  struct cfg *cfg;          /**< Pointer to global configuration structure */
  rlb_scope scope;          /**< CLIENT=outside connection SERVER=backend server */
  struct sockaddr sa;       /**< Accepted client address */
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
  int  (*fl)(struct connection *, int, void *); /**< Filter after read    rlb_filter() */
  void (*cl)(struct connection *, void *);      /**< Connection close     rlb_close() */
  void (*gs)(struct connection *, void *);      /**< Custom choose server rlb_get_server() */
  int  (*in)(struct cfg *, void **);            /**< Global init          rlb_init() */
  void (*fr)(struct cfg *, void **);            /**< Global shutdown      rlb_cleanup() */
};
#endif

struct cfg {
  int bufsize, num, daemon, fd, check, max; 
  int si, cs, ci, rr, stubborn, delay;
  struct connection *conn;                      /**< Array of 'max' connections */
  struct buffer *buffers;                       /**< Array of 'max' buffers */
  struct server *servers;                       /**< Array of 'si' servers */
  struct client *clients;                       /**< Array of 'ci' clients */
  char *jail, *user;                            /**< chroot() jail / Run as 'user' */
  struct timeval to;                            /**< Timeout value (seconds) */
  char host[64], port[8];                       /**< Listen host and port */
  struct sockaddr oaddr;                        /**< Bind to this address on 'connect()' */
  size_t olen;
#ifdef RLB_SO
  struct filter *filters;                       /**< Array of 'fi' filters */
  int fi, ini, fri, gsi, fli, cli, cf;
#endif
};

#endif
