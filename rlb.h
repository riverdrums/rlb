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

#ifdef RLB_SO
#include <dlfcn.h>
#endif

#define RLB_VERSION   "0.8"
#define RLB_TIMEOUT   30        /**< Socket timeout and dead server check interval */
#define RLB_BUFSIZE   4096      /**< Default buffer size and number of clients to track */

typedef enum { RLB_NONE, RLB_CLIENT, RLB_SERVER 
#if defined(RLB_SO) && defined(RLB_CONTROL)
  , RLB_CTRL
#endif
} rlb_scope;

typedef enum { RLB_DEAD, RLB_ACTIVE, RLB_CLOSED } rlb_status;

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
#ifdef RLB_SO
  struct server *so_server; /**< Pointer to our own defined server to connect to */
  int reconnect;            /**< Reconnect to another server during a connection */
  int nowrite;              /**< Don't write data when this is set */
  void **userdata;          /**< Persistent across a connection (one for each filter) */
# ifdef RLB_CONTROL
  char fn[256];             /**< Shared object name for rlb engine to load */
# endif
#endif
};

#ifdef RLB_SO
struct filter {
  char name[64];                                /**< Reporting purposes only */
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
  size_t olen;                                  /**< Outbound address size */
#ifdef RLB_SO
  struct filter *filters;                       /**< Array of 'fi' filters */
  int fi, ini, fri, gsi, fli, cli, cf;          /**< Filter counters */
# ifdef RLB_CONTROL
  char kh[64], kp[8];                           /**< Control host and port */
  int kfd;                                      /**< Control socket */
  struct timeval kto;                           /**< Control socket timeout */
# endif
#endif
};

struct addrinfo * rlb_get_addrinfo(char *h, char *p);
int rlb_socket(struct cfg *cfg, struct addrinfo *a, int nb, int o);
int rlb_closefd(int fd);
int rlb_sockopt(const int fd, int nb);
int rlb_check_server(struct cfg *cfg, struct server *s);
char * rlb_strnstr(char *str, char *find, int n);
int rlb_str_insert(struct connection *c, char *start, char *end, char *insert, int len);

#endif
