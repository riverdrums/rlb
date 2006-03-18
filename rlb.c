/* rlb.c � RIVERDRUMS 2006 $Id$ */
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <event.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/resource.h>

#define _VERSION  "0.4"
#define _TIMEOUT  30
#define _CHECK    60
#define _BUFSIZE  4096

struct server {
  int weight, status, num, max;
  struct addrinfo *ai;
  time_t last;
};

struct connection {
  int c, s;
  char *rb, *wb;
  size_t rlen, rpos, wlen, wpos;
  struct event c_rev, c_wev, s_rev, s_wev;
  struct server *server;
  struct cfg *cfg;
};

struct cfg {
  int bufsize, si, cs, num, daemon, fd, check, max, ci;
  struct connection *conn;
  struct server *servers;
  struct client *clients;
  struct timeval to;
  char host[64], port[8];
  struct sockaddr oaddr;
  size_t olen;
};

static struct server * _get_server(struct cfg *cfg, struct connection *c);
struct addrinfo * _get_addrinfo(struct cfg *cfg, char *h, char *p);
static int  _cmdline(struct cfg *cfg, int argc, char *argv[]);
static void _check_server(struct cfg *cfg, struct server *s);
static void _client(const int s, short event, void *ev);
static void _write(const int fd, short event, void *c);
static int  _lookup_oaddr(struct cfg *cfg, char *outb);
static void _read(const int fd, short event, void *c);
static int  _parse_server(struct cfg *cfg, char *str);
static int  _connect_server(struct connection *c);
static int  _sockopt(const int fd, int nb);
static void _close(struct connection *c);
static void _cleanup(struct cfg *cfg);
static int  _options(struct cfg *cfg);
static int  _server(struct cfg *cfg);
static void _sig(int signo);
static void _version(void);
static void _usage(void);
struct cfg *_gcfg = NULL;

int main(int argc, char *argv[]) {
  struct event ev;
  struct cfg cfg;

  if (_cmdline(&cfg, argc, argv) < 0) _usage();

  if ( (cfg.fd = _server(&cfg)) < 0 || _options(&cfg) < 0) {
    if (cfg.fd == -1) fprintf(stderr, "server: %s\n", strerror(errno));
    _cleanup(&cfg); exit(-1);
  }

  memset(&ev, 0, sizeof(ev)); _gcfg = &cfg;
  signal(SIGINT, _sig); signal(SIGTERM, _sig); signal(SIGQUIT, _sig);

  event_init();
  event_set(&ev, cfg.fd, EV_READ | EV_PERSIST, _client, &cfg);
  event_add(&ev, NULL);
  return event_dispatch();
}

static void
_sig(int signo)
{
  _cleanup(_gcfg); exit(0);
}

static void
_cleanup(struct cfg *cfg)
{
  int i;
  for (i = 0; i < cfg->max; i++) {
    _close(&cfg->conn[i]);
    if (cfg->conn[i].rb) free(cfg->conn[i].rb); 
    if (cfg->conn[i].wb) free(cfg->conn[i].wb);
  }
  for (i = 0; i < cfg->si; i++) freeaddrinfo(cfg->servers[i].ai);
  if (cfg->servers) free(cfg->servers); cfg->servers = NULL;
  if (cfg->conn) free(cfg->conn); cfg->conn = NULL;
}

static void
_read(const int fd, short event, void *c)
{
  struct connection *cn = c;
  struct cfg *cfg = cn->cfg;
  size_t *l = NULL, o = 0;
  struct event *e = NULL;
  int bs = cfg->bufsize;
  char *b = NULL;
  ssize_t r = 0;

  if (event & EV_TIMEOUT) return _close(cn);
  if (cn->c == fd) { l = &cn->rlen; b = cn->rb; e = &cn->s_wev; o = cn->s; }
  if (cn->s == fd) { l = &cn->wlen; b = cn->wb; e = &cn->c_wev; o = cn->c; }
  do { r = recv(fd, b + *l, bs - *l, 0); } while (r == -1 && errno == EINTR);
  if (r <= 0) { if (r < 0 && !*l && cn->s == fd) cn->server->status = 0; return _close(cn); }
  *l += r;
  event_set(e, o, EV_WRITE, _write, cn);
  event_add(e, &cfg->to);
}

static void
_write(const int fd, short event, void *c)
{
  struct connection *cn = c;
  struct cfg *cfg = cn->cfg;
  struct event *e = NULL, *e2 = NULL;
  size_t *l = NULL, o = 0, *p = NULL;
  char *b = NULL;
  ssize_t r = 0;

  if (event & EV_TIMEOUT) return _close(cn);
  if (cn->c == fd) { l = &cn->wlen; b = cn->wb; e = &cn->s_rev; e2 = &cn->c_wev; o = cn->s; p = &cn->wpos; }
  if (cn->s == fd) { l = &cn->rlen; b = cn->rb; e = &cn->c_rev; e2 = &cn->s_wev; o = cn->c; p = &cn->rpos; }

  if (*l > 0) {
    do { r = send(fd, b + *p, *l - *p, MSG_NOSIGNAL); } while (r == -1 && errno == EINTR);
    if (r != *l - *p) {
      if (r <= 0) return _close(cn);
      *p += r;
      event_add(e2, &cfg->to);
      return;
    }
    *l = 0;
  }
  *p = 0;
  event_set(e, o, EV_READ, _read, cn);
  event_add(e, &cfg->to);
}

static void
_close(struct connection *c)
{
  c->rlen = c->rpos = c->wlen = c->wpos = 0;
  if (c->server) c->server->num--;
  if (EVENT_FD((&c->c_rev)) >= 0) { event_del(&c->c_rev); c->c_rev.ev_fd = -1; }
  if (EVENT_FD((&c->c_wev)) >= 0) { event_del(&c->c_wev); c->c_wev.ev_fd = -1; }
  if (EVENT_FD((&c->s_rev)) >= 0) { event_del(&c->s_rev); c->s_rev.ev_fd = -1; }
  if (EVENT_FD((&c->s_wev)) >= 0) { event_del(&c->s_wev); c->s_wev.ev_fd = -1; }
  if (c->s >= 0) { shutdown(c->s, 2); close(c->s); c->s = -1; }
  if (c->c >= 0) { shutdown(c->c, 2); close(c->c); c->c = -1; }
}

static struct server *
_get_server(struct cfg *cfg, struct connection *c)
{
  struct server *s = NULL;
  int i = cfg->cs;
  time_t now = 0;
  do {
    cfg->cs %= cfg->si;
    s = &cfg->servers[cfg->cs];
    cfg->cs++;
    if (!s->status) {
      if (!s->last) s->last = time(NULL);
      else { if (!now) now = time(NULL); if (now - s->last >= cfg->check) _check_server(cfg, s); }
    }
    if (!s->status || (s->max && s->num + 1 > s->max) ) s = NULL;
  } while (!s && cfg->cs != i);
  return s;
}
 
static int
_connect_server(struct connection *c)
{
  struct cfg *cfg = c->cfg;
  struct addrinfo *a;
  int fd = -1, r;

  while ( (c->server = _get_server(cfg, c)) ) {
    if ( !(a = c->server->ai) ) return -1;
    if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) return -1;
    if (_sockopt(fd, 1) < 0) { close(fd); return -1; }
    if (cfg->olen) if (bind(fd, &cfg->oaddr, cfg->olen) < 0) { close(fd); return -1; }
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r < 0 && errno != EINPROGRESS) { c->server->status = 0; close(fd); continue; }
    break;
  }
  if (!c->server || fd < 0) return -1;

  c->s = fd; c->server->num++;
  event_set(&c->s_rev, fd, EV_READ, _read, c);
  event_add(&c->s_rev, &cfg->to);
  return 0;
}

static void
_check_server(struct cfg *cfg, struct server *s)
{
  int fd, r;
  struct addrinfo *a = s->ai;
  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) return;
  if (_sockopt(fd, 0) < 0) { close(fd); return; }
  if (cfg->olen) if (bind(fd, &cfg->oaddr, cfg->olen) < 0) { close(fd); return; }
  do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
  close(fd);
  if (!r) { s->status = 1; s->last = 0; s->num = 0; }
  else    { s->status = 0; s->last = time(NULL); }
}

static void
_client(const int s, short event, void *config)
{
  int c;
  struct sockaddr sa;
  socklen_t l = sizeof(sa);
  struct cfg *cfg = config;
  struct connection *cn = NULL;

  if ( (c = accept(s, &sa, &l)) < 0)  return;
  if (c >= cfg->max)      { close(c); return; }
  if (_sockopt(c, 1) < 0) { close(c); return; }

  cn    = &cfg->conn[c];
  cn->c = c;
  cn->s = -1;
  cn->rlen = cn->rpos = (size_t) 0U;
  cn->wlen = cn->wpos = (size_t) 0U;
  cn->c_rev.ev_fd = cn->c_wev.ev_fd = -1;
  cn->s_rev.ev_fd = cn->s_wev.ev_fd = -1;

  if (_connect_server(cn) < 0) return _close(cn);
  event_set(&cn->c_rev, cn->c, EV_READ, _read, cn);
  event_add(&cn->c_rev, &cfg->to);
}

static int
_sockopt(const int fd, int nb)
{
  int ret = 0, on = 1;

#ifdef SO_LINGER
  {
    struct linger l;
    l.l_onoff = l.l_linger = 0;
    ret |= setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
  }
#endif
#ifdef SO_KEEPALIVE
  ret |= setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
#endif
#ifdef SO_REUSEADDR
  ret |= setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#endif

  if (nb) ret |= fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  return ret;
}

static int
_server(struct cfg *cfg)
{
  int i, fd;
  struct rlimit rl;
  struct addrinfo *ai;

  getrlimit(RLIMIT_NOFILE, &rl);
  cfg->max = rl.rlim_cur = rl.rlim_max;
  setrlimit(RLIMIT_NOFILE, &rl);

  if ( !(cfg->conn = calloc(cfg->max, sizeof(struct connection))) ) return -1;
  for (i = 3; i < cfg->max; i++) close(i);

  if ( !(ai = _get_addrinfo(cfg, cfg->host, cfg->port))) return -2;
  if ( (fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 ||
        _sockopt(fd, 1) < 0 ||
        bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
    if (fd >= 0) close(fd); freeaddrinfo(ai);
    return -1;
  }

  freeaddrinfo(ai);
  return fd;
}

static int
_options(struct cfg *cfg)
{
  int i = 0;
  unsigned int l = sizeof(cfg->bufsize);

  if (cfg->check == 0) cfg->check = _CHECK;
  if (cfg->to.tv_sec <= 0) cfg->to.tv_sec = _TIMEOUT;   /* XXX Timeout handling */

  if (!cfg->bufsize) getsockopt(cfg->fd, SOL_SOCKET, SO_SNDBUF, &cfg->bufsize, &l);
  if (!cfg->bufsize) cfg->bufsize = _BUFSIZE;

  if (cfg->daemon) {
    close(0); close(1); close(2);
    if (fork()) _exit(0); setsid(); if (fork()) _exit(0);

    if (cfg->num) {
      pid_t ppid = getpid();
      for (i = 0; i < cfg->num; i++) if (!fork()) break;
      if (getpid() == ppid) _exit(0);
    }
  }

  for (i = 0; i < cfg->max; i++) {
    if (i == cfg->fd) continue;
    cfg->conn[i].c = cfg->conn[i].s = -1;
    if ( !(cfg->conn[i].rb = calloc(1, cfg->bufsize)) ) return -1;
    if ( !(cfg->conn[i].wb = calloc(1, cfg->bufsize)) ) return -1;
    cfg->conn[i].cfg = cfg;
  }

  if (listen(cfg->fd, SOMAXCONN) < 0) { close(cfg->fd); return -1; }
  return 0;
}

static int
_parse_server(struct cfg *cfg, char *str)
{
  char *p = NULL, *cp = NULL;
  struct server *sv = NULL, *s = NULL;

  if (!cfg || !str || !*str || !(cp = strchr(str, ':'))) return -1;
  if (!*(cp + 1)) return -1; *cp = 0;
  if ( (p = strchr(cp + 1, ':')) ) *p = 0;

  if ( !(sv = realloc(cfg->servers, (cfg->si + 1) * sizeof(struct server))) ) return -1;
  cfg->servers = sv; s = &sv[cfg->si]; memset(s, 0, sizeof(struct server));
  if ( !(s->ai = _get_addrinfo(cfg, str, cp + 1)) ) return -1; cfg->si++;

  if (p) { *p++ = ':'; if (*p) s->max = atoi(p); } *cp = ':';
  _check_server(cfg, s);
  return 0;
}

static int
_lookup_oaddr(struct cfg *cfg, char *outb)
{
  struct addrinfo *res = _get_addrinfo(cfg, outb, NULL);
  if (!res) return -1;
  memcpy(&cfg->oaddr, res->ai_addr, res->ai_addrlen);
  cfg->olen = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}

struct addrinfo *
_get_addrinfo(struct cfg *cfg, char *h, char *p)
{
  struct addrinfo hints, *res = NULL;
  int rv;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags    = AI_PASSIVE;
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if ( (rv = getaddrinfo(*h ? h : NULL, p, &hints, &res)) ) { 
    fprintf(stderr, "%s - %s\n", *h ? h : "", gai_strerror(rv)); 
    if (res) freeaddrinfo(res);
    return NULL; 
  }
  return res;
}

static int
_cmdline(struct cfg *cfg, int argc, char *argv[])
{
  int i, j;
  memset(cfg, 0, sizeof(struct cfg)); cfg->daemon = 1;
  for (i = j = 1; i < argc; j = ++i) {
    if (argv[i][0] != '-') return -1;
    if ( (argv[j][1] != 'f' && argv[j][1] != 'v' && argv[j][1] != 'd') && 
          ++i >= argc) return -1;

    switch (argv[j][1]) {
      case 'v': _version();                                       break;
      case 'f': cfg->daemon     = 0;                              break;
      case 'c': cfg->check      = atoi(argv[i]);                  break;
      case 'n': cfg->num        = atoi(argv[i]);                  break;
      case 's': cfg->bufsize    = atoi(argv[i]);                  break;
      case 't': cfg->to.tv_sec  = atoi(argv[i]);                  break;
      case 'h': if (_parse_server(cfg, argv[i]) < 0) return -1;   break;
      case 'B': if (_lookup_oaddr(cfg, argv[i]) < 0) return -1;   break;
      case 'b': snprintf(cfg->host, sizeof(cfg->host), argv[i]);  break;
      case 'p': snprintf(cfg->port, sizeof(cfg->port), argv[i]);  break;
      default : return -1;
    }
  }
  if (!cfg->si) return -1;
  return 0;
}

static void
_usage(void)
{
  fprintf(stderr, "\nrlb %s\nCopyright � 2006 RIVERDRUMS\n\n", _VERSION);
  fprintf(stderr, "usage: rlb [-b host] -p port [-B addr] -h host:port[:max]... [-t secs] [-c secs] [-s size] [-n num] [-f]\n");
  exit(-1);
}

static void
_version(void)
{
  printf("rlb-%s by Jason Armstrong <ja@riverdrums.com>\n", _VERSION);
  exit(0);
}
