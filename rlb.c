/* rlb.c Jason Armstrong <ja@riverdrums.com> © 2006 RIVERDRUMS
 * $ gcc -Wall -02 -o rlb rlb.c -levent (-lnsl -lsocket) 
 * $Id$ */

#include "rlb.h"

#define _VERSION  "0.4"
#define _TIMEOUT  30        /**< Socket timeout and dead server check interval */
#define _BUFSIZE  4096      /**< Buffer size and number of clients to track */

#ifdef RLB_SO
#include <dlfcn.h>
static int _parse_so(struct cfg *cfg, const char *path);
#endif

struct cfg *_gcfg = NULL;
static void _usage(void);
static void _sig(int signo);
static int  _startup(struct cfg *cfg);
static void _cleanup(struct cfg *cfg);
static int  _sockopt(const int fd, int nb);
static int  _connect_server(struct connection *c);
static int  _parse_server(struct cfg *cfg, char *str);
static void _read(const int fd, short event, void *c);
static int  _lookup_oaddr(struct cfg *cfg, char *outb);
static void _write(const int fd, short event, void *c);
static void _client(const int s, short event, void *ev);
static int  _cmdline(struct cfg *cfg, int ac, char *av[]);
static void _close(struct cfg *cfg, struct connection *c);
static void _check_server(struct cfg *cfg, struct server *s);
static int  _socket(struct cfg *cfg, struct addrinfo *a, int nb, int o);
static struct client * _find_client(struct cfg *cfg, unsigned int addr);
static struct addrinfo * _get_addrinfo(struct cfg *cfg, char *h, char *p);
static struct server * _get_server(struct cfg *cfg, struct connection *c);

int main(int argc, char *argv[]) {
  struct event ev;
  struct cfg cfg;
  int r;

  if (_cmdline(&cfg, argc, argv) < 0) _usage();
  memset(&ev, 0, sizeof(ev)); _gcfg = &cfg;

  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);

  if ( (r = _startup(&cfg)) < 0) {
    if (r == -1) fprintf(stderr, "rlb: %s\n", strerror(errno));
    _cleanup(&cfg); exit(-1);
  }

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
  if (cfg->fd >= 0) { shutdown(cfg->fd, 2); close(cfg->fd); }
  for (i = 0; i < cfg->max; i++) {
    _close(cfg, &cfg->conn[i]);
    if (cfg->conn[i].rb) free(cfg->conn[i].rb); 
    if (cfg->conn[i].wb) free(cfg->conn[i].wb);
  }
  for (i = 0; i < cfg->si; i++) freeaddrinfo(cfg->servers[i].ai);
  if (cfg->servers) free(cfg->servers); cfg->servers = NULL;
  if (cfg->conn) free(cfg->conn); cfg->conn = NULL;
#ifdef RLB_SO
  if (cfg->fr) cfg->fr(cfg);
  if (cfg->h) dlclose(cfg->h);
#endif
}

static void
_read(const int fd, short event, void *c)
{
  struct connection *cn = c;
  struct cfg *cfg = cn->cfg;
  size_t *l = NULL, o = 0;
  struct event *e = NULL;
  unsigned int *nr = NULL;
  char *b = NULL;
  ssize_t r = 0;
  int bs = 0;

  if (event & EV_TIMEOUT) return _close(cfg, cn);
  if (cn->c == fd) { l = &cn->rlen; b = cn->rb; e = &cn->s_wev; o = cn->s; bs = cn->rbs; nr = &cn->cnr; }
  if (cn->s == fd) { l = &cn->wlen; b = cn->wb; e = &cn->c_wev; o = cn->c; bs = cn->wbs; nr = &cn->snr; }
  do { r = read(fd, b + *l, bs - *l); } while (r == -1 && errno == EINTR);
  if (r <= 0) { if (r < 0 && !*l && cn->s == fd) cn->server->status = 0; return _close(cfg, cn); }
  *nr += r;
#ifdef RLB_SO
  if (cn->c == fd && cfg->cf) if (cfg->cf(&b, *l, &r, &bs, *nr - r) < 0) return _close(cfg, cn);
  if (cn->s == fd && cfg->sf) if (cfg->sf(&b, *l, &r, &bs, *nr - r) < 0) return _close(cfg, cn);
  if (cn->c == fd && cfg->delay && cfg->gs && *nr - r == 0) cfg->gs(cfg, cn);
#endif
  *l += r;
  if (cn->c == fd && cfg->delay && *nr - r == 0) { if (_connect_server(cn) < 0) return _close(cfg, cn); o = cn->s; }
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
  unsigned int *w = NULL;
  char *b = NULL;
  ssize_t r = 0;

  if (event & EV_TIMEOUT) return _close(cfg, cn);
  if (cn->c == fd) { l = &cn->wlen; b = cn->wb; e = &cn->s_rev; e2 = &cn->c_wev; o = cn->s; p = &cn->wpos; w = &cn->cnw; }
  if (cn->s == fd) { l = &cn->rlen; b = cn->rb; e = &cn->c_rev; e2 = &cn->s_wev; o = cn->c; p = &cn->rpos; w = &cn->snw; }

  if (*l > 0) {
    do { r = write(fd, b + *p, *l - *p); } while (r == -1 && errno == EINTR);
    if (r != *l - *p) {
      if (r <= 0) {
        if (cn->s == fd && cn->snw == 0) { /* XXX Try next server */ }
        return _close(cfg, cn);
      }
      *p += r; *w += r;
      event_add(e2, &cfg->to);
      return;
    }
    *l = 0; *w += r;
  }
  *p = 0;
  event_set(e, o, EV_READ, _read, cn);
  event_add(e, &cfg->to);
}

static void
_close(struct cfg *cfg, struct connection *c)
{
#ifdef RLB_SO
  if (cfg->cl && c->server) cfg->cl(c);
#endif
  if (c->s >= 0) { shutdown(c->s, 2); close(c->s); c->s = -1; }
  if (c->c >= 0) { shutdown(c->c, 2); close(c->c); c->c = -1; }
  if (c->server) c->server->num--; c->server = NULL;
  if (EVENT_FD((&c->c_rev)) >= 0) { event_del(&c->c_rev); c->c_rev.ev_fd = -1; }
  if (EVENT_FD((&c->c_wev)) >= 0) { event_del(&c->c_wev); c->c_wev.ev_fd = -1; }
  if (EVENT_FD((&c->s_rev)) >= 0) { event_del(&c->s_rev); c->s_rev.ev_fd = -1; }
  if (EVENT_FD((&c->s_wev)) >= 0) { event_del(&c->s_wev); c->s_wev.ev_fd = -1; }
  if (c->client) { c->client->last = time(NULL); c->client = NULL; }
  c->rlen = c->rpos = c->wlen = c->wpos = 0;
  c->cnr = c->cnw = c->snr = c->snw = 0;
}

static struct server *
_get_server(struct cfg *cfg, struct connection *c)
{
  struct server *s = NULL;
  int i = cfg->cs, j;
  time_t now = 0;

#ifdef RLB_SO
  if (cfg->delay && (j = c->so_server) >= 0) {
    c->so_server = -1; s = &cfg->servers[j]; 
    if (s->status && (s->max ? s->num + 1 <= s->max : 1)) return s; 
    if (!s->status) {
      if (!s->last) s->last = time(NULL);
      else if (time(NULL) - s->last >= cfg->check) { _check_server(cfg, s); if (s->status) return s; }
    }
    return NULL;
  }
#endif

  if (!cfg->rr && (j = c->client->server) >= 0) { 
    s = &cfg->servers[j]; 
    if (s->status && (s->max ? s->num + 1 <= s->max : 1)) return s; 
    if (cfg->stubborn) {
      if (!s->status) {
        if (!s->last) s->last = time(NULL);
        else if (time(NULL) - s->last >= cfg->check) { _check_server(cfg, s); if (s->status) return s; }
      }
      return NULL;
    }
  }

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
    if ( (fd = _socket(cfg, (a = c->server->ai), 0, 1)) < 0) return -1;
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r < 0 && errno != EINPROGRESS) { c->server->status = 0; close(fd); continue; }
    break;
  }
  if (!c->server || (!cfg->rr && !c->client) || fd < 0) return -1;
  if (!cfg->rr && c->client->server < 0) { c->client->server = c->server->id; c->client->last = time(NULL); }

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
  if ( (fd = _socket(cfg, a, 0, 1)) < 0) return;
  do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
  shutdown(fd, 2); close(fd);
  if (!r) { s->status = 1; s->last = 0; s->num = 0; }
  else    { s->status = 0; s->last = time(NULL); }
}

static void
_client(const int s, short event, void *config)
{
  int c;
  struct sockaddr sa;
  struct sockaddr_in *si;
  socklen_t l = sizeof(sa);
  struct cfg *cfg = config;
  struct connection *cn = NULL;

  if ( (c = accept(s, &sa, &l)) < 0)  return;
  if (c >= cfg->max || _sockopt(c, 1) < 0) { close(c); return; }

  cn    = &cfg->conn[c];
  cn->c = c; cn->s = -1;
  cn->rlen = cn->rpos = (size_t) 0U;
  cn->wlen = cn->wpos = (size_t) 0U;
  cn->c_rev.ev_fd = cn->c_wev.ev_fd = -1;
  cn->s_rev.ev_fd = cn->s_wev.ev_fd = -1;

  if (!cfg->rr) {
    si = (struct sockaddr_in *) &sa;
    cn->client = _find_client(cfg, si->sin_addr.s_addr);
  }

  if (!cfg->delay) if (_connect_server(cn) < 0) return _close(cfg, cn);
  event_set(&cn->c_rev, cn->c, EV_READ, _read, cn);
  event_add(&cn->c_rev, &cfg->to);
}

static struct client *
_find_client(struct cfg *cfg, unsigned int addr)
{
  int i, j = 0;
  struct client *cl;
  time_t oldest = 0;
  for (i = 0; i < cfg->ci; i++) {
    cl = &cfg->clients[i];
    if (cl->id == 0) { cl->id = addr; cl->server = -1; return cl; }
    if (cl->id == addr) return cl;
    if (!oldest || cl->last < oldest) { oldest = cl->last; j = i; }
  }
  cl = &cfg->clients[j]; cl->id = addr; cl->server = -1;
  return cl;
}

static int
_startup(struct cfg *cfg)
{
  struct rlimit rl;
  struct addrinfo *ai;
  struct passwd *pw = NULL;
  unsigned int i = 0, l = sizeof(cfg->bufsize);

  getrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = rl.rlim_max;
  setrlimit(RLIMIT_NOFILE, &rl);

  if (cfg->max == 0)      cfg->max = rl.rlim_cur;
  else if (cfg->max < 8)  cfg->max = 8;

  if (!cfg->check)      cfg->check      = _TIMEOUT;
  if (!cfg->to.tv_sec)  cfg->to.tv_sec  = _TIMEOUT;
  if (!cfg->bufsize)    getsockopt(cfg->fd, SOL_SOCKET, SO_SNDBUF, &cfg->bufsize, &l);
  if (!cfg->bufsize)    cfg->bufsize    = _BUFSIZE;
  if (!cfg->ci)         cfg->ci         = _BUFSIZE;

  if ( !(cfg->clients = calloc(cfg->ci, sizeof(struct client))) )   return -1;
  if ( !(cfg->conn = calloc(cfg->max, sizeof(struct connection))) ) return -1;
  for (i = 3; i < cfg->max; i++) close(i);

  if ( !(ai = _get_addrinfo(cfg, cfg->host, cfg->port))) return -2;
  cfg->fd = _socket(cfg, ai, 1, 0);
  if (cfg->fd >= 0) if (bind(cfg->fd, ai->ai_addr, ai->ai_addrlen) < 0) { close(cfg->fd); cfg->fd = -1; }
  freeaddrinfo(ai);
  if (cfg->fd < 0) return -1;

  if (cfg->user)  if ( !(pw = getpwnam(cfg->user)) )                    return -1;
  if (cfg->jail)  if (chroot(cfg->jail) < 0)                            return -1;
  if (pw)         if (setgid(pw->pw_gid < 0) || setuid(pw->pw_uid) < 0) return -1;

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
    cfg->conn[i].wbs = cfg->conn[i].rbs = cfg->bufsize;
    cfg->conn[i].cfg = cfg;
#ifdef RLB_SO
    cfg->conn[i].so_server = -1;
#endif
  }

#ifdef RLB_SO
  if (cfg->in) if (cfg->in(cfg) < 0) return -1;
#endif

  return listen(cfg->fd, SOMAXCONN);
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
  if ( !(s->ai = _get_addrinfo(cfg, str, cp + 1)) ) return -1; s->id = cfg->si++;

  if (p) { *p++ = ':'; if (*p) s->max = atoi(p); } *cp = ':';
  _check_server(cfg, s);
  return 0;
}

static int
_lookup_oaddr(struct cfg *cfg, char *outb)
{
  struct addrinfo *res = _get_addrinfo(cfg, outb, NULL);
  if (!res) return -1;
  memcpy(&cfg->oaddr, res->ai_addr, (cfg->olen = res->ai_addrlen) );
  freeaddrinfo(res);
  return 0;
}

struct addrinfo *
_get_addrinfo(struct cfg *cfg, char *h, char *p)
{
  struct addrinfo hints, *res = NULL;
  int r;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags    = AI_PASSIVE;
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if ( (r = getaddrinfo(*h ? h : NULL, p, &hints, &res)) ) { 
    fprintf(stderr, "%s - %s\n", *h ? h : "", gai_strerror(r)); 
    if (res) freeaddrinfo(res);
    return NULL; 
  }
  return res;
}

static int
_socket(struct cfg *cfg, struct addrinfo *a, int nb, int o)
{
  int fd = -1;
  if (cfg == NULL || a == NULL) return -1;
  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) return -1;
  if (_sockopt(fd, nb) < 0) { close(fd); return -1; }
  if (o && cfg->olen) if (bind(fd, &cfg->oaddr, cfg->olen) < 0) { close(fd); return -1; }
  return fd;
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

#ifdef RLB_SO
static int
_parse_so(struct cfg *cfg, const char *path)
{
  dlerror();
  if ( !(cfg->h = dlopen(path, RTLD_GLOBAL | RTLD_NOW)) ) { fprintf(stderr, dlerror()); return -1; }
  cfg->cf = dlsym(cfg->h, "rlb_client_filter");
  cfg->sf = dlsym(cfg->h, "rlb_server_filter");
  cfg->cl = dlsym(cfg->h, "rlb_close");
  cfg->gs = dlsym(cfg->h, "rlb_get_server");
  cfg->in = dlsym(cfg->h, "rlb_init");
  cfg->fr = dlsym(cfg->h, "rlb_cleanup");
  return 0;
}
#endif

static int
_cmdline(struct cfg *cfg, int ac, char *av[])
{
  int i, j;
  memset(cfg, 0, sizeof(struct cfg)); cfg->daemon = 1;
  for (i = j = 1; i < ac; j = ++i) {
    if (av[j][0] != '-' || (av[j][1] != 'f' && av[j][1] != 'r' && 
                            av[j][1] != 'S' && av[j][1] != 'd' &&
                            ++i >= ac)) return -1;
    switch (av[j][1]) {
      case 'S': cfg->stubborn   = 1;                            break;
      case 'f': cfg->daemon     = 0;                            break;
      case 'd': cfg->delay      = 1;                            break;
      case 'r': cfg->rr         = 1;                            break;
      case 'j': cfg->jail       = av[i];                        break;
      case 'u': cfg->user       = av[i];                        break;
      case 'l': cfg->ci         = atoi(av[i]);                  break;
      case 'm': cfg->max        = atoi(av[i]);                  break;
      case 'n': cfg->num        = atoi(av[i]);                  break;
      case 'c': cfg->check      = atoi(av[i]);                  break;
      case 's': cfg->bufsize    = atoi(av[i]);                  break;
      case 't': cfg->to.tv_sec  = atoi(av[i]);                  break;
#ifdef RLB_SO
      case 'o': if (_parse_so(cfg, av[i]) < 0) return -1;       break;
#endif
      case 'h': if (_parse_server(cfg, av[i]) < 0) return -1;   break;
      case 'B': if (_lookup_oaddr(cfg, av[i]) < 0) return -1;   break;
      case 'b': snprintf(cfg->host, sizeof(cfg->host), av[i]);  break;
      case 'p': snprintf(cfg->port, sizeof(cfg->port), av[i]);  break;
      default : return -1;
    }
  }
  if (!cfg->si) return -1;
  return 0;
}

static void
_usage(void)
{
  fprintf(stderr, "\nrlb %s Copyright © 2006 RIVERDRUMS\n\n", _VERSION);
  fprintf(stderr, "usage: rlb -p port [-b addr] [-B addr] -h host:port[:max]... [-m max] [-t secs] [-c secs] [-s size] [-n num] [-u user] [-j jail] [-l clients] [-r] [-S] [-d] [-f]");
#ifdef RLB_SO
  fprintf(stderr, " [-o so]");
#endif
  fprintf(stderr, "\n");
  exit(-1);
}
