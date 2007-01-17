/* rlb.c Jason Armstrong <ja@riverdrums.com> � 2006-2007 RIVERDRUMS
 * $ gcc [-DRLB_SO] -Wall -02 -o rlb rlb.c -levent (-lnsl -lsocket) 
 * $Id$ */

#include "rlb.h"

#define _VERSION  "0.5"
#define _TIMEOUT  30        /**< Socket timeout and dead server check interval */
#define _BUFSIZE  4096      /**< Default buffer size and number of clients to track */

#ifdef RLB_SO
#include <dlfcn.h>
static int _load_so(struct cfg *cfg, const char *path);
#endif

#ifdef RLB_DEBUG
FILE *_rlb_fp = NULL;
# define RLOG(f,...) do { if (_rlb_fp) { fprintf(_rlb_fp, "[%s:%d] " f "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); fflush(_rlb_fp); } } while(0)
# define SCOPE  (c->scope == RLB_CLIENT) ? " < CLIENT" : (c->scope == RLB_SERVER) ? " > SERVER" : " +  NONE "
#else
# define RLOG(f,...)
# define SCOPE ""
#endif

struct cfg *_gcfg = NULL;
static void _usage(void);
static void _stat(int signo);
static int  _startup(struct cfg *cfg);
static int  _sockopt(const int fd, int nb);
static int  _parse_server(struct cfg *cfg, char *str);
static void _event(const int fd, short event, void *c);
static int  _lookup_oaddr(struct cfg *cfg, char *outb);
static void _event_set(struct connection *c, short event);
static void _reset(struct cfg *cfg, struct connection *c);
static void _client(const int s, short event, void *config);
static int  _check_server(struct cfg *cfg, struct server *s);
static int  _socket(struct cfg *cfg, struct addrinfo *a, int nb, int o);
static struct server * _get_server(struct cfg *cfg, struct connection *c);
static struct client * _find_client(struct cfg *cfg, unsigned int addr);
static int  _cmdline(struct cfg *cfg, int ac, char *av[]);
static void _close(struct cfg *cfg, struct connection *c);
static struct addrinfo * _get_addrinfo(char *h, char *p);
static void _write(const int fd, struct connection *c);
static int  _server(struct connection *c, short event);
static void _read(const int fd, struct connection *c);
static void _reset_conn(struct connection *c);
static void _cleanup(struct cfg *cfg);
static int  _bind(struct cfg *cfg);
static void _check(int signo);
static int  _closefd(int fd);
static void _sig(int signo);

int main(int argc, char *argv[]) {
  struct event ev;
  struct cfg cfg;
  int r;

  if (_cmdline(&cfg, argc, argv) < 0) _usage();
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);

  if ( (r = _startup(&cfg)) < 0) {
    if (r == -1) fprintf(stderr, "rlb: %s\n", strerror(errno));
    _cleanup(&cfg); exit(EXIT_FAILURE);
  }

  signal(SIGINT, _sig); signal(SIGTERM, _sig); signal(SIGQUIT, _sig);
  signal(SIGUSR1, _stat); signal(SIGUSR2, _check);

  event_init();
  event_set(&ev, cfg.fd, EV_READ | EV_PERSIST, _client, &cfg);
  event_add(&ev, NULL);
  return event_dispatch();
}

static void _sig(int signo)
{
  _stat(signo); _cleanup(_gcfg); exit(EXIT_SUCCESS);
}

static void _cleanup(struct cfg *cfg)
{
  int i;
  if (cfg->fd >= 0) cfg->fd = _closefd(cfg->fd);
  for (i = 0; i < cfg->max; i++) {
    _close(cfg, &cfg->conn[i]);
    if (cfg->conn[i].b) free(cfg->conn[i].b);
  }
  for (i = 0; i < cfg->si; i++) freeaddrinfo(cfg->servers[i].ai);
  if (cfg->servers) { free(cfg->servers); cfg->servers = NULL; } cfg->si  = 0;
  if (cfg->clients) { free(cfg->clients); cfg->clients = NULL; } cfg->ci  = 0;
  if (cfg->conn)    { free(cfg->conn);    cfg->conn    = NULL; } cfg->max = 0;
#ifdef RLB_SO
  for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
    struct filter *fl = &cfg->filters[cfg->cf];
    if (fl->fr) fl->fr(cfg, &(fl->userdata));
    if (fl->h) dlclose(fl->h);
  }
  if (cfg->filters) { free(cfg->filters); cfg->filters = NULL; } cfg->fi  = 0;
#endif
}

static void _event(const int fd, short event, void *c)
{
  struct connection *cn = c;
  if (!cn) return;
  else if (event & EV_READ)     _read(fd, cn);
  else if (event & EV_WRITE)    _write(fd, cn);
  else if (event & EV_TIMEOUT)  _close(cn->cfg, cn);
}

static void _read(const int fd, struct connection *c)
{
  struct connection *co = NULL;
  struct cfg *cfg = c->cfg;
  ssize_t r = 0;

  if (c->scope == RLB_SERVER && c->od < 0) return _close(cfg, c);
  if (c->closed) { event_del(&c->ev); return; }
  if (c->len == c->bs) return;
  if (c->od >= 0) co = &cfg->conn[c->od];
  do { r = read(fd, c->b + c->len, c->bs - c->len); } while (r == -1 && errno == EINTR);
  RLOG("%s - R: %d fd=%d (pos=%d len=%d)", SCOPE, r, fd, c->pos, c->len);
  if (r <= 0) {
    if (r < 0 && c->scope == RLB_SERVER) co->server->status = 0; 
    return _close(cfg, c);
  }
  c->nr += r; c->len += r;
#ifdef RLB_SO
  if (cfg->fli) {
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->fl) if (fl->fl(c, r, fl->userdata) < 0) return _close(cfg, c);
    }
  }
#endif
  if (cfg->delay && c->nr - r == 0 && c->scope == RLB_CLIENT) {
#ifdef RLB_SO
    if (cfg->gsi) {
      for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
        struct filter *fl = &cfg->filters[cfg->cf];
        if (fl->gs) fl->gs(c, fl->userdata);
      }
    }
#endif
    if (_server(c, EV_WRITE) < 0) return _close(cfg, c); 
  } else _event_set(co, EV_WRITE);
  event_add(&c->ev, &cfg->to);
}

static void _write(const int fd, struct connection *c)
{
  struct connection *co = NULL;
  ssize_t r = 0;

  if (c->closed) { event_del(&c->ev); return; }
  if (c->od < 0) return _close(c->cfg, c); co = &c->cfg->conn[c->od];
#ifdef RLB_SO
  if (co->nowrite == 0) {
    if (c->scope == RLB_SERVER && ((co->so_server && co->server != co->so_server) || co->reconnect) ) {
      _reset(c->cfg, c); c->od = -1;     /* XXX What if there is data (c->len) */
      if (co->server) { if (co->connected) co->server->num--; co->server = NULL; co->connected = 0; }
      if (_server(co, EV_WRITE) < 0) _close(c->cfg, co);
      return;
    }
    co->so_server = NULL;
#endif
    if (co->len > 0) {
      do { r = write(fd, co->b + co->pos, co->len); } while (r == -1 && errno == EINTR);
      RLOG("%s - W: %d fd=%d (pos=%d len=%d)", SCOPE, r, fd, co->pos, co->len);
      if (r != co->len) {
        if (r <= 0) {
          if (c->scope == RLB_SERVER && c->nw == 0) { /* XXX Try next server */ }
          return _close(c->cfg, c);
        }
        co->pos += r; c->nw += r; co->len -= r;
        event_add(&c->ev, &c->cfg->to);
        return;
      }
      co->len = 0; c->nw += r;
    }
    co->pos = 0;
#ifdef RLB_SO
  }
#endif
  if (co->closed) return _close(c->cfg, c);
  _event_set(co, EV_READ); _event_set(c, EV_READ);
}

static void _event_set(struct connection *c, short event)
{
  if (!c) return;
  event_del(&c->ev);
  event_set(&c->ev, c->fd, event, _event, c);
  event_add(&c->ev, &c->cfg->to);
}

static void _close(struct cfg *cfg, struct connection *c)
{
  _reset(cfg, c);
  if (c->od >= 0 && !c->closed) { _reset(cfg, &cfg->conn[c->od]); cfg->conn[c->od].od = c->od = -1; }
}

static void _reset(struct cfg *cfg, struct connection *c)
{
#ifdef RLB_DEBUG
  if (c->fd >= 0) RLOG("-- %s - CLOSE fd=%d od=%d (pos=%d len=%d bs=%d) (nr=%u nw=%u cl=%d)",
      SCOPE, c->fd, c->od, c->pos, c->len, c->bs, c->nr, c->nw, c->closed);
#endif
  if (c->len && c->od >= 0) { event_del(&c->ev); c->closed++; }
  else _reset_conn(c);
}

static void _reset_conn(struct connection *c)
{
#ifdef RLB_SO
  if (c->cfg && c->cfg->cli) {
    for (c->cfg->cf = 0; c->cfg->cf < c->cfg->fi; c->cfg->cf++) {
      struct filter *fl = &c->cfg->filters[c->cfg->cf];
      if (fl->cl) fl->cl(c, fl->userdata);
    }
  }
#endif
  if (c->fd >= 0) c->fd = _closefd(c->fd);
  c->len = c->pos = c->nr = c->nw = c->closed = 0; c->scope = RLB_NONE;
  if (c->server) { if (c->connected) c->server->num--; c->server = NULL; c->connected = 0; }
  if (c->client) { c->client->last = time(NULL); c->client = NULL; }
  event_del(&c->ev);
}

static struct server * _get_server(struct cfg *cfg, struct connection *c)
{
  struct server *s = NULL;
  int i = cfg->cs;
  time_t now = time(NULL);

#ifdef RLB_SO
  if (c->reconnect) c->reconnect = 0;
  if ( (s = c->so_server) ) {
    c->so_server = NULL;
    if (s->status && (s->max ? s->num + 1 <= s->max : 1) ) return s; 
    if (!s->status) {
      if (!s->last) s->last = now;
      else if (now - s->last >= cfg->check) if (_check_server(cfg, s)) return s;
    }
    return NULL;
  }
#endif

  if (!cfg->rr && c->client && (s = c->client->server) ) {
    if (s->status && (s->max ? s->num + 1 <= s->max : 1) ) return s; 
    if (cfg->stubborn) {
      if (!s->status) {
        if (!s->last) s->last = now;
        else if (now - s->last >= cfg->check) if (_check_server(cfg, s)) return s;
      }
      return NULL;
    }
  }

  do {
    cfg->cs++; cfg->cs %= cfg->si; s = &cfg->servers[cfg->cs];
    if (!s->status) {
      if (!s->last) s->last = now;
      else if (now - s->last >= cfg->check) _check_server(cfg, s);
    }
    if (!s->status || (s->max && s->num + 1 > s->max) ) s = NULL;
  } while (!s && cfg->cs != i);
  return s;
}
 
static int _server(struct connection *c, short event)
{
  struct cfg *cfg = c->cfg;
  struct connection *cn = NULL;
  struct addrinfo *a;
  int fd = -1, r;

  if (c->scope != RLB_CLIENT) return -1;
  while ( (c->server = _get_server(cfg, c)) ) {
    if ( (fd = _socket(cfg, (a = c->server->ai), 1, 1)) < 0) return -1;
    if (fd >= cfg->max) return _closefd(fd);
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r < 0 && errno != EINPROGRESS) { c->server->status = 0; _closefd(fd); continue; }
    break;
  }
  if (!c->server || (!cfg->rr && !c->client) || fd < 0) return -1;
  if (!cfg->rr && !c->client->server) { c->client->server = c->server; c->client->last = time(NULL); }
  c->server->num++; c->connected = 1;
#ifdef RLB_DEBUG
  {
    char cl[64], h[64], p[64]; struct sockaddr *sa = &c->sa;
    if (getnameinfo(sa, sizeof(*sa), cl, sizeof(cl), NULL, 0, NI_NUMERICHOST)) *cl = 0;
    sa = c->server->ai->ai_addr;
    if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = 0;
    RLOG("== %s - CONNECT fd=%d (client=%s) (server=%s:%s num=%d)", SCOPE, fd, cl, h, p, c->server->num);
  }
#endif
  cn = &cfg->conn[fd];
  cn->len = cn->pos = (size_t) 0U;
  cn->fd = c->od = fd; cn->od = c->fd;
  cn->server = NULL; cn->client = NULL;
  cn->closed = 0; cn->scope = RLB_SERVER;
  event_set(&cn->ev, fd, event, _event, cn);
  return event_add(&cn->ev, &cfg->to);
}

static int _check_server(struct cfg *cfg, struct server *s)
{
  int fd, r;
  if ( (fd = _socket(cfg, s->ai, 0, 1)) < 0) return 0;
  do { r = connect(fd, s->ai->ai_addr, s->ai->ai_addrlen); } while (r == -1 && errno == EINTR);
  _closefd(fd); s->status = !r; s->last = r ? time(NULL) : 0;
  return s->status;
}

static void _client(const int s, short event, void *config)
{
  int fd;
  struct sockaddr sa;
  socklen_t l = sizeof(sa);
  struct cfg *cfg = config;
  struct connection *cn = NULL;

  if ( (fd = accept(s, &sa, &l)) < 0) return;
  if (fd >= cfg->max || _sockopt(fd, 1) < 0) { _closefd(fd); return; }

  cn = &cfg->conn[fd];
  cn->scope = RLB_CLIENT;
  cn->len = cn->pos = (size_t) 0U;
  cn->fd = fd; cn->od = -1;
  cn->closed = cn->connected = 0; memcpy(&cn->sa, &sa, l);
  RLOG("++ � CLIENT - CONNECT fd=%d", cn->fd);

  if (!cfg->rr) {
    struct sockaddr_in *si = (struct sockaddr_in *) &sa;
    cn->client = _find_client(cfg, si->sin_addr.s_addr);
  }
#ifdef RLB_SO
  if (!cfg->delay && cfg->gsi) {
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->gs) fl->gs(cn, fl->userdata);
    }
  }
#endif
  if (!cfg->delay) if (_server(cn, EV_READ) < 0) return _close(cfg, cn);
  event_set(&cn->ev, cn->fd, EV_READ, _event, cn);
  event_add(&cn->ev, &cfg->to);
}

static struct client * _find_client(struct cfg *cfg, unsigned int addr)
{
  int i, j = 0;
  struct client *cl;
  time_t oldest = 0;
  for (i = 0; i < cfg->ci; i++) {
    cl = &cfg->clients[i];
    if (cl->id == 0) { cl->id = addr; cl->server = NULL; return cl; }
    if (cl->id == addr) return cl;
    if (!oldest || cl->last < oldest) { oldest = cl->last; j = i; }
  }
  cl = &cfg->clients[j]; cl->id = addr; cl->server = NULL;
  return cl;
}

static int _startup(struct cfg *cfg)
{
  struct rlimit rl;
  struct passwd *pw = NULL;
  unsigned int i = 0;
  int rc;

  getrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = rl.rlim_max;
  setrlimit(RLIMIT_NOFILE, &rl);
  if (cfg->max == 0)      cfg->max = rl.rlim_cur;
  else if (cfg->max < 8)  cfg->max = 8;

  if (!cfg->check)      cfg->check      = _TIMEOUT;
  if (!cfg->to.tv_sec)  cfg->to.tv_sec  = _TIMEOUT;
  if (!cfg->ci)         cfg->ci         = _BUFSIZE;

  if ( !(cfg->clients = calloc(cfg->ci, sizeof(struct client))) )       return -1;
  if ( !(cfg->conn = calloc(cfg->max, sizeof(struct connection))) )     return -1;
  if (cfg->user)  if ( !(pw = getpwnam(cfg->user)) )                    return -1;
  if (cfg->jail)  if (chdir(cfg->jail) < 0 || chroot(cfg->jail) < 0)    return -1;
  if (pw)         if (setgid(pw->pw_gid < 0) || setuid(pw->pw_uid) < 0) return -1;
  for (i = 3; i < cfg->max; i++) _closefd(i);

  if (cfg->daemon) {
    _closefd(0); _closefd(1); _closefd(2);
    if ( (rc = _bind(cfg)) < 0) return rc;
    if (fork()) _exit(0); setsid(); if (fork()) _exit(0);

    if (cfg->num > 1) {
      pid_t ppid = getpid();
      for (i = 0; i < cfg->num; i++) if (!fork()) break;
      if (getpid() == ppid) _exit(0);
    }
  } else if ( (rc = _bind(cfg)) < 0) return rc;

  for (i = 0; i < cfg->max; i++) {
    cfg->conn[i].fd = cfg->conn[i].od = -1;
    cfg->conn[i].cfg      = cfg;
    cfg->conn[i].scope    = RLB_NONE;
    if (i == cfg->fd) continue;
    if ( !(cfg->conn[i].b = malloc(cfg->bufsize + 1)) ) return -1;
    cfg->conn[i].bs       = cfg->bufsize;
#ifdef RLB_SO
    cfg->conn[i].so_server = NULL;
#endif
  }

#ifdef RLB_SO
  for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
    struct filter *fl = &cfg->filters[cfg->cf];
    if (fl->in) if (fl->in(cfg, &(fl->userdata)) < 0) return -1;
  }
#endif
#ifdef RLB_DEBUG
  if (cfg->daemon) { char f[32]; snprintf(f, 32, "rlb.dbg.%u", getpid()); _rlb_fp = fopen(f, "w+"); } else _rlb_fp = stdout;
  RLOG("Listening on port %d", cfg->fd);
#endif
  return listen(cfg->fd, SOMAXCONN);
}

static int _bind(struct cfg *cfg)
{
  struct addrinfo *ai = _get_addrinfo(cfg->host, cfg->port);
  unsigned int l = sizeof(cfg->bufsize);
  if (!ai) return -2; cfg->fd = _socket(cfg, ai, 1, 0);
  if (cfg->fd >= 0) if (bind(cfg->fd, ai->ai_addr, ai->ai_addrlen) < 0) cfg->fd = _closefd(cfg->fd);
  freeaddrinfo(ai); if (cfg->fd < 0) return -1;
  if (!cfg->bufsize) getsockopt(cfg->fd, SOL_SOCKET, SO_SNDBUF, &cfg->bufsize, &l);
  if (!cfg->bufsize) cfg->bufsize = _BUFSIZE;
  return 0;
}

static int _parse_server(struct cfg *cfg, char *str)
{
  char *p = NULL, *cp = NULL;
  struct server *sv = NULL, *s = NULL;

  if (!*str) return -1;
  if ( !(cp = strchr(str, ':')) ) { if (!*(cfg->port)) return -1; cp = cfg->port; }
  else { if ( !*(cp + 1) ) return -1; *cp = 0; }
  if ( (p = strchr(cp + 1, ':')) ) *p = 0;

  if ( !(sv = realloc(cfg->servers, (cfg->si + 1) * sizeof(struct server))) ) return -1;
  cfg->servers = sv; s = &sv[cfg->si]; memset(s, 0, sizeof(struct server));
  if ( !(s->ai = _get_addrinfo(str, *cp ? cp : cp + 1)) ) return -1; cfg->si++;

  if (p) { *p++ = ':'; if (*p) s->max = atoi(p); } if (!*cp) *cp = ':';
  return _check_server(cfg, s);
}

static int _lookup_oaddr(struct cfg *cfg, char *outb)
{
  struct addrinfo *res = _get_addrinfo(outb, NULL);
  if (!res) return -1;
  memcpy(&cfg->oaddr, res->ai_addr, (cfg->olen = res->ai_addrlen) );
  freeaddrinfo(res);
  return 0;
}

struct addrinfo * _get_addrinfo(char *h, char *p)
{
  struct addrinfo hints, *res = NULL;
  int r;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags    = AI_PASSIVE;
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  if ( (r = getaddrinfo(*h ? h : NULL, p, &hints, &res)) ) { 
    fprintf(stderr, "%s:%s - %s\n", *h ? h : "", p, gai_strerror(r)); 
    if (res) freeaddrinfo(res);
    return NULL; 
  }
  return res;
}

static int _socket(struct cfg *cfg, struct addrinfo *a, int nb, int o)
{
  int fd;
  if (cfg == NULL || a == NULL) return -1;
  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) return -1;
  if (_sockopt(fd, nb) < 0) return _closefd(fd);
  if (o && cfg->olen) if (bind(fd, &cfg->oaddr, cfg->olen) < 0) return _closefd(fd);
  return fd;
}

static int _closefd(int fd)
{
  int r;
  do { r = close(fd); } while (r == -1 && errno == EINTR);
  return -1;
}

static int _sockopt(const int fd, int nb)
{
  int ret = 0, on = 1;
#ifdef SO_LINGER
  struct linger l;
  l.l_onoff = l.l_linger = 0;
  ret |= setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
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
static int _load_so(struct cfg *cfg, const char *path)
{
  struct filter *fl = NULL, *f = NULL;
  if ( !(fl = realloc(cfg->filters, (cfg->fi + 1) * sizeof(struct filter))) ) return -1;
  cfg->filters = fl; f = &fl[cfg->fi]; memset(f, 0, sizeof(struct filter)); cfg->fi++; dlerror();
  if ( !(f->h = dlopen(path, RTLD_GLOBAL | RTLD_NOW)) ) { fprintf(stderr, dlerror()); return -1; }
  if ( (f->fl = dlsym(f->h, "rlb_filter")) )      cfg->fli++;
  if ( (f->cl = dlsym(f->h, "rlb_close")) )       cfg->cli++;
  if ( (f->gs = dlsym(f->h, "rlb_get_server")) )  cfg->gsi++;
  if ( (f->in = dlsym(f->h, "rlb_init")) )        cfg->ini++;
  if ( (f->fr = dlsym(f->h, "rlb_cleanup")) )     cfg->fri++;
  return 0;
}
#endif

static int _cmdline(struct cfg *cfg, int ac, char *av[])
{
  int i, j;
  memset(cfg, 0, sizeof(struct cfg)); cfg->daemon = 1; _gcfg = cfg;
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
      case 'o': if (_load_so(cfg, av[i]) < 0) return -1;        break;
#endif
      case 'h': if (_parse_server(cfg, av[i]) < 0) return -1;   break;
      case 'B': if (_lookup_oaddr(cfg, av[i]) < 0) return -1;   break;
      case 'b': snprintf(cfg->host, sizeof(cfg->host), av[i]);  break;
      case 'p': snprintf(cfg->port, sizeof(cfg->port), av[i]);  break;
      default : return -1;
    }
  }
  return (cfg->si && *cfg->port) ? 0 : -1;
}

static void _usage(void)
{
  fprintf(stderr, "\nrlb %s Copyright � 2006-2007 RIVERDRUMS\n\n", _VERSION);
  fprintf(stderr, "usage: rlb -p port -h host[:service:max] [-h host[:service:max] ...]\n"
                  "          [-b address] [-B address] [-m max] [-t timeout] [-c check interval]\n"
                  "          [-s bufsize] [-n servers] [-u user] [-j jail] [-l clients to track]\n"
                  "          [-r (round-robin)] [-S (stubborn)] [-d (delay)] [-f (foreground)]\n");
#ifdef RLB_SO
  fprintf(stderr, "          [-o shared object [-o shared object] ...]\n");
#endif
  fprintf(stderr, "\n"); exit(EXIT_SUCCESS);
}

static void _check(int signo)
{
  int i;
  for (i = 0; i < _gcfg->si; i++) _check_server(_gcfg, &_gcfg->servers[i]);
  signal(SIGUSR2, _check);
}

static void _stat(int signo)
{
  int i;
  struct cfg *cfg = _gcfg;
  char last[32], *cp, h[32], p[8];
  struct in_addr in; 
#ifndef RLB_DEBUG
  char statusfile[32];
  FILE *_rlb_fp;
  if (signo != SIGUSR1) return;
  snprintf(statusfile, 32, "rlb.status.%u", getpid());
  _rlb_fp = fopen(statusfile, "w+");
# undef RLOG
# undef SCOPE
# define RLOG(f,...) do { if (_rlb_fp) { fprintf(_rlb_fp, f "\n", ##__VA_ARGS__); fflush(_rlb_fp); } } while(0)
# define SCOPE  (c->scope == RLB_CLIENT) ? " < CLIENT" : (c->scope == RLB_SERVER) ? " > SERVER" : " +  NONE "
#else
  RLOG("**** STATUS ****");
#endif
  RLOG("listen => %d rlb_fp => %d", cfg->fd, fileno(_rlb_fp));
  for (i = 0; i < cfg->max; i++) {
    struct connection *c = &cfg->conn[i];
    if (c->fd >= 0 || c->od >= 0) {
      RLOG(" ++ %s - [%4d] STATUS fd=%d od=%d ev=%d (pos=%d len=%d nr=%u nw=%u cl=%d)",
            SCOPE, i, c->fd, c->od, c->ev.ev_fd, c->pos, c->len, c->nr, c->nw, c->closed);
    }
  }
  for (i = 0; i < cfg->si; i++) {
    struct server *s = &cfg->servers[i];
    struct sockaddr *sa = s->ai->ai_addr;
    snprintf(last, sizeof(last), "%s", ctime(&s->last)); if ( (cp = strchr(last, '\n')) ) *cp = 0;
    if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = 0;
    RLOG(" oo SERVER - (%p) %s:%s status=%d num=%d max=%d last='%s'", s, h, p, s->status, s->num, s->max, last);
  }
  for (i = 0; i < cfg->ci; i++) {
    struct client *cl = &cfg->clients[i];
    if ( (in.s_addr = cl->id) ) {
      snprintf(last, sizeof(last), "%s", ctime(&cl->last)); if ( (cp = strchr(last, '\n')) ) *cp = 0;
      RLOG(" 00 CLIENT - (%p) last='%s' ip=%s", cl->server, last, inet_ntoa(in));
    }
  }
#ifndef RLB_DEBUG
if (_rlb_fp) fclose(_rlb_fp);
# undef RLOG
# undef SCOPE
# define RLOG(f,...)
# define SCOPE ""
#endif
  signal(SIGUSR1, _stat);
}
