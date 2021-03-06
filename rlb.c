/* rlb.c Jason Armstrong <ja@riverdrums.com> � 2006-2009 RIVERDRUMS
 * $Id$ */

#include "rlb.h"

#ifdef RLB_DEBUG
static FILE *_rlb_fp = NULL;
# define RLOG(f,...) do { if (_rlb_fp) { struct timeval tv; gettimeofday(&tv, NULL); fprintf(_rlb_fp, "%lu.%06lu [%7s:%d] " f "\n", tv.tv_sec, tv.tv_usec, __FUNCTION__, __LINE__, ##__VA_ARGS__); fflush(_rlb_fp); } } while(0)
# if defined(RLB_SO) && defined(RLB_CONTROL)
#   define SCOPE  (c->scope == RLB_CLIENT) ? "CLIENT" : (c->scope == RLB_SERVER) ? "SERVER" : (c->scope == RLB_CTRL) ? " CTRL " : " NONE "
# else
#   define SCOPE  (c->scope == RLB_CLIENT) ? "CLIENT" : (c->scope == RLB_SERVER) ? "SERVER" : " NONE "
# endif
#else
# define RLOG(f,...)
# define SCOPE ""
#endif

#define ERR1(x)  _error(cfg, c, __LINE__, x)
#define ERR2(x)  _error(c->cfg, c, __LINE__, x)
#define ERR3(x)  _error(cfg, NULL, __LINE__, x)

#define ER1   "Read error (no buffer)"
#define ER2   "Read error (SERVER: no client)"
#define ER3   "Read error"
#define EF1   "Filter returned error"
#define EW1   "Write error (no buffer)"
#define EW2   "Write error (no data)"
#define EW3   "Write error"
#define EG1   "Filter server unavailable"
#define EG2   "Stubborn server unavailable"
#define EG3   "No server available"
#define ES1   "Socket error"
#define ES2   "Max limit (SERVER)"
#define ES3   "Connect error: SERVER now DEAD"
#define EC1   "Accept error"
#define EC2   "Max limit on accept (CLIENT)"
#define EC3   "Sockopt error"
#define EB1   "Buffer index out of range"
#define EB2   "No buffer available"
#define EIN   "Filter initialisation failed"

static struct cfg *_gcfg = NULL;
static void _usage(void);
static int  _startup(struct cfg *cfg);
static void _write(struct connection *c);
static void _timeout(struct connection *c);
static int  _parse_server(struct cfg *cfg, char *str);
static void _event(const int fd, short event, void *c);
static int  _lookup_oaddr(struct cfg *cfg, char *outb);
static void _event_set(struct connection *c, short event);
static void _client(const int s, short event, void *config);
static struct server * _get_server(struct cfg *cfg, struct connection *c);
static int  _error(struct cfg *cfg, struct connection *c, int line, char *s);
static struct client * _find_client(struct cfg *cfg, unsigned int addr);
static int  _cmdline(struct cfg *cfg, int ac, char *av[]);
static void _close(struct cfg *cfg, struct connection *c);
static int  _server(struct connection *c, short event);
static struct buffer * _buffer(struct connection *c);
static int  _bind_kp(struct cfg *cfg, int n);
static void _no_server(struct connection *c);
static void _read(struct connection *c);
static void _cleanup(struct cfg *cfg);
static int  _bind(struct cfg *cfg);
static void _sig(int signo);
#ifdef RLB_SO
static int _load_so(struct cfg *cfg, const char *path, int init);
#endif

#ifdef __VOS__
/* Declare API functions here directly */
int   rlb_init(struct cfg *cfg, void **data);
void  rlb_cleanup(struct cfg *cfg, void **data);
int   rlb_filter(struct connection *c, int r, void *data);
void  rlb_close(struct connection *c, void *data);
void  rlb_error(struct cfg *cfg, struct connection *c, int line, char *s, void *data);
#endif

int main(int argc, char *argv[]) {
  struct event ev;
#if defined(RLB_SO) && defined(RLB_CONTROL)
  struct event kev;
#endif
  struct cfg cfg;
  int r;

  if (_cmdline(&cfg, argc, argv) < 0) _usage();
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);

  if ( (r = _startup(&cfg)) < 0) {
    if (r == -1) fprintf(stderr, "rlb: %s\n", strerror(errno));
    _cleanup(&cfg); exit(EXIT_FAILURE);
  }

  signal(SIGINT, _sig); signal(SIGTERM, _sig); signal(SIGQUIT, _sig);

  event_init();
  event_set(&ev, cfg.fd, EV_READ | EV_PERSIST, _client, &cfg);
  event_add(&ev, NULL);
#if defined(RLB_SO) && defined(RLB_CONTROL)
  if (cfg.kfd >= 0) {
    event_set(&kev, cfg.kfd, EV_READ | EV_PERSIST, _client, &cfg);
    event_add(&kev, NULL);
  }
#endif
  return event_dispatch();
}

static void _sig(int signo)
{
  _cleanup(_gcfg); exit(EXIT_SUCCESS);
}

static void _cleanup(struct cfg *cfg)
{
  int i;
  if (cfg->fd >= 0) cfg->fd = rlb_closefd(cfg->fd);
  for (i = 0; i < cfg->max; i++) {
    _close(cfg, &cfg->conn[i]); if (cfg->buffers[i].b) free(cfg->buffers[i].b);
#ifdef RLB_SO
    if (cfg->conn[i].userdata) free(cfg->conn[i].userdata);
#endif
  }
  for (i = 0; i < cfg->si; i++) if (cfg->servers[i].ai) freeaddrinfo(cfg->servers[i].ai);
  if (cfg->servers) { free(cfg->servers); cfg->servers = NULL; } cfg->si  = 0;
  if (cfg->clients) { free(cfg->clients); cfg->clients = NULL; } cfg->ci  = 0;
  if (cfg->buffers) { free(cfg->buffers); cfg->buffers = NULL; } 
  if (cfg->conn)    { free(cfg->conn);    cfg->conn    = NULL; } cfg->max = 0;
#ifdef RLB_SO
# ifdef RLB_CONTROL
  if (cfg->kfd >= 0) cfg->kfd = rlb_closefd(cfg->kfd);
# endif
  for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
    struct filter *fl = &cfg->filters[cfg->cf];
    if (fl->fr) fl->fr(cfg, &(fl->userdata));
#ifndef __VOS__
    if (fl->h) dlclose(fl->h);
#endif
  }
  if (cfg->filters) { free(cfg->filters); cfg->filters = NULL; } cfg->fi  = 0;
#endif
}

static void _event(const int fd, short event, void *c)
{
  struct connection *cn = c;
  if      (!cn || cn->fd != fd)  return; /* XXX ERROR */
  else if (event & EV_READ)     _read(cn);
  else if (event & EV_WRITE)    _write(cn);
  else if (event & EV_TIMEOUT)  _timeout(cn);
}

static void _read(struct connection *c)
{
  struct connection *co = NULL;
  struct cfg *cfg = c->cfg;
  struct buffer *b = c->rb;
  ssize_t r = 0;

  if ( !b || (c->scope == RLB_SERVER && c->od < 0) ) { ERR1(b ? ER2 : ER1); return _close(cfg, c); }
  if (b->pos + b->len == b->bs) { 
    if (b->pos) { memmove(b->b, b->b + b->pos, b->len); b->pos = 0; } 
    else { if (c->od < 0) _close(cfg, c); else event_del(&c->ev); return; }
  }
  if (c->od >= 0) co = &cfg->conn[c->od];
  do { r = read(c->fd, b->b + b->pos + b->len, b->bs - b->len - b->pos); } while (r == -1 && errno == EINTR);
  RLOG(" R fd=%-4d od=%-4d %s %4d (%d:%d %d)", c->fd, c->od, SCOPE, r, b->pos, b->len, b->bs);
  if (r <= 0) {
    if (r < 0) { ERR1(ER3); if (c->scope == RLB_SERVER) c->server->status = RLB_DEAD; }
    if (co && b->len == 0) _close(cfg, co); return _close(cfg, c);
  }
  c->nr += r; b->len += r;
#ifdef RLB_SO
  if (cfg->fli) {
    int rc = 0;
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->fl) if ( (rc = fl->fl(c, r, fl->userdata)) < 0) { ERR1(EF1); return _close(cfg, c); }
# if defined(RLB_CONTROL) && ! defined(__VOS__)
      if (c->scope == RLB_CTRL) {
        if (rc > 1 && rc - 2 < cfg->fi) {
          fl = &cfg->filters[rc - 2];
          if (fl && fl->h) dlclose(fl->h); memset(fl, 0, sizeof(*fl));
        } else if (*c->fn) { _load_so(cfg, c->fn, 1); *c->fn = '\0'; }
      }
# endif
      if (rc) return _event_set(c, EV_WRITE);
    }
  }
# if defined(RLB_SO) && defined(RLB_CONTROL)
  if (c->scope == RLB_CTRL) { event_add(&c->ev, &cfg->kto); return; }
# endif
#endif
  if (cfg->delay && !c->nowrite && c->od < 0 && c->scope == RLB_CLIENT) {
#ifdef RLB_SO
    if (cfg->gsi) {
      for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
        struct filter *fl = &cfg->filters[cfg->cf];
        if (fl->gs) fl->gs(c, fl->userdata);
      }
    }
#endif
    if (_server(c, EV_WRITE) < 0) return _no_server(c); /* XXX ERROR */
  } else { 
    if (c->nowrite) _event_set(c, EV_READ); else _event_set(co, EV_WRITE); 
  }
  event_add(&c->ev, &cfg->to);
}

static void _write(struct connection *c)
{
  struct connection *co = NULL;
  struct buffer *b = c->wb;
  ssize_t r = 0;

  if ( !b || (c->od < 0 && b->len == 0) ) { ERR2(b ? EW2 : EW1); return _close(c->cfg, c); }
  if (c->od >= 0) co = &c->cfg->conn[c->od];
#ifdef RLB_SO
  if ( (co && co->nowrite == 0) || !co) {
    if (co && c->scope == RLB_SERVER && ((co->so_server && co->server != co->so_server) || co->reconnect) ) {
      _close(c->cfg, c); /* XXX What if there is data (c->rb->len) */
      if (_server(co, EV_WRITE) < 0) _no_server(co); /* XXX ERROR */
      return;
    }
    if (co) co->so_server = NULL;
#endif
    if (b->len > 0) {
      do { r = write(c->fd, b->b + b->pos, b->len); } while (r == -1 && errno == EINTR);
      RLOG(" W fd=%-4d od=%-4d %s %4d (%d:%d %d)", c->fd, c->od, SCOPE, r, b->pos, b->len, b->bs);
      if (r != b->len) {
        if (r <= 0) {
          ERR2(EW3);
          if (c->scope == RLB_SERVER && c->nw == 0) {
            c->server->status = RLB_DEAD; _close(c->cfg, c);
            if (co) if (_server(co, EV_WRITE) < 0) _no_server(co); /* XXX ERROR */
            return;
          }
          if (co) _close(c->cfg, co); return _close(c->cfg, c); /* XXX ERROR */
        }
        b->pos += r; c->nw += r; b->len -= r;
        event_add(&c->ev, &c->cfg->to);
        return;
      }
      b->len = 0; c->nw += r;
    }
    b->pos = 0;
#ifdef RLB_SO
  }
# ifdef RLB_CONTROL
  if (c->scope == RLB_CTRL) { _event_set(c, EV_READ); return; }
# endif
#endif
  if (c->od < 0) return _close(c->cfg, c);
  if (co) _event_set(co, EV_READ); _event_set(c, EV_READ);
}

static void _timeout(struct connection *c)
{
  if (c->rb && !c->rb->len && c->od >= 0) _close(c->cfg, &c->cfg->conn[c->od]);
  _close(c->cfg, c);
}

static void _event_set(struct connection *c, short event)
{
  if (!c || c->fd < 0) return; /* XXX ERROR */
  //if (event == EV_WRITE) event |= EV_READ;
  if (c->ev.ev_events != event) { event_del(&c->ev); event_set(&c->ev, c->fd, event, _event, c); }
#if defined(RLB_SO) && defined(RLB_CONTROL)
  if (c->scope == RLB_CTRL) { event_add(&c->ev, &c->cfg->kto); return; }
#endif
  event_add(&c->ev, &c->cfg->to);
}

static void _close(struct cfg *cfg, struct connection *c)
{
  struct connection *co = NULL;
  struct buffer *rb = c->rb;
#ifdef RLB_DEBUG
  char b[16]; 
  if (rb) snprintf(b, 16, "(%d:%d)", rb->pos, rb->len); else snprintf(b, 16, "(*:*)");
  if (c->fd >= 0) RLOG("X: fd=%-4d od=%-4d %s    * %s (r=%u w=%u)", c->fd, c->od, SCOPE, b, c->nr, c->nw);
#endif
#ifdef RLB_SO
  if (cfg->cli) {
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->cl) fl->cl(c, fl->userdata);
    }
  }
#endif
  if (c->od >= 0) { co = &cfg->conn[c->od]; co->od = -1; }
  if (c->wb && !co) { c->wb->taken = c->wb->pos = c->wb->len = 0; }
  if (rb && (!rb->len || !co)) { if (co) co->wb = NULL; rb->taken = rb->pos = rb->len = 0; }
  c->fd = c->od = rlb_closefd(c->fd); c->wb = rb = NULL; c->nr = c->nw = c->nowrite = 0; 
  if (c->scope == RLB_SERVER) (c->server->num)--; 
  c->server = NULL; c->scope = RLB_NONE;
  if (c->client) { c->client->last = time(NULL); c->client = NULL; }
  event_del(&c->ev);
}

static struct server * _get_server(struct cfg *cfg, struct connection *c)
{
  struct server *s = NULL;
  int i = cfg->cs;
  time_t now = time(NULL);

#ifdef RLB_SO
  if ( !(c->reconnect = 0) && (s = c->so_server) ) {
    c->so_server = NULL;
    if (s->status == RLB_ACTIVE && (s->max ? s->num + 1 <= s->max : 1) ) return s; 
    if (!s->status) {
      if (!s->last) s->last = now;
      else if (now - s->last >= cfg->check) if (rlb_check_server(cfg, s)) return s;
    }
    ERR1(EG1);
    return NULL;
  }
#endif

  if (!cfg->rr && c->client && (s = c->client->server) ) {
    if (s->status == RLB_ACTIVE && (s->max ? s->num + 1 <= s->max : 1) ) return s; 
    if (cfg->stubborn) {
      if (!s->status) {
        if (!s->last) s->last = now;
        else if (now - s->last >= cfg->check) if (rlb_check_server(cfg, s)) return s;
      }
      ERR1(EG2);
      return NULL;
    }
  }

  do {
    cfg->cs++; cfg->cs %= cfg->si; s = &cfg->servers[cfg->cs];
    if (!s->status) {
      if (!s->last) s->last = now;
      else if (now - s->last >= cfg->check) rlb_check_server(cfg, s);
    }
    if (s->status != RLB_ACTIVE || (s->max && s->num + 1 > s->max) ) s = NULL;
  } while (!s && cfg->cs != i);
  if (!s) ERR1(EG3);
  return s;
}
 
static int _server(struct connection *c, short event)
{
  struct connection *cn = NULL;
  struct addrinfo *a = NULL;
  struct cfg *cfg = c->cfg;
  int fd = -1, r;

  while ( (c->server = _get_server(cfg, c)) ) {
    if ( (fd = rlb_socket(cfg, (a = c->server->ai), 1, 1)) < 0) return ERR1(ES1);
    if (fd >= cfg->max) { ERR1(ES2); return rlb_closefd(fd); }
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r < 0 && errno != EINPROGRESS) { ERR1(ES3); c->server->status = RLB_DEAD; rlb_closefd(fd); continue; }
    break;
  }
  if (!c->server || (!cfg->rr && !c->client) || fd < 0) return rlb_closefd(fd); /* XXX ERROR ??? */
  if (!cfg->rr && !c->client->server) { c->client->server = c->server; c->client->last = time(NULL); }
  (c->server->num)++;
#ifdef RLB_DEBUG
  { char h[64], p[8]; struct sockaddr *sa = c->server->ai->ai_addr;
    if (getnameinfo(sa, sizeof(*sa), h, 64, p, 8, NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = '\0';
    RLOG("O: fd=%-4d od=%-4d         %s:%s %p n=%d", fd, c->fd, h, p, c->server, c->server->num);
  }
#endif
  cn = &cfg->conn[fd]; cn->scope = RLB_SERVER;
  cn->fd = c->od = fd; cn->od = c->fd;
  cn->rb = c->wb = _buffer(cn); cn->wb = c->rb;
  memcpy(&cn->sa, a->ai_addr, sizeof(cn->sa));
  cn->server = c->server; cn->client = NULL;
  event_set(&cn->ev, fd, event, _event, cn);
  return event_add(&cn->ev, &cfg->to);
}

static void _client(const int s, short event, void *config)
{
  int fd;
  struct sockaddr sa;
  socklen_t l = sizeof(sa);
  struct cfg *cfg = config;
  struct connection *c = NULL;

  if ( (fd = accept(s, &sa, &l)) < 0) { ERR1(EC1); return; }
  if (fd >= cfg->max || rlb_sockopt(fd, 1) < 0) { ERR1(fd >= cfg->max ? EC2 : EC3); rlb_closefd(fd); return; }

  c = &cfg->conn[fd]; c->fd = fd; c->od = -1;
  c->scope = RLB_CLIENT; c->rb = _buffer(c); c->wb = NULL;
  if (c->rb == NULL) return _close(cfg, c);
  memcpy(&c->sa, &sa, l);
#ifdef RLB_DEBUG
  { char h[64], p[8];
    if (getnameinfo(&c->sa, sizeof(c->sa), h, 64, p, 8, NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = '\0';
    RLOG("C: fd=%-4d                 %s:%s", c->fd, h, p);
  }
#endif
#if defined(RLB_SO) && defined(RLB_CONTROL)
  if (s == cfg->kfd) { c->scope = RLB_CTRL; return _event_set(c, EV_READ); }
#endif
  if (!cfg->rr) {
    struct sockaddr_in *si = (struct sockaddr_in *) &sa;
    if ( !(c->client = _find_client(cfg, si->sin_addr.s_addr))) return _close(cfg, c);
  }
#ifdef RLB_SO
  if (!cfg->delay && cfg->gsi) {
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->gs) fl->gs(c, fl->userdata);
    }
  }
#endif
  if (!cfg->delay) if (_server(c, EV_READ) < 0) return _no_server(c);
  _event_set(c, EV_READ);
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

static struct buffer * _buffer(struct connection *c)
{
  struct buffer *b = NULL;
  int i = c->fd;

  if (i < 0 || i >= c->cfg->max) { ERR2(EB1); return NULL; }
  if ( (b = &c->cfg->buffers[i]) && !b->taken) { b->taken = 1; return b; }
  do {
    i++; i %= c->cfg->max; b = &c->cfg->buffers[i];
    if (!b->taken) { b->taken = 1; return b; }
  } while (i != c->fd);
  ERR2(EB2);
  return NULL;
}

static int _startup(struct cfg *cfg)
{
  struct passwd *pw = NULL;
  unsigned int i = 0;
  struct rlimit rl;
  int rc;

  getrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = rl.rlim_max;
  setrlimit(RLIMIT_NOFILE, &rl);

  if (cfg->max == 0)      cfg->max = rl.rlim_cur;
  else if (cfg->max < 8)  cfg->max = 8;

  if (!cfg->check)      cfg->check      = RLB_TIMEOUT;
  if (!cfg->to.tv_sec)  cfg->to.tv_sec  = RLB_TIMEOUT;
  if (!cfg->ci)         cfg->ci         = RLB_BUFSIZE;

  if ( !(cfg->clients = calloc(cfg->ci,  sizeof(*cfg->clients))) )  return -1;
  if ( !(cfg->buffers = calloc(cfg->max, sizeof(*cfg->buffers))) )  return -1;
  if ( !(cfg->conn    = calloc(cfg->max, sizeof(*cfg->conn))) )     return -1;
  for (i = 3; i < cfg->max; i++) rlb_closefd(i); cfg->cs = cfg->si - 1;

#ifdef __VOS__
  _load_so(cfg, "VOS", 0);
#else
  if (cfg->daemon) {
    rlb_closefd(0); rlb_closefd(1); rlb_closefd(2);
    if ( (rc = _bind(cfg)) < 0) return rc;
    if (fork()) _exit(0); setsid(); if (fork()) _exit(0);

    if (cfg->num > 1) {
      pid_t ppid = getpid();
      for (i = 0; i < cfg->num; i++) if (!fork()) break;
      if (getpid() == ppid) _exit(0);
      if ( (rc = _bind_kp(cfg, i)) < 0) return rc;
    } else if ( (rc = _bind_kp(cfg, 0)) < 0) return rc;
  } else 
#endif
    if ( (rc = _bind(cfg)) < 0 || (rc = _bind_kp(cfg, 0)) < 0) return rc;

  if (cfg->user)  if ( !(pw = getpwnam(cfg->user)) )                    return -1;
#ifndef __VOS__
  if (cfg->jail)  if (chdir(cfg->jail) < 0 || chroot(cfg->jail) < 0)    return -1;
#endif
  if (pw)         if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) return -1;

  for (i = 0; i < cfg->max; i++) {
    cfg->conn[i].cfg   = cfg;
    cfg->conn[i].scope = RLB_NONE;
    cfg->buffers[i].bs = cfg->bufsize;
    cfg->conn[i].fd = cfg->conn[i].od = -1;
    if ( !(cfg->buffers[i].b = malloc(cfg->bufsize + 1)) ) return -1;
#ifdef RLB_SO
    if ( !(cfg->conn[i].userdata = calloc(cfg->fi, sizeof(void *)))) return -1;
#endif
  }
#ifdef RLB_DEBUG
  if (cfg->daemon) { char f[32]; snprintf(f, 32, "rlb.dbg.%u", (unsigned int) getpid()); _rlb_fp = fopen(f, "w+"); } else _rlb_fp = stdout;
  RLOG("LISTEN  port %d", cfg->fd);
#endif
#ifdef RLB_SO
  for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
    struct filter *fl = &cfg->filters[cfg->cf];
    if (fl->in) if (fl->in(cfg, &(fl->userdata)) < 0) return -1;
  }
# ifdef RLB_CONTROL
  RLOG("CONTROL port %d", cfg->kfd);
  if (cfg->kfd >= 0) if (listen(cfg->kfd, cfg->kmax ? cfg->kmax : SOMAXCONN) < 0) return -1;
  if (!cfg->kto.tv_sec) cfg->kto.tv_sec = RLB_TIMEOUT * 4;
# endif
#endif
  return listen(cfg->fd, SOMAXCONN);
}

static int _error(struct cfg *cfg, struct connection *c, int line, char *s)
{
#ifdef RLB_SO
  if (!cfg) if (c) cfg = c->cfg;
  if (cfg && cfg->eli) {
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->el) fl->el(cfg, c, line, s, fl->userdata);
    }
  }
#endif
  return -1;
}

static void _no_server(struct connection *c)
{
#ifdef RLB_SO
  struct cfg *cfg = c->cfg;
  if (cfg && cfg->nsi) {
    for (cfg->cf = 0; cfg->cf < cfg->fi; cfg->cf++) {
      struct filter *fl = &cfg->filters[cfg->cf];
      if (fl->ns) if (fl->ns(c, fl->userdata) > 0) return _event_set(c, EV_WRITE);
    }
  }
#endif
  _close(c->cfg, c);
}

static int _bind(struct cfg *cfg)
{
  struct addrinfo *ai = rlb_get_addrinfo(cfg->host, cfg->port);
  unsigned int l = sizeof(cfg->bufsize);
  if (!ai) return -2; cfg->fd = rlb_socket(cfg, ai, 1, 0);
  if (cfg->fd >= 0) if (bind(cfg->fd, ai->ai_addr, ai->ai_addrlen) < 0) cfg->fd = rlb_closefd(cfg->fd);
  freeaddrinfo(ai); if (cfg->fd < 0) return -1; /* XXX ERROR (but this is at startup) */
  if (!cfg->bufsize) getsockopt(cfg->fd, SOL_SOCKET, SO_SNDBUF, &cfg->bufsize, &l);
  if (!cfg->bufsize) cfg->bufsize = RLB_BUFSIZE;
  return 0;
}

static int _bind_kp(struct cfg *cfg, int n)
{
#if defined(RLB_SO) && defined(RLB_CONTROL)
  cfg->kfd = -1;
  if (*cfg->kp) {
    struct addrinfo *ai = NULL;
    int i = atoi(cfg->kp); 
    if (i <= 0) { fprintf(stderr, "Invalid control: %d\n", i); return -2; }
    i += n; snprintf(cfg->kp, sizeof(cfg->kp), "%u", i);
    if ( !(ai = rlb_get_addrinfo(cfg->kh, cfg->kp)) ) { rlb_closefd(cfg->fd); return -2; }
    cfg->kfd = rlb_socket(cfg, ai, 1, 0);
    if (cfg->kfd >= 0) if (bind(cfg->kfd, ai->ai_addr, ai->ai_addrlen) < 0) cfg->kfd = rlb_closefd(cfg->kfd);
    freeaddrinfo(ai); if (cfg->kfd < 0) return (cfg->fd = rlb_closefd(cfg->fd));
  }
#endif
  return 0;
}

static int _parse_server(struct cfg *cfg, char *str)
{
  char *p = NULL, *cp = NULL;
  struct server *sv = NULL, *s = NULL;

  if (!*str) return -1;
  if ( !(cp = strchr(str, ':')) ) { if (!*(cfg->port)) return -1; cp = cfg->port; }
  else { if ( !*(cp + 1) ) return -1; *cp = '\0'; }
  if ( (p = strchr(cp + 1, ':')) ) *p = '\0';

  if ( !(sv = realloc(cfg->servers, (cfg->si + 1) * sizeof(*sv))) ) return -1;
  cfg->servers = sv; s = &sv[cfg->si]; memset(s, 0, sizeof(*s));
  if ( !(s->ai = rlb_get_addrinfo(str, *cp ? cp : cp + 1)) ) return -1; cfg->si++;

  if (p) { *p++ = ':'; if (*p) s->max = atoi(p); } if (!*cp) *cp = ':';
  return rlb_check_server(cfg, s);
}

static int _lookup_oaddr(struct cfg *cfg, char *outb)
{
  struct addrinfo *res = rlb_get_addrinfo(outb, NULL);
  if (!res) return -1;
  memcpy(&cfg->oaddr, res->ai_addr, (cfg->olen = res->ai_addrlen) );
  freeaddrinfo(res);
  return 0;
}

#ifdef RLB_SO
static int _load_so(struct cfg *cfg, const char *path, int init)
{
  struct filter *fl = NULL, *f = NULL;
  int i;
#ifndef __VOS__
  char *p = strrchr(path, '/');
#else
  if (cfg->fi) return 0;
#endif
  for (i = 0; i < cfg->fi; i++, f = NULL) if (!cfg->filters[i].h) { f = &cfg->filters[i]; break; }
  if (!f) {
    if ( !(fl = realloc(cfg->filters, (cfg->fi + 1) * sizeof(*fl))) ) return ERR3("");
    cfg->filters = fl; f = &fl[cfg->fi]; memset(f, 0, sizeof(*f));
    if (init) {
      for (i = 0; i < cfg->max; i++) {
        void **ud = cfg->conn[i].userdata;
        if ( !(ud = realloc(cfg->conn[i].userdata, (cfg->fi + 1) * sizeof(*ud)))) return ERR3("");
        cfg->conn[i].userdata = ud; cfg->conn[i].userdata[cfg->fi] = NULL;
      }
    }
    cfg->fi++;
  }
#ifdef __VOS__    /* Point to the functions directly */
  snprintf(f->name, sizeof(f->name), "VOS");
  f->in = rlb_init;        cfg->ini++;
  f->fr = rlb_cleanup;     cfg->fri++;
  f->fl = rlb_filter;      cfg->fli++;
  f->cl = rlb_close;       cfg->cli++;
  f->el = rlb_error;       cfg->eli++;
/*f->gs = rlb_get_server;  cfg->gsi++;
  f->ns = rlb_no_server;   cfg->nsi++; */
#else
  dlerror();
  if ( !(f->h = dlopen(path, RTLD_GLOBAL | RTLD_NOW)) ) { fprintf(stderr, dlerror()); return ERR3(""); }
  snprintf(f->name, sizeof(f->name), "%s", p ? p + 1 : path);
  if ( (f->in = dlsym(f->h, "rlb_init")) )        cfg->ini++;
  if ( (f->fr = dlsym(f->h, "rlb_cleanup")) )     cfg->fri++;
  if ( (f->fl = dlsym(f->h, "rlb_filter")) )      cfg->fli++;
  if ( (f->cl = dlsym(f->h, "rlb_close")) )       cfg->cli++;
  if ( (f->gs = dlsym(f->h, "rlb_get_server")) )  cfg->gsi++;
  if ( (f->ns = dlsym(f->h, "rlb_no_server")) )   cfg->nsi++;
  if ( (f->el = dlsym(f->h, "rlb_error")) )       cfg->eli++;
  if (init && f->in) if (f->in(cfg, &f->userdata) < 0) return ERR3(EIN);
#endif
  return 0;
}
#endif

static int _cmdline(struct cfg *cfg, int ac, char *av[])
{
  int i, j;
  memset(cfg, 0, sizeof(*cfg)); _gcfg = cfg; cfg->daemon = 1;
  for (i = j = 1; i < ac; j = ++i) {
    if (av[j][0] != '-' || (av[j][1] != 'f' && av[j][1] != 'r' && 
                            av[j][1] != 'S' && av[j][1] != 'd' &&
                           ++i >= ac) || strlen(av[j]) > 2) return -1;
    switch (av[j][1]) {
      case 'f': cfg->daemon     = 0;                            break;
      case 'S': cfg->stubborn   = 1;                            break;
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
# ifdef RLB_CONTROL
      case 'M': cfg->kmax       = atoi(av[i]);                  break;
      case 'T': cfg->kto.tv_sec = atoi(av[i]);                  break;
      case 'k': snprintf(cfg->kp, sizeof(cfg->kp), av[i]);      break;
      case 'K': snprintf(cfg->kh, sizeof(cfg->kh), av[i]);      break;
# endif
      case 'o': if (_load_so(cfg, av[i], 0) < 0) return -1;     break;
#endif
      case 'h': if (_parse_server(cfg, av[i]) < 0) return -1;   break;
      case 'B': if (_lookup_oaddr(cfg, av[i]) < 0) return -1;   break;
      case 'b': snprintf(cfg->host, sizeof(cfg->host), av[i]);  break;
      case 'p': snprintf(cfg->port, sizeof(cfg->port), av[i]);  break;
      default : return -1;
    }
  }
  return (*cfg->port) ? 0 : -1;
}

static void _usage(void)
{
  fprintf(stderr, "\nrlb %s Copyright � 2006-2009 RIVERDRUMS\n\n", RLB_VERSION);
  fprintf(stderr, "usage: rlb -p port -h host[:service:max] [-h host[:service:max] ...]\n"
                  "          [-b <address>] [-B <address>] [-m <max>] [-t <timeout>] [-c <check interval>]\n"
                  "          [-s <bufsize>] [-n <servers>] [-u <user>] [-j <jail>] [-l <clients to track>]\n"
                  "          [-r (round-robin)] [-S (stubborn)] [-d (delay)] [-f (foreground)]\n");
#ifdef RLB_SO
# ifdef RLB_CONTROL
  fprintf(stderr, " control: [-k <port>] [-K <address>] [-T <timeout>] [-M <max>]\n");
# endif
# ifndef __VOS__
  fprintf(stderr, " filters: [-o <shared object> [-o <shared object>] ...]\n");
# endif
#endif
  fprintf(stderr, "\n"); exit(EXIT_SUCCESS);
}
