/* rlb_ctrl.c Jason Armstrong <ja@riverdrums.com> © 2007 RIVERDRUMS
 * $ gcc -DRLB_SO -DRLB_CONTROL -Wall -O2 -I. -fPIC -shared -o rlb_ctrl.so rlb_ctrl.c 
 * $Id$ */

#ifdef RLB_CONTROL

#include <rlb.h>
#include <stdarg.h>
#include <ctype.h>

#define PROMPT  "\nrlb> "

struct rlb_ctrl { 
  char cmd[8]; char val[256]; 
  struct timeval tv1;
};


/* API functions */
int   rlb_init(struct cfg *cfg, void **data);
void  rlb_cleanup(struct cfg *cfg, void **data);
int   rlb_filter(struct connection *c, int r, void *data);
void  rlb_close(struct connection *c, void *data);

int show_config(struct connection *c);
int show_summary(struct connection *c);
int show_connections(struct connection *c);
int show_buffers(struct connection *c);
int show_servers(struct connection *c);
int show_clients(struct connection *c);
int show_detail(struct connection *c);
int show_filter(struct connection *c);

int version(struct connection *c);
int copyright(struct connection *c);
int help(struct connection *c);
int quit(struct connection *c);

int  _add(struct connection *c, char *str, ...);
int  _num(struct connection *c);
void _start(struct connection *c, struct rlb_ctrl *ctrl);
int  _prompt(struct connection *c);

enum { PARAM_NONE, PARAM_INT, PARAM_STR };

struct _cmds {
  char *name;
  char *desc;
  int param;
  int (*func)(struct connection *);
} cmds[] = {
  { "g",    "Show configuration",             PARAM_NONE, show_config },
  { "m",    "Show status summary",            PARAM_NONE, show_summary },
  { "n",    "Show connection status",         PARAM_NONE, show_connections },
  { "b",    "Show buffer status",             PARAM_NONE, show_buffers },
  { "s",    "Show server status",             PARAM_NONE, show_servers },
  { "c",    "Show client status",             PARAM_NONE, show_clients },
  { "d",    "Show connection detail",         PARAM_INT,  show_detail },
  { "f",    "Show filter details",            PARAM_INT,  show_filter },
  
  { "sep",  "",                               PARAM_NONE, NULL },

  { "vers", "Show RLB version",               PARAM_NONE, version},
  { "copy", "Show RLB copyright",             PARAM_NONE, copyright},
  { "help", "List help commands",             PARAM_NONE, help },
  { "quit", "Exit control interface",         PARAM_NONE, quit },

  { NULL,   NULL,                             PARAM_NONE, NULL }
};

int rlb_init(struct cfg *cfg, void **data)
{
  struct rlb_ctrl *ctrl = calloc(1, sizeof(*ctrl));
  return (*data = ctrl) ? 0 : -1;
}

void rlb_cleanup(struct cfg *cfg, void **data)
{
  struct rlb_ctrl *ctrl = *data;
  if (ctrl) free(ctrl);
  *data = NULL;
}


int rlb_filter(struct connection *c, int r, void *data) 
{
  if (c->scope == RLB_CTRL) {
    struct rlb_ctrl *ctrl = data;
    int rc;

    _start(c, ctrl);
    if (*(ctrl->cmd)) {
      int i = 0;
      while (cmds[i].name) {
        if (strcmp(ctrl->cmd, cmds[i].name) == 0 && cmds[i].func) {
          if ( (rc = cmds[i].func(c)) < 0) return rc;
          _prompt(c);
          return rc;
        }
        i++;
      }
    }
    help(c);
    return _prompt(c);
  }

  return 0;
}


void rlb_close(struct connection *c, void *data)
{
  struct rlb_ctrl *ctrl = data;
  
  if (!ctrl || !c->cfg || !c->cfg->conn) return;

  if (c == &c->cfg->conn[c->cfg->cf]) {
    c->userdata[c->cfg->cf] = NULL;
    return;
  }
}

int show_config(struct connection *c)
{
  struct cfg *cfg = c->cfg;
  char last[32], h[32], p[8], *cp;
  int i;

  _add(c, "\n");
  _add(c, "  PID                        : %u\n", (unsigned int) getpid());
  _add(c, "  Running as a daemon process: %d\n", cfg->daemon);
  _add(c, "  Number of running instances: %d\n", cfg->num ? cfg->num : 1);
  _add(c, "  Maximum connection number  : %d\n", cfg->max);
  _add(c, "  Dead server check interval : %d\n", cfg->check);
  _add(c, "  Event timeout              : %d\n", cfg->to.tv_sec);
  _add(c, "  Control Port Event timeout : %d\n", cfg->kto.tv_sec);
  _add(c, "  Buffer size                : %d\n", cfg->bufsize);
  _add(c, "  Number of servers          : %d\n", cfg->si);

  for (i = 0, *h = *p = '\0'; i < cfg->si; i++) {
    struct server *s = &cfg->servers[i];
    struct sockaddr *sa = s->ai ? s->ai->ai_addr : NULL;

    if (sa) {
      snprintf(last, sizeof(last), "%s", ctime(&s->last)); if ( (cp = strchr(last, '\n')) ) *cp = '\0';
      if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = '\0';
    }
    _add(c, "        %d. %s:%s s=%d n=%d\n", i + 1, sa ? h : "(deleted)", sa ? p : "", s->status, s->num);
  }

  _add(c, "  Number of clients to track : %d\n", cfg->ci);
  _add(c, "  Server Round Robin         : %d\n", cfg->rr);
  _add(c, "  Stubborn server selection  : %d\n", cfg->stubborn);
  _add(c, "  Delay server connect       : %d\n", cfg->delay);
  _add(c, "  Jail                       : %s\n", cfg->jail ? cfg->jail : "(none)");
  _add(c, "  User                       : %s\n", cfg->user ? cfg->user : "(none)");
  _add(c, "  Listening on interface     : %s\n", cfg->host);
  _add(c, "  Listening on port          : %s\n", cfg->port);

  *h = '\0';
  if (cfg->olen) {
    getnameinfo(&cfg->oaddr, sizeof(struct sockaddr), h, sizeof(h), NULL, 0, NI_NUMERICHOST);
  }

  _add(c, "  Interface on connect       : %s\n", h);
  _add(c, "  Control Port               : %s\n", cfg->kp);
  _add(c, "  Control interface          : %s\n", cfg->kh);
  _add(c, "  Number of filters loaded   : %d\n", cfg->fi);
  for (i = 0; i < cfg->fi; i++) {
    _add(c, "        %d. %s %s\n", i + 1, &cfg->filters[i].name, cfg->filters[i].h == NULL ? "(unloaded)" : "");
  }
  if (i) {
    _add(c, "    rlb_init()               : %d\n", cfg->ini);
    _add(c, "    rlb_cleanup()            : %d\n", cfg->fri);
    _add(c, "    rlb_filter()             : %d\n", cfg->fli);
    _add(c, "    rlb_close()              : %d\n", cfg->cli);
    _add(c, "    rlb_get_server()         : %d\n", cfg->gsi);
  }

  return 1;
}

int show_connections(struct connection *c)
{
  struct cfg *cfg = c->cfg;
  int i;

  _add(c, "fd=%d kfd=%d\n", cfg->fd, cfg->kfd);

  for (i = 0; i < cfg->max; i++) {
    struct connection *cn = &cfg->conn[i];
    if (cn->fd >= 0 || cn->od >= 0) {
      _add(c, "%c %d:%d %d:%d %u:%u\n",
            cn->scope == RLB_SERVER ? 'S' : cn->scope == RLB_CLIENT ? 'C' : cn->scope == RLB_CTRL ? 'K' : '*',
            cn->fd, cn->od, cn->rb ? cn->rb->pos : -1, cn->rb ? cn->rb->len : -1, cn->nr, cn->nw);
    }
  }

  return 1;
}

int show_buffers(struct connection *c)
{
  struct cfg *cfg = c->cfg;
  int i;

  for (i = 0; i < cfg->max; i++) {
    struct buffer *b = &cfg->buffers[i];
    if (b->taken) _add(c, "%d %d:%d\n", i, b->pos, b->len);
  }

  return 1;
}

int show_servers(struct connection *c)
{
  char last[32], *cp, h[32], p[8];
  struct cfg *cfg = c->cfg;
  int i;

  for (i = 0; i < cfg->si; i++) {
    struct server *s = &cfg->servers[i];
    struct sockaddr *sa = s->ai ? s->ai->ai_addr : NULL;
    if (!sa) continue;
    snprintf(last, sizeof(last), "%s", ctime(&s->last)); if ( (cp = strchr(last, '\n')) ) *cp = '\0';
    if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = '\0';
    _add(c, " %d. %s:%s s=%d n=%d m=%d last='%s' (%p)\n", i + 1, h, p, s->status, s->num, s->max, last, s);
  }

  return 1;
}

int show_clients(struct connection *c)
{
  int i;
  struct in_addr in; 
  char last[32], *cp;
  struct cfg *cfg = c->cfg;

  for (i = 0; i < cfg->ci; i++) {
    struct client *cl = &cfg->clients[i];
    if ( (in.s_addr = cl->id) ) {
      snprintf(last, sizeof(last), "%s", ctime(&cl->last)); if ( (cp = strchr(last, '\n')) ) *cp = '\0';
      _add(c, " %d. %s last='%s' server=%p\n", i + 1, inet_ntoa(in), last, cl->server);
    }
  }

  return 1;
}

int show_detail(struct connection *c)
{
  struct cfg *cfg = c->cfg;
  struct connection *cn;
  char h[64], p[64];
  int i = _num(c);

  if (i < 0 || i >= cfg->max) return _add(c, "INVALID [%d]\n", i);

  cn = &cfg->conn[i];
  if (getnameinfo(&cn->sa, sizeof(cn->sa), h, sizeof(h), p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV)) *h = *p = '\0';

  _add(c, "   scope             %s\n", 
       cn->scope == RLB_SERVER ? "SERVER" : cn->scope == RLB_CLIENT ? "CLIENT" : cn->scope == RLB_CTRL ? "CTRL" : "*");
  _add(c, "   structure address %p\n", cn);
  _add(c, "   file descriptor   %d\n", cn->fd);
  _add(c, "   other descriptor  %d\n", cn->od);
  _add(c, "   read buffer       %p\n", cn->rb ? cn->rb : 0);
  if (cn->rb) _add(c, "                     pos=%d len=%d size=%d\n", cn->rb->pos, cn->rb->len, cn->rb->bs);
  _add(c, "   write buffer      %p\n", cn->wb ? cn->wb : 0);
  if (cn->wb) _add(c, "                     pos=%d len=%d size=%d\n", cn->wb->pos, cn->wb->len, cn->wb->bs);
  _add(c, "   bytes read        %u\n", cn->nr);
  _add(c, "   bytes written     %u\n", cn->nw);
  _add(c, "   server            %p\n", cn->server ? cn->server : 0);
  _add(c, "   client            %p\n", cn->client ? cn->client : 0);
  _add(c, "   address and port  %s:%s\n", h, p);

  return 1;
}

int show_filter(struct connection *c)
{
  struct filter *fl;
  int n = _num(c);

  if (n <= 0 || n > c->cfg->fi || !(fl = &c->cfg->filters[n - 1])) return _add(c, "INVALID [%d]\n", n);

  _add(c, " name              %s\n", fl->name);
  _add(c, " handle            %p\n", fl->h);
  _add(c, " userdata          %p\n", fl->userdata);
  _add(c, "   rlb_init        %p\n", fl->in);
  _add(c, "   rlb_cleanup     %p\n", fl->cl);
  _add(c, "   rlb_filter      %p\n", fl->fl);
  _add(c, "   rlb_close       %p\n", fl->cl);
  _add(c, "   rlb_get_server  %p\n", fl->gs);

  return 1;
}

int show_summary(struct connection *c)
{
  struct cfg *cfg = c->cfg;
  int i, j, k, l, m;

  for (i = j = k = l = m = 0; i < cfg->max; i++) {
    struct connection *cn = &cfg->conn[i];
    if (cn->fd >= 0 || cn->od >= 0) j++; 
    cn->scope == RLB_CLIENT ? k++ : cn->scope == RLB_SERVER ? l++ : cn->scope == RLB_CTRL ? m++ : 1;
  }
  if (j) _add(c, "* connections = %d\n", j);
  if (k) _add(c, "   clients = %d\n", k);
  if (l) _add(c, "   servers = %d\n", l);
  if (m) _add(c, "   control = %d\n", m);

  for (i = j = 0; i < cfg->max; i++) if (cfg->buffers[i].taken) j++;
  if (j) _add(c, "* buffers     = %d\n", j);

  for (i = j = k = l = 0; i < cfg->si; i++) {
    struct server *s = &cfg->servers[i];
    if (s->ai) s->status == RLB_ACTIVE ? j++ : s->status == RLB_CLOSED ? k++ : l++;
  }
  _add(c, "* servers\n");
  if (l) _add(c, "         dead = %d\n", l);
  if (j) _add(c, "       active = %d\n", j);
  if (k) _add(c, "       closed = %d\n", k);

  for (i = j = 0; i < cfg->ci; i++) if (cfg->clients[i].id) j++;
  if (j) _add(c, "* clients     = %d\n", j);

  return 1;
}

int help(struct connection *c)
{
  int i;

  _add(c, "  %-6s %5s  %s\n", "CMD", "PARAM", "DESCRIPTION");
  for (i = 0; cmds[i].name; i++) {
    if (strcmp(cmds[i].name, "sep") == 0) _add(c, "\n");
    else _add(c, "  %-6s %5s  %s\n", 
                  cmds[i].name, 
                  cmds[i].param == PARAM_INT ? "[num]" : cmds[i].param == PARAM_STR ? "[str]" : "",
                  cmds[i].desc);
  }

  return 1;
}

int version(struct connection *c)
{
  return _add(c, "rlb %s\n", RLB_VERSION);
}

int copyright(struct connection *c)
{
  _add(c, "Riverdrums Load Balancer version %s\n\n", RLB_VERSION);
  _add(c, " Copyright  (c) 2006-2007 RIVERDRUMS\n");
  _add(c, " Jason Armstrong <ja@riverdrums.com>\n");
  _add(c, " http://rlb.sourceforge.net\n\n");
  return 1;
}

int quit(struct connection *c)
{
  c->userdata[c->cfg->cf] = NULL;
  return -1;
}

int _add(struct connection *c, char *str, ...)
{
  va_list args;
  struct buffer *b = c->rb;

  va_start(args, str);
  vsnprintf(b->b + b->pos + b->len, b->bs - b->len - b->pos, str, args);
  va_end(args);
  b->len = strlen(b->b + b->pos);

  return 1;
}

int _num(struct connection *c)
{
  struct rlb_ctrl *ctrl = c->userdata[c->cfg->cf];
  return ctrl ? atoi(ctrl->val) : 0;
}

int _prompt(struct connection *c)
{
  struct rlb_ctrl *ctrl = c->userdata[c->cfg->cf];

  if (ctrl) {
    struct timeval tv2;
    long sec, msec;

    gettimeofday(&tv2, NULL);

    sec  = tv2.tv_sec  - ctrl->tv1.tv_sec; 
    msec = tv2.tv_usec - ctrl->tv1.tv_usec; 
    c->userdata[c->cfg->cf] = NULL;

    if (msec < 0) { sec--; msec += 1000000; } 
    _add(c, "\n    %lu.%06lu", sec, msec);
  }

  c->wb = c->rb;
  return _add(c, PROMPT);
}

void _start(struct connection *c, struct rlb_ctrl *ctrl)
{
  char *p, *cp = c->rb->b;
  int i = 0, cmd = 2, s;

  if ( !(c->userdata[c->cfg->cf] = ctrl) ) return;

  gettimeofday(&ctrl->tv1, NULL);
  p = ctrl->cmd; s = sizeof(ctrl->cmd);
  *ctrl->cmd = *ctrl->val = '\0';

  if (*cp == (char) 4) { 
    snprintf(ctrl->cmd, sizeof(ctrl->cmd), "quit");
  } else {
    while (cp && *cp && cp < c->rb->b + c->rb->len) {
      if (isspace(*cp)) { 
        p[i] = '\0';
        if (cmd-- == 2) { p = ctrl->val; s = sizeof(ctrl->val); }
        if (cmd) i = 0;
      } else {
        if (i >= s - 1) break;
        p[i++] = *cp;
      }
      if (!cmd) break;
      cp++;
    }
    p[i] = '\0';
  }
  c->rb->pos = c->rb->len = 0;
}

#endif
