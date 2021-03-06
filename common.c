/* common.c Jason Armstrong <ja@riverdrums.com> � 2006-2009 RIVERDRUMS
 * $Id$ */

#include <rlb.h>

struct addrinfo * rlb_get_addrinfo(char *h, char *p)
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

int rlb_socket(struct cfg *cfg, struct addrinfo *a, int nb, int o)
{
  int fd;
  if (cfg == NULL || a == NULL) return -1;
  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) return -1;
  if (rlb_sockopt(fd, nb) < 0) return rlb_closefd(fd);
  if (o && cfg->olen) if (bind(fd, &cfg->oaddr, cfg->olen) < 0) return rlb_closefd(fd);
  return fd;
}

int rlb_closefd(int fd)
{
  int r;
  if (fd >= 0) do { r = close(fd); } while (r == -1 && errno == EINTR);
  return -1;
}

int rlb_sockopt(const int fd, int nb)
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

int rlb_check_server(struct cfg *cfg, struct server *s)
{
  int fd, r;
  if (s->status == RLB_ACTIVE) return RLB_ACTIVE;
  if (s->status == RLB_CLOSED || !s->ai) return RLB_DEAD;
  if ( (fd = rlb_socket(cfg, s->ai, 0, 1)) < 0) return RLB_DEAD;
  do { r = connect(fd, s->ai->ai_addr, s->ai->ai_addrlen); } while (r == -1 && errno == EINTR);
  rlb_closefd(fd); s->status = !r; s->last = r ? time(NULL) : 0;
  return s->status;
}

/* These aren't used by rlb itself but by the filters */
char * rlb_strnstr(char *str, char *find, int n)
{
  char *p = str, *end = str + n;
  int len = strlen(find);
  for (; p < end && len < n; p++, n--) if (strncmp(p, find, len) == 0) return p;
  return NULL;
}

int rlb_str_insert(struct connection *c, char *start, char *end, char *insert, int len)
{
  int rest, need;
  struct buffer *b;

  if (strncmp(start, insert, len) == 0 && end - start == len) return 0;
  if ( !(b = c->rb) || end < start) return -1;
  if (end < b->b || start < b->b || end > b->b + b->bs || start > b->b + b->bs) return -1;

  rest = b->len - ((end - start) - len);
  need = b->pos + rest;

  if (need >= b->bs) need += b->bs - b->pos + b->len;

  if (need > b->bs) {
    char *buf = b->b;
    int startpos = start - buf, endpos = end - buf;
    if ( (buf = realloc(b->b, (need + 1) * sizeof(*buf))) ) {
      b->bs = need; b->b = buf;
      start = buf + startpos;
      end   = buf + endpos;
    } else return -1;
  }

  if ( (end - start) != len) {
    memmove(start + len, end, b->len - (end - (b->b + b->pos)));
  }
  memcpy(start, insert, len);
  b->len -= (end - start) - len;

  return 0;
}
