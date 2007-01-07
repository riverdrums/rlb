/* rlb_http_filter.c Jason Armstrong <ja@riverdrums.com> � 2006 RIVERDRUMS
 * $ gcc -DRLB_SO -Wall -O2 -I. -fPIC -shared -o filter.so rlb_http_filter.c
 * $Id$ */

#include <rlb.h>
#include <ctype.h>

/**
 * This shared object filter is intended to be used with rlb as a 
 * front-end to a cluster of web servers.
 */


/***********************************
 **  USER CONFIGURABLE VARIABLES  **
 ***********************************/

/**
 * Change this variable to the public name (or IP address) and port 
 * of the machine running rlb. It is used in 'Location' headers, to
 * replace the address of the backend server with the address of the
 * load balancer itself. It is used when filtering data from the
 * server back to the client, for example in 302 replies (Location). 
 * Comment this line out if you don't require this, but note that 
 * this could cause the client to try to bypass your load balancer ...
 */
#define RLB_HERE   "192.168.10.100:8000"  /**< Change to the address and port running rlb */


/**
 * This variable is substituted in the 'Host' and 'Referer' headers
 * sent to the backend server. It is called when filtering data
 * from the client to the server.
 * If the public name of the load balancing machine is the same 
 * as the name of the website, then you can comment this line out.
 */
#define RLB_HOST   "www.riverdrums.com"  /**< Host header and Referer */


/**
 * If you have a separate image server, define that here. All URLs that
 * have RLB_IMAGE_STRING in the first 32 bytes of the request will be 
 * redirected to this server.
 * Comment the first line out if you don't want this
 */
#define RLB_IMAGE_SERVER  "192.168.10.102"
#define RLB_IMAGE_PORT    "82"        /**< Port on image server */
#define RLB_IMAGE_STRING  "thumbs"    /**< What to look for in the URL */


/**
 * Where to log to. Make sure that there are sufficient permissions on this
 * file if you set either of the 'user' or 'jail' options for rlb.
 */
#define LOGFILE     "access_log"      /**< Logfile */


/**
 * If you want to replace the 'Server: ' line with a customised value, then
 * edit and uncomment the following line. Used when filtering data from the
 * server back to the client.
 */
#define RLB_SERVER_HDR  "Riverdrums Load Balancer"


/**
 * Uncomment this to see header information in both directions, but 
 * you need to run rlb with the -f option.
 */
//#define RLB_FILTER_DEBUG


/****************************************
 ** END OF USER CONFIGURABLE VARIABLES **
 ****************************************/


/**
 * Header field to look for
 */

#define LOCATION    "Location: http://"

/**
 * Data that we extract from a request. 
 *
 *  - request     : GET /index.html HTTP/1.1
 *  - user_agent  : Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20050922 Firefox/1.0.7 (Debian package 1.0.7-1)
 *  - referer     : http://riverdrums.com/test.html
 *  - code        : Code returned by server (eg 200)
 *  - size        : Size of data returned
 *
 *  Because we can never be sure when all the data from the server
 *  has been written to the client, we log both on incoming data
 *  from the client to the server, and when the connection is closed.
 */
struct request {
  char request[256], user_agent[256], referer[256];
  int code;
  unsigned int size;
};

/**
 * Data structure persistent whilst rlb is running
 */
struct rlbfilter {
  FILE *f;            /**< Logfile handle, kept open for the whole process */
  struct server *s;   /**< Our own custom servers */
  int si;             /**< Number of servers */
};

/* API Function declarations */
int   rlb_init(struct cfg *cfg);
void  rlb_cleanup(struct cfg *cfg);
int   rlb_filter(struct connection *c, int r);
int   rlb_close(struct connection *c);
void  rlb_get_server(struct connection *c);

/* Internal function declarations */
void  _log(struct cfg *cfg, struct connection *c);
int   _move(struct connection *c, char *start, char *end, char *insert, int len);
char *_strnstr(char *str, char *find, int hl);
void  _add_server(struct rlbfilter *rlbf, char *host, char *port);
struct request *  _request(char *buf, int len);
struct addrinfo * _get_addrinfo(char *h, char *p);

/**
 * Startup code. Store a global file pointer to the logfile. 
 * Initialise our own set of servers.
 */
int rlb_init(struct cfg *cfg) 
{
  struct rlbfilter *rlbf = calloc(1, sizeof(struct rlbfilter));
  if (rlbf) {
    cfg->userdata = (void *) rlbf;
    if ( (rlbf->f = fopen(LOGFILE, "a+")) == NULL) {
      char pwd[256];
      fprintf(stderr, "(%s)|%s: %s\n", getcwd(pwd, sizeof(pwd)), LOGFILE, strerror(errno));
    }
#ifdef RLB_IMAGE_SERVER
    _add_server(rlbf, RLB_IMAGE_SERVER, RLB_IMAGE_PORT);
#endif
  }
  return rlbf ? 0 : -1;
}


/**
 * Add a server to our own server structure
 */
void _add_server(struct rlbfilter *rlbf, char *host, char *port)
{
  struct server *sv = NULL, *s = NULL;
  int r, rc, fd;
  struct addrinfo *a;
  if ( !(sv = realloc(rlbf->s, (rlbf->si + 1) * sizeof(struct server))) ) return;
  rlbf->s = sv; s = &sv[rlbf->si]; memset(s, 0, sizeof(struct server));
  if ( !(s->ai = a = _get_addrinfo(host, port)) ) return; rlbf->si++;
  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) return;
  do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
  do { rc = close(fd); } while (rc == -1 && errno == EINTR);
  if (!r) { s->status = 1; s->last = 0; s->num = 0; }
  else    { s->status = 0; s->last = time(NULL); }
}


/**
 * Close the logfile if needed. Free server and data structures.
 */
void rlb_cleanup(struct cfg *cfg) 
{
  struct rlbfilter *rlbf = (struct rlbfilter *) cfg->userdata;
  if (rlbf) {
    if (rlbf->f) fclose(rlbf->f);
    if (rlbf->s) free(rlbf->s);
    free(rlbf);
  }
}

/**
 * Filter data in both directions.
 *  
 *  - RLB_CLIENT: Rewrite the 'Host' and 'Referer' headers, and 
 *                extract data from the request that will be
 *                logged at a later point. Redirect traffic to
 *                our custom image server.
 *  - RLB_SERVER: Rewrite the 'Location' header returned from the
 *                server. Extract the server return code, and keep
 *                a running track of the data size being returned.
 */

int rlb_filter(struct connection *c, int r) 
{
  struct cfg *cfg = c->cfg;

  if (c->scope == RLB_CLIENT) {
    struct request *r = NULL;

    /* Rewrite header information */
    if (c->len > 4 &&
         (strncmp(c->b + c->pos, "GET ",  4) == 0 ||
          strncmp(c->b + c->pos, "POST ", 5) == 0 || 
          strncmp(c->b + c->pos, "HEAD ", 5) == 0) ) {
      
      /* Log any previous requests on this connection that haven't been closed */
      _log(cfg, c);

      /* This is guaranteed to work, provided that when we realloc() that we also
       * add one (as in rlb.c) */
      *(c->b + c->pos + c->len) = 0;


#ifdef RLB_HOST
      {
        char *p, *cp;
        int hl = strlen(RLB_HOST);

        /* Rewrite the 'Host: ' header for HTTP/1.1 requests */
        if ( (p = _strnstr(c->b + c->pos, "Host: ", c->len)) && (p += 6) ) {
          if ( (cp = memchr(p, '\n', (c->b + c->pos + c->len) - p)) ) {
            while (isspace(*cp)) cp--; cp++;
            if (_move(c, p, cp, RLB_HOST, hl) < 0) return -1;
          }
        }

        /* Rewrite the 'Referer: http://' header */
        if ( (p = _strnstr(c->b + c->pos, "Referer:", c->len)) && (p += 8) ) {
          if (p + 8 < c->b + c->pos + c->len &&
              strncasecmp(p, " http://", 8) == 0) p += 8;
          if ( (cp = memchr(p, '/', (c->b + c->pos + c->len) - p)) ) {
            if (_move(c, p, cp, RLB_HOST, hl) < 0) return -1;
          }
        }
      }
#endif

      /* 
       * Parse the header and store the information for later logging.
       * We do this after the above two have been rewritten so that
       * our logfiles look correct.
       */
      if ( (r = _request(c->b + c->pos, c->len)) ) {
        c->userdata = (void *) r;
      }

#ifdef RLB_FILTER_DEBUG
      /* Print out any header data */
      *(c->b + c->pos + c->len) = 0;
      printf("\n------\n%s", c->b + c->pos);
      fflush(stdout);
#endif

#ifdef RLB_IMAGE_SERVER
      {
        struct rlbfilter *rlbf = (struct rlbfilter *) cfg->userdata;
        if (_strnstr(c->b + c->pos, RLB_IMAGE_STRING, 32)) {
          c->so_server = &rlbf->s[0];
        } else if (c->server && c->server == &rlbf->s[0]) {
          c->reconnect = 1;
        }
      }
#endif

    }

  } else if (c->scope == RLB_SERVER) {
    /* 
     * The RLB_CLIENT allocates the userdata variable (above), 
     * so we need to look at the 'other' side of the connection 
     * to access the request data 
     */
    struct connection *co = c->od >= 0 ? &cfg->conn[c->od] : NULL;
    struct request *rq    = co ? (struct request *) co->userdata : NULL;

    if (rq) {
      if (c->len > 7 && 
          strncmp(c->b + c->pos, "HTTP/1.", 7) == 0) {
        char *p = memchr(c->b + c->pos, ' ', c->len), *cp2;
        int l = 0;

        *(c->b + c->pos + c->len) = 0;

        /* Find the result code */
        if (p && (cp2 = memchr(++p, ' ', (c->b + c->pos + c->len) - p)) ) {
          *cp2 = 0; rq->code = atoi(p); *cp2 = ' ';
        }

#ifdef RLB_HERE
        /* Modify 'Location' header */
        if ( (p = _strnstr(c->b + c->pos, LOCATION, c->len)) && (p += strlen(LOCATION)) ) {
          char *cp = memchr(p, '/', (c->b + c->pos + c->len) - p);
          if (cp) {
            if (_move(c, p, cp, RLB_HERE, strlen(RLB_HERE)) < 0) return -1;
          }
        }
#endif

#ifdef RLB_SERVER_HDR
        /* Modify the 'Server' header */
        if ( (p = _strnstr(c->b + c->pos, "Server: ", c->len)) && (p += 8) ) {
          char *cp = memchr(p, '\r', (c->b + c->pos + c->len) - p);
          if (!cp) cp = memchr(p, '\n', (c->b + c->pos + c->len) - p);
          if (cp) {
            if (_move(c, p, cp, RLB_SERVER_HDR, strlen(RLB_SERVER_HDR)) < 0) return -1;
          }
        }
#endif

        /* Look for the end of the header */
        if ( ( (p = _strnstr(c->b + c->pos, "\r\n\r\n", c->len)) && (l = 4) ) || 
             ( (p = _strnstr(c->b + c->pos, "\n\n",     c->len)) && (l = 2) ) ) {
#ifdef RLB_FILTER_DEBUG
          char sav = *p;
          *p = '\0';
          printf("======\n%s\n", c->b + c->pos);
          fflush(stdout);
          *p = sav;
#endif
          p += l;

          /* The request size doesn't include the header */
          rq->size = (c->b + c->pos + c->len) - p;
        }

      } else {
        /* Keep counting the data */
        rq->size += r;
      }
    }
  }

  return 0;
}

/**
 * Move data about, allocating more memory if necessary.
 * Note that 1 extra byte is allocated (as in rlb.c) so that
 * requests can always be 0 terminated without affecting the
 * data itself
 */
int _move(struct connection *c, char *start, char *end, char *insert, int len) 
{
  int rest, need;

  /* If they're the same, don't do anything */
  if (strncmp(start, insert, len) == 0 && end - start == len) return 0;
  if (end <= start) return -1;

  rest = c->len - ((end - start) - len);
  need = c->pos + rest;

  /* Do we need more memory */
  if (need > c->bs) {
    char *b = c->b;
    int startpos = start - c->b, endpos = end - c->b;
    if ( (b = (char *) realloc(c->b, need + 1)) ) {
      c->bs = need;
      c->b  = b;
      start = c->b + startpos;
      end   = c->b + endpos;
    } else {
      return -1;
    }
  }

  if (end - start != len) {
    memmove(start + len, end, c->len - (end - (c->b + c->pos)));
  }
  memcpy(start, insert, len);
  c->len -= (end - start) - len;

  return 0;
}

/**
 * Gets called twice when a connection is closed, one for
 * the CLIENT end and once for the SERVER end. However, only
 * the CLIENT connection sets the 'userdata' variable.
 */

int rlb_close(struct connection *c) 
{
  struct cfg *cfg = NULL;

  if (c && (cfg = c->cfg) ) {
    struct request *r = NULL;
    _log(cfg, c);
    /* Only assign this here, as the call to log itself will free the
     * userdata data */
    if ( (r = (struct request *) c->userdata) ) free(r); c->userdata = NULL;
  }

  return 0;
}

/**
 * Log what happened, and release the allocated memory
 */
void
_log(struct cfg *cfg, struct connection *c)
{
  struct request *r = NULL;
  struct rlbfilter *rlbf = NULL;
  
  if (!c || c->scope != RLB_CLIENT) return;
  if ( (r = (struct request *) c->userdata) && (rlbf = (struct rlbfilter *) cfg->userdata) && rlbf->f) {
    char h[64], buf[32], *tf = "%d/%b/%Y:%T %z";
    struct sockaddr *sa = &c->sa;
    time_t t;
    if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), NULL, 0, NI_NUMERICHOST) != 0) *h = 0;
    t = time(NULL); strftime(buf, sizeof(buf) - 1, tf, localtime(&t));
    fprintf(rlbf->f, "%s - - [%s] \"%s\" %d %u \"%s\" \"%s\"\n", 
                      *h ? h : "UNKNOWN", buf, 
                      r->request, r->code, r->size,
                      *r->referer    ? r->referer    : "-",
                      *r->user_agent ? r->user_agent : "-");
    fflush(rlbf->f);
  }
  if (r) free(r); c->userdata = NULL;
}


/**
 * Parse the request header for relevant data
 */

struct request *
_request(char *buf, int len)
{
  int i = 0;
  char *p = buf, rq[256];
  struct request *r = NULL;

  while (*p && i < sizeof(rq) - 1 && p < buf + len && *p != 10 && *p != 13) rq[i++] = *p++;

  if (i && (r = calloc(1, sizeof(struct request))) ) {
    int nl = 0, got = 0;
    char *p2 = NULL, sav;

    memcpy(r->request, rq, i);
    r->request[i] = '\0';

    while (p && *p && p < buf + len) {
      if (*p == 10) nl++; else if (*p != 13) nl = 0;
      if (nl >= 2) break;

      /* Store User-Agent: for logging */
      if (strncasecmp(p, "User-Agent:", 11) == 0) {
        p += 11;
        while (*p && isspace(*p)) p++; if (!*p) break;
        if ( (p2 = strchr(p, '\n')) ) {
          if (*(p2 - 1) == '\r') p2--;
          sav = *p2; *p2 = '\0';
          snprintf(r->user_agent, sizeof(r->user_agent), p);
          p = p2; *p2 = sav; got++;
        }
      } else if (strncasecmp(p, "Referer:", 8) == 0) {
        p += 8;
        while (*p && isspace(*p)) p++; if (!*p) break;
        if ( (p2 = strchr(p, '\n')) ) {
          if (*(p2 - 1) == '\r') p2--;
          sav = *p2; *p2 = '\0';
          snprintf(r->referer, sizeof(r->referer), p);
          p = p2; *p2 = sav; got++;
        }
      }
      if (got == 2) break;
      p++;
    }
  }

  return r;
}


/**
 * Look for a string in another string, but limit the 
 * scope as the 'str' might not be nul terminated
 */

char *
_strnstr(char *str, char *find, int hl)
{
  char *p = str, *end = str + hl;
  int len = strlen(find);

  for (; p < end && len < hl; p++, hl--) {
    if (strncmp(p, find, len) == 0) return p;
  }

  return NULL;
}

/**
 * This could get called:
 *  - If there is no 'delay': after the client connects, before connecting to the server
 *  - With 'delay': After the first read from the client, after any filter, before connecting to the server

void rlb_get_server(struct connection *c)
{
  if (c->so_server == NULL) {
    struct cfg *cfg = c->cfg;
    struct rlbfilter *rlbf = (struct rlbfilter *) cfg->userdata;
    if (rlbf && rlbf->s) c->so_server = &rlbf->s[0];
  }
}
 */

/**
 * Do what RLB does
 */
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
    fprintf(stderr, "%s - %s\n", *h ? h : "", gai_strerror(r)); 
    if (res) freeaddrinfo(res);
    return NULL; 
  }

  return res;
}
