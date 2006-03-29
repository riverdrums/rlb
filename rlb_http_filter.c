/* rlb_http_filter.c Jason Armstrong <ja@riverdrums.com> � 2006 RIVERDRUMS
 * $ gcc -DRLB_SO -Wall -O2 -I. -fPIC -shared -o filter.so rlb_http_filter.c
 * $Id$ */

#include <rlb.h>
#include <ctype.h>


/************************************
 *    USER CONFIGURABLE VARIABLES
 ************************************/

/**
 * Change this variable to the public name (or IP address) and port 
 * of the machine running rlb. It is used in 'Location' headers, to
 * replace the address of the backend server with the address of the
 * load balancer itself. It is used when filtering data from the
 * server back to the client.
 */
#define RLB_HERE   "my.ip.address:80"  /**< Change to the address and port running rlb */

/**
 * This variable is substituted in the 'Host' and 'Referer' headers
 * sent to the backend server. It is called when filtering data
 * from the client to the server.
 * Note that if the public name of the load balancing machine is the same 
 * as the name of the website, then you can comment this line out.
 */
#define RLB_HOST   "riverdrums.com"  /**< Host header and Referer */

/**
 * Where to log to. Make sure that there are sufficient permissions on this
 * file if you set either of the 'user' or 'jail' options for rlb
 */
#define LOGFILE     "access_log"      /**< Logfile */

/************************************
 * END OF USER CONFIGURABLE VARIABLES
 ************************************/


/**
 * Header fields to look for
 */

#define USERAGENT   "User-Agent:"
#define REFERER     "Referer:"
#define LOCATION    "Location: http://"

/**
 * Data that we extract from a request. 
 *
 *  - request     : GET /index.html HTTP/1.1
 *  - user_agent  : 
 *  - referer     : 
 *  - code        : Code returned by server
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

int   rlb_init(struct cfg *cfg);
void  rlb_cleanup(struct cfg *cfg);
int   rlb_filter(struct connection *c, int r);
int   rlb_close(struct connection *c);
int   _request(struct request *r, char *buf, int len);
void  _log(struct cfg *cfg, struct connection *c);
int   _move(struct connection *c, char *start, char *end, char *insert, int len);
char *_strnstr(char *str, char *find, int hl);

/**
 * Startup code. Store a global file pointer to the logfile
 */
int rlb_init(struct cfg *cfg) 
{
  FILE *f = fopen(LOGFILE, "a+");
  if (f) cfg->userdata = (FILE *) f;
  return 0;
}

/**
 * Close the logfile if needed
 */
void rlb_cleanup(struct cfg *cfg) 
{
  FILE *f = (FILE *) cfg->userdata;
  if (f) fclose(f);
}

/**
 * Filter data in both directions.
 *  
 *  - RLB_CLIENT: Rewrite the 'Host' and 'Referer' headers, and 
 *                extract data from the request that will be
 *                logged at a later point.
 *  - RLB_SERVER: Rewrite the 'Location' header returned from the
 *                server. Extract the server return code, and keep
 *                a running track of the data size being returned.
 */

int rlb_filter(struct connection *c, int r) 
{
  struct cfg *cfg = c->cfg;

  if (c->scope == RLB_CLIENT) {
    struct request r, *rr = NULL;

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
        if ( (p = _strnstr(c->b + c->pos, REFERER, c->len)) && (p += strlen(REFERER)) ) {
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
       * our logfiles look ok.
       */
      if (_request(&r, c->b + c->pos, c->len)) {
        rr = (struct request *) malloc(sizeof(struct request));
        memcpy(rr, &r, sizeof(struct request));
        c->userdata = (void *) rr;
      }
    }

  } else if (c->scope == RLB_SERVER) {
    /* 
     * Only the RLB_CLIENT allocates the userdata variable, so we
     * need to look at the 'other' side of the connection to
     * access the request data 
     */
    struct connection *co = &cfg->conn[c->od];
    struct request *rq = (struct request *) co->userdata;

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

        /* Look for the end of the header */
        if ( ( (p = _strnstr(c->b + c->pos, "\r\n\r\n", c->len)) && (l = 4) ) || 
             ( (p = _strnstr(c->b + c->pos, "\n\n", c->len)) && (l = 2) ) ) {
          p += l;
          /* The request size doesn't include the header */
          rq->size = (c->b + c->pos + c->len) - p;
        }

        /* Modify 'Location' header */
        if ( (p = _strnstr(c->b + c->pos, LOCATION, c->len)) && (p += strlen(LOCATION)) ) {
          char *cp = memchr(p, '/', (c->b + c->pos + c->len) - p);
          if (cp) {
            if (_move(c, p, cp, RLB_HERE, strlen(RLB_HERE)) < 0) return -1;
          }
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

  memmove(start + len, end, c->len - (end - (c->b + c->pos)));
  memcpy(start, insert, len);
  c->len -= (end - start) - len;

  return 0;
}

/**
 * Get's called twice when a connection is closed, one for
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
  FILE *f = NULL;
  struct request *r = NULL;
  
  if (!c || c->scope != RLB_CLIENT) return;
  if ( (r = (struct request *) c->userdata) && (f = (FILE *) cfg->userdata) ) {
    char h[64], buf[32], *tf = "%d/%b/%Y:%T %z";
    struct sockaddr *sa = &c->sa;
    time_t t;
    if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), NULL, 0, NI_NUMERICHOST) != 0) *h = 0;
    t = time(NULL); strftime(buf, sizeof(buf) - 1, tf, localtime(&t));
    fprintf(f, "%s - - [%s] \"%s\" %d %u \"%s\" \"%s\"\n", 
                    *h ? h : "UNKNOWN", buf, 
                    r->request, r->code, r->size,
                    *r->referer    ? r->referer    : "-",
                    *r->user_agent ? r->user_agent : "-");
    fflush(f);
    free(r); c->userdata = NULL;
  }
}


/**
 * Parse the request header for relevant data
 */

int
_request(struct request *r, char *buf, int len)
{
  int i = 0;
  char *p = buf;

  memset(r, 0, sizeof(struct request));
  while (*p && i < sizeof(r->request) - 1 && p < buf + len && *p != 10 && *p != 13) r->request[i++] = *p++;
  r->request[i] = *r->referer = *r->user_agent = 0;

  if (i) {
    int ul = strlen(USERAGENT), rl = strlen(REFERER), nl = 0;
    char *p2 = NULL, sav;

    while (p && *p && p < buf + len) {
      if (*p == 10) nl++; else if (*p != 13) nl = 0;
      if (nl >= 2) break;

      /* Store User-Agent: for logging */
      if (strncasecmp(p, USERAGENT, ul) == 0) {
        p += ul;
        while (*p && isspace(*p)) p++; if (!*p) break;
        if ( (p2 = strchr(p, '\n')) ) {
          if (*(p2 - 1) == '\r') p2--;
          sav = *p2; *p2 = 0;
          snprintf(r->user_agent, sizeof(r->user_agent), p);
          p = p2; *p2 = sav;
        }
      } else if (strncasecmp(p, REFERER, rl) == 0) {
        p += rl;
        while (*p && isspace(*p)) p++; if (!*p) break;
        if ( (p2 = strchr(p, '\n')) ) {
          if (*(p2 - 1) == '\r') p2--;
          sav = *p2; *p2 = 0;
          snprintf(r->referer, sizeof(r->referer), p);
          p = p2; *p2 = sav;
        }
      }
      p++;
    }
  }

  return i;
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

