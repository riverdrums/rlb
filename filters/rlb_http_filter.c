/* rlb_http_filter.c Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#include <rlb.h>
#include <ctype.h>


/**
 *   HTTP CONTENT FILTER
 *   ===================
 *
 *  This shared object filter is intended to be used with 
 *  rlb as a front-end to a cluster of web servers.
 *
 *  Load at startup with the -o option to rlb: 
 *
 *    $ rlb [other options] -o /path/to/rlb_http_filter.so
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
#define RLB_HERE          "192.168.10.100:8000"  /**< Change to the address and port running rlb */


/**
 * This variable is substituted in the 'Host' and 'Referer' headers
 * sent to the backend server. It is called when filtering data
 * from the client to the server.
 * If the public name of the load balancing machine is the same 
 * as the name of the website, then you can comment this line out.
 */
#define RLB_HOST          "www.riverdrums.com"  /**< Host header and Referer */


/**
 * If you have a separate image server, define that here. All URLs that
 * have RLB_IMAGE_STRING in the first 32 bytes of the request will be 
 * redirected to this server.
 * Comment the first line out if you don't want this
 */
//#define RLB_IMAGE_SERVER  "192.168.10.102"
#define RLB_IMAGE_PORT    "82"                  /**< Port on image server */
#define RLB_IMAGE_STRING  "thumbs"              /**< What to look for in the URL */


/**
 * Where to log to. Make sure that there are sufficient permissions on this
 * file if you set either of the 'user' (-u) or 'jail' (-j) options to rlb.
 * Comment this line out if you don't want to log anything
 */
#define RLB_LOGFILE       "access_log"


/**
 * If you want to replace the 'Server: ' line with a customised value, then
 * edit the following line. Used when filtering data from the server back to
 * the client. 
 * Comment this line out if you just want to send back the Server signature of
 * your backend webservers.
 */
#define RLB_SERVER_HDR    "Riverdrums Load Balancer"


/**
 * Uncomment this to see header information in both directions, but 
 * you need to run rlb with the -f option.
 */
// #define RLB_FILTER_DEBUG


/****************************************
 ** END OF USER CONFIGURABLE VARIABLES **
 ****************************************/



/**
 * Write back to client without connecting to the cluster
 */

#define NOTALLOWED "\
HTTP/1.0 501 Not Implemented\r\n\
Server: Riverdrums Load Balancer " RLB_VERSION "\r\n\
Allow: GET, HEAD\r\n\
Connection: close\r\n\
\r\n\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n\
<HTML>\r\n\
  <HEAD>\r\n\
    <TITLE>501 Not Implemented</TITLE>\r\n\
    <META name='Server' value='RLB-" RLB_VERSION "' />\r\n\
  </HEAD>\r\n\
  <BODY>\r\n\
    <H1>501 Not Implemented</H1>\r\n\
    <HR size='1' color='black' width='10%%' align='left' />\r\n\
    <ADDRESS>\r\n\
      <A href='http://rlb.sourceforge.net'>Riverdrums Load Balancer</A>\r\n\
    </ADDRESS>\r\n\
  </BODY>\r\n\
</HTML>\r\n"


/*********************
 ** DATA STRUCTURES **
 *********************/

/**
 * Data that we extract from a request. 
 *
 *  - request     : GET /index.html HTTP/1.1
 *  - user_agent  : Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)
 *  - referer     : http://riverdrums.com/test.html
 *  - code        : Code returned by server (eg 200)
 *  - size        : Size of data returned
 *
 *  Because we can never be sure when all the data from the server
 *  has been written to the client, we log both on incoming data
 *  from the client to the server, and when the connection is closed.
 */

#define RLB_REQUEST_SIZE 512
struct request {
  char request[RLB_REQUEST_SIZE],
       user_agent[256],
       referer[256];
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
int   rlb_init(struct cfg *cfg, void **data);
void  rlb_cleanup(struct cfg *cfg, void **data);
int   rlb_filter(struct connection *c, int r, void *data);
int   rlb_close(struct connection *c, void *data);


/* Internal function declarations */
struct request *  _rlbf_request(char *buf, int len);
char * _rlbf_extract(char *buf, char *find, int len, char *dst, int dlen);
void  _rlbf_log(struct connection *c, void *data);
void  _rlbf_add_server(struct rlbfilter *rlbf, char *host, char *port);



/*************************
 **    API FUNCTIONS    **
 *************************/

/**
 * Startup code. Store a global file pointer to the logfile. 
 * Initialise our own set of servers if required.
 */

int rlb_init(struct cfg *cfg, void **data)
{
  struct rlbfilter *rlbf = calloc(1, sizeof(*rlbf));

  if (rlbf) {
    *data = rlbf;

#ifdef RLB_LOGFILE
    if ( (rlbf->f = fopen(RLB_LOGFILE, "a+")) == NULL) {
      char pwd[256];
      fprintf(stderr, "(%s)|%s: %s\n", getcwd(pwd, sizeof(pwd)), RLB_LOGFILE, strerror(errno));
    }
#endif

#ifdef RLB_IMAGE_SERVER
    _rlbf_add_server(rlbf, RLB_IMAGE_SERVER, RLB_IMAGE_PORT);
#endif

  }

  return rlbf ? 0 : -1;
}


/**
 * Close the logfile if needed. Free server and data structures.
 */

void rlb_cleanup(struct cfg *cfg, void **data)
{
  struct rlbfilter *rlbf = *data;

  if (rlbf) {
    if (rlbf->f) {
      fclose(rlbf->f);
    }

    if (rlbf->s) {
      free(rlbf->s);
    }

    free(rlbf);
    *data = NULL;
  }
}


/**
 * Filter data in both directions.
 *  
 *  - RLB_CLIENT: Rewrite the 'Host' and 'Referer' headers, and 
 *                extract data from the request that will be
 *                logged at a later point. Redirect traffic to
 *                our custom image server.
 *                Note that we only support GET POST and HEAD requests
 *                to our servers, you might want to add further methods
 *                such as PROPFIND, CONNECT &c
 *
 *  - RLB_SERVER: Rewrite the 'Location' header returned from the
 *                server. Extract the server return code, and keep
 *                a running track of the data size being returned.
 */

int rlb_filter(struct connection *c, int r, void *data)
{
  struct cfg *cfg = c->cfg;
  struct buffer *b = c->rb;

  if (!b) {
    return -1;
  }

  if (c->scope == RLB_CLIENT) {
    struct request *rq = NULL;

    /* Rewrite header information */
    if (b->len > 4 &&
         (strncmp(b->b + b->pos, "GET ",  4) == 0 ||
          strncmp(b->b + b->pos, "POST ", 5) == 0 || 
          strncmp(b->b + b->pos, "HEAD ", 5) == 0) ) {
      
#ifdef RLB_LOGFILE
      /* Log any previous requests on this connection that haven't been closed */
      _rlbf_log(c, data);
#endif

      /* This is guaranteed to work, provided that when we realloc() that we also
       * add one (as in rlb.c) */
      *(b->b + b->pos + b->len) = '\0';


#ifdef RLB_HOST
      {
        char *p, *cp;
        int hl = strlen(RLB_HOST);

        /* Rewrite the 'Host: ' header for HTTP/1.1 requests */
        if ( (p = rlb_strnstr(b->b + b->pos, "Host: ", b->len)) && (p += 6) ) {
          if ( (cp = memchr(p, '\n', (b->b + b->pos + b->len) - p)) ) {
            while (isspace(*cp)) {
              cp--;
            }

            cp++;

            if (rlb_str_insert(c, p, cp, RLB_HOST, hl) < 0) {
              return -1;
            }
          }
        }

        /* Rewrite the 'Referer: http://' header */
        if ( (p = rlb_strnstr(b->b + b->pos, "Referer:", b->len)) && (p += 8) ) {
          if (p + 8 < b->b + b->pos + b->len && strncasecmp(p, " http://", 8) == 0) {
            p += 8;
          }

          if ( (cp = memchr(p, '/', (b->b + b->pos + b->len) - p)) ) {
            if (rlb_str_insert(c, p, cp, RLB_HOST, hl) < 0) {
              return -1;
            }
          }
        }
      }
#endif


#ifdef RLB_LOGFILE
      /* 
       * Parse the header and store the information for later logging.
       * We do this after the above two have been rewritten so that
       * our logfiles look correct.
       */

      if ( (rq = _rlbf_request(b->b + b->pos, b->len)) ) {
        c->userdata[cfg->cf] = rq;
      }
#endif


#ifdef RLB_FILTER_DEBUG
      /* Print out any header data */
      *(b->b + b->pos + b->len) = '\0';
      printf("\n------\n%s", b->b + b->pos);
      fflush(stdout);
#endif


#ifdef RLB_IMAGE_SERVER
      {
        struct rlbfilter *rlbf = data;

        if (rlb_strnstr(b->b + b->pos, RLB_IMAGE_STRING, 32)) {
          /* This tells rlb to reconnect to the image server */
          c->so_server = &rlbf->s[0];

        } else if (c->server && c->server == &rlbf->s[0]) {
          /* Tells rlb to reconnect to the original server (ie not the image server) */
          c->reconnect = 1;
        }

      }
#endif

    } else if (c->nr - r == 0) {

      /* 
       * 501 Not Implemented 
       *  This will tell rlb to write the data buffer (c->wb) straight back to
       *  the client and disconnect. If we have used the -d (delay) option to rlb
       *  then no connection to the cluster will have been made.
       */

      snprintf(b->b, b->bs, NOTALLOWED);
      b->len = strlen(b->b); 
      c->wb = c->rb;
      b->pos = 0;
      return 1;
    }

  } else if (c->scope == RLB_SERVER) {
    /* 
     * The RLB_CLIENT allocates the userdata variable (above), 
     * so we need to look at the 'other' side of the connection 
     * to access the request data 
     */
    struct connection *co = c->od >= 0 ? &cfg->conn[c->od] : NULL;
    struct request *rq    = co ? co->userdata[cfg->cf] : NULL;

    if (rq) {
      if (b->len > 7 && 
          strncmp(b->b + b->pos, "HTTP/1.", 7) == 0) {
        char *p = memchr(b->b + b->pos, ' ', b->len), *cp2;
        int l = 0;

        *(b->b + b->pos + b->len) = '\0';

        /* Find the result code */
        if (p && (cp2 = memchr(++p, ' ', (b->b + b->pos + b->len) - p)) ) {
          *cp2 = '\0';
          rq->code = atoi(p);
          *cp2 = ' ';
        }

#ifdef RLB_HERE
        /* Modify 'Location' header */
        if ( (p = rlb_strnstr(b->b + b->pos, "Location: http://", b->len)) && (p += 17) ) {
          char *cp = memchr(p, '/', (b->b + b->pos + b->len) - p);
          if (cp) {
            if (rlb_str_insert(c, p, cp, RLB_HERE, strlen(RLB_HERE)) < 0) {
              return -1;
            }
          }
        }
#endif

#ifdef RLB_SERVER_HDR
        /* Modify the 'Server' header */
        if ( (p = rlb_strnstr(b->b + b->pos, "Server: ", b->len)) && (p += 8) ) {
          char *cp = memchr(p, '\r', (b->b + b->pos + b->len) - p);

          if (cp == NULL) {
            cp = memchr(p, '\n', (b->b + b->pos + b->len) - p);
          }

          if (cp) {
            if (rlb_str_insert(c, p, cp, RLB_SERVER_HDR, strlen(RLB_SERVER_HDR)) < 0) {
              return -1;
            }
          }
        }
#endif

        /* Look for the end of the header */
        if ( ( (p = rlb_strnstr(b->b + b->pos, "\r\n\r\n", b->len)) && (l = 4) ) || 
             ( (p = rlb_strnstr(b->b + b->pos, "\n\n",     b->len)) && (l = 2) ) ) {
#ifdef RLB_FILTER_DEBUG
          char sav = *p;
          *p = '\0';
          printf("======\n%s\n\n", b->b + b->pos);
          fflush(stdout);
          *p = sav;
#endif
          p += l;

          /* The request size doesn't include the header */
          rq->size = (b->b + b->pos + b->len) - p;
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
 * Gets called twice when a connection is closed, one for
 * the CLIENT end and once for the SERVER end. However, only
 * the CLIENT connection sets the 'userdata' variable.
 */

int rlb_close(struct connection *c, void *data)
{
#ifdef RLB_LOGFILE
  if (c && c->scope == RLB_CLIENT) {
    _rlbf_log(c, data);
  }
#endif

  return 0;
}



/**************************
 **  INTERNAL FUNCTIONS  **
 **************************/

/**
 * Add a server to our own server structure. This gets tricky :-) sometimes
 * because the rlb interface isn't fully clear. For example, client tracking to
 * customised backend servers isn't supported within the rlb engine.
 */

void _rlbf_add_server(struct rlbfilter *rlbf, char *host, char *port)
{
  struct server *sv = NULL, *s = NULL;
  struct addrinfo *a;
  int r, rc, fd;

  if ( (sv = realloc(rlbf->s, (rlbf->si + 1) * sizeof(*sv))) == NULL) {
    return;
  }

  rlbf->s = sv; 
  s = &sv[rlbf->si]; 
  memset(s, 0, sizeof(*s));

  if ( (s->ai = a = rlb_get_addrinfo(host, port)) == NULL) {
    return; 
  }

  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) < 0) {
    return;
  }

  rlbf->si++;

  do { 
    r = connect(fd, a->ai_addr, a->ai_addrlen); 
  } while (r == -1 && errno == EINTR);

  do { 
    rc = close(fd); 
  } while (rc == -1 && errno == EINTR);

  s->status = !r;
  s->last   = r ? time(NULL) : 0;
}


/**
 * Log what happened, and release the allocated memory
 */

void _rlbf_log(struct connection *c, void *data)
{
  struct request *r = NULL;
  struct rlbfilter *rlbf = NULL;
  
  if (c == NULL || c->scope != RLB_CLIENT) {
    return;
  }

  if ( (r = c->userdata[c->cfg->cf]) && (rlbf = data) && rlbf->f) {
    char h[64], buf[32], *tf = "%d/%b/%Y:%T %z";
    struct sockaddr *sa = &c->sa;
    time_t t;

    if (getnameinfo(sa, sizeof(*sa), h, sizeof(h), NULL, 0, NI_NUMERICHOST) != 0) {
      *h = '\0';
    }

    t = time(NULL); 
    strftime(buf, sizeof(buf) - 1, tf, localtime(&t));

    fprintf(rlbf->f, "%s - - [%s] \"%s\" %d %u \"%s\" \"%s\"\n", 
                      *h ? h : "UNKNOWN", buf, 
                      r->request, r->code, r->size,
                      *r->referer    ? r->referer    : "-",
                      *r->user_agent ? r->user_agent : "-");
    fflush(rlbf->f);
  }

  if (r) {
    free(r);
  }

  c->userdata[c->cfg->cf] = NULL;
}


/**
 * Parse the request header for relevant data
 */

struct request * _rlbf_request(char *buf, int len)
{
  int i = 0;
  char *p = buf, rq[RLB_REQUEST_SIZE];
  struct request *r = NULL;

  while (*p && i < RLB_REQUEST_SIZE - 1 && p < buf + len && *p != '\n' && *p != '\r') {
    rq[i++] = *p++;
  }

  if (i && (r = calloc(1, sizeof(*r))) ) {
    int nl = 0, got = 0;
    char *p2 = NULL;

    memcpy(r->request, rq, i);
    r->request[i] = '\0';

    while (*p && p < buf + len) {

      if (*p == '\n') {
        nl++;
      } else if (*p != '\r') {
        nl = 0;
      }

      if (nl >= 2) {
        break;
      }

      /* Store User-Agent and Referer for logging */
      if ( (p2 = _rlbf_extract(p, "User-Agent:", 11, r->user_agent, sizeof(r->user_agent))) ||
           (p2 = _rlbf_extract(p, "Referer:", 8, r->referer, sizeof(r->referer))) ) {
        got++;
        p = p2;
      }

      if (got == 2) {
        break;
      }

      p++;
    }
  }

  return r;
}


/**
 * Copy some information into a destination buffer. Used for extracting
 * user-agent and referer headers into the request data structure.
 */

char * _rlbf_extract(char *buf, char *find, int len, char *dst, int dlen)
{
  char *p = buf;

  if (strncasecmp(p, find, len) == 0) {
    char *p2 = NULL, sav;

    p += len;

    while (*p && isspace(*p)) {
      p++;
    }

    if (!*p) {
      return NULL;
    }

    if ( (p2 = strchr(p, '\n')) ) {
      if (*(p2 - 1) == '\r') {
        p2--;
      }

      sav = *p2; 
      *p2 = '\0';
      snprintf(dst, dlen, p);
      *p2 = sav;
      return p2;
    }
  }

  return NULL;
}
