/* common.c Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#include "common.h"

static int _select(int fd, int max, int writep);

void _usage(char *prog)
{
  printf("usage: %s <forks> <host> <port> [timeout]\n", prog);
  exit(EXIT_SUCCESS);
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
  }

  return r ? NULL : res;
}

int writen(int fd, char *buf, int len, int timeout)
{
  int r = 0, tot = 0;

  while (len > 0) {
    do {
      do { r = _select(fd, timeout, 1); } while (r == -1 && errno == EINTR);
      if (r <= 0) return -1;
      r = write(fd, buf, len);
    } while (r == -1 && (errno == EINTR || errno == EAGAIN) );

    if (r <= 0) return r;
    tot += r; buf += r; len -= r;
  }

  return tot;
}

static int _select(int fd, int max, int writep)
{
  fd_set fds, exceptfds;
  struct timeval timeout;

  FD_ZERO(&fds);
  FD_SET (fd, &fds);

  FD_ZERO(&exceptfds);
  FD_SET (fd, &exceptfds);

  timeout.tv_sec = max;
  timeout.tv_usec = 0;

  return (select (fd + 1, 
                  writep ? NULL : &fds, 
                  writep ? &fds : NULL,
                  &exceptfds, 
                  &timeout));
}
