/* tornado.c Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#include "common.h"

int  _tornado(int forks, char *host, char *port, int timeout);
void _do_tornado(struct addrinfo *a, char *tornado, int timeout);

int main(int argc, char *argv[]) {
  if (argc < 4) _usage("tornado");
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);
  return _tornado(atoi(argv[1]), argv[2], argv[3], argc == 4 ? TIMEOUT : atoi(argv[4]));
}

int _tornado(int forks, char *host, char *port, int timeout)
{
  struct addrinfo *ai = _get_addrinfo(host, port);
  char *tornado = malloc(SIZE * sizeof *tornado);
  if (!ai || !tornado) return -1;
  while (forks--) {
    if (fork() == 0) {
      do { _do_tornado(ai, tornado, timeout); } while (1);
      exit(0);
    }
  }
  return 0;
}

void _do_tornado(struct addrinfo *a, char *tornado, int timeout)
{
  int fd, r, on = 1, len = SIZE;

  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) >= 0) {
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
    setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on));
    on = SIZE; setsockopt(fd, SOL_SOCKET, SO_SNDLOWAT, &on, sizeof(on));
               setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &on, sizeof(on));
               setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &on, sizeof(on));
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r == 0) do { r = writen(fd, tornado, len, timeout); } while (r > 0);
    on = 0; setsockopt(fd, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
    do { r = close(fd); } while (r == -1 && errno == EINTR);
  }
}

