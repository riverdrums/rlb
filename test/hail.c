/* hail.c Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#include "common.h"

int  _hail(int forks, char *host, char *port, int timeout);
void _do_hail(struct addrinfo *a, int timeout);

int main(int argc, char *argv[]) {
  if (argc < 4) _usage("hail");
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);
  return _hail(atoi(argv[1]), argv[2], argv[3], argc == 4 ? TIMEOUT : atoi(argv[4]));
}

int _hail(int forks, char *host, char *port, int timeout)
{
  struct addrinfo *ai = _get_addrinfo(host, port);
  if (!ai) return -1;
  while (forks--) {
    if (fork() == 0) {
      do { _do_hail(ai, timeout); } while (1);
      exit(0);
    }
  }
  return 0;
}

void _do_hail(struct addrinfo *a, int timeout)
{
  char *one = "*";
  int fd, r, on = 1;

  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) >= 0) {
    on = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    on = 1024; setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &on, sizeof(on));
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r == 0) {
      if (writen(fd, "GET /", 5, timeout) == 5) {
        do { r = writen(fd, &one[0], 1, timeout); } while (r > 0);
      }
    }
    do { r = close(fd); } while (r == -1 && errno == EINTR);
  }
}

