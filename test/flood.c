/* flood.c Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#include "common.h"

int  _flood(int forks, char *host, char *port);
void _do_flood(struct addrinfo *a);

int main(int argc, char *argv[]) {
  if (argc < 4) _usage("flood");
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);
  return _flood(atoi(argv[1]), argv[2], argv[3]);
}

int _flood(int forks, char *host, char *port)
{
  struct addrinfo *ai = _get_addrinfo(host, port);
  if (!ai) return -1;
  while (forks--) {
    if (fork() == 0) {
      do { _do_flood(ai); } while (1);
      exit(0);
    }
  }
  return 0;
}

void _do_flood(struct addrinfo *a)
{
  int fd, r;
  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) >= 0) {
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    do { r = close(fd); } while (r == -1 && errno == EINTR);
  }
}
