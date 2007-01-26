/* common.h Jason Armstrong <ja@riverdrums.com> © 2006-2007 RIVERDRUMS
 * $Id$ */

#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>

#define TIMEOUT 30
#define SIZE    (32*1024)

struct addrinfo * _get_addrinfo(char *h, char *p);
int writen(int fd, char *buf, int len, int timeout);
void _usage(char *prog);

#endif
