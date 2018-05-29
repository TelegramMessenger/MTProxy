/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
    
    Copyright 2014-2016 Telegram Messenger Inc             
                   2016 Vitaly Valtman
*/

#pragma once

#include <netinet/in.h>

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

#define	MAX_EVENTS		(1 << 19)

#define	EVT_READ	4
#define EVT_WRITE	2
#define EVT_SPEC	1
#define	EVT_RW		(EVT_READ | EVT_WRITE)
#define	EVT_RWX		(EVT_READ | EVT_WRITE | EVT_SPEC)
#define EVT_LEVEL	8
#define	EVT_OPEN	0x80
#define EVT_CLOSED	0x40
#define EVT_IN_EPOLL	0x20
#define	EVT_NEW		0x100
#define EVT_NOHUP	0x200
#define EVT_FROM_EPOLL	0x400

#define EVA_CONTINUE	0
#define EVA_RERUN	-2
#define EVA_REMOVE	-3
#define EVA_DESTROY	-5
#define EVA_ERROR	-8
#define EVA_FATAL	-666

#define MAX_UDP_SENDBUF_SIZE	(1L << 24)
#define MAX_UDP_RCVBUF_SIZE	(1L << 24)


typedef struct event_descr event_t;
typedef int (*event_handler_t)(int fd, void *data, event_t *ev);

struct event_descr {
  int fd;
  int state;		// actions that we should wait for (read/write/special) + status
  int ready;		// actions we are ready to do
  int epoll_state;	// current state in epoll()
  int epoll_ready;	// result of epoll()
  int timeout;		// timeout in ms (UNUSED)
  int priority;		// priority (0-9)
  int in_queue;		// position in heap (0=not in queue)
  long long timestamp;
  long long refcnt;
  event_handler_t work;
  void *data;
  //  struct sockaddr_in peer;
};

extern double last_epoll_wait_at;
extern int ev_heap_size;
extern event_t Events[MAX_EVENTS];

extern double tot_idle_time, a_idle_time, a_idle_quotient;

int init_epoll (void);

int remove_event_from_heap (event_t *ev, int allow_hole);
int put_event_into_heap (event_t *ev);
int put_event_into_heap_tail (event_t *ev, int ts_delta);

int epoll_sethandler (int fd, int prio, event_handler_t handler, void *data);
int epoll_fetch_events (int timeout);
int epoll_work (int timeout);
int epoll_insert (int fd, int flags);
int epoll_remove (int fd);
int epoll_close (int fd);

extern int epoll_fd;

//extern volatile unsigned long long pending_signals;
extern volatile int main_thread_interrupt_status;

//int insert_event_timer (event_timer_t *et);
//int remove_event_timer (event_timer_t *et);
//static inline int event_timer_active (event_timer_t *et) { return et->h_idx; }
//static inline void event_timer_init (event_timer_t *et) { et->h_idx = 0;}

#define	PRIVILEGED_TCP_PORTS	1024

extern int tcp_maximize_buffers;
extern struct in_addr settings_addr;

#define SM_UDP	1
#define SM_IPV6	2
#define	SM_IPV6_ONLY	4
#define	SM_LOWPRIO	8
#define SM_REUSE 16
#define	SM_SPECIAL	0x10000
#define	SM_NOQACK	0x20000
#define	SM_RAWMSG	0x40000

int server_socket (int port, struct in_addr in_addr, int backlog, int mode);
int client_socket (in_addr_t in_addr, int port, int mode);
int client_socket_ipv6 (const unsigned char in6_addr_ptr[16], int port, int mode);

void maximize_sndbuf (int sfd, int max);
void maximize_rcvbuf (int sfd, int max);

unsigned get_my_ipv4 (void);
int get_my_ipv6 (unsigned char ipv6[16]);

union sockaddr_in46 {
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
};

static inline int is_4in6 (const unsigned char ipv6[16]) { return !*((long long *) ipv6) && ((int *) ipv6)[2] == -0x10000; }
static inline unsigned extract_4in6 (const unsigned char ipv6[16]) { return (((unsigned *) ipv6)[3]); }
static inline void set_4in6 (unsigned char ipv6[16], unsigned ip) {  *(long long *) ipv6 = 0; ((int *) ipv6)[2] = -0x10000; ((unsigned *) ipv6)[3] = ip; }

const char *conv_addr (in_addr_t a, char *buf);
const char *show_ip (unsigned ip);
const char *conv_addr6 (const unsigned char a[16], char *buf);
const char *show_ipv6 (const unsigned char ipv6[16]);

extern int epoll_sleep_ns;
