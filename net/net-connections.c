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
    
    Copyright 2014      Telegram Messenger Inc             
              2014      Nikolai Durov
              2014      Andrey Lopatin

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#define        _FILE_OFFSET_BITS        64

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "crc32.h"
#include "jobs/jobs.h"
#include "net/net-events.h"
//#include "net/net-buffers.h"
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "net/net-connections.h"
#include "net/net-config.h"
#include "vv/vv-io.h"
#include "vv/vv-tree.h"
#include "pid.h"
#include "common/mp-queue.h"

#include "net/net-msg-buffers.h"
#include "net/net-tcp-connections.h"

#include "common/common-stats.h"

//struct process_id PID;

#define        USE_EPOLLET        1
#define        MAX_RECONNECT_INTERVAL        20

#define MODULE connections

static int max_accept_rate;
static double cur_accept_rate_remaining;
static double cur_accept_rate_time;
static int max_connection;
static int conn_generation;
static int max_connection_fd = MAX_CONNECTIONS;

int active_special_connections, max_special_connections = MAX_CONNECTIONS;

int special_listen_sockets;

static struct {
  int fd, generation;
} special_socket[MAX_SPECIAL_LISTEN_SOCKETS];

static struct mp_queue *free_later_queue;


MODULE_STAT_TYPE {
int active_connections, active_dh_connections;
int outbound_connections, active_outbound_connections, ready_outbound_connections, listening_connections;
int allocated_outbound_connections, allocated_inbound_connections;
int inbound_connections, active_inbound_connections;

long long outbound_connections_created, inbound_connections_accepted;
int ready_targets;

long long netw_queries, netw_update_queries, total_failed_connections, total_connect_failures, unused_connections_closed;

int allocated_targets, active_targets, inactive_targets, free_targets;
int allocated_connections, allocated_socket_connections;
long long accept_calls_failed, accept_nonblock_set_failed, accept_connection_limit_failed,
          accept_rate_limit_failed, accept_init_accepted_failed;

long long tcp_readv_calls, tcp_writev_calls, tcp_readv_intr, tcp_writev_intr;
long long tcp_readv_bytes, tcp_writev_bytes;

int free_later_size;
long long free_later_total;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_I (active_connections);
  SB_SUM_ONE_I (active_dh_connections);
  
  SB_SUM_ONE_I (outbound_connections);
  SB_SUM_ONE_I (ready_outbound_connections); 
  SB_SUM_ONE_I (active_outbound_connections); 
  SB_SUM_ONE_LL (outbound_connections_created);
  SB_SUM_ONE_LL (total_connect_failures);
  
  SB_SUM_ONE_I (inbound_connections);
  //SB_SUM_ONE_I (ready_inbound_connections); 
  SB_SUM_ONE_I (active_inbound_connections); 
  SB_SUM_ONE_LL (inbound_connections_accepted);

  SB_SUM_ONE_I (listening_connections);
  SB_SUM_ONE_LL (unused_connections_closed);
  SB_SUM_ONE_I (ready_targets);
  SB_SUM_ONE_I (allocated_targets);
  SB_SUM_ONE_I (active_targets);
  SB_SUM_ONE_I (inactive_targets);
  SB_SUM_ONE_I (free_targets);
  sb_printf (sb,
    "max_connections\t%d\n"
    "active_special_connections\t%d\n"
    "max_special_connections\t%d\n"
    ,
    max_connection_fd,
    active_special_connections,
    max_special_connections
    );
  SBP_PRINT_I32(max_accept_rate);
  SBP_PRINT_DOUBLE(cur_accept_rate_remaining);
  SBP_PRINT_I32(max_connection);
  SBP_PRINT_I32(conn_generation);

  SB_SUM_ONE_I (allocated_connections);
  SB_SUM_ONE_I (allocated_outbound_connections);
  SB_SUM_ONE_I (allocated_inbound_connections);
  SB_SUM_ONE_I (allocated_socket_connections);
  SB_SUM_ONE_LL (tcp_readv_calls);
  SB_SUM_ONE_LL (tcp_readv_intr);
  SB_SUM_ONE_LL (tcp_readv_bytes);
  SB_SUM_ONE_LL (tcp_writev_calls);
  SB_SUM_ONE_LL (tcp_writev_intr);
  SB_SUM_ONE_LL (tcp_writev_bytes);
  SB_SUM_ONE_I (free_later_size);
  SB_SUM_ONE_LL (free_later_total);

  SB_SUM_ONE_LL (accept_calls_failed);
  SB_SUM_ONE_LL (accept_nonblock_set_failed);
  SB_SUM_ONE_LL (accept_connection_limit_failed);
  SB_SUM_ONE_LL (accept_rate_limit_failed);
  SB_SUM_ONE_LL (accept_init_accepted_failed);
MODULE_STAT_FUNCTION_END

void fetch_connections_stat (struct connections_stat *st) {
#define COLLECT_I(__x)        st->__x = SB_SUM_I (__x);
#define COLLECT_LL(__x)        st->__x = SB_SUM_LL (__x);
  COLLECT_I (active_connections);
  COLLECT_I (active_dh_connections);
  COLLECT_I (outbound_connections);
  COLLECT_I (active_outbound_connections);
  COLLECT_I (ready_outbound_connections);
  st->max_special_connections = max_special_connections;
  st->active_special_connections = active_special_connections;
  COLLECT_I (allocated_connections);
  COLLECT_I (allocated_outbound_connections);
  COLLECT_I (allocated_inbound_connections);
  COLLECT_I (allocated_socket_connections);
  COLLECT_I (allocated_targets);
  COLLECT_I (ready_targets);
  COLLECT_I (active_targets);
  COLLECT_I (inactive_targets);
  COLLECT_LL (tcp_readv_calls);
  COLLECT_LL (tcp_readv_intr);
  COLLECT_LL (tcp_readv_bytes);
  COLLECT_LL (tcp_writev_calls);
  COLLECT_LL (tcp_writev_intr);
  COLLECT_LL (tcp_writev_bytes);
  COLLECT_LL (accept_calls_failed);
  COLLECT_LL (accept_nonblock_set_failed);
  COLLECT_LL (accept_rate_limit_failed);
  COLLECT_LL (accept_init_accepted_failed);
  COLLECT_LL (accept_connection_limit_failed);
#undef COLLECT_I
#undef COLLECT_LL
}

void connection_event_incref (int fd, long long val);

void tcp_set_max_accept_rate (int rate) {
  max_accept_rate = rate;
}

int set_write_timer (connection_job_t C);

int prealloc_tcp_buffers (void);
int clear_connection_write_timeout (connection_job_t c);

static int tcp_recv_buffers_num;
static int tcp_recv_buffers_total_size;
static struct iovec tcp_recv_iovec[MAX_TCP_RECV_BUFFERS + 1];
static struct msg_buffer *tcp_recv_buffers[MAX_TCP_RECV_BUFFERS];

int prealloc_tcp_buffers (void) /* {{{ */ {
  assert (!tcp_recv_buffers_num);   

  int i;
  for (i = MAX_TCP_RECV_BUFFERS - 1; i >= 0; i--) {
    struct msg_buffer *X = alloc_msg_buffer ((tcp_recv_buffers_num) ? tcp_recv_buffers[i + 1] : 0, TCP_RECV_BUFFER_SIZE);
    if (!X) {
      vkprintf (0, "**FATAL**: cannot allocate tcp receive buffer\n");
      exit (2);
    }
    vkprintf (3, "allocated %d byte tcp receive buffer #%d at %p\n", X->chunk->buffer_size, i, X);
    tcp_recv_buffers[i] = X;
    tcp_recv_iovec[i + 1].iov_base = X->data;
    tcp_recv_iovec[i + 1].iov_len = X->chunk->buffer_size;
    ++ tcp_recv_buffers_num;
    tcp_recv_buffers_total_size += X->chunk->buffer_size;
  }
  return tcp_recv_buffers_num;
}
/* }}} */

int tcp_prepare_iovec (struct iovec *iov, int *iovcnt, int maxcnt, struct raw_message *raw) /* {{{ */ {
  int t = rwm_prepare_iovec (raw, iov, maxcnt, raw->total_bytes);
  if (t < 0) {
    *iovcnt = maxcnt;
    int i;
    t = 0;
    for (i = 0; i < maxcnt; i++) {
      t += iov[i].iov_len;
    }
    assert (t < raw->total_bytes);
    return t;
  } else {
    *iovcnt = t;
    return raw->total_bytes;
  }
}
/* }}} */

void assert_main_thread (void) {}
void assert_net_cpu_thread (void) {}
void assert_net_net_thread (void) {}
void assert_engine_thread (void) {
  assert (this_job_thread && (this_job_thread->thread_class == JC_ENGINE || this_job_thread->thread_class == JC_MAIN));
}

socket_connection_job_t alloc_new_socket_connection (connection_job_t C);

#define X_TYPE connection_job_t
#define X_CMP(a,b) (((a) < (b)) ? -1 : ((a) > (b)) ? 1 : 0)
#define TREE_NAME connection
#define TREE_MALLOC
#define TREE_PTHREAD
#define TREE_INCREF job_incref
#define TREE_DECREF job_decref_f
#include "vv/vv-tree.c"

static inline int connection_is_active (int flags) {
  return (flags & C_CONNECTED) && !(flags & C_READY_PENDING);
}

/* {{{ compute_conn_events */
#if USE_EPOLLET
static inline int compute_conn_events (socket_connection_job_t c) {
  unsigned flags = SOCKET_CONN_INFO(c)->flags;
  if (flags & C_ERROR) {
    return 0;
  } else {
    return EVT_READ | EVT_WRITE | EVT_SPEC;
  }
}
#else
static inline int compute_conn_events (connection_job_t c) {
  unsigned flags = CONN_INFO(c)->flags;
  if (flags & (C_ERROR | C_FAILED | C_NET_FAILED)) {
    return 0;
  }
  return (((flags & (C_WANTRD | C_STOPREAD)) == C_WANTRD) ? EVT_READ : 0) | (flags & C_WANTWR ? EVT_WRITE : 0) | EVT_SPEC 
       | (((flags & (C_WANTRD | C_NORD)) == (C_WANTRD | C_NORD))
         || ((flags & (C_WANTWR | C_NOWR)) == (C_WANTWR | C_NOWR)) ? EVT_LEVEL : 0);
}
#endif
/* }}} */

void connection_write_close (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  if (c->status == conn_working) {
    socket_connection_job_t S = c->io_conn;
    if (S) {
      __sync_fetch_and_or (&SOCKET_CONN_INFO(S)->flags, C_STOPREAD);
    }
    __sync_fetch_and_or (&c->flags, C_STOPREAD);
    c->status = conn_write_close;

    job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);
  }
}
/* }}} */

/* qack {{{ */
static inline void disable_qack (int fd) {
  vkprintf (2, "disable TCP_QUICKACK for %d\n", fd);
  assert (setsockopt (fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, sizeof (int)) >= 0);
}

static inline void cond_disable_qack (socket_connection_job_t C) {
  struct socket_connection_info *c = SOCKET_CONN_INFO (C);
  if (c->flags & C_NOQACK) {
    disable_qack (c->fd);
  }
}
/* }}} */



/* {{{ CPU PART OF CONNECTION */ 

/* {{{ TIMEOUT */
int set_connection_timeout (connection_job_t C, double timeout) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  if (c->flags & C_ERROR) { return 0; }

  __sync_fetch_and_and (&c->flags, ~C_ALARM);
  
  if (timeout > 0) {
    job_timer_insert (C, precise_now + timeout);
    return 0;
  } else {
    job_timer_remove (C);
    return 0;
  }
}
/* }}} */

int clear_connection_timeout (connection_job_t C) /* {{{ */ {
  set_connection_timeout (C, 0);
  return 0;
}
/* }}} */

/* }}} */


/*
  can be called from any thread and without lock
  just sets error code and sends JS_ABORT to connection job
*/
void fail_connection (connection_job_t C, int err) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
    
  if (!(__sync_fetch_and_or (&c->flags, C_ERROR) & C_ERROR)) {
    c->status = conn_error;
    if (c->error >= 0) {
      c->error = err;
    }

    job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
  }
}
/* }}} */

/* 
  just runs ->reader and ->writer virtual methods
*/
int cpu_server_read_write (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  c->type->reader (C);
  c->type->writer (C);
  return 0;
}
/* }}} */

/*
  frees connection structure, including mpq and buffers
*/
int cpu_server_free_connection (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  assert (C->j_refcnt == 1);
  
  struct connection_info *c = CONN_INFO (C);
  if (!(c->flags & C_ERROR)) {
    vkprintf (0, "target = %p, basic=%d\n", c->target, c->basic_type);
  }
  assert (c->flags & C_ERROR);
  assert (c->flags & C_FAILED);
  assert (!c->target);
  assert (!c->io_conn);
 
  vkprintf (1, "Closing connection socket #%d\n", c->fd);

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->out_queue, 4);
    if (!raw) { break; }
    rwm_free (raw);
    free (raw);
  }

  free_mp_queue (c->out_queue);
  c->out_queue = NULL;

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->in_queue, 4);
    if (!raw) { break; }
    rwm_free (raw);
    free (raw);
  }

  free_mp_queue (c->in_queue);
  c->in_queue = NULL;

  if (c->type->crypto_free) {
    c->type->crypto_free (C);
  }
  
  close (c->fd);
  c->fd = -1;
  
  MODULE_STAT->allocated_connections --;
  if (c->basic_type == ct_outbound) {
    MODULE_STAT->allocated_outbound_connections --;
  }
  if (c->basic_type == ct_inbound) {
    MODULE_STAT->allocated_inbound_connections --;
  }

  return c->type->free_buffers (C);
}
/* }}} */

/*
  deletes link to io_conn
  deletes link to target
  aborts pending queries
  updates stats
*/
int cpu_server_close_connection (connection_job_t C, int who) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO(C);
  
  assert (c->flags & C_ERROR);
  assert (c->status == conn_error);
  assert (c->flags & C_FAILED);
    
  if (c->error != -17) {
    MODULE_STAT->total_failed_connections ++;
    if (!connection_is_active (c->flags)) {
      MODULE_STAT->total_connect_failures ++; 
    }
  } else {
    MODULE_STAT->unused_connections_closed ++;
  }

  if (c->flags & C_ISDH) {
    MODULE_STAT->active_dh_connections --;
    __sync_fetch_and_and (&c->flags, ~C_ISDH);
  }

  assert (c->io_conn);
  job_signal (JOB_REF_PASS (c->io_conn), JS_ABORT);

  if (c->basic_type == ct_outbound) {   
    MODULE_STAT->outbound_connections --;

    if (connection_is_active (c->flags)) {
      MODULE_STAT->active_outbound_connections --;
    }

    if (c->target) {
      job_signal (JOB_REF_PASS (c->target), JS_RUN);
    }
  } else {
    MODULE_STAT->inbound_connections --;

    if (connection_is_active (c->flags)) {
      MODULE_STAT->active_inbound_connections --;
    }
  }
  
  if (connection_is_active (c->flags)) {
    MODULE_STAT->active_connections --;
  }

  if (c->flags & C_SPECIAL) {
    c->flags &= ~C_SPECIAL;
    int orig_special_connections = __sync_fetch_and_add (&active_special_connections, -1);
    if (orig_special_connections == max_special_connections) {
      int i;
      for (i = 0; i < special_listen_sockets; i++) {
        connection_job_t LC = connection_get_by_fd_generation (special_socket[i].fd, special_socket[i].generation);
        assert (LC);
        job_signal (JOB_REF_PASS (LC), JS_AUX);
      }
    }
  }
 
  job_timer_remove (C);
  return 0;
}
/* }}} */ 

int do_connection_job (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  connection_job_t C = job;

  struct connection_info *c = CONN_INFO (C);

  if (op == JS_RUN) { // RUN IN NET-CPU THREAD
    assert_net_cpu_thread ();
    if (!(c->flags & C_ERROR)) {
      if (c->flags & C_READY_PENDING) {
        assert (c->flags & C_CONNECTED);
        __sync_fetch_and_and (&c->flags, ~C_READY_PENDING);
        MODULE_STAT->active_outbound_connections ++;        
        MODULE_STAT->active_connections ++;
        if (c->target) {
          __sync_fetch_and_add (&CONN_TARGET_INFO(c->target)->active_outbound_connections, 1);
        }
        if (c->status == conn_connecting) {
          if (!__sync_bool_compare_and_swap (&c->status, conn_connecting, conn_working)) {
            assert (c->status == conn_error);
          }
        }
        c->type->connected (C);
      }
      c->type->read_write (C);
    }
    return 0;
  }
  if (op == JS_ALARM) { // RUN IN NET-CPU THREAD
    if (!job_timer_check (job)) {
      return 0;
    }
    if (!(c->flags & C_ERROR)) {
      c->type->alarm (C);
    }
    return 0;
  }
  if (op == JS_ABORT) { // RUN IN NET-CPU THREAD
    assert (c->flags & C_ERROR);
    if (!(__sync_fetch_and_or (&c->flags, C_FAILED) & C_FAILED)) {
      c->type->close (C, 0);
    }
    return JOB_COMPLETED;
  }
  if (op == JS_FINISH) { // RUN IN NET-CPU THREAD
    assert (C->j_refcnt == 1);
    c->type->free (C);
    return job_free (JOB_REF_PASS (C));
  }
  return JOB_ERROR;
}
/* }}} */

/*
  allocates inbound or outbound connection
  runs init_accepted or init_outbound
  updates stats
  creates socket_connection
*/
connection_job_t alloc_new_connection (int cfd, conn_target_job_t CTJ, listening_connection_job_t LCJ, int basic_type, conn_type_t *conn_type, void *conn_extra, unsigned peer, unsigned char peer_ipv6[16], int peer_port) /* {{{ */ {
  if (cfd < 0) {
    return NULL;
  }
  assert_main_thread ();

  struct conn_target_info *CT = CTJ ? CONN_TARGET_INFO (CTJ) : NULL;
  struct listening_connection_info *LC = LCJ ? LISTEN_CONN_INFO (LCJ) : NULL;

  unsigned flags;
  if ((flags = fcntl (cfd, F_GETFL, 0) < 0) || fcntl (cfd, F_SETFL, flags | O_NONBLOCK) < 0) {
    kprintf ("cannot set O_NONBLOCK on accepted socket #%d: %m\n", cfd);
    MODULE_STAT->accept_nonblock_set_failed ++;
    close (cfd);
    return NULL;
  }  
  
  flags = 1;
  setsockopt (cfd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof (flags));
  if (tcp_maximize_buffers) {
    maximize_sndbuf (cfd, 0);
    maximize_rcvbuf (cfd, 0);
  }

  if (cfd >= max_connection_fd) {
    vkprintf (2, "cfd = %d, max_connection_fd = %d\n", cfd, max_connection_fd);
    MODULE_STAT->accept_connection_limit_failed ++;
    close (cfd);
    return NULL;
  }

  if (cfd > max_connection) {
    max_connection = cfd;
  }

  connection_job_t C = create_async_job (do_connection_job, JSC_ALLOW (JC_CONNECTION, JS_RUN) | JSC_ALLOW (JC_CONNECTION, JS_ALARM) | JSC_ALLOW (JC_CONNECTION, JS_ABORT) | JSC_ALLOW (JC_CONNECTION, JS_FINISH), -2, sizeof (struct connection_info), JT_HAVE_TIMER, JOB_REF_NULL);

  struct connection_info *c = CONN_INFO (C);
  //memset (c, 0, sizeof (*c)); /* no need, create_async_job memsets itself */

  c->fd = cfd;
  c->target = CTJ;
  c->generation = new_conn_generation ();
  
  c->flags = 0;//SS ? C_WANTWR : C_WANTRD;
  if (basic_type == ct_inbound) {
    c->flags = C_CONNECTED;
  }

  int raw = C_RAWMSG;

  if (raw) {
    c->flags |= C_RAWMSG;
    rwm_init (&c->in, 0); 
    rwm_init (&c->out, 0); 
    rwm_init (&c->in_u, 0); 
    rwm_init (&c->out_p, 0); 
  } else {
    assert (0);
  }

  c->type = conn_type;
  c->extra = conn_extra;
  assert (c->type);
  
  c->basic_type = basic_type;
  c->status = (basic_type == ct_outbound) ? conn_connecting : conn_working;
  
  c->flags |= c->type->flags & C_EXTERNAL;
  if (LC) {
    c->flags |= LC->flags & C_EXTERNAL;
  }

  union sockaddr_in46 self;
  unsigned self_addrlen = sizeof (self);
  memset (&self, 0, sizeof (self));
  getsockname (cfd, (struct sockaddr *) &self, &self_addrlen);

  if (self.a4.sin_family == AF_INET) {
    assert (self_addrlen == sizeof (struct sockaddr_in));
    c->our_ip = ntohl (self.a4.sin_addr.s_addr);
    c->our_port = ntohs (self.a4.sin_port);
    assert (peer);
    c->remote_ip = peer;
  } else {
    assert (self.a6.sin6_family == AF_INET6);
    assert (!peer);
    if (is_4in6 (peer_ipv6)) {
      assert (is_4in6 (self.a6.sin6_addr.s6_addr));
      c->our_ip = ntohl (extract_4in6 (self.a6.sin6_addr.s6_addr));
      c->our_port = ntohs (self.a6.sin6_port);
      c->remote_ip = ntohl (extract_4in6 (peer_ipv6));
    } else {
      memcpy (c->our_ipv6, self.a6.sin6_addr.s6_addr, 16);
      c->our_port = ntohs (self.a6.sin6_port);
      c->flags |= C_IPV6;
      memcpy (c->remote_ipv6, peer_ipv6, 16);
    }
  }
  c->remote_port = peer_port;
  
  c->in_queue = alloc_mp_queue_w ();
  c->out_queue = alloc_mp_queue_w ();
  //c->out_packet_queue = alloc_mp_queue_w ();
  
  if (basic_type == ct_outbound) {
    vkprintf (1, "New outbound connection #%d %s:%d -> %s:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);
  } else {
    vkprintf (1, "New inbound connection #%d %s:%d -> %s:%d\n", c->fd, show_remote_ip (C), c->remote_port, show_our_ip (C), c->our_port);
  }


  int (*func)(connection_job_t) = (basic_type == ct_outbound) ? c->type->init_outbound : c->type->init_accepted;

  vkprintf (3, "func = %p\n", func);
  

  if (func (C) >= 0) {
    if (basic_type == ct_outbound) {

      MODULE_STAT->outbound_connections ++;
      MODULE_STAT->allocated_outbound_connections ++;
      MODULE_STAT->outbound_connections_created ++;

      if (CTJ) {
        job_incref (CTJ);
        CT->outbound_connections ++;
      }
    } else {
      MODULE_STAT->inbound_connections_accepted ++;
      MODULE_STAT->allocated_inbound_connections ++;
      MODULE_STAT->inbound_connections ++;
      MODULE_STAT->active_inbound_connections ++;
      MODULE_STAT->active_connections ++;
    
      if (LCJ) {
        c->listening = LC->fd;
        c->listening_generation = LC->generation;
        if (LC->flags & C_NOQACK) {
          c->flags |= C_NOQACK;
        }
      
        c->window_clamp = LC->window_clamp;
        
        if (LC->flags & C_SPECIAL) {
          c->flags |= C_SPECIAL;
          __sync_fetch_and_add (&active_special_connections, 1);

          if (active_special_connections > max_special_connections) {
            vkprintf (active_special_connections >= max_special_connections + 16 ? 0 : 1, "ERROR: forced to accept connection when special connections limit was reached (%d of %d)\n", active_special_connections, max_special_connections);
          }
          if (active_special_connections >= max_special_connections) {
            vkprintf (2, "**Invoking epoll_remove(%d)\n", LC->fd);
            epoll_remove (LC->fd);
          }
        }
      }
      if (c->window_clamp) {
        if (setsockopt (cfd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &c->window_clamp, 4) < 0) {
          vkprintf (0, "error while setting window size for socket #%d to %d: %m\n", cfd, c->window_clamp);
        } else {
          int t1 = -1, t2 = -1;
          socklen_t s1 = 4, s2 = 4;
          getsockopt (cfd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &t1, &s1);
          getsockopt (cfd, SOL_SOCKET, SO_RCVBUF, &t2, &s2);
          vkprintf (2, "window clamp for socket #%d is %d, receive buffer is %d\n", cfd, t1, t2);
        }
      }
    }

    alloc_new_socket_connection (C);

    MODULE_STAT->allocated_connections ++;
   
    return C;
  } else {
    MODULE_STAT->accept_init_accepted_failed ++;
    if (c->flags & C_RAWMSG) {
      rwm_free (&c->in);
      rwm_free (&c->out);
      rwm_free (&c->in_u);
      rwm_free (&c->out_p);
    }
    c->basic_type = ct_none;
    close (cfd);

    free_mp_queue (c->in_queue);
    free_mp_queue (c->out_queue);

    job_free (JOB_REF_PASS (C));
    this_job_thread->jobs_active --;

    return NULL;
  }
}
/* }}} */

/* }}} */

/* {{{ IO PART OF CONNECTION */

/*
  Have to have lock on socket_connection to run this method

  removes event from evemt heap and epoll
*/
void fail_socket_connection (socket_connection_job_t C, int who) /* {{{ */ {
  assert_main_thread ();

  struct socket_connection_info *c = SOCKET_CONN_INFO (C);
  assert (C->j_flags & JF_LOCKED);

  if (!(__sync_fetch_and_or (&c->flags, C_ERROR) & C_ERROR)) {
    job_timer_remove (C);

    remove_event_from_heap (c->ev, 0);
    connection_event_incref (c->fd, -1);
    epoll_insert (c->fd, 0);
    c->ev = NULL;

    c->type->socket_close (C);

    fail_connection (c->conn, who);
  }
}
/* }}} */

/*
  Frees socket_connection structure
  Removes link to cpu_connection
*/
int net_server_socket_free (socket_connection_job_t C) /* {{{ */ {
  assert_net_net_thread ();
  
  struct socket_connection_info *c = SOCKET_CONN_INFO (C);

  assert (!c->ev);
  assert (c->flags & C_ERROR);

  if (c->conn) {
    fail_connection (c->conn, -201);
    job_decref (JOB_REF_PASS (c->conn));
  }

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->out_packet_queue, 4);
    if (!raw) { break; }
    rwm_free (raw);
    free (raw);
  }

  free_mp_queue (c->out_packet_queue);

  rwm_free (&c->out);

  MODULE_STAT->allocated_socket_connections --;
  return 0;
}
/* }}} */

/* 
  Reads data from socket until all data is read
  Then puts it to conn->in_queue and send JS_RUN signal
*/
int net_server_socket_reader (socket_connection_job_t C) /* {{{ */ {
  assert_net_net_thread ();
  struct socket_connection_info *c = SOCKET_CONN_INFO (C);

  while ((c->flags & (C_WANTRD | C_NORD | C_STOPREAD | C_ERROR | C_NET_FAILED)) == C_WANTRD) {
    if (!tcp_recv_buffers_num) {
      prealloc_tcp_buffers ();
    }

    struct raw_message *in = malloc (sizeof (*in));
    rwm_init (in, 0);
    
    int s = tcp_recv_buffers_total_size;
    assert (s > 0);

    int p = 1;

    __sync_fetch_and_or (&c->flags, C_NORD);
    int r = readv (c->fd, tcp_recv_iovec + p, MAX_TCP_RECV_BUFFERS + 1 - p);
    MODULE_STAT->tcp_readv_calls ++;

    if (r <= 0) {
      if (r < 0 && errno == EAGAIN) {
      } else if (r < 0 && errno == EINTR) {
        __sync_fetch_and_and (&c->flags, ~C_NORD);
        MODULE_STAT->tcp_readv_intr ++;
        continue;
      } else {
        vkprintf (1, "Connection %d: Fatal error %m\n", c->fd);
        job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
        __sync_fetch_and_or (&c->flags, C_NET_FAILED);
        return 0;
      }
    } else {
      __sync_fetch_and_and (&c->flags, ~C_NORD);
    }
      
    if (verbosity > 0 && r < 0 && errno != EAGAIN) {
      perror ("recv()");
    }
    vkprintf (2, "readv from %d: %d read out of %d\n", c->fd, r, s);

    if (r <= 0) {
      rwm_free (in);
      free (in);
      break;
    }

    MODULE_STAT->tcp_readv_bytes += r;
    struct msg_part *mp = 0;
    assert (p == 1);
    mp = new_msg_part (0, tcp_recv_buffers[p - 1]);
    assert (tcp_recv_buffers[p - 1]->data == tcp_recv_iovec[p].iov_base);
    mp->offset = 0;
    mp->data_end = r > tcp_recv_iovec[p].iov_len ? tcp_recv_iovec[p].iov_len : r;
    r -= mp->data_end;
    in->first = in->last = mp;
    in->total_bytes = mp->data_end;
    in->first_offset = 0;
    in->last_offset = mp->data_end;
    p ++;

    int rs = r;
    while (rs > 0) {
      mp = new_msg_part (0, tcp_recv_buffers[p - 1]);
      mp->offset = 0;
      mp->data_end = rs > tcp_recv_iovec[p].iov_len ? tcp_recv_iovec[p].iov_len : rs;
      rs -= mp->data_end;
      in->last->next = mp;
      in->last = mp;
      in->last_offset = mp->data_end;
      in->total_bytes += mp->data_end;
      p ++;
    }
    assert (!rs);

    int i;
    for (i = 0; i < p - 1; i++) {
      struct msg_buffer *X = alloc_msg_buffer (tcp_recv_buffers[i], TCP_RECV_BUFFER_SIZE);
      if (!X) {
        vkprintf (0, "**FATAL**: cannot allocate tcp receive buffer\n");
        assert (0);
      }
      tcp_recv_buffers[i] = X;
      tcp_recv_iovec[i + 1].iov_base = X->data;
      tcp_recv_iovec[i + 1].iov_len = X->chunk->buffer_size;
    }

    assert (c->conn);
    mpq_push_w (CONN_INFO(c->conn)->in_queue, in, 0);
    job_signal (JOB_REF_CREATE_PASS (c->conn), JS_RUN);
  }
  return 0;
}
/* }}} */

/* 
  Get data from out raw message and writes it to socket 
*/
int net_server_socket_writer (socket_connection_job_t C) /* {{{ */{
  assert_net_net_thread ();
  struct socket_connection_info *c = SOCKET_CONN_INFO (C);
  
  struct raw_message *out = &c->out;

  int check_watermark = out->total_bytes >= c->write_low_watermark;
  int t = 0;

  int stop = c->flags & C_STOPWRITE;

  while ((c->flags & (C_WANTWR | C_NOWR | C_ERROR | C_NET_FAILED)) == C_WANTWR) {
    if (!out->total_bytes) {
      __sync_fetch_and_and (&c->flags, ~C_WANTWR);
      break;
    }

    struct iovec iov[384];
    int iovcnt = -1;

    int s = tcp_prepare_iovec (iov, &iovcnt, sizeof (iov) / sizeof (iov[0]), out);
    assert (iovcnt > 0 && s > 0);

    __sync_fetch_and_or (&c->flags, C_NOWR);
    int r = writev (c->fd, iov, iovcnt);
    MODULE_STAT->tcp_writev_calls ++;

    if (r <= 0) {
      if (r < 0 && errno == EAGAIN) {
        if (++c->eagain_count > 100) {
          kprintf ("Too much EAGAINs for connection %d (%s), dropping\n", c->fd, show_remote_socket_ip (C));
          job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
          __sync_fetch_and_or (&c->flags, C_NET_FAILED);
          return 0;
        }
      } else if (r < 0 && errno == EINTR) {
        __sync_fetch_and_and (&c->flags, ~C_NOWR);
        MODULE_STAT->tcp_writev_intr ++;
        continue;
      } else {
        vkprintf (1, "Connection %d: Fatal error %m\n", c->fd);
        job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
        __sync_fetch_and_or (&c->flags, C_NET_FAILED);
        return 0;
      }
    } else {
      __sync_fetch_and_and (&c->flags, ~C_NOWR);
      MODULE_STAT->tcp_writev_bytes += r;
      c->eagain_count = 0;
      t += r;
    }
    
    if (verbosity && r < 0 && errno != EAGAIN) {
      perror ("writev()");
    }
    vkprintf (2, "send/writev() to %d: %d written out of %d in %d chunks\n", c->fd, r, s, iovcnt);

    if (r > 0) {
      rwm_skip_data (out, r);
      if (c->type->data_sent) {
        c->type->data_sent (C, r);
      }
    }
  }

  if (check_watermark && out->total_bytes < c->write_low_watermark) {
    if (c->type->ready_to_write) {
      c->type->ready_to_write (C);
    }
  }

  if (stop && !(c->flags & C_WANTWR)) {
    vkprintf (1, "Closing write_close socket\n");
    job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
    __sync_fetch_and_or (&c->flags, C_NET_FAILED);
  }

  vkprintf (2, "socket_server_writer: written %d bytes to %d, flags=0x%08x\n", t, c->fd, c->flags);
  return out->total_bytes;
}
/* }}} */

/*
  checks if outbound connections become connected
  merges contents of out_packet_queue mpq to out raw message
  runs socket_reader and socket_writer
*/
int net_server_socket_read_write (socket_connection_job_t C) /* {{{ */ {
  assert_net_net_thread ();
  
  struct socket_connection_info *c = SOCKET_CONN_INFO (C);

  if (c->flags & C_ERROR) {
    return 0;
  }
 
  if (!(c->flags & C_CONNECTED)) {
    if (!(c->flags & C_NOWR)) {
      __sync_fetch_and_and (&c->flags, C_PERMANENT);
      __sync_fetch_and_or (&c->flags, C_WANTRD | C_CONNECTED);
      __sync_fetch_and_or (&CONN_INFO(c->conn)->flags, C_READY_PENDING | C_CONNECTED);
        
      c->type->socket_connected (C);
      job_signal (JOB_REF_CREATE_PASS (c->conn), JS_RUN);
    } else {
      return compute_conn_events (C);
    }
  }
  
  vkprintf (2, "END processing connection %d, flags=%d\n", c->fd, c->flags);

  while ((c->flags & (C_WANTRD | C_NORD | C_ERROR | C_STOPREAD | C_NET_FAILED)) == C_WANTRD) {
    c->type->socket_reader (C);
  }
  
  struct raw_message *out = &c->out;

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->out_packet_queue, 4);
    if (!raw) { break; }
    rwm_union (out, raw);
    free (raw);
  }

  if (out->total_bytes) {
    __sync_fetch_and_or (&c->flags, C_WANTWR);
  }
 
  while ((c->flags & (C_NOWR | C_ERROR | C_WANTWR | C_NET_FAILED)) == C_WANTWR) {  
    c->type->socket_writer (C);
  }

  return compute_conn_events (C);
}
/* }}} */

/*
  removes C_NOWR and C_NORD flags if necessary
  reads errors from socket
  sends JS_RUN signal to socket_connection
*/
int net_server_socket_read_write_gateway (int fd, void *data, event_t *ev) /* {{{ */ {
  assert_main_thread ();
  if (!data) { return EVA_REMOVE; }

  assert ((int)ev->refcnt);
 
  socket_connection_job_t C = (socket_connection_job_t) data;
  assert (C);
  struct socket_connection_info *c = SOCKET_CONN_INFO (C);
  assert (c->type);

  if (ev->ready & EVT_FROM_EPOLL) {
    // update C_NORD / C_NOWR only if we arrived from epoll()
    vkprintf (2, "fd=%d state=%d ready=%d epoll_ready=%d\n", ev->fd, ev->state, ev->ready, ev->epoll_ready);
    ev->ready &= ~EVT_FROM_EPOLL;

    int clear_flags = 0;
    if ((ev->state & EVT_READ) && (ev->ready & EVT_READ)) {
      clear_flags |= C_NORD;
    }
    if ((ev->state & EVT_WRITE) && (ev->ready & EVT_WRITE)) {
      clear_flags |= C_NOWR;
    }
    __sync_fetch_and_and (&c->flags, ~clear_flags);

    if (ev->epoll_ready & EPOLLERR) {
      int error = 0;
      socklen_t errlen = sizeof (error);
      if (getsockopt (c->fd, SOL_SOCKET, SO_ERROR, (void *) &error, &errlen) == 0) {
        vkprintf (1, "got error for tcp socket #%d, [%s]:%d : %s\n", c->fd, show_remote_socket_ip (C), c->remote_port, strerror (error));
      }

      job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
      return EVA_REMOVE;
    }
    if (ev->epoll_ready & (EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLPRI)) {
      vkprintf (!(ev->epoll_ready & EPOLLPRI), "socket #%d: disconnected (epoll_ready=%02x), cleaning\n", c->fd, ev->epoll_ready);

      job_signal (JOB_REF_CREATE_PASS (C), JS_ABORT);
      return EVA_REMOVE;
    }
  }

  job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);
  return EVA_CONTINUE;
}
/* }}} */

int do_socket_connection_job (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  socket_connection_job_t C = job;

  struct socket_connection_info *c = SOCKET_CONN_INFO (C);

  if (op == JS_ABORT) { // MAIN THREAD 
    fail_socket_connection (C, -200);
    return JOB_COMPLETED;
  }
  if (op == JS_RUN) { // IO THREAD
    if (!(c->flags & C_ERROR)) {
      int res = c->type->socket_read_write (job);
      if (res != c->current_epoll_status) {
        c->current_epoll_status = res;
        return JOB_SENDSIG (JS_AUX);
      }
    }
    return 0;
  }
  if (op == JS_AUX) { // MAIN THREAD
    if (!(c->flags & C_ERROR)) {
      epoll_insert (c->fd, compute_conn_events (job));
    }
    return 0;
  }

  if (op == JS_FINISH) { // ANY THREAD
    assert (C->j_refcnt == 1);
    c->type->socket_free (C);
    return job_free (JOB_REF_PASS (C));
  }
  
  return JOB_ERROR;
}
/* }}} */

/* 
  creates socket_connection structure
  insert event to epoll
*/
socket_connection_job_t alloc_new_socket_connection (connection_job_t C) /* {{{ */ {
  assert_main_thread ();
  struct connection_info *c = CONN_INFO (C);

  socket_connection_job_t S = create_async_job (do_socket_connection_job, JSC_ALLOW (JC_CONNECTION_IO, JS_RUN) | JSC_ALLOW (JC_CONNECTION_IO, JS_ALARM) | JSC_ALLOW (JC_EPOLL, JS_ABORT) | JSC_ALLOW (JC_CONNECTION_IO, JS_FINISH) | JSC_ALLOW (JC_EPOLL, JS_AUX), -2, sizeof (struct socket_connection_info), JT_HAVE_TIMER, JOB_REF_NULL);
  S->j_refcnt = 2;
  struct socket_connection_info *s = SOCKET_CONN_INFO (S);
  //memset (s, 0, sizeof (*s)); /* no need, create_async_job memsets itself */

  s->fd = c->fd;
  s->type = c->type;
  s->conn = job_incref (C);
  s->flags = C_WANTWR | C_WANTRD | (c->flags & C_CONNECTED);
  
  s->our_ip = c->our_ip;
  s->our_port = c->our_port;
  memcpy (s->our_ipv6, c->our_ipv6, 16);
  
  s->remote_ip = c->remote_ip;
  s->remote_port = c->remote_port;
  memcpy (s->remote_ipv6, c->remote_ipv6, 16);

  s->out_packet_queue = alloc_mp_queue_w ();
  
  struct event_descr *ev = Events + s->fd;
  assert (!ev->data);
  assert (!ev->refcnt);

  s->ev = ev;
    
  epoll_sethandler (s->fd, 0, net_server_socket_read_write_gateway, S);

  s->current_epoll_status = compute_conn_events (S);
  epoll_insert (s->fd, s->current_epoll_status);

  c->io_conn = S;
  
  rwm_init (&s->out, 0);
  unlock_job (JOB_REF_CREATE_PASS (S));

  MODULE_STAT->allocated_socket_connections ++;
  return S;
}
/* }}} */
/* }}} */

/* {{{ LISTENING CONNECTION */

/*
  accepts new connections
  executes alloc_new_connection ()
*/
int net_accept_new_connections (listening_connection_job_t LCJ) /* {{{ */ {
  struct listening_connection_info *LC = LISTEN_CONN_INFO (LCJ);

  union sockaddr_in46 peer;
  unsigned peer_addrlen;
  int cfd, acc = 0;

  while (Events[LC->fd].state & EVT_IN_EPOLL) {   
    peer_addrlen = sizeof (peer);
    memset (&peer, 0, sizeof (peer));
    cfd = accept (LC->fd, (struct sockaddr *) &peer, &peer_addrlen);

    vkprintf (2, "%s: cfd = %d\n", __func__, cfd);
    if (cfd < 0) {
      if (errno != EAGAIN) {
        MODULE_STAT->accept_calls_failed ++;
      }
      if (!acc) {
        vkprintf ((errno == EAGAIN) * 2, "accept(%d) unexpectedly returns %d: %m\n", LC->fd, cfd);
      }
      break;
    }
    
    acc ++;
    MODULE_STAT->inbound_connections_accepted ++;
    
    if (max_accept_rate) {
      cur_accept_rate_remaining += (precise_now - cur_accept_rate_time) * max_accept_rate;
      cur_accept_rate_time = precise_now;
      if (cur_accept_rate_remaining > max_accept_rate) {
        cur_accept_rate_remaining = max_accept_rate;
      }
      
      if (cur_accept_rate_remaining < 1) {
        MODULE_STAT->accept_rate_limit_failed ++;
        close (cfd);
        continue;
      }

      cur_accept_rate_remaining -= 1;
    }
     
    if (LC->flags & C_IPV6) {
      assert (peer_addrlen == sizeof (struct sockaddr_in6));
      assert (peer.a6.sin6_family == AF_INET6);
    } else {
      assert (peer_addrlen == sizeof (struct sockaddr_in));
      assert (peer.a4.sin_family == AF_INET);
    }
   
    connection_job_t C;
    if (peer.a4.sin_family == AF_INET) {
      C = alloc_new_connection (cfd, NULL, LCJ, ct_inbound, LC->type, LC->extra,
        ntohl (peer.a4.sin_addr.s_addr), NULL, ntohs (peer.a4.sin_port));
    } else {
      C = alloc_new_connection (cfd, NULL, LCJ, ct_inbound, LC->type, LC->extra,
        0, peer.a6.sin6_addr.s6_addr, ntohs (peer.a6.sin6_port));
    }
    if (C) {
      assert (CONN_INFO(C)->io_conn);
      unlock_job (JOB_REF_PASS (C));
    }
  }
  return 0;
}
/* }}} */

int do_listening_connection_job (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  listening_connection_job_t LCJ = job;

  if (op == JS_RUN) {
    net_accept_new_connections (LCJ);
    return 0;
  } else if (op == JS_AUX) {
    vkprintf (2, "**Invoking epoll_insert(%d,%d)\n", LISTEN_CONN_INFO(LCJ)->fd, EVT_RWX);
    epoll_insert (LISTEN_CONN_INFO(LCJ)->fd, EVT_RWX);
    return 0;
  }
  return JOB_ERROR;
}
/* }}} */

int init_listening_connection_ext (int fd, conn_type_t *type, void *extra, int mode, int prio) /* {{{ */ {
  if (check_conn_functions (type, 1) < 0) {
    return -1;
  }
  if (fd >= max_connection_fd) {
    vkprintf (0, "TOO big fd for listening connection %d (max %d)\n", fd, max_connection_fd);
    return -1;
  }
  if (fd > max_connection) {
    max_connection = fd;
  }
  
  listening_connection_job_t LCJ = create_async_job (do_listening_connection_job, JSC_ALLOW (JC_EPOLL, JS_RUN) | JSC_ALLOW (JC_EPOLL, JS_AUX) | JSC_ALLOW (JC_EPOLL, JS_FINISH), -2, sizeof (struct listening_connection_info), JT_HAVE_TIMER, JOB_REF_NULL);
  LCJ->j_refcnt = 2;

  struct listening_connection_info *LC = LISTEN_CONN_INFO (LCJ);
  memset (LC, 0, sizeof (*LC));

  LC->fd = fd;
  LC->type = type;
  LC->extra = extra;

  struct event_descr *ev = Events + fd;
  assert (!ev->data);
  assert (!ev->refcnt);
  LC->ev = ev;

  LC->generation = new_conn_generation ();

  if (mode & SM_LOWPRIO) {
    prio = 10;
  }

  if (mode & SM_SPECIAL) {
    LC->flags |= C_SPECIAL;
    int idx = __sync_fetch_and_add (&special_listen_sockets, 1);
    assert (idx < MAX_SPECIAL_LISTEN_SOCKETS);
    special_socket[idx].fd = LC->fd; 
    special_socket[idx].generation = LC->generation; 
  }

  if (mode & SM_NOQACK) {
    LC->flags |= C_NOQACK;
    disable_qack (LC->fd);
  }

  if (mode & SM_IPV6) {
    LC->flags |= C_IPV6;
  }

  if (mode & SM_RAWMSG) {
    LC->flags |= C_RAWMSG;
  }

  epoll_sethandler (fd, prio, net_server_socket_read_write_gateway, LCJ);
  epoll_insert (fd, EVT_RWX);

  MODULE_STAT->listening_connections ++;

  unlock_job (JOB_REF_PASS (LCJ));  
  
  return 0;
}

int init_listening_connection (int fd, conn_type_t *type, void *extra) {
  return init_listening_connection_ext (fd, type, extra, 0, -10);
}

int init_listening_tcpv6_connection (int fd, conn_type_t *type, void *extra, int mode) {
  return init_listening_connection_ext (fd, type, extra, mode, -10);
}
/* }}} */ 

/* }}} */

/* {{{ connection refcnt */
void connection_event_incref (int fd, long long val) {
  struct event_descr *ev = &Events[fd];

  if (!__sync_add_and_fetch (&ev->refcnt, val) && ev->data) {
    socket_connection_job_t C = ev->data;
    ev->data = NULL;
    job_decref (JOB_REF_PASS (C));
  }
}

connection_job_t connection_get_by_fd (int fd) {
  struct event_descr *ev = &Events[fd];  
  if (!(int)(ev->refcnt) || !ev->data) { return NULL; }

  while (1) {
    long long v = __sync_fetch_and_add (&ev->refcnt, (1ll << 32));
    if (((int)v) != 0) { break; }
    v = __sync_fetch_and_add (&ev->refcnt, -(1ll << 32));
    if (((int)v) != 0) { continue; }
    return NULL;
  }
  __sync_fetch_and_add (&ev->refcnt, 1 - (1ll << 32));
  socket_connection_job_t C = job_incref (ev->data);
  
  connection_event_incref (fd, -1);

  if (C->j_execute == &do_listening_connection_job) {
    return C;
  }

  assert (C->j_execute == &do_socket_connection_job);

  struct socket_connection_info *c = SOCKET_CONN_INFO (C);
  if (c->flags & C_ERROR) {
    job_decref (JOB_REF_PASS (C));
    return NULL;
  } else {
    assert (c->conn);
    connection_job_t C2 = job_incref (c->conn);
    job_decref (JOB_REF_PASS (C));
    return C2;
  }
}

connection_job_t connection_get_by_fd_generation (int fd, int generation) {
  connection_job_t C = connection_get_by_fd (fd);
  if (C && CONN_INFO(C)->generation != generation) {
    job_decref (JOB_REF_PASS (C));
    return NULL;
  } else {
    return C;
  }
}
/* }}} */


/* {{{ Sample server functions */

int server_check_ready (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  if (c->status == conn_none || c->status == conn_connecting) {
    return c->ready = cr_notyet;
  }
  if (c->status == conn_error || c->ready == cr_failed) {
    return c->ready = cr_failed;
  }
  return c->ready = cr_ok;
}
/* }}} */

int server_noop (connection_job_t C) /* {{{ */ {
  return 0;  
}
/* }}} */

int server_failed (connection_job_t C) /* {{{ */ {
  kprintf ("connection %d: call to pure virtual method\n", CONN_INFO(C)->fd);
  assert (0);
  return -1;
}
/* }}} */

int server_flush (connection_job_t C) /* {{{ */ {
  //job_signal (job_incref (C), JS_RUN);
  return 0;
}
/* }}} */

int check_conn_functions (conn_type_t *type, int listening) /* {{{ */ {
  if (type->magic != CONN_FUNC_MAGIC) {
    return -1;
  }
  if (!type->title) {
    type->title = "(unknown)";
  }
  if (!type->socket_read_write) {
    type->socket_read_write = net_server_socket_read_write;
  }
  if (!type->socket_reader) {
    type->socket_reader = net_server_socket_reader;
  }
  if (!type->socket_writer) {
    type->socket_writer = net_server_socket_writer;
  }
  if (!type->socket_close) {
    type->socket_close = server_noop;
  }

  if (!type->accept) {
    if (listening) {
      type->accept = net_accept_new_connections;
    } else {
      type->accept = server_failed;
    }
  }
  if (!type->init_accepted) {
    if (listening) {
      type->init_accepted = server_noop;
    } else {
      type->init_accepted = server_failed;
    }
  }
  
  if (!type->close) {
    type->close = cpu_server_close_connection;
  }
  if (!type->init_outbound) {
    type->init_outbound = server_noop;
  }
  if (!type->wakeup) {
    type->wakeup = server_noop;
  }
  if (!type->alarm) {
    type->alarm = server_noop;
  }
  if (!type->connected) {
    type->connected = server_noop;
  }
  if (!type->flush) {
    type->flush = server_flush;
  }
  if (!type->check_ready) {
    type->check_ready = server_check_ready;
  }
  if (!type->read_write) {
    type->read_write = cpu_server_read_write;
  }
  if (!type->free) {
    type->free = cpu_server_free_connection;
  }
  if (!type->socket_connected) {
    type->socket_connected = server_noop;
  }
  if (!type->socket_free) {
    type->socket_free = net_server_socket_free;
  }
  if (type->flags & C_RAWMSG) {
    if (!type->free_buffers) {
      type->free_buffers = cpu_tcp_free_connection_buffers;
    }
    if (!type->reader) {
      type->reader = cpu_tcp_server_reader;
      if (!type->parse_execute) {
        return -1;
      }
    }
    if (!type->writer) {
      type->writer = cpu_tcp_server_writer;
    }
  } else {
    if (!type->free_buffers) {
      assert (0);
    }
    if (!type->reader) {
      assert (0);
    }
    if (!type->writer) {
      assert (0);
    }
  }
  return 0;
}
/* }}} */

/* }}} */



/* CONN TARGETS {{{ */

void compute_next_reconnect (conn_target_job_t CT) /* {{{ */{
  struct conn_target_info *S = CONN_TARGET_INFO (CT);
  if (S->next_reconnect_timeout < S->reconnect_timeout || S->active_outbound_connections) {
    S->next_reconnect_timeout = S->reconnect_timeout;
  }
  S->next_reconnect = precise_now + S->next_reconnect_timeout;
  if (!S->active_outbound_connections && S->next_reconnect_timeout < MAX_RECONNECT_INTERVAL) {
    S->next_reconnect_timeout = S->next_reconnect_timeout * 1.5 + drand48_j () * 0.2;
  }
}
/* }}} */

static void count_connection_num (connection_job_t C, void *good_c, void *stopped_c, void *bad_c) /* {{{ */ {
  int cr = CONN_INFO(C)->type->check_ready (C); 
  switch (cr) {
    case cr_notyet:
    case cr_busy:
      break;
    case cr_ok:
      (*(int *)good_c)++;
      break;
    case cr_stopped:
      (*(int *)stopped_c)++;
      break;
    case cr_failed:
      (*(int *)bad_c)++;
      break;
    default:
      assert (0);
  }
}
/* }}} */

static void find_bad_connection (connection_job_t C, void *x) /* {{{ */ {
  connection_job_t *T = x;
  if (*T) { return; }
  if (CONN_INFO(C)->flags & C_ERROR) {
    *T = C;
  }
}
/* }}} */

/*
  Deletes failed connections (with flag C_ERROR) from target's tree
*/
void destroy_dead_target_connections (conn_target_job_t CTJ) /* {{{ */ {
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);

  struct tree_connection *T = CT->conn_tree;  
  if (T) {
    __sync_fetch_and_add (&T->refcnt, 1);
  }
  
  while (1) {
    connection_job_t CJ = NULL;
    tree_act_ex_connection (T, find_bad_connection, &CJ);
    if (!CJ) { break; }
    
    if (connection_is_active (CONN_INFO (CJ)->flags)) {    
      __sync_fetch_and_add (&CT->active_outbound_connections, -1);
    }
    __sync_fetch_and_add (&CT->outbound_connections, -1);

    T = tree_delete_connection (T, CJ);     
  }
  
  int good_c = 0, bad_c = 0, stopped_c = 0;

  tree_act_ex3_connection (T, count_connection_num, &good_c, &stopped_c, &bad_c);
  
  int was_ready = CT->ready_outbound_connections;
  CT->ready_outbound_connections = good_c;

  if (was_ready != CT->ready_outbound_connections) {
    MODULE_STAT->ready_outbound_connections += CT->ready_outbound_connections - was_ready;
  }

  if (was_ready && !CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets --;
  }
  if (!was_ready && CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets ++;
  }

  if (T == CT->conn_tree) {
    tree_free_connection (T);
  } else {
    struct tree_connection *old = CT->conn_tree;
    CT->conn_tree = T;
    barrier ();
    __sync_synchronize ();
    free_tree_ptr_connection (old);
  }
}
/* }}} */

/*
  creates new connections for target 
  must be called in main thread, because we can allocate new connections only in main thread
*/
int create_new_connections (conn_target_job_t CTJ) /* {{{ */ {
  assert_main_thread ();

  destroy_dead_target_connections (CTJ);
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);

  int count = 0, good_c = 0, bad_c = 0, stopped_c = 0, need_c;

  tree_act_ex3_connection (CT->conn_tree, count_connection_num, &good_c, &stopped_c, &bad_c);

  int was_ready = CT->ready_outbound_connections;
  CT->ready_outbound_connections = good_c;

  if (was_ready != CT->ready_outbound_connections) {
    MODULE_STAT->ready_outbound_connections += CT->ready_outbound_connections - was_ready;
  }

  if (was_ready && !CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets --;
  }
  if (!was_ready && CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets ++;
  }

  need_c = CT->min_connections + bad_c + ((stopped_c + 1) >> 1);
  if (need_c > CT->max_connections) {
    need_c = CT->max_connections;
  }

  if (precise_now >= CT->next_reconnect || CT->active_outbound_connections) {
    struct tree_connection *T = CT->conn_tree;  
    if (T) {
      __sync_fetch_and_add (&T->refcnt, 1);
    }

    while (CT->outbound_connections < need_c) {
      int cfd = -1;
      if (CT->target.s_addr) {
        cfd = client_socket (CT->target.s_addr, CT->port, 0);
        vkprintf (1, "Created NEW connection #%d to %s:%d\n", cfd, inet_ntoa (CT->target), CT->port);
      } else {
        cfd = client_socket_ipv6 (CT->target_ipv6, CT->port, SM_IPV6);
        vkprintf (1, "Created NEW ipv6 connection #%d to [%s]:%d\n", cfd, show_ipv6 (CT->target_ipv6), CT->port);
      }
      if (cfd < 0) {
        if (CT->target.s_addr) {
          vkprintf (1, "error connecting to %s:%d: %m\n", inet_ntoa (CT->target), CT->port);
        } else {
          vkprintf (1, "error connecting to [%s]:%d\n", show_ipv6 (CT->target_ipv6), CT->port);
        }
        break;
      }

      connection_job_t C = alloc_new_connection (cfd, CTJ, NULL, ct_outbound, CT->type, CT->extra,
          ntohl (CT->target.s_addr), CT->target_ipv6, CT->port);

      if (C) {
        assert (CONN_INFO(C)->io_conn);
        count ++;        
        unlock_job (JOB_REF_CREATE_PASS (C));
        T = tree_insert_connection (T, C, lrand48_j ());
      } else {
        break;
      }
    }

    if (T == CT->conn_tree) {
      tree_free_connection (T);
    } else {
      struct tree_connection *old = CT->conn_tree;
      CT->conn_tree = T;
      __sync_synchronize ();
      free_tree_ptr_connection (old);
    }
  
    compute_next_reconnect (CTJ);
  }
  

  return count;
}
/* }}} */

conn_target_job_t HTarget[PRIME_TARGETS];
pthread_mutex_t TargetsLock = PTHREAD_MUTEX_INITIALIZER;

/* must be called with mutex held */
/* mode = 0 -- lookup, mode = 1 -- insert, mode = -1 -- delete */
static conn_target_job_t find_target (struct in_addr ad, int port, conn_type_t *type, void *extra, int mode, conn_target_job_t new_target) /* {{{ */ {
  assert (ad.s_addr);
  unsigned h1 = ((unsigned long) type * 0xabacaba + ad.s_addr) % PRIME_TARGETS;
  h1 = (h1 * 239 + port) % PRIME_TARGETS;
  conn_target_job_t *prev = HTarget + h1, cur;
  while ((cur = *prev) != 0) {
    struct conn_target_info *S = CONN_TARGET_INFO (cur);
    if (S->target.s_addr == ad.s_addr && S->port == port && S->type == type && S->extra == extra) {
      if (mode < 0) {
        *prev = S->hnext;
        S->hnext = 0;
        return cur;
      }
      assert (!mode);
      return cur;
    }
    prev = &S->hnext;
  }
  assert (mode >= 0);
  if (mode > 0) {
    CONN_TARGET_INFO (new_target)->hnext = HTarget[h1];
    HTarget[h1] = new_target;
    return new_target;
  }
  return 0;
}
/* }}} */

/* must be called with mutex held */
/* mode = 0 -- lookup, mode = 1 -- insert, mode = -1 -- delete */
static conn_target_job_t find_target_ipv6 (unsigned char ad_ipv6[16], int port, conn_type_t *type, void *extra, int mode, conn_target_job_t new_target) /* {{{ */ {
  assert (*(long long *)ad_ipv6 || ((long long *) ad_ipv6)[1]);
  unsigned h1 = ((unsigned long) type * 0xabacaba) % PRIME_TARGETS;
  int i;
  for (i = 0; i < 4; i++) {
    h1 = ((unsigned long long) h1 * 17239 + ((unsigned *) ad_ipv6)[i]) % PRIME_TARGETS;
  }
  h1 = (h1 * 239 + port) % PRIME_TARGETS;
  conn_target_job_t *prev = HTarget + h1, cur;
  while ((cur = *prev) != 0) {
    struct conn_target_info *S = CONN_TARGET_INFO (cur);
    if (
        ((long long *)S->target_ipv6)[1] == ((long long *)ad_ipv6)[1] &&
        *(long long *)S->target_ipv6 == *(long long *)ad_ipv6 &&
        S->port == port && S->type == type && !S->target.s_addr && S->extra == extra) {
      if (mode < 0) {
        *prev = S->hnext;
        S->hnext = 0;
        return cur;
      }
      assert (!mode);
      return cur;
    }
    prev = &S->hnext;
  }
  assert (mode >= 0);
  if (mode > 0) {
    CONN_TARGET_INFO (new_target)->hnext = HTarget[h1];
    HTarget[h1] = new_target;
    return new_target;
  }
  return 0;
}
/* }}} */

static int free_target (conn_target_job_t CTJ) /* {{{ */ {
  pthread_mutex_lock (&TargetsLock);
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);
  if (CT->global_refcnt > 0 || CT->conn_tree) {
    pthread_mutex_unlock (&TargetsLock);
    return -1;
  }

  assert (CT && CT->type && !CT->global_refcnt);
  assert (!CT->conn_tree);
  if (CT->target.s_addr) {
    vkprintf (1, "Freeing unused target to %s:%d\n", inet_ntoa (CT->target), CT->port);
    assert (CTJ == find_target (CT->target, CT->port, CT->type, CT->extra, -1, 0));
  } else {
    vkprintf (1, "Freeing unused ipv6 target to [%s]:%d\n", show_ipv6 (CT->target_ipv6), CT->port);
    assert (CTJ == find_target_ipv6 (CT->target_ipv6, CT->port, CT->type, CT->extra, -1, 0));
  }

  pthread_mutex_unlock (&TargetsLock);

  MODULE_STAT->inactive_targets --;
  MODULE_STAT->free_targets ++;

  job_decref (JOB_REF_PASS (CTJ));

  return 1;
}
 /* }}} */

static void fail_connection_gw (connection_job_t C) {
  fail_connection (C, -17);
}

int clean_unused_target (conn_target_job_t CTJ) /* {{{ */ {
  assert (CTJ);  
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);
  assert (CT->type);
  if (CT->global_refcnt) {
    return 0;
  }
  if (CT->conn_tree) {
    tree_act_connection (CT->conn_tree, fail_connection_gw);
    return 0;
  }
  job_timer_remove (CTJ);
  return 0;
}
/* }}} */

int destroy_target (JOB_REF_ARG (CTJ)) /* {{{ */ {
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);
  assert (CT);
  assert (CT->type);
  assert (CT->global_refcnt > 0);

  int r;
  if (!((r = __sync_add_and_fetch (&CT->global_refcnt, -1)))) {
    MODULE_STAT->active_targets--;
    MODULE_STAT->inactive_targets++;

    job_signal (JOB_REF_PASS (CTJ), JS_RUN);
  } else {
    job_decref (JOB_REF_PASS (CTJ));
  }
  return r;
}
/*}}} */

int do_conn_target_job (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  if (epoll_fd <= 0) {
    job_timer_insert (job, precise_now + 0.01);
    return 0;
  }
  conn_target_job_t CTJ = job;
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);

  if (op == JS_ALARM || op == JS_RUN) {
    if (op == JS_ALARM && !job_timer_check (job)) {
      return 0;
    }
    if (!CT->global_refcnt) {
      destroy_dead_target_connections (CTJ);
      clean_unused_target (CTJ);
      compute_next_reconnect (CTJ);
    } else {
      create_new_connections (CTJ);
    }

    if (CTJ->j_flags & JF_COMPLETED) { return 0; }

    if (CT->global_refcnt || CT->conn_tree) {
      job_timer_insert (CTJ, precise_now + 0.1);
      return 0;
    } else {
      if (free_target (CTJ) >= 0) {
        return JOB_COMPLETED;
      } else {
        job_timer_insert (CTJ, precise_now + 0.1);
        return 0;
      }
    }
  }
  if (op == JS_FINISH) {
    assert (CTJ->j_flags & JF_COMPLETED);
    MODULE_STAT->allocated_targets --;
    return job_free (JOB_REF_PASS (job));
  }

  return JOB_ERROR;
}
/* }}} */

conn_target_job_t create_target (struct conn_target_info *source, int *was_created) /* {{{ */ {
  if (check_conn_functions (source->type, 0) < 0) {
    return NULL;
  }
  pthread_mutex_lock (&TargetsLock);

  conn_target_job_t T = 
    source->target.s_addr ? 
    find_target (source->target, source->port, source->type, source->extra, 0, 0) :
    find_target_ipv6 (source->target_ipv6, source->port, source->type, source->extra, 0, 0);

  if (T) {
    struct conn_target_info *t = CONN_TARGET_INFO (T);
    
    t->min_connections = source->min_connections;
    t->max_connections = source->max_connections;
    t->reconnect_timeout = source->reconnect_timeout;

    if (!__sync_fetch_and_add (&t->global_refcnt, 1)) {
      MODULE_STAT->active_targets++;
      MODULE_STAT->inactive_targets--;
    
      if (was_created) {
        *was_created = 2;
      }
    } else {
      if (was_created) {
        *was_created = 0;
      }
    }

    job_incref (T);
  } else {
    //assert (MODULE_STAT->allocated_targets < MAX_TARGETS);
    T = create_async_job (do_conn_target_job, JSC_ALLOW (JC_EPOLL, JS_RUN) | JSC_ALLOW (JC_EPOLL, JS_ABORT) | JSC_ALLOW (JC_EPOLL, JS_ALARM) | JSC_ALLOW (JC_EPOLL, JS_FINISH), -2, sizeof (struct conn_target_info), JT_HAVE_TIMER, JOB_REF_NULL);
    T->j_refcnt = 2;
       
    struct conn_target_info *t = CONN_TARGET_INFO (T);
    memcpy (t, source, sizeof (*source));
    job_timer_init (T);

    //t->generation = 1;
    MODULE_STAT->active_targets ++;
    MODULE_STAT->allocated_targets ++;

    if (source->target.s_addr) {
      find_target (source->target, source->port, source->type, source->extra, 1, T);
    } else {
      find_target_ipv6 (source->target_ipv6, source->port, source->type, source->extra, 1, T);
    }

    if (was_created) {
      *was_created = 1;
    }
    t->global_refcnt = 1;
    schedule_job (JOB_REF_CREATE_PASS (T));
  }
  
  pthread_mutex_unlock (&TargetsLock);

  return T;
}
/* }}} */


/* }}} */




void tcp_set_max_connections (int maxconn) /* {{{ */ {  
  max_connection_fd = maxconn;
  if (!max_special_connections || max_special_connections > maxconn) {
    max_special_connections = maxconn;
  }
}
/* }}} */

int create_all_outbound_connections_limited (int limit) /* {{{ */ {
  return 0;
  /*int count = 0;
  get_utime_monotonic ();
  //close_some_unneeded_connections ();
  //ready_outbound_connections = ready_targets = 0;
  int new_ready_outbound_connections = 0;
  int new_ready_targets = 0;

  pthread_mutex_lock (&TargetsLock);
  conn_target_job_t S;
  for (S = CONN_TARGET_INFO(ActiveTargets)->next_target; S != ActiveTargets && count < limit; S = CONN_TARGET_INFO(S)->next_target) {
    struct conn_target_info *s = CONN_TARGET_INFO (S);

    assert (s->type && s->refcnt > 0);
    count += create_new_connections (S);

    if (s->ready_outbound_connections) {
      new_ready_outbound_connections += s->ready_outbound_connections;
      new_ready_targets++;
    }
  }
  pthread_mutex_unlock (&TargetsLock);
  MODULE_STAT->ready_targets = new_ready_targets;
  MODULE_STAT->ready_outbound_connections = new_ready_outbound_connections;
  return count;    */
}
/* }}} */ 

int create_all_outbound_connections (void) /* {{{ */ {
  return create_all_outbound_connections_limited (0x7fffffff);
}
/* }}} */

/* {{{ conn_target_get_connection */
static void check_connection (connection_job_t C, void *x) {
  connection_job_t *P = x;
  if (*P) { return; }

  int r = CONN_INFO (C)->type->check_ready (C);

  if (r == cr_ok) {
    *P = C;
    return;
  }
}

static void check_connection_stopped (connection_job_t C, void *x) {
  connection_job_t *P = x;

  if (*P && CONN_INFO (*P)->ready == cr_ok) { return; }

  int r = CONN_INFO (C)->type->check_ready (C);

  if (r == cr_ok) {
    *P = C;
    return;
  }

  if (r == cr_stopped && (!*P || CONN_INFO (*P)->unreliability > CONN_INFO (C)->unreliability)) {
    *P = C;
    return;
  }
}

connection_job_t conn_target_get_connection (conn_target_job_t CT, int allow_stopped) {
  assert (CT);

  struct conn_target_info *t = CONN_TARGET_INFO (CT);

  struct tree_connection *T = get_tree_ptr_connection (&t->conn_tree);

  connection_job_t S = NULL;
  tree_act_ex_connection (T, allow_stopped ? check_connection_stopped : check_connection, &S);

  if (S) { job_incref (S); }
  tree_free_connection (T);

  return S;
}
/* }}} */

void insert_free_later_struct (struct free_later *F) {
  if (!free_later_queue) {
    free_later_queue = alloc_mp_queue_w ();
  }
  mpq_push_w (free_later_queue, F, 0);
  MODULE_STAT->free_later_size ++;
  MODULE_STAT->free_later_total ++;
}

void free_later_act (void) {
  if (!free_later_queue) { return; }
  while (1) {
    struct free_later *F = mpq_pop_nw (free_later_queue, 4);
    if (!F) { return; }
    MODULE_STAT->free_later_size --;
    F->free (F->ptr);
    free (F);
  }
}

void free_connection_tree_ptr (struct tree_connection *T) /* {{{ */ {
  free_tree_ptr_connection (T);
}
/* }}} */ 


void incr_active_dh_connections (void) {
  MODULE_STAT->active_dh_connections ++;
}

int new_conn_generation (void) {
  return __sync_fetch_and_add (&conn_generation, 1);
}

int get_cur_conn_generation (void) {
  return conn_generation;
}

// -----

int nat_info_rules;
unsigned nat_info[MAX_NAT_INFO_RULES][2];

int net_add_nat_info (char *str) {
  char *str2 = strrchr (str, ':');
  if (!str2) {
    fprintf (stderr, "expected <local-addr>:<global-addr> in --nat-info\n");
    return -1;
  }
  *str2++ = 0;
  struct in_addr l_addr, g_addr;
  if (inet_pton (AF_INET, str, &l_addr) <= 0) {
    fprintf (stderr, "cannot translate host '%s' in --nat-info\n", str);
    return -1;
  }
  if (inet_pton (AF_INET, str2, &g_addr) <= 0) {
    fprintf (stderr, "cannot translate host '%s' in --nat-info\n", str2);
    return -1;
  }
  if (nat_info_rules >= MAX_NAT_INFO_RULES) {
    fprintf (stderr, "too many rules in --nat-info\n");
    return -1;
  }
  nat_info[nat_info_rules][0] = ntohl (l_addr.s_addr);
  nat_info[nat_info_rules][1] = ntohl (g_addr.s_addr);
  return nat_info_rules++;
}

unsigned nat_translate_ip (unsigned local_ip) {
  int i;
  vkprintf (6, "nat_info: %d rules\n", nat_info_rules);
  for (i = 0; i < nat_info_rules; i++) {
    vkprintf (6, "nat_info rule #%d: %s to %s\n", i, show_ip (nat_info[i][0]), show_ip (nat_info[i][1]));
    if (nat_info[i][0] == local_ip) {
      vkprintf (4, "translating ip by nat_info rules: %s to %s\n", show_ip (local_ip), show_ip (nat_info[i][1]));
      return nat_info[i][1];
    }
  }
  return local_ip;
}
