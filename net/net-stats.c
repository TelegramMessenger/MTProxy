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
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "net/net-connections.h"
#include "net/net-config.h"
#include "vv/vv-io.h"
#include "pid.h"
#include "common/common-stats.h"

#include "net/net-msg-buffers.h"

#include "engine/engine.h"

struct process_id PID;

extern int zheap_debug;
long long queries_allocated;
long long max_queries_allocated;
long long max_queries_allocated_sec;
long long max_queries_allocated_prev_sec;

long long total_vv_tree_nodes;

int tl_rpc_op_stat __attribute__ ((weak));
int op_stat_write (stats_buffer_t *sb) __attribute__ ((weak));
int op_stat_write (stats_buffer_t *sb) { return 0; }


int my_pid;

int connections_prepare_stat (stats_buffer_t *sb);
int udp_prepare_stat (stats_buffer_t *sb);
int tl_parse_prepare_stat (stats_buffer_t *sb);
int raw_msg_prepare_stat (stats_buffer_t *sb);
int raw_msg_buffer_prepare_stat (stats_buffer_t *sb);
int crypto_aes_prepare_stat (stats_buffer_t *sb);
int crypto_dh_prepare_stat (stats_buffer_t *sb);
int jobs_prepare_stat (stats_buffer_t *sb);
int aio_prepare_stat (stats_buffer_t *sb);
int mp_queue_prepare_stat (stats_buffer_t *sb);
int timers_prepare_stat (stats_buffer_t *sb);
int rpc_targets_prepare_stat (stats_buffer_t *sb);

//static double safe_div (double x, double y) { return y > 0 ? x/y : 0; }

int recent_idle_percent (void) {
  return a_idle_quotient > 0 ? a_idle_time / a_idle_quotient * 100 : a_idle_time;
}

extern long long epoll_calls;
extern long long epoll_intr;
extern long long event_timer_insert_ops;
extern long long event_timer_remove_ops;

extern long long long_queries_cnt;
extern long long long_cpu_queries_cnt;

int prepare_stats (char *buff, int buff_size) {
  if (buff_size <= 0) {
    /* (SIGSEGV guard)                                */
    /* in snprintf function second arg type is size_t */
    return 0;
  }
  double um = get_utime_monotonic ();
  stats_buffer_t sb;
  sb_init (&sb, buff, buff_size);

  if (!my_pid) {
    my_pid = getpid ();
  }
  int uptime = now - start_time;

  sb_printf (&sb,
      "pid\t%d\n"
      "start_time\t%d\n"
      "current_time\t%d\n"
      "uptime\t%d\n"
      "tot_idle_time\t%.3f\n"
      "average_idle_percent\t%.3f\n"
      "recent_idle_percent\t%.3f\n"
      "active_network_events\t%d\n"
      "time_after_epoll\t%.6f\n"
      "epoll_calls\t%lld\n"
      "epoll_intr\t%lld\n"
      "PID\t" PID_PRINT_STR "\n"
      ,
      my_pid,
      start_time,
      now,
      uptime,
      tot_idle_time,
      uptime > 0 ? tot_idle_time / uptime * 100 : 0,
      a_idle_quotient > 0 ? a_idle_time / a_idle_quotient * 100 : a_idle_time,
      ev_heap_size,
      get_utime (CLOCK_MONOTONIC) - last_epoll_wait_at,
      epoll_calls,
      epoll_intr,
      PID_TO_PRINT (&PID)
      );


  connections_prepare_stat (&sb);
  raw_msg_prepare_stat (&sb);
  raw_msg_buffer_prepare_stat (&sb);
  tl_parse_prepare_stat (&sb);
  crypto_aes_prepare_stat (&sb);
  crypto_dh_prepare_stat (&sb);
  jobs_prepare_stat (&sb);
  mp_queue_prepare_stat (&sb);
  timers_prepare_stat (&sb);
  rpc_targets_prepare_stat (&sb);

  sb_printf (&sb,
    "stats_generate_time\t%.6f\n",
    get_utime_monotonic () - um);
  return sb.pos;
}

void output_std_stats (void) {
  static char debug_stats[1 << 20];
  int len = prepare_stats (debug_stats, sizeof (debug_stats) - 1);
  if (len > 0) {
    kprintf ("-------------- network statistics ------------\n%s\n-------------------------------------\n", debug_stats);
  }
}
