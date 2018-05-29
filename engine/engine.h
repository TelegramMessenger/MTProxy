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

    Copyright 2013 Vkontakte Ltd
              2013 Vitaliy Valtman              
              2013 Anton Maydell
    
    Copyright 2014 Telegram Messenger Inc             
              2014 Vitaly Valtman     
              2014 Anton Maydell
    
    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaliy Valtman
*/

#pragma once

// GLIBC DEFINES RTMAX as function
// engine_init () asserts, that OUT_SIGRTMAX == SIGRTMAX
#define OUR_SIGRTMAX 64

#include "common/common-stats.h"
#include "engine/engine-rpc.h"
#include "common/tl-parse.h"

#include "net/net-connections.h"
#include "net/net-tcp-rpc-server.h"
#include "net/net-http-server.h"

#define DEFAULT_LONG_QUERY_THRES 0.1

#define SIG2INT(sig) (((sig) == 64) ? 1ull : (1ull << (unsigned long long)(sig)))
#define SIG_INTERRUPT_MASK (SIG2INT(SIGTERM) | SIG2INT(SIGINT))

extern double precise_now_diff;

#pragma pack(push,4)

struct rpc_custom_op {
  unsigned op;
  void (*func)(struct tl_in_state *tlio_in, struct query_work_params *params);
};

#pragma pack(pop)

#define ENGINE_NO_AUTO_APPEND 2
#define ENGINE_NO_PORT 4

#define ENGINE_ENABLE_IPV6 0x4ull
#define ENGINE_ENABLE_TCP 0x10ull
#define ENGINE_ENABLE_MULTITHREAD 0x1000000ull
#define ENGINE_ENABLE_SLAVE_MODE 0x2000000ull

#define ENGINE_DEFAULT_ENABLED_MODULES (ENGINE_ENABLE_TCP)

typedef struct {
  void (*cron) (void);
  void (*precise_cron) (void);
  void (*on_exit) (void);
  int (*on_waiting_exit) (void); //returns 0 -> stop wait and exit, X > 0 wait X microsenconds */
  void (*on_safe_quit) (void);

  void (*close_net_sockets) (void);

  unsigned long long flags;
  unsigned long long allowed_signals;
  unsigned long long forbidden_signals;
  unsigned long long default_modules;
  unsigned long long default_modules_disabled;
  
  void (*prepare_stats)(stats_buffer_t *sb);

  void (*prepare_parse_options)(void);
  int (*parse_option)(int val);
  void (*parse_extra_args)(int count, char *args[]);

  void (*pre_init)(void);

  void (*pre_start)(void);

  void (*pre_loop)(void);
  int (*run_script)(void);

  const char *FullVersionStr;
  const char *ShortVersionStr;

  int epoll_timeout;
  double aio_timeout;

  struct tl_act_extra *(*parse_function) (struct tl_in_state *tlio_in, long long actor_id);
  int (*get_op)(struct tl_in_state *tlio_in);

  void (*signal_handlers[65])(void);
  struct rpc_custom_op *custom_ops;

  struct tcp_rpc_server_functions *tcp_methods;

  conn_type_t *http_type;
  struct http_server_functions *http_functions;

  int cron_subclass;
  int precise_cron_subclass;
} server_functions_t;

typedef struct {
  struct in_addr settings_addr;
  int do_not_open_port;
  int epoll_wait_timeout;
  int sfd;

  unsigned long long modules;
  int port;
  int start_port, end_port;

  int backlog;
  int maxconn;
  int required_io_threads;
  int required_cpu_threads;
  int required_tcp_cpu_threads;
  int required_tcp_io_threads;
  
  char *aes_pwd_file;

  server_functions_t *F;
} engine_t;

typedef struct event_precise_cron {
  struct event_precise_cron *next, *prev;
  void (*wakeup)(struct event_precise_cron *arg);
} event_precise_cron_t;

void precise_cron_function_insert (struct event_precise_cron *ev);
void precise_cron_function_remove (struct event_precise_cron *ev);

void set_signals_handlers (void);
void engine_init (const char *const pwd_filename, int do_not_open_port);
void engine_set_epoll_wait_timeout (int epoll_wait_timeout);
int signal_check_pending_and_clear (int sig);
int signal_check_pending (int sig);
void signal_set_pending (int sig);

#define ENGINE_FLAG_PARAM(name,flag) \
  static inline void engine_enable_ ## name (void) { engine_state->modules |= ENGINE_ENABLE_ ## flag; } \
  static inline void engine_disable_ ## name (void) { engine_state->modules &= ~ENGINE_ENABLE_ ## flag; } \
  static inline int engine_check_ ## name ## _enabled (void) { return (engine_state->modules & ENGINE_ENABLE_ ## flag) != 0; } \
  static inline int engine_check_ ## name ## _disabled (void) { return (engine_state->modules & ENGINE_ENABLE_ ## flag) == 0; } \

#define ENGINE_STR_PARAM(name,field) \
  static inline void engine_set_ ## name (const char *s) { \
    if (engine_state->field) { \
      free (engine_state->field); \
    } \
    engine_state->field = s ? strdup (s) : NULL; \
  } \
  static inline const char *engine_get_ ## name (void) { \
    return engine_state->field; \
  } \


#define ENGINE_T_PARAM(type,name,field) \
  static inline void engine_set_ ## name (type s) { \
    engine_state->field = s;\
  } \
  static inline type engine_get_ ## name (void) { \
    return engine_state->field; \
  } \

#define ENGINE_INT_PARAM(name,field) ENGINE_T_PARAM(int,name,field)
#define ENGINE_DOUBLE_PARAM(name,field) ENGINE_T_PARAM(double,name,field)
#define ENGINE_LONG_PARAM(name,field) ENGINE_T_PARAM(long long,name,field)

extern engine_t *engine_state;

ENGINE_FLAG_PARAM(ipv6,IPV6)
ENGINE_FLAG_PARAM(tcp,TCP)

ENGINE_FLAG_PARAM(multithread,MULTITHREAD)
ENGINE_FLAG_PARAM(slave_mode,SLAVE_MODE)

ENGINE_STR_PARAM(aes_pwd_file,aes_pwd_file) 
 
ENGINE_INT_PARAM(backlog,backlog);
ENGINE_INT_PARAM(required_io_threads,required_io_threads);
ENGINE_INT_PARAM(required_cpu_threads,required_cpu_threads);
ENGINE_INT_PARAM(required_tcp_cpu_threads,required_tcp_cpu_threads);
ENGINE_INT_PARAM(required_tcp_io_threads,required_tcp_io_threads);

void reopen_logs (void);
int default_main (server_functions_t *F, int argc, char *argv[]);
void default_parse_extra_args (int argc, char *argv[]);
void engine_tl_init (struct tl_act_extra *(*parse)(struct tl_in_state *,long long), void (*stat)(), int (get_op)(struct tl_in_state *), double timeout, const char *name);
void server_init (conn_type_t *listen_connection_type, void *listen_connection_extra);
void usage (void);

extern engine_t *engine_state;
