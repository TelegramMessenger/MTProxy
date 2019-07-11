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

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>

#include "common/common-stats.h"
#include "common/kprintf.h"
#include "common/precise-time.h"
#include "common/server-functions.h"
#include "common/tl-parse.h"

#include "engine/engine.h"
#include "engine/engine-net.h"
#include "engine/engine-rpc.h"
#include "engine/engine-signals.h"

#include "jobs/jobs.h"

#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-msg-buffers.h"
#include "net/net-thread.h"

#include "vv/vv-io.h"


#define DEFAULT_EPOLL_WAIT_TIMEOUT 37

char *local_progname;

double precise_now_diff;

engine_t *engine_state;

unsigned char server_ipv6[16];

void default_cron (void) {
  double new_precise_now_diff = get_utime_monotonic () - get_double_time ();
  precise_now_diff = precise_now_diff * 0.99 + 0.01 * new_precise_now_diff;
}

static void default_nop (void) {}

static int default_parse_option (int val) {
  return -1;
}

/* {{{ SIGNAL ACTIONS */
static void default_sighup (void) {
}

static void default_sigusr1 (void) {
  reopen_logs_ext (engine_check_slave_mode_enabled ());
}


static void default_sigrtmax_9 (void) {
}

static void default_sigrtmax_8 (void) {
}

static void default_sigrtmax_4 (void) {
}

static void default_sigrtmax_1 (void) {
}

static void default_sigrtmax (void) {
}
/* }}} */

void set_signals_handlers (void) /* {{{ */ {
  ksignal (SIGINT, sigint_immediate_handler);
  ksignal (SIGTERM, sigterm_immediate_handler);

  set_debug_handlers ();
}
/* }}} */


/* {{{ PIPE TO WAKEUP MAIN THREAD */
static int pipe_read_end;
static int pipe_write_end;

void create_main_thread_pipe (void) {
  int p[2];
  if (pipe_read_end > 0) {
    /* used in copyexec sending results child process */
    vkprintf (2, "%s: closing #%d pipe read end file descriptor.\n", __func__, pipe_read_end);
    close (pipe_read_end);
  }
  if (pipe_write_end > 0) {
    vkprintf (2, "%s: closing #%d pipe write end file descriptor.\n", __func__, pipe_write_end);
    close (pipe_write_end);
  }
  assert (pipe2 (p, O_NONBLOCK) >= 0);
  pipe_read_end = p[0];
  pipe_write_end = p[1];
}

void wakeup_main_thread (void) {
  if (!pipe_write_end) { return; }
  int x = 0;
  int r = write (pipe_write_end, &x, 4);
  if (r < 0) { assert (errno == EINTR || errno == EAGAIN); }
}

static int epoll_nop (int fd, void *data, event_t *ev) {
  int x[100];
  while (read (fd, x, 400) == 400) {}
  return EVA_CONTINUE;
}
/* }}} */


const char *get_version_string_override (void) __attribute__ ((weak));
const char *get_version_string_override (void) {
  return "unknown compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__;
}

const char *get_version_string (void) {
  if (engine_state && engine_state->F && engine_state->F->FullVersionStr) {
    return engine_state->F->FullVersionStr;
  } else {
    return get_version_string_override ();
  }
}

void engine_set_epoll_wait_timeout (int epoll_wait_timeout) /* {{{ */ {
  assert (1 <= epoll_wait_timeout && epoll_wait_timeout <= 1000);
  engine_state->epoll_wait_timeout = epoll_wait_timeout;
}
/* }}} */

static void raise_file_limit (int maxconn) /* {{{ */ {
  const int gap = 16;
  if (getuid ()) {
    struct rlimit rlim;
    if (getrlimit (RLIMIT_NOFILE, &rlim) < 0) {
      kprintf ("%s: getrlimit (RLIMIT_NOFILE) fail. %m\n", __func__);
      exit (1);
    }
    if (maxconn > rlim.rlim_cur - gap) {
      maxconn = rlim.rlim_cur - gap;
    }
    tcp_set_max_connections (maxconn);
  } else {
    if (raise_file_rlimit (maxconn + gap) < 0) {
      kprintf ("fatal: cannot raise open file limit to %d\n", maxconn + gap);
      exit (1);
    }
  }
}
/* }}} */

/* {{{ engine_init */ 

void engine_init (const char *const pwd_filename, int do_not_open_port) {
  engine_t *E = engine_state;

  if (!do_not_open_port) {
    engine_do_open_port ();
  }

  raise_file_limit (E->maxconn);

  int aes_load_res = aes_load_pwd_file (pwd_filename);
  if (aes_load_res < 0 && (aes_load_res != -0x80000000 || pwd_filename)) {
    kprintf ("fatal: cannot load secret definition file `%s'\n", pwd_filename);
    exit (1);
  }

  if (change_user_group (username, groupname) < 0) {
    kprintf ("fatal: cannot change user to %s\n", username ? username : "(none)");
    exit (1);
  }



  if (!do_not_open_port && E->port <= 0 && E->start_port <= E->end_port) {
    E->port = try_open_port_range (E->start_port, E->end_port, 100, get_port_mod (), 1);
    assert (E->port >= 0);
  }
  
  unsigned int ipv4 = 0;

  if (E->settings_addr.s_addr) {
    ipv4 = ntohl (E->settings_addr.s_addr);
    if ((ipv4 >> 24) != 10) {
      kprintf ("Bad binded IP address " IP_PRINT_STR ", search in ifconfig\n", IP_TO_PRINT (ipv4));
      ipv4 = 0;
    }
  }
  init_server_PID (ipv4 ? ipv4 : get_my_ipv4 (), E->port);
  get_my_ipv6 (server_ipv6);
  init_msg_buffers (0);

  init_async_jobs ();
  
  int nc;
  nc = engine_get_required_io_threads ();
  if (nc <= 0) {
    nc = DEFAULT_IO_JOB_THREADS;
  }
  create_new_job_class (JC_IO, nc, nc);
  nc = engine_get_required_cpu_threads ();
  if (nc <= 0) {
    nc = DEFAULT_CPU_JOB_THREADS;
  }
  create_new_job_class (JC_CPU, nc, nc);
  
  if (engine_check_multithread_enabled ()) {
    int nc;
    nc = engine_get_required_tcp_cpu_threads ();
    if (nc <= 0) {
      nc = 1;
    }
    create_new_job_class (JC_CONNECTION, nc, nc);
    nc = engine_get_required_tcp_io_threads ();
    if (nc <= 0) {
      nc = 1;
    }
    create_new_job_class (JC_CONNECTION_IO, nc, nc);
    create_new_job_class (JC_ENGINE, 1, 1);
  }

  create_main_thread_pipe ();
  alloc_timer_manager (JC_EPOLL);
  notification_event_job_create ();
  
  kprintf ("Started as " PID_PRINT_STR "\n", PID_TO_PRINT (&PID));
}
/* }}} */

void server_init (conn_type_t *listen_connection_type, void *listen_connection_extra) /* {{{ */  {
  engine_t *E = engine_state;
  server_functions_t *F = E->F;
  assert (F && "server functions aren't defined");

  init_epoll ();
  
  epoll_sethandler (pipe_read_end, 0, epoll_nop, NULL);
  epoll_insert (pipe_read_end, EVT_READ | EVT_LEVEL);

  if (daemonize) {
    setsid ();
    reopen_logs_ext (engine_check_slave_mode_enabled ());
  }

  if (!E->do_not_open_port) {
    if (E->port <= 0) {
      kprintf ("fatal: port isn't defined\n");
      exit (1);
    }
    if (E->sfd <= 0) {
      assert (try_open_port (E->port, 1) >= 0);
    }
      
    if (engine_check_tcp_enabled ()) {
      if (!engine_check_ipv6_enabled ()) {
        assert (init_listening_connection (E->sfd, listen_connection_type, listen_connection_extra) >= 0);
      } else {
        assert (init_listening_tcpv6_connection (E->sfd, listen_connection_type, listen_connection_extra, SM_IPV6) >= 0);
      }
    }
    
  }

  ksignal (SIGINT,  sigint_handler);
  ksignal (SIGTERM, sigterm_handler);
  ksignal (SIGPIPE, empty_signal_handler);
  ksignal (SIGPOLL, empty_signal_handler);

  if (daemonize) {
    ksignal (SIGHUP, default_signal_handler);
  }
}
/* }}} */

void server_exit (void) /* {{{ */ {
  engine_t *E = engine_state;
  server_functions_t *F = E->F;
  
  F->close_net_sockets ();

  if (signal_check_pending (SIGTERM)) {
    kprintf ("Terminated by SIGTERM.\n");
  } else if (signal_check_pending (SIGINT)) {
    kprintf ("Terminated by SIGINT.\n");
  }
}
/* }}} */

/* {{{ precise cron */ 

struct event_precise_cron precise_cron_events = {
  .next = &precise_cron_events,
  .prev = &precise_cron_events
};

void precise_cron_function_insert (struct event_precise_cron *ev) {
  ev->next = &precise_cron_events;
  ev->prev = precise_cron_events.prev;
  ev->next->prev = ev->prev->next = ev;
}

void precise_cron_function_remove (struct event_precise_cron *ev) {
  ev->next->prev = ev->prev;
  ev->prev->next = ev->next;
  ev->prev = ev->next = NULL;
}

static void do_precise_cron (void) {
  engine_t *E = engine_state;
  server_functions_t *F = E->F;
  engine_process_signals ();
  
  static int last_cron_time;
  if (last_cron_time != now) {
    last_cron_time = now;
    F->cron ();
  }
  
  if (F->precise_cron) {
    F->precise_cron ();
  }
  
  if (precise_cron_events.next != &precise_cron_events) {
    struct event_precise_cron ev = precise_cron_events;
    ev.next->prev = &ev;
    ev.prev->next = &ev;
    precise_cron_events.next = precise_cron_events.prev = &precise_cron_events;
    while (ev.next != &ev) {
      struct event_precise_cron *e = ev.next;
      ev.next->wakeup (ev.next);
      if (e == ev.next) {
        precise_cron_function_remove (e);
        precise_cron_function_insert (e);
      }
    }
  }

  free_later_act ();
}
/* }}} */

double update_job_stats_gw (void *ex) {
  update_all_thread_stats ();
  return 10 + precise_now;
}

struct precise_cron_job_extra {
  struct event_timer ev;
};

int precise_cron_job_run (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  if (op != JS_RUN && op != JS_ALARM) {
    return JOB_ERROR;
  }
  if (op == JS_ALARM && !job_timer_check (job)) {
    return 0;
  }

  do_precise_cron ();
  job_timer_insert (job, precise_now + 0.001 * (1 + drand48_j ()));
  return 0;
}
/* }}} */ 

int terminate_job_run (job_t job, int op, struct job_thread *JT) {
  if (op == JS_RUN) {
    engine_t *E = engine_state;
    server_functions_t *F = E->F;

    if (F->on_exit) {
      F->on_exit ();
    }
    server_exit ();
    exit (0);
    return 0;
  }
  return JOB_ERROR;
}

void default_engine_server_start (void) /* {{{ */ {
  engine_t *E = engine_state;
  server_functions_t *F = E->F;

  engine_server_init ();

  vkprintf (1, "Server started\n");

  register_custom_op_cb (RPC_REQ_RESULT, engine_work_rpc_req_result);
  if (F->custom_ops) {
    struct rpc_custom_op *O = F->custom_ops;
    while (O->op) {
      register_custom_op_cb (O->op, O->func);
      O ++;
    }
  }

  job_t precise_cron_job = create_async_job (precise_cron_job_run, JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ALARM) | JSC_ALLOW (JC_ENGINE, JS_FINISH), F->cron_subclass, sizeof (struct precise_cron_job_extra), JT_HAVE_TIMER, JOB_REF_NULL);
  //struct precise_cron_job_extra *e = (void *)precise_cron_job->j_custom;
  //memset (e, 0, sizeof (*e)); /* no need, create_async_job memsets itself */
  precise_cron_job->j_refcnt ++;
  schedule_job (JOB_REF_PASS (precise_cron_job));

  job_t update_job_stats = job_timer_alloc (JC_MAIN, update_job_stats_gw, NULL);
  job_timer_insert (update_job_stats, 1.0);

  F->pre_loop ();

  job_t terminate_job = create_async_job (terminate_job_run, JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_FINISH), -1, 0, 0, JOB_REF_NULL);
  unlock_job (JOB_REF_CREATE_PASS (terminate_job));

  int i;
  vkprintf (0, "main loop\n");
  for (i = 0; ; i++) {
    epoll_work (engine_check_multithread_enabled () ? E->epoll_wait_timeout : 1);
    if (interrupt_signal_raised ()) {
      if (F->on_waiting_exit) {
        while (1) {
          useconds_t t = F->on_waiting_exit ();
          if (t <= 0) {
            break;
          }
          usleep (t);
          run_pending_main_jobs ();
        }
      }
      if (terminate_job) {
        job_signal (JOB_REF_PASS (terminate_job), JS_RUN);
        run_pending_main_jobs ();
      }
      break;
    }
    
    run_pending_main_jobs ();
  }
  sleep (120);
  kprintf ("Did not exit after 120 seconds\n");
  assert (0);
}
/* }}} */


#define DATA_BUF_SIZE (1 << 20)
static char data_buf[DATA_BUF_SIZE + 1];

int engine_prepare_stats (void) {
  if (!engine_state) { return 0; }
  stats_buffer_t sb;
  sb_init (&sb, data_buf, DATA_BUF_SIZE);
  if (engine_state->F->prepare_stats) {
    engine_state->F->prepare_stats (&sb);
  }
  return sb.pos;
}

void engine_rpc_stats (struct tl_out_state *tlio_out) {
  engine_prepare_stats ();
  tl_store_stats (tlio_out, data_buf, 0);
}

void output_engine_stats (void) {
  int len = engine_prepare_stats ();
  if (len > 0) {
    kprintf ("-------------- network/memcache statistics ------------\n");
    kwrite (2, data_buf, len);
  }
}

int default_get_op (struct tl_in_state *tlio_in) {
  return tl_fetch_lookup_int ();
}

void usage ();

void check_signal_handler (server_functions_t *F, int sig, void (*default_f)(void)) {
  if (F->allowed_signals & SIG2INT(sig)) {
    if (!F->signal_handlers[sig]) {
      F->signal_handlers[sig] = default_f;
    }
  }
}

unsigned long long default_signal_mask = SIG2INT(SIGHUP) | SIG2INT(SIGUSR1) | SIG2INT(OUR_SIGRTMAX) | SIG2INT(OUR_SIGRTMAX-1) | SIG2INT(OUR_SIGRTMAX-4) | SIG2INT(OUR_SIGRTMAX-8) | SIG2INT(OUR_SIGRTMAX-9);

static void check_server_functions (void) /* {{{ */ {
  engine_t *E = engine_state;
  server_functions_t *F = E->F;
  F->allowed_signals = (F->allowed_signals | default_signal_mask) & ~F->forbidden_signals;

  check_signal_handler (F, SIGHUP, default_sighup);
  check_signal_handler (F, SIGUSR1, default_sigusr1);
  check_signal_handler (F, SIGRTMAX-9, default_sigrtmax_9);
  check_signal_handler (F, SIGRTMAX-8, default_sigrtmax_8);
  check_signal_handler (F, SIGRTMAX-4, default_sigrtmax_4);
  check_signal_handler (F, SIGRTMAX-1, default_sigrtmax_1);
  check_signal_handler (F, SIGRTMAX, default_sigrtmax);

  if (!F->close_net_sockets) { F->close_net_sockets = default_close_network_sockets; }
  if (!F->cron) { F->cron = default_cron; }
  if (!F->parse_option) { F->parse_option = default_parse_option; }
  if (!F->prepare_parse_options) { F->prepare_parse_options = default_nop; }
  if (!F->pre_init) { F->pre_init = default_nop; }
  if (!F->pre_start) { F->pre_start = default_nop; }
  if (!F->parse_extra_args) { F->parse_extra_args = default_parse_extra_args; }
  if (!F->pre_loop) { F->pre_loop = default_nop; }

  if (!F->epoll_timeout) { F->epoll_timeout = 1; }
  if (!F->aio_timeout) { F->aio_timeout = 0.5; }

  if (!F->get_op) { F->get_op = default_get_op; }
  
  int i;
  for (i = 1; i <= 64; i++) {
    if (F->allowed_signals & SIG2INT (i)) {
      //fix log spamming hack for image-engine: 
      ksignal (i, i == SIGCHLD ? quiet_signal_handler : default_signal_handler);
    }
  }
}
/* }}} */

void engine_startup (engine_t *E, server_functions_t *F) /* {{{ */ {
  E->F = F;
  E->modules = (ENGINE_DEFAULT_ENABLED_MODULES | F->default_modules) & ~F->default_modules_disabled;
  engine_set_backlog (DEFAULT_BACKLOG);
  tcp_set_default_rpc_flags (0xffffffff, RPCF_USE_CRC32C);
  E->port = -1;

  precise_now_diff = get_utime_monotonic () - get_double_time ();

  assert (SIGRTMAX == OUR_SIGRTMAX);
  assert (SIGRTMAX - SIGRTMIN >= 20);
  
  E->sfd = 0;
  E->epoll_wait_timeout = DEFAULT_EPOLL_WAIT_TIMEOUT;
  E->maxconn = MAX_CONNECTIONS;

  check_server_functions ();
}
/* }}} */ 

int default_main (server_functions_t *F, int argc, char *argv[]) {
  set_signals_handlers ();

  engine_t *E = calloc (sizeof (*E), 1);
  engine_state = E;

  engine_startup (E, F);
  engine_set_epoll_wait_timeout (F->epoll_timeout);

  if (F->tcp_methods) {
    engine_set_tcp_methods (F->tcp_methods);
  }
  if (F->http_functions) {
    conn_type_t *H = F->http_type;
    if (!H) {
      H = &ct_http_server;
    }
    assert (check_conn_functions (H, 1) >= 0);
    engine_set_http_fallback (H, F->http_functions);
  }


  kprintf ("Invoking engine %s\n", F->FullVersionStr);


  progname = argv[0];
  local_progname = argv[0];

  add_builtin_parse_options ();

  F->prepare_parse_options ();
  
  parse_engine_options_long (argc, argv);

  F->parse_extra_args (argc - optind, argv + optind);

  E->do_not_open_port = (F->flags & ENGINE_NO_PORT);

  F->pre_init ();

  engine_init (engine_get_aes_pwd_file (), E->do_not_open_port);

  vkprintf (3, "Command line parsed\n");

  F->pre_start ();
  
  start_time = time (NULL);

  if (F->run_script) {
    int r = F->run_script ();
    if (r >= 0) {
      return 0;
    } else {
      return -r;
    }
  }

  engine_tl_init (F->parse_function, engine_rpc_stats, F->get_op, F->aio_timeout, F->ShortVersionStr);
  init_epoll ();
  default_engine_server_start ();

  return 0;
}

    
static int f_parse_option_engine (int val) {
  switch (val) {
    case 227:
      engine_set_required_cpu_threads (atoi (optarg));
      break;
    case 228:
      engine_set_required_io_threads (atoi (optarg));
      break;
    case 258:
      if (optarg && atoi (optarg) == 0) {
        engine_disable_multithread ();
      } else {
        engine_enable_multithread ();
        epoll_sleep_ns = 10000;
      }
      break;
    case 301:
      engine_set_required_tcp_cpu_threads (atoi (optarg));
      break;
    case 302:
      engine_set_required_tcp_io_threads (atoi (optarg));
      break;
    default:
      return -1;
  }
  return 0;
}

static void parse_option_engine_builtin (const char *name, int arg, int *var, int val, unsigned flags, const char *help, ...) __attribute__ ((format (printf, 6, 7)));
static void parse_option_engine_builtin (const char *name, int arg, int *var, int val, unsigned flags, const char *help, ...) {
  char *h;
  va_list ap;
  va_start (ap, help);
  assert (vasprintf (&h, help, ap) >= 0);
  va_end (ap);

  parse_option_ex (name, arg, var, val, flags, f_parse_option_engine, "%s", h);

  free (h);
}

void engine_add_engine_parse_options (void) {
  parse_option_engine_builtin ("cpu-threads", required_argument, 0, 227, LONGOPT_JOBS_SET, "Number of CPU threads (1-64, default 8)");
  parse_option_engine_builtin ("io-threads", required_argument, 0, 228, LONGOPT_JOBS_SET,  "Number of I/O threads (1-64, default 16)");
  parse_option_engine_builtin ("multithread", optional_argument, 0, 258, LONGOPT_JOBS_SET, "run in multithread mode");
  parse_option_engine_builtin ("tcp-cpu-threads", required_argument, 0, 301, LONGOPT_JOBS_SET, "number of tcp-cpu threads");
  parse_option_engine_builtin ("tcp-iothreads", required_argument, 0, 302, LONGOPT_JOBS_SET, "number of tcp-io threads");
}

void default_parse_extra_args (int argc, char *argv[]) /* {{{ */ {
  if (argc != 0) {
    vkprintf (0, "Extra args\n");
    usage ();
  }
}
/*}}}*/

int default_parse_option_func (int a) {
  if (engine_state) {
    server_functions_t *F = engine_state->F;
    if (F->parse_option) {
      return F->parse_option (a);
    } else {
      return -1;
    }
  } else {
    return -1;
  }
}

