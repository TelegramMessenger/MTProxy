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
              2011-2013 Oleg Davydov
              2012-2013 Arseny Smirnov
              2012-2013 Aliaksei Levin
              2012-2013 Anton Maydell
                   2013 Vitaliy Valtman

    Copyright 2014-2018 Telegram Messenger Inc
              2014-2018 Vitaly Valtman
*/


#define _FILE_OFFSET_BITS 64

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>

#include "common/kprintf.h"
#include "net/net-connections.h"
#include "net/net-events.h"
#include "net/net-msg-buffers.h"

#include "server-functions.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)


long long max_allocated_buffer_bytes __attribute__ ((weak));

int engine_options_num;
char *engine_options[MAX_ENGINE_OPTIONS];


int start_time;

int daemonize = 0;
const char *username, *progname, *groupname;

int change_user_group (const char *username, const char *groupname) {
  struct passwd *pw;
  /* lose root privileges if we have them */
  if (getuid() == 0 || geteuid() == 0) {
    if (username == 0 || *username == '\0') {
      username = DEFAULT_ENGINE_USER;
    }
    if ((pw = getpwnam (username)) == 0) {
      kprintf ("change_user_group: can't find the user %s to switch to\n", username);
      return -1;
    }
    gid_t gid = pw->pw_gid;
    if (setgroups (1, &gid) < 0) {
      kprintf ("change_user_group: failed to clear supplementary groups list: %m\n");
      return -1;
    }

    if (groupname) {
      struct group *g = getgrnam (groupname);
      if (g == NULL) {
        kprintf ("change_user_group: can't find the group %s to switch to\n", groupname);
        return -1;
      }
      gid = g->gr_gid;
    }

    if (setgid (gid) < 0) {
      kprintf ("change_user_group: setgid (%d) failed. %m\n", (int) gid);
      return -1;
    }

    if (setuid (pw->pw_uid) < 0) {
      kprintf ("change_user_group: failed to assume identity of user %s\n", username);
      return -1;
    }
  }
  return 0;
}

int change_user (const char *username) {
  struct passwd *pw;
  /* lose root privileges if we have them */
  if (getuid() == 0 || geteuid() == 0) {
    if (username == 0 || *username == '\0') {
      username = DEFAULT_ENGINE_USER;
//      fprintf (stderr, "can't run as root without the -u switch\n");
//      return -1;
    }
    if ((pw = getpwnam (username)) == 0) {
      kprintf ("can't find the user %s to switch to\n", username);
      return -1;
    }
    gid_t gid = pw->pw_gid;
    if (setgroups(1, &gid) < 0) {
      kprintf ("failed to clear supplementary groups list: %m\n");
      return -1;
    }
    if (initgroups(username, gid) != 0) {
      kprintf ("failed to load groups of user %s: %m\n", username);
      return -1;
    }
    if (setgid (pw->pw_gid) < 0 || setuid (pw->pw_uid) < 0) {
      kprintf ("failed to assume identity of user %s\n", username);
      return -1;
    }
  }
  return 0;
}

int raise_file_rlimit (int maxfiles) {
  struct rlimit rlim;
  
  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    kprintf ("failed to getrlimit number of files\n");
    return -1;
  } else {
    if (rlim.rlim_cur < maxfiles)
      rlim.rlim_cur = maxfiles + 3;
    if (rlim.rlim_max < rlim.rlim_cur)
      rlim.rlim_max = rlim.rlim_cur;
    if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
      kprintf ("failed to set rlimit for open files. Try running as root or requesting smaller maxconns value.\n");
      return -1;
    }
  }
  return 0;
}


const char *get_version_string (void) __attribute__ ((weak));
const char *get_version_string (void) {
  return "unknown compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__;
}

void print_backtrace (void) {
  void *buffer[64];
  int nptrs = backtrace (buffer, 64);
  kwrite (2, "\n------- Stack Backtrace -------\n", 33);
  backtrace_symbols_fd (buffer, nptrs, 2);
  kwrite (2, "-------------------------------\n", 32);
  const char *s = get_version_string ();
  if (s) {
    kwrite (2, s, strlen (s));
    kwrite (2, "\n", 1);
  }
}

pthread_t debug_main_pthread_id;

void kill_main (void) {
  if (debug_main_pthread_id && debug_main_pthread_id != pthread_self ()) {
    pthread_kill (debug_main_pthread_id, SIGABRT);
  }
}

//can be called inside signal handler
void ksignal (int sig, void (*handler) (int)) {
  struct sigaction act;
  sigemptyset (&act.sa_mask);
  act.sa_flags = SA_ONSTACK | SA_RESTART;
  act.sa_handler = handler;

  if (sigaction (sig, &act, NULL) != 0) {
    kwrite (2, "failed sigaction\n", 17);
    //_exit (EXIT_FAILURE);
  }
}

void ksignal_ex (int sig, void (*handler) (int, siginfo_t *, void *)) {
  struct sigaction act;
  sigemptyset (&act.sa_mask);
  act.sa_flags = SA_ONSTACK | SA_RESTART | SA_SIGINFO;
  act.sa_sigaction = handler;

  if (sigaction (sig, &act, NULL) != 0) {
    kwrite (2, "failed sigaction\n", 17);
    _exit (EXIT_FAILURE);
  }
}

void queries_log_store (void *N, int limit, int max_size, int max_entry_size, int plain) __attribute__ ((weak));
void queries_log_store (void *N, int limit, int max_size, int max_entry_size, int plain) {}

void engine_set_terminal_attributes (void) __attribute__ ((weak));
void engine_set_terminal_attributes (void) {}

void extended_debug_handler (int sig, siginfo_t *info, void *cont) {
  ksignal (sig, SIG_DFL);
  
  print_backtrace ();
    
  kill_main ();
  
  _exit (EXIT_FAILURE);
}

void set_debug_handlers (void) {
  ksignal_ex (SIGSEGV, extended_debug_handler);
  ksignal_ex (SIGABRT, extended_debug_handler);
  ksignal_ex (SIGFPE, extended_debug_handler);
  ksignal_ex (SIGBUS, extended_debug_handler);
  debug_main_pthread_id = pthread_self ();
}

void usage (void) __attribute ((weak));

void usage (void) {
  printf ("usage: %s <args>\n",
    progname ? progname : "SOMETHING");
  exit (2);
}

long long parse_memory_limit (const char *s) {
  long long x;
  char c = 0;
  if (sscanf (s, "%lld%c", &x, &c) < 1) {
    kprintf ("Parsing limit for option fail: %s\n", s);
    usage ();
    exit (1);
  }
  switch (c | 0x20) {
    case ' ': break;
    case 'k':  x <<= 10; break;
    case 'm':  x <<= 20; break;
    case 'g':  x <<= 30; break;
    case 't':  x <<= 40; break;
    default: 
      kprintf ("Parsing limit fail. Unknown suffix '%c'.\n", c); 
      usage ();
      exit (1);
  }
  return x;
}

struct engine_parse_option *engine_parse_options;
int engine_parse_options_size;
int engine_parse_options_num;

int find_parse_option (int val) {
  int i;
  for (i = 0; i < engine_parse_options_num; i++) {
    struct engine_parse_option *P = &engine_parse_options[i];
    int j;
    for (j = 0; j < P->val_cnt; j++) {
      if (P->vals[j] == val) {
        return i;
      }
    }
  }
  return -1;
}

int find_parse_option_name (const char *name) {
  int i;
  for (i = 0; i < engine_parse_options_num; i++) {
    struct engine_parse_option *P = &engine_parse_options[i];
    int j;
    for (j = 0; j < P->longopts_cnt; j++) {
      if (!strcmp (P->longopts[j], name)) {
        return i;
      }
    }
  }
  return -1;
}

int default_parse_option_func (int a) __attribute__ ((weak));
int default_parse_option_func (int a) { return -1; }

void parse_option_up (struct engine_parse_option *P) {
  struct engine_parse_option *Q = P - 1;
  while (Q >= engine_parse_options && Q->smallest_val > P->smallest_val) {
    Q --;
  }
  Q ++;
  if (Q != P) {
    struct engine_parse_option T;
    T = *P;
    memmove (Q + 1, Q, (P - Q) * sizeof (struct engine_parse_option));
    *Q = T;
  }
}

void parse_option_down (struct engine_parse_option *P) {
  struct engine_parse_option *Q = P + 1;
  while (Q < engine_parse_options + engine_parse_options_num && Q->smallest_val < P->smallest_val) {
    Q ++;
  }
  Q --;
  if (Q != P) {
    struct engine_parse_option T;
    T = *Q;
    memmove (P + 1, P, (P - Q) * sizeof (struct engine_parse_option));
    *P = T;
  }
}

void parse_option_internal (const char *name, int arg, int *var, int val, unsigned flags, int (*func)(int), char *help) {
  int p = find_parse_option (val);
  if (p >= 0) {
    kprintf ("duplicate parse option %d\n", val);    
    usage ();
  }
  assert (engine_parse_options_num <= engine_parse_options_size);
  if (engine_parse_options_num == engine_parse_options_size) {
    engine_parse_options_size = 10 + 2 * engine_parse_options_size;
    engine_parse_options = realloc (engine_parse_options, sizeof (struct engine_parse_option) * engine_parse_options_size);
  }
  assert (engine_parse_options_num < engine_parse_options_size);
  struct engine_parse_option *P = &engine_parse_options[engine_parse_options_num ++];
  P->arg = arg;
  P->flags = flags;
  P->func = func ? func : default_parse_option_func; 
  P->help = help;
    

  P->longopts = malloc (sizeof (void *));
  P->longopts[0] = name;
  P->longopts_cnt = 1;

  P->vals = malloc (sizeof (int));
  P->vals[0] = val;
  P->val_cnt = 1;
  P->smallest_val = val;
  P->base_val = val;

  parse_option_up (P);
}

void parse_option_ex (const char *name, int arg, int *var, int val, unsigned flags, int (*func)(int), const char *help, ...) {
  char *h;
  va_list ap;
  va_start (ap, help);
  assert (vasprintf (&h, help, ap) >= 0);
  va_end (ap);

  parse_option_internal (name, arg, var, val, flags, func, h);
}

void parse_option (const char *name, int arg, int *var, int val, const char *help, ...) {
  char *h;
  va_list ap;
  va_start (ap, help);
  assert (vasprintf (&h, help, ap) >= 0);
  va_end (ap);

  parse_option_internal (name, arg, var, val, LONGOPT_CUSTOM_SET, NULL, h);
}

int builtin_parse_option (int val);
void parse_option_builtin (const char *name, int arg, int *var, int val, unsigned flags, const char *help, ...) {
  parse_option_internal (name, arg, var, val, flags, builtin_parse_option, help ? strdup (help) : NULL);
}


void remove_parse_option_completely (int val) {
  int t = find_parse_option (val);
  assert (t >= 0);

  struct engine_parse_option *P = &engine_parse_options[t];

  assert (P->vals[0] == val);
  if (P->help) {
    free (P->help);
  }
  free (P->vals);
  free (P->longopts);
  memmove (engine_parse_options + t, engine_parse_options + t + 1, (engine_parse_options_num - t - 1) * sizeof (struct engine_parse_option));
  engine_parse_options_num --;
  return;
}

void remove_parse_option (int val) {
  int t = find_parse_option (val);
  if (t < 0) {
    kprintf ("Can not remove unknown option %d\n", val);
    usage ();
  }

  struct engine_parse_option *P = &engine_parse_options[t];

  if (P->val_cnt == 1) {
    assert (P->vals[0] == val);
    free (P->help);
    free (P->vals);
    free (P->longopts);
    memmove (engine_parse_options + t, engine_parse_options + t + 1, (engine_parse_options_num - t - 1) * sizeof (struct engine_parse_option));
    engine_parse_options_num --;
    return;
  }

  int *new_vals = malloc (4 * (P->val_cnt - 1));
  int i;
  int p = 0;
  for (i = 0; i < P->val_cnt; i++) {
    if (P->vals[i] != val) {
      new_vals[p ++] = P->vals[i];
    }
  }
  free (P->vals);
  P->vals = new_vals;
  P->val_cnt --;

  if (P->smallest_val == val) {
    P->smallest_val = 0x7fffffff;
    int i;
    for (i = 0; i < P->val_cnt; i++) {
      if (P->vals[i] < P->smallest_val) {
        P->smallest_val = P->vals[i];
      }
    }
    parse_option_down (P);
  }
  if (P->base_val == val) {
    P->base_val = P->smallest_val;
  }
}

void parse_option_alias (const char *name, int val) {
  int l = find_parse_option (val);
  if (l >= 0) {
    if (val >= 33 && val <= 127) {
      kprintf ("Duplicate option `%c`\n", (char)val);
    } else {
      kprintf ("Duplicate option %d\n", val);
    }
    usage ();
  }
  l = find_parse_option_name (name);
  if (l < 0) {
    kprintf ("can't find option '%s'\n", name);
    usage ();
  }

  struct engine_parse_option *P = &engine_parse_options[l];
  P->val_cnt ++;
  P->vals = realloc (P->vals, 4 * P->val_cnt);
  P->vals[P->val_cnt - 1] = val;
  if (val < P->smallest_val) {
    P->smallest_val = val;
    parse_option_up (P);
  }
}

void parse_option_long_alias (const char *name, const char *alias_name) {
  int l = find_parse_option_name (alias_name);
  if (l >= 0) {
    kprintf ("Duplicate option %s\n", alias_name);
    usage ();
  }
  l = find_parse_option_name (name);
  if (l < 0) {
    kprintf ("can't find option '%s'\n", name);
    usage ();
  }

  struct engine_parse_option *P = &engine_parse_options[l];
  P->longopts_cnt ++;
  P->longopts = realloc (P->longopts, sizeof (void *) * P->longopts_cnt);
  P->longopts[P->longopts_cnt - 1] = alias_name;
}

int parse_usage (void) {
  int max = 0;

  int i;
  for (i = 0; i < engine_parse_options_num; i++) {
    struct engine_parse_option *P = &engine_parse_options[i];
    int cur = 0;
    int j;
    for (j = 0; j < P->val_cnt; j++) {
      if (P->vals[j] <= 127) {
        cur += 3;
      }
    }
    for (j = 0; j < P->longopts_cnt; j++) {
      cur += strlen (P->longopts[j]) + 3;
    }
    
    if (P->arg == required_argument) {
      cur += 6;
    } else if (P->arg == optional_argument) {
      cur += 6;
    }
    if (cur > max) { 
      max = cur; 
    }
  }

  for (i = 0; i < engine_parse_options_num; i++) {
    struct engine_parse_option *P = &engine_parse_options[i];
    int cur = 0;
    printf ("\t");
    int j;
    for (j = 0; j < P->longopts_cnt; j++) {
      if (cur) {
        printf ("/");
        cur ++;
      }
      cur += strlen (P->longopts[j]) + 2;
      printf ("--%s", P->longopts[j]);
    }
    for (j = 0; j < P->val_cnt; j++) {
      if (P->vals[j] <= 127) {
        if (cur) {
          printf ("/");
          cur ++;
        }
        printf ("-%c", (char)P->vals[j]);
        cur += 2;
      }
    }
    if (P->arg == required_argument) {
      printf (" <arg>");
      cur += 6;
    } else if (P->arg == optional_argument) {
      printf (" {arg}");
      cur += 6;
    }
    while (cur < max) { 
      printf (" ");
      cur ++;
    }
    printf ("\t");
    if (P->help) {
      char *e = P->help;
      while (*e) {
        printf ("%c", *e);
        if (*e == '\n') {
          printf ("\t");
          int i;
          for (i = 0; i < max; i++) {
            printf (" ");
          }
          printf ("\t");
        }
        e ++;
      }
      printf ("\n");
//      printf ("%s\n", global_longopts_help[s]);
    } else {
      printf ("no help provided\n");
    }
  }
  return 0;
}

int builtin_parse_option (int val) {
  switch (val) {
    case 'v':
      if (!optarg) {
        verbosity++;
      } else {
        verbosity = atoi (optarg);
      }
      break;
    case 'h':
      usage ();
      exit (2);
    case 'u':
      if (username) {
        kprintf ("wrong option -u%s, username is already defined as '%s'.\n", optarg, username);
        exit (1);
      }
      username = optarg;
      break;
    case 'l':
      logname = optarg;
      break;
    case 'd':
      if (!optarg) {
        daemonize ^= 1;
      } else {
        daemonize = atoi (optarg) != 0;
      }
      break;
    case 202:
      errno = 0;
      if (nice (atoi (optarg)) == -1 && errno) {
        perror ("nice");
      }
      break;
    case 208:
      max_allocated_buffer_bytes = parse_memory_limit (optarg);
      break;
    default:
      return -1;
  }
  return 0;
}

int parse_one_option (int val) {
  int t = find_parse_option (val);
  if (t < 0) {
    return -1;
  }
  struct engine_parse_option *P = &engine_parse_options[t];
  return P->func (P->base_val);
}

int parse_engine_options_long (int argc, char **argv) {
  engine_options_num = argc;
  memcpy ((void *)engine_options, argv, sizeof (void *) * argc);

  int total_longopts = 0;
  int total_shortopts_len = 0;
  int i;
  for (i = 0; i < engine_parse_options_num; i++) {
    struct engine_parse_option *P = &engine_parse_options[i];
    total_longopts += P->longopts_cnt;
    int j;
    for (j = 0; j < P->val_cnt; j++) {
      if (P->vals[j] <= 127) {
        total_shortopts_len += (P->arg == required_argument) ? 2 : 1;
      }
    }
  }
  
  char *shortopts = malloc (total_shortopts_len + 1);
  assert (shortopts);
  struct option *longopts = malloc ((total_longopts + 1) * sizeof (struct option));
  int lpos = 0;
  int spos = 0;

  for (i = 0; i < engine_parse_options_num; i++) {
    struct engine_parse_option *P = &engine_parse_options[i];
    int j;

    for (j = 0; j < P->longopts_cnt; j++) {
      assert (lpos < total_longopts);
      longopts[lpos].flag = NULL;
      longopts[lpos].has_arg = P->arg;
      longopts[lpos].name = P->longopts[j];
      longopts[lpos].val = P->base_val;
      lpos ++;
    }

    for (j = 0; j < P->val_cnt; j++) {
      if (P->vals[j] <= 127) {
        assert (spos < total_shortopts_len);
        shortopts[spos ++] = P->vals[j];
        if (P->arg == required_argument) {
          assert (spos < total_shortopts_len);
          shortopts[spos ++] = ':';
        }
      }
    }
  }

  assert (lpos == total_longopts);
  memset (&longopts[lpos], 0, sizeof (struct option));
  assert (spos == total_shortopts_len);
  shortopts[spos] = 0;

  while (1) {
    int option_index = -1;
    int c = getopt_long (argc, argv, shortopts, longopts, &option_index);
    if (c == -1) { break; }
    if (!c) { continue; }
    if (c == '?') {
      kprintf ("Unrecognized option\n");
      usage ();
    }
    if (parse_one_option (c) < 0) {
      if (option_index >= 0) {
        assert (option_index < total_longopts);
        kprintf ("Can not parse option %s\n", longopts[option_index].name);
        usage ();
      } else if (c <= 127) {
        kprintf ("Can not parse option '%c'\n", (char)c);
        usage ();
      } else {
        kprintf ("Can not parse option %d\n", c);
        usage ();
      }
    }
  }
  return 0;
}

int in_keep_options_list (const unsigned *list, unsigned num) {
  if (!list) { return 0; }
  const unsigned *a = list;
  while (*a) {
    if (*a == num) { return 1; }
    a ++;
  }
  return 0;
}

void engine_add_net_parse_options (void) __attribute__ ((weak));
void engine_add_net_parse_options (void) {}
void engine_add_engine_parse_options (void) __attribute__ ((weak));
void engine_add_engine_parse_options (void) {}

void add_builtin_parse_options (void) {
  parse_option_builtin ("verbosity", optional_argument, 0, 'v', LONGOPT_COMMON_SET, "sets or increases verbosity level");
  parse_option_builtin ("help", no_argument, 0, 'h', LONGOPT_COMMON_SET, "prints help and exits");
  parse_option_builtin ("user", required_argument, 0, 'u', LONGOPT_COMMON_SET, "sets user name to make setuid");
  parse_option_builtin ("log", required_argument, 0, 'l', LONGOPT_COMMON_SET, "sets log file name");
  parse_option_builtin ("daemonize", optional_argument, 0, 'd', LONGOPT_COMMON_SET, "changes between daemonize/not daemonize mode");
  parse_option_builtin ("nice", required_argument, 0, 202, LONGOPT_COMMON_SET, "sets niceness");
  parse_option_ex ("msg-buffers-size", required_argument, 0, 208, LONGOPT_COMMON_SET, builtin_parse_option, "sets maximal buffers size (default %lld)", (long long)MSG_DEFAULT_MAX_ALLOCATED_BYTES);
  //parse_option_builtin ("tl-history", optional_argument, 0, 210, LONGOPT_NET_SET, "long },
  //parse_option_builtin ("tl-op-stat", no_argument, 0, 211, LONGOPT_NET_SET, "enabled stat about op usage");
  //{ "rwm-peak-recovery", no_argument, 0, 213},

  engine_add_net_parse_options ();
  engine_add_engine_parse_options ();
}
  
