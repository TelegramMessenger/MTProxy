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
#include <signal.h>
#include <unistd.h>

#include "common/kprintf.h"
#include "common/server-functions.h"

#include "engine/engine.h"
#include "engine/engine-signals.h"

volatile static unsigned long long pending_signals;

void engine_set_terminal_attributes (void) __attribute__ ((weak));
void engine_set_terminal_attributes (void) {}

/* {{{ PENDING SIGNALS */

void signal_set_pending (int sig) {
  __sync_fetch_and_or (&pending_signals, SIG2INT(sig));
}

int signal_check_pending (int sig) {
  return (pending_signals & SIG2INT(sig)) != 0;
}

int signal_check_pending_and_clear (int sig) {
  int res = (pending_signals & SIG2INT(sig)) != 0;
  if (res) {
    __sync_fetch_and_and (&pending_signals, ~SIG2INT(sig));
  }
  return res;
}
/* }}} */

void sigint_immediate_handler (const int sig) /* {{{ */ {
  static const char message[] = "SIGINT handled immediately.\n";
  kwrite (2, message, sizeof (message) - (size_t)1);
  engine_set_terminal_attributes ();
  _exit (1);
}
/* }}} */

void sigterm_immediate_handler (const int sig) /* {{{ */ {
  static const char message[] = "SIGTERM handled immediately.\n";
  kwrite (2, message, sizeof (message) - (size_t) 1);
  engine_set_terminal_attributes ();
  _exit (1);
}
/* }}} */

void sigint_handler (const int sig) /* {{{ */ {
  static const char message[] = "SIGINT handled.\n";
  kwrite (2, message, sizeof (message) - (size_t) 1);
  signal_set_pending (SIGINT);
  ksignal (sig, sigint_immediate_handler);
}
/* }}} */

void sigterm_handler (const int sig) /* {{{ */ {
  static const char message[] = "SIGTERM handled.\n";
  kwrite (2, message, sizeof (message) - (size_t) 1);
  signal_set_pending (SIGTERM);
  ksignal (sig, sigterm_immediate_handler);
}
/* }}} */

static const char sig_message[] = "received signal ??\n";

void default_signal_handler (const int sig) /* {{{ */ {
  char msg[sizeof (sig_message)];
  int i;
  for (i = 0; i < sizeof (sig_message); i++) {
    msg[i] = sig_message[i];
  }
  msg[sizeof (sig_message) - 4] = '0' + (sig / 10);
  msg[sizeof (sig_message) - 3] = '0' + (sig % 10);
  kwrite (2, msg, sizeof (sig_message) - (size_t) 1);

  signal_set_pending (sig);
}

void quiet_signal_handler (const int sig) {
  if (verbosity >= 1) {
    char msg[sizeof (sig_message)];
    int i;
    for (i = 0; i < sizeof (sig_message); i++) {
      msg[i] = sig_message[i];
    }
    msg[sizeof (sig_message) - 4] = '0' + (sig / 10);
    msg[sizeof (sig_message) - 3] = '0' + (sig % 10);
    kwrite (2, msg, sizeof (sig_message) - (size_t) 1);
  }

  signal_set_pending (sig);
}

/* }}} */

void empty_signal_handler (const int sig) {}

int interrupt_signal_raised (void) /* {{{ */ {
  return (pending_signals & SIG_INTERRUPT_MASK) != 0;
}
/* }}} */


int engine_process_signals (void) /* {{{ */ {
  engine_t *E = engine_state;
  server_functions_t *F = E->F;

  long long allowed = F->allowed_signals;
  long long forbidden = 0;
  while (1) {
    long long t = allowed & pending_signals & ~forbidden;
    if (!t) {
      break;
    }
    int i = __builtin_ctzll (t);
    if (!i) {
      i += 64;
    }
    assert (F->signal_handlers[i]);
    if (signal_check_pending_and_clear (i)) {
      F->signal_handlers[i] ();
    }
    forbidden |= SIG2INT(i);
  }

  return 1;
}
/* }}} */
