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
#pragma once

#define	MAX_EVENT_TIMERS	(1 << 19)

typedef struct event_timer event_timer_t;

struct event_timer {
  int h_idx;
  int flags;
  int (*wakeup)(event_timer_t *et);
  double wakeup_time;
  double real_wakeup_time;
};

int thread_run_timers (void);
double timers_get_first (void);
