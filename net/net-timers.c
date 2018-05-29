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

    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman     
    
*/
#include "net/net-timers.h"
#include "jobs/jobs.h"
#include "common/common-stats.h"
#include "common/kprintf.h"
#include "common/precise-time.h"

/* {{{ STAT */
#define MODULE timers

MODULE_STAT_TYPE {
  long long event_timer_insert_ops; 
  long long event_timer_remove_ops; 
  long long event_timer_alarms;
  int total_timers;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_LL (event_timer_insert_ops);
  SB_SUM_ONE_LL (event_timer_remove_ops);
  SB_SUM_ONE_LL (event_timer_alarms);
  SB_SUM_ONE_I (total_timers);
MODULE_STAT_FUNCTION_END
/* }}} */

static __thread event_timer_t **et_heap;
__thread int et_heap_size;


static inline int basic_et_adjust (event_timer_t *et, int i) {
  int j;
  while (i > 1) {
    j = (i >> 1);
    if (et_heap[j]->wakeup_time <= et->wakeup_time) {
      break;
    }
    et_heap[i] = et_heap[j];
    et_heap[i]->h_idx = i;
    i = j;
  }
  j = 2*i;
  while (j <= et_heap_size) {
    if (j < et_heap_size && et_heap[j]->wakeup_time > et_heap[j+1]->wakeup_time) {
      j++;
    }
    if (et->wakeup_time <= et_heap[j]->wakeup_time) {
      break;
    }
    et_heap[i] = et_heap[j];
    et_heap[i]->h_idx = i;
    i = j;
    j <<= 1;
  }
  et_heap[i] = et;
  et->h_idx = i;
  return i;
}

int insert_event_timer (event_timer_t *et) {
  if (!et_heap) {
    et_heap = calloc (sizeof (void *), MAX_EVENT_TIMERS);
  }
  MODULE_STAT->event_timer_insert_ops ++;
  int i;
  if (et->h_idx) {
    i = et->h_idx;
    assert (i > 0 && i <= et_heap_size && et_heap[i] == et);
  } else {
    MODULE_STAT->total_timers ++;
    assert (et_heap_size < MAX_EVENT_TIMERS);
    i = ++et_heap_size;
  }
  return basic_et_adjust (et, i);
}

int remove_event_timer (event_timer_t *et) {
  if (!et_heap) {
    et_heap = calloc (sizeof (void *), MAX_EVENT_TIMERS);
  }
  int i = et->h_idx;
  if (!i) {
    return 0;
  }
  MODULE_STAT->total_timers --;
  MODULE_STAT->event_timer_remove_ops ++;
  assert (i > 0 && i <= et_heap_size && et_heap[i] == et);
  et->h_idx = 0;

  et = et_heap[et_heap_size--];
  if (i > et_heap_size) {
    return 1;
  }
  basic_et_adjust (et, i);
  return 1;
}
  
int thread_run_timers (void) {  
  if (!et_heap) {
    et_heap = calloc (sizeof (void *), MAX_EVENT_TIMERS);
  }
  double wait_time;
  event_timer_t *et;
  if (!et_heap_size) {
    return 100000;
  }
  wait_time = et_heap[1]->wakeup_time - precise_now;
  if (wait_time > 0) {
    //do not remove this useful debug!
    vkprintf (3, "%d event timers, next in %.3f seconds\n", et_heap_size, wait_time);
    return (int) (wait_time*1000) + 1;
  }
  while (et_heap_size > 0 && et_heap[1]->wakeup_time <= precise_now) {
    et = et_heap[1];
    assert (et->h_idx == 1);
    remove_event_timer (et);
    et->wakeup (et); 
    MODULE_STAT->event_timer_alarms ++;
  }
  
  if (!et_heap_size) {
    return 100000;
  }
  wait_time = et_heap[1]->wakeup_time - precise_now;
  if (wait_time > 0) {
    //do not remove this useful debug!
    vkprintf (3, "%d event timers, next in %.3f seconds\n", et_heap_size, wait_time);
    return (int) (wait_time*1000) + 1;
  }

  assert (0);
  return 0;
}

double timers_get_first (void) {
  if (!et_heap_size) { return 0; }
  return et_heap[1]->wakeup_time;
}
