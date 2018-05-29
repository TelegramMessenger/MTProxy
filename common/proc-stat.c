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

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/
#include "common/proc-stat.h"

#include <stdio.h>

int read_proc_stats (int pid, int tid, struct proc_stats *s) { 
  const char *format = "%d %s %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %lu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu %llu"; 

  char buf[256]; 
  if (tid <= 0) {
    sprintf (buf, "/proc/%d/stat", pid); 
  } else {
    sprintf (buf, "/proc/%d/task/%d/stat", pid, tid); 
  }

  FILE *proc = fopen (buf, "r"); 
  if (proc) { 
    if (42 == fscanf (proc, format, 
          &s->pid,
          s->comm,
          &s->state,
          &s->ppid,
          &s->pgrp,
          &s->session,
          &s->tty_nr,
          &s->tpgid,
          &s->flags,
          &s->minflt,
          &s->cminflt,
          &s->majflt,
          &s->cmajflt,
          &s->utime,
          &s->stime,
          &s->cutime,
          &s->cstime,
          &s->priority,
          &s->nice,
          &s->num_threads,
          &s->itrealvalue,
          &s->starttime,
          &s->vsize,
          &s->rss,
          &s->rlim,
          &s->startcode,
          &s->endcode,
          &s->startstack,
          &s->kstkesp,
          &s->kstkeip,
          &s->signal,
          &s->blocked,
          &s->sigignore,
          &s->sigcatch,
          &s->wchan,
          &s->nswap,
          &s->cnswap,
          &s->exit_signal,
          &s->processor,
          &s->rt_priority,
          &s->policy,
          &s->delayacct_blkio_ticks
      )
    ) { 
      fclose(proc); 
      return 1; 
    } else { 
      fclose(proc); 
      return 0; 
    } 
  } else {  
    return 0; 
  } 
} 
