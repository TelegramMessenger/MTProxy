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
#pragma once 

struct proc_stats { 
  int pid;                        // %d 
  char comm[256];                // %s
  char state;                        // %c
  int ppid;                        // %d
  int pgrp;                        // %d
  int session;                // %d
  int tty_nr;                        // %d
  int tpgid;                        // %d
  unsigned long flags;        // %lu
  unsigned long minflt;        // %lu
  unsigned long cminflt;        // %lu
  unsigned long majflt;        // %lu
  unsigned long cmajflt;        // %lu
  unsigned long utime;        // %lu
  unsigned long stime;         // %lu
  long cutime;                // %ld
  long cstime;                // %ld
  long priority;                // %ld
  long nice;                        // %ld
  long num_threads;                // %ld
  long itrealvalue;                // %ld
  unsigned long starttime;        // %lu
  unsigned long vsize;        // %lu
  long rss;                        // %ld
  unsigned long rlim;                // %lu
  unsigned long startcode;        // %lu
  unsigned long endcode;        // %lu
  unsigned long startstack;        // %lu
  unsigned long kstkesp;        // %lu
  unsigned long kstkeip;        // %lu
  unsigned long signal;        // %lu
  unsigned long blocked;        // %lu
  unsigned long sigignore;        // %lu
  unsigned long sigcatch;        // %lu
  unsigned long wchan;        // %lu
  unsigned long nswap;        // %lu
  unsigned long cnswap;        // %lu
  int exit_signal;                // %d
  int processor;                // %d
  unsigned long rt_priority;        // %lu 
  unsigned long policy;        // %lu 
  unsigned long long delayacct_blkio_ticks;        // %llu 
}; 

int read_proc_stats (int pid, int tid, struct proc_stats *s);
