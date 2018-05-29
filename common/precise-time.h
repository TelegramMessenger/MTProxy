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
              2014 Anton Maydell
*/
#pragma once

#include <time.h>

/* RDTSC */
#if defined(__i386__)
static __inline__ unsigned long long rdtsc(void) {
  unsigned long long int x;
  __asm__ volatile ("rdtsc" : "=A" (x));
  return x;
}
#elif defined(__x86_64__)
static __inline__ unsigned long long rdtsc(void) {
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
#endif

/* net-event.h */
extern __thread int now;
extern __thread double precise_now;
extern __thread long long precise_now_rdtsc;
double get_utime_monotonic (void);

/* common/server-functions.h */
double get_utime (int clock_id);
extern long long precise_time;  // (long long) (2^16 * precise unixtime)
extern long long precise_time_rdtsc; // when precise_time was obtained
long long get_precise_time (unsigned precision);

/* ??? */
double get_double_time (void);

static inline void precise_sleep (int seconds, int nanoseconds) {
  struct timespec t;
  t.tv_sec  = seconds;
  t.tv_nsec = nanoseconds;
  nanosleep (&t, NULL);
}
