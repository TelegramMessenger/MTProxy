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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Anton Maydell
    
    Copyright 2014-2017 Telegram Messenger Inc             
              2014-2017 Anton Maydell
*/

#define	_FILE_OFFSET_BITS	64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "common/common-stats.h"
#include "net/net-connections.h"

static int read_whole_file (char *filename, void *output, int olen) {
  int fd = open (filename, O_RDONLY), n = -1;
  if (fd < 0) {
    vkprintf (1, "%s: open (\"%s\", O_RDONLY) failed. %m\n", __func__, filename);
    return -1;
  }
  do {
    n = read (fd, output, olen);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      vkprintf (1, "%s: read from %s failed. %m\n", __func__, filename);
    }
    break;
  } while (1);
  while (close (fd) < 0 && errno == EINTR) {}
  if (n < 0)  {
    return -1;
  }
  if (n >= olen) {
    vkprintf (1, "%s: output buffer is too small (%d bytes).\n", __func__, olen);
    return -1;
  }
  unsigned char *p = output;
  p[n] = 0;
  return n;
}

static int parse_statm (const char *buf, long long *a, int m) {
  static long long page_size = -1;
  if (page_size < 0) {
    page_size = sysconf (_SC_PAGESIZE);
    assert (page_size > 0);
  }
  int i;
  if (m > 7) {
    m = 7;
  }
  const char *p = buf;
  char *q;
  errno = 0;
  for (i = 0; i < m; i++) {
    a[i] = strtoll (p, &q, 10);
    if (p == q || errno) {
      return -1;
    }
    a[i] *= page_size;
    p = q;
  }
  return 0;
}

int am_get_memory_usage (pid_t pid, long long *a, int m) {
  char proc_filename[32];
  char buf[4096];
  assert (snprintf (proc_filename, sizeof (proc_filename), "/proc/%d/statm",  (int) pid) < sizeof (proc_filename));
  if (read_whole_file (proc_filename, buf, sizeof (buf)) < 0) {
    return -1;
  }
  return parse_statm (buf, a, m);
}

int am_get_memory_stats (am_memory_stat_t *S, int flags) {
  if (!flags) {
    return -1;
  }
  long long a[6];

  if (flags & AM_GET_MEMORY_USAGE_SELF) {
    if (am_get_memory_usage (getpid (), a, 6) < 0) {
      return -1;
    }
    S->vm_size = a[0];
    S->vm_rss = a[1];
    S->vm_data = a[5];
  }

  if (flags & AM_GET_MEMORY_USAGE_OVERALL) {
    char buf[16384], *p;
    if (read_whole_file ("/proc/meminfo", buf, sizeof (buf)) < 0) {
      return -1;
    }
    vkprintf (4, "/proc/meminfo: %s\n", buf);
    char suffix[32];
    long long value;
    int r = 0;
    for (p = strtok (buf, "\n"); r != 15 && p != NULL; p = strtok (NULL, "\n")) {
      switch (*p++) {
        case 'C':
        if (!memcmp (p, "ached:", 6)) {
          if (sscanf (p + 6, "%lld%31s", &value, suffix) == 2 && !strcmp (suffix, "kB")) {
            S->mem_cached = value << 10;
            r |= 8;
          }
        }
        break;
        case 'M':
        if (!memcmp (p, "emFree:", 7)) {
          if (sscanf (p + 7, "%lld%31s", &value, suffix) == 2 && !strcmp (suffix, "kB")) {
            S->mem_free = value << 10;
            r |= 1;
          }
        }
        break;
        case 'S':
        if (!memcmp (p, "wapTotal:", 9)) {
          if (sscanf (p + 9, "%lld%31s", &value, suffix) == 2 && !strcmp (suffix, "kB")) {
            S->swap_total = value << 10;
            r |= 2;
          }
        } else if (!memcmp (p, "wapFree:", 8)) {
          if (sscanf (p + 8, "%lld%31s", &value, suffix) == 2 && !strcmp (suffix, "kB")) {
            S->swap_free = value << 10;
            r |= 4;
          }
        }
        break;
      }
    }
    if (r != 15) {
      return -1;
    }
    S->swap_used = S->swap_total - S->swap_free;
  }
  return 0;
}

struct stat_fun_en {
  stat_fun_t func;
  struct stat_fun_en *next;
};
struct stat_fun_en *stat_func_first = NULL;

int sb_register_stat_fun (stat_fun_t func) {
  struct stat_fun_en *last = NULL, *p;
  for (p = stat_func_first; p; p = p->next) {
    last = p;
    if (p->func == func) {
      return 0;
    }
  }
  p = malloc (sizeof (*p));
  p->func = func;
  p->next = NULL;
  if (last) {
    last->next = p;
  } else {
    stat_func_first = p;
  }
  return 1;
}

/************************ stats buffer functions **********************************/
void sb_init (stats_buffer_t *sb, char *buff, int size) {
  sb->buff = buff;
  sb->pos = 0;
  sb->size = size;
  sb->flags = 0;
}

void sb_alloc (stats_buffer_t *sb, int size) {
  if (size < 16) {
    size = 16;
  }
  sb->buff = malloc (size);
  assert (sb->buff);
  sb->pos = 0;
  sb->size = size;
  sb->flags = 1;
}

void sb_release (stats_buffer_t *sb) {
  if (sb->flags & 1) {
    free (sb->buff);
  }
  sb->buff = NULL;
}

static void sb_truncate (stats_buffer_t *sb) {
  sb->buff[sb->size - 1] = 0;
  sb->pos = sb->size - 2;
  while (sb->pos >= 0 && sb->buff[sb->pos] != '\n') {
    sb->buff[sb->pos--] = 0;
  }
  sb->pos++;
}

static int sb_full (stats_buffer_t *sb) {
  return (sb->pos == sb->size - 1 && sb->buff[sb->pos]) || sb->pos >= sb->size;
}

void sb_prepare (stats_buffer_t *sb) {
  sb->pos = prepare_stats (sb->buff, sb->size);
  if (sb_full (sb)) {
    sb_truncate (sb);
    return;
  }
  struct stat_fun_en *p;
  for (p = stat_func_first; p; p = p->next) {
    p->func (sb);
    if (sb_full (sb)) {
      sb_truncate (sb);
      return;
    }
  }
}

void sb_printf (stats_buffer_t *sb, const char *format, ...) {
  if (sb->pos >= sb->size) { return; }
  const int old_pos = sb->pos;
  va_list ap;
  va_start (ap, format);
  sb->pos += vsnprintf (sb->buff + old_pos, sb->size - old_pos, format, ap);
  va_end (ap);
  if (sb->pos >= sb->size) {
    if (sb->flags & 1) {
      sb->size = 2 * sb->pos;
      sb->buff = realloc (sb->buff, sb->size);
      assert (sb->buff);
      va_start (ap, format);
      sb->pos = old_pos + vsnprintf (sb->buff + old_pos, sb->size - old_pos, format, ap);
      va_end (ap);
      assert (sb->pos < sb->size);
    } else {
      sb_truncate (sb);
    }
  }
}
/************************************************************************************/

void sb_memory (stats_buffer_t *sb, int flags) {
  am_memory_stat_t S;
  if (!am_get_memory_stats (&S, flags & AM_GET_MEMORY_USAGE_SELF)) {
    sb_printf (sb,
      "vmsize_bytes\t%lld\n"
      "vmrss_bytes\t%lld\n"
      "vmdata_bytes\t%lld\n",
    S.vm_size, S.vm_rss, S.vm_data);
  }

  if (!am_get_memory_stats (&S, flags & AM_GET_MEMORY_USAGE_OVERALL)) {
    sb_printf (sb,
        "memfree_bytes\t%lld\n"
        "memcached_bytes\t%lld\n"
        "swap_used_bytes\t%lld\n"
        "swap_total_bytes\t%lld\n",
    S.mem_free, S.mem_cached, S.swap_used, S.swap_total);
  }
}

void sb_print_queries (stats_buffer_t *sb, const char *const desc, long long q) {
  sb_printf (sb, "%s\t%lld\nqps_%s\t%.3lf\n", desc, q, desc, safe_div (q, now - start_time));
}

int sb_sum_i (void **base, int len, int offset) {
  int res = 0;
  int i;
  for (i = 0; i < len; i++) if (base[i]) {
    res += *(int *)((base[i]) + offset);
  }
  return res;
}

long long sb_sum_ll (void **base, int len, int offset) {
  long long res = 0;
  int i;
  for (i = 0; i < len; i++) if (base[i]) {
    res += *(long long *)((base[i]) + offset);
  }
  return res;
}

double sb_sum_f (void **base, int len, int offset) {
  double res = 0;
  int i;
  for (i = 0; i < len; i++) if (base[i]) {
    res += *(double *)((base[i]) + offset);
  }
  return res;
}

void sbp_print_date (stats_buffer_t *sb, const char *key, time_t unix_time) {
  struct tm b;
  struct tm *t = gmtime_r (&unix_time, &b);
  if (t) {
    char s[256];
    size_t l = strftime (s, sizeof (s), "%c", t);
    if (l > 0) {
      sb_printf (sb, "%s\t%s\n", key, s);
    }
  }
}
