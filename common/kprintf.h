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

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#pragma once

#include <stddef.h>
#include <sys/types.h>

extern int verbosity;
extern const char *logname;

void reopen_logs (void);
void reopen_logs_ext (int slave_mode);
int hexdump (const void *start, const void *end);

extern double reindex_speed;

// safely writes buf to fd, considering write speed limit
void kdb_write (int fd, const void *buf, long long count, const char *filename);

// write message with timestamp and pid, safe to call inside handler
int kwrite (int fd, const void *buf, int count);

// print message with timestamp
void kprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));
#define vkprintf(verbosity_level, format, ...) do { \
    if ((verbosity_level) > verbosity) { \
      break; \
    } \
    kprintf ((format), ##__VA_ARGS__); \
  } while (0)

void nck_write (int fd, const void *data, size_t len);
void nck_pwrite (int fd, const void *data, size_t len, off_t offset);
