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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "md5.h"
#include "common/parse-config.h"
#include "resolver.h"
#include "kprintf.h"

#define MAX_CONFIG_SIZE (16 << 20)

static char *config_buff;
char *config_name, *cfg_start, *cfg_end, *cfg_cur;
int config_bytes, cfg_lno, cfg_lex = -1;

int cfg_skipspc (void) {
  while (*cfg_cur == ' ' || *cfg_cur == 9 || *cfg_cur == 13 || *cfg_cur == 10 || *cfg_cur == '#') {
    if (*cfg_cur == '#') {
      do cfg_cur++; while (*cfg_cur && *cfg_cur != 10);
      continue;
    }
    if (*cfg_cur == 10) { 
      cfg_lno++; 
    }
    cfg_cur++;
  }
  return (unsigned char) *cfg_cur;
}

int cfg_skspc (void) {
  while (*cfg_cur == ' ' || *cfg_cur == 9) {
    cfg_cur++;
  }
  return (unsigned char) *cfg_cur;
}

int cfg_getlex (void) {
  switch (cfg_skipspc()) {
  case ';':
  case ':':
  case '{':
  case '}':
    return cfg_lex = *cfg_cur++;
  case 0:
    return cfg_lex = 0;
  }
  return cfg_lex = -1;
}

int cfg_getword (void) {
  cfg_skspc();
  char *s = cfg_cur;
  if (*s != '[') {
    while ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '.' || *s == '-' || *s == '_') {
      s++;
    }
  } else {
    s++;
    while ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '.' || *s == '-' || *s == '_' || *s == ':') {
      s++;
    }
    if (*s == ']') {
      s++;
    }
  }
  return s - cfg_cur;
}

int cfg_getstr (void) {
  cfg_skspc();
  char *s = cfg_cur;
  if (*s == '"') { return 1; } // fix later
  while (*s > ' ' && *s != ';') {
    s++;
  }
  return s - cfg_cur;
}

long long cfg_getint (void) {
  cfg_skspc ();
  char *s = cfg_cur;
  long long x = 0;
  while (*s >= '0' && *s <= '9') {
    x = x * 10 + *(s ++) - '0';
  }
  cfg_cur = s;
  return x;
}

long long cfg_getint_zero (void) {
  cfg_skspc ();
  char *s = cfg_cur;
  long long x = 0;
  while (*s >= '0' && *s <= '9') {
    x = x * 10 + *(s ++) - '0';
  }
  if (cfg_cur == s) {
    return -1;
  } else {
    cfg_cur = s;
    return x;
  }
}

long long cfg_getint_signed_zero (void) {
  cfg_skspc ();
  char *s = cfg_cur;
  long long x = 0;
  int sgn = 1;
  if (*s == '-') {
    sgn = -1;
    ++s;
  }
  while (*s >= '0' && *s <= '9') {
    x = x * 10 + sgn * (*(s++) - '0');
  }
  if (s == cfg_cur + (sgn < 0)) {
    return (-1LL << 63);
  } else {
    cfg_cur = s;
    return x;
  }
}

void syntax (const char *msg, ...) {
  if (!msg) {
    msg = "syntax error";
  }
  if (cfg_lno) {
    fprintf (stderr, "%s:%d: ", config_name, cfg_lno);
  }
  fprintf (stderr, "fatal: ");
  va_list args;
  va_start (args, msg);
  vfprintf (stderr, msg, args);
  va_end (args);
  int len = 0;
  while (cfg_cur[len] && cfg_cur[len] != 13 && cfg_cur[len] != 10 && len < 20) {
    len++;
  }
  fprintf (stderr, " near %.*s%s\n", len, cfg_cur, len >= 20 ? " ..." : "");
}

void syntax_warning (const char *msg, ...) {
  va_list args;
  if (cfg_lno) {
    fprintf (stderr, "%s:%d: ", config_name, cfg_lno);
  }
  fputs ("warning: ", stderr);
  va_start (args, msg);
  vfprintf (stderr, msg, args);
  va_end (args);
  int len = 0;
  while (cfg_cur[len] && cfg_cur[len] != 13 && cfg_cur[len] != 10 && len < 20) {
    len++;
  }
  fprintf (stderr, " near %.*s%s\n", len, cfg_cur, len >= 20 ? " ..." : "");
}

int expect_lexem (int lexem) {
  if (cfg_lex != lexem) {
    syntax ("%c expected", lexem);
    return -1;
  } else {
    return 0;
  }
}

int expect_word (const char *name, int len) {
  int l = cfg_getword ();
  if (len != l || memcmp (name, cfg_cur, len)) {
    syntax ("Expected %.*s", len, name);
    return -1;
  }
  cfg_cur += l;
  return 0;
}

struct hostent *cfg_gethost_ex (int verb) {
  struct hostent *h;
  int l = cfg_getword ();  
  if (!l || l > 63) {
    syntax ("hostname expected");
    return 0;
  }
  char c = cfg_cur[l];
  //hostname = cfg_cur;
  cfg_cur[l] = 0;

  if (!(h = kdb_gethostbyname (cfg_cur)) || !h->h_addr_list || !h->h_addr) {  
    if (verbosity >= verb) {
      syntax ("cannot resolve '%s'\n", cfg_cur);
    }
    *(cfg_cur += l) = c;
    return 0;
  }
  *(cfg_cur += l) = c;
  return h;
}

struct hostent *cfg_gethost (void) {
  return cfg_gethost_ex (0);
}

void reset_config (void) {
  assert (config_buff);
  cfg_cur = cfg_start = config_buff;
  cfg_end = cfg_start + config_bytes;
  *cfg_end = 0;
  cfg_lno = 0;
}

int load_config (const char *file, int fd) {
  if (!config_buff) {
    config_buff = malloc (MAX_CONFIG_SIZE+4);
    assert (config_buff);
  }
  if (fd < 0) {
    fd = open (file, O_RDONLY);
    if (fd < 0) {
      fprintf (stderr, "Can not open file %s: %m\n", file);
      return -1;
    }
  }
  int r;
  config_bytes = r = read (fd, config_buff, MAX_CONFIG_SIZE + 1);
  if (r < 0) {
    fprintf (stderr, "error reading configuration file %s: %m\n", config_name);
    return -2;
  }
  if (r > MAX_CONFIG_SIZE) {
    fprintf (stderr, "configuration file %s too long (max %d bytes)\n", config_name, MAX_CONFIG_SIZE);
    return -2;
  }
  if (config_name) {
    free (config_name);
  }
  if (file) {
    config_name = strdup (file);
  }

  reset_config ();
  return fd;
}

void md5_hex_config (char *out) {
  assert (config_buff);
  md5_hex (config_buff, config_bytes, out);
}

void close_config (int *fd) {
  if (config_buff) {
    free (config_buff);
    config_buff = NULL;
  }
  if (config_name) {
    free (config_name);
    config_name = NULL;
  }
  config_bytes = 0;
  cfg_cur = cfg_start = cfg_end = NULL;
  if (fd) {
    if (*fd >= 0) {
      assert (!close (*fd));
      *fd = -1;
    }
  }
}
