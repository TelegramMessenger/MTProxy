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

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
*/

#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <netdb.h>

#include "kprintf.h"
#include "resolver.h"

#define	HOSTS_FILE	"/etc/hosts"
#define	MAX_HOSTS_SIZE	(1L << 24)

int kdb_hosts_loaded;

static int pr[] = {
29,
41,
59,
89,
131,
197,
293,
439,
659,
991,
1481,
2221,
3329,
4993,
7487,
11239,
16843,
25253,
37879,
56821,
85223,
127837,
191773,
287629,
431441,
647161,
970747,
1456121,
2184179,
3276253,
4914373,
7371571,
11057357,
16586039,
24879017,
37318507
};

#pragma pack(push,1)
struct host {
  unsigned ip;
  char len;
  char name[];
};
#pragma pack(pop)


static unsigned ipaddr;
static char *h_array[] = {(char *)&ipaddr, 0};
static struct hostent hret = {
.h_aliases = 0,
.h_addrtype = AF_INET,
.h_length = 4,
.h_addr_list = h_array
};

/*
static unsigned char ipv6_addr[16];
static char *h_array6[] = {(char *)ipv6_addr, 0};
static struct hostent hret6 = {
.h_aliases = 0,
.h_addrtype = AF_INET6,
.h_length = 16,
.h_addr_list = h_array6
};
*/

static struct resolver_conf {
  int hosts_loaded;
  int hsize;
  struct host **htable;
  long long fsize;
  int ftime;
} Hosts, Hosts_new;

static struct host *getHash (struct resolver_conf *R, const char *name, int len, unsigned ip) {
  int h1 = 0, h2 = 0, i;

  assert ((unsigned)len < 128);

  for (i = 0; i < len; i++) {
    h1 = (h1 * 17 + name[i]) % R->hsize;
    h2 = (h2 * 239 + name[i]) % (R->hsize - 1);
  }
  ++h2;
  while (R->htable[h1]) {
    if (len == R->htable[h1]->len && !memcmp (R->htable[h1]->name, name, len)) {
      return R->htable[h1];
    }
    h1 += h2;
    if (h1 >= R->hsize) {
      h1 -= R->hsize;
    }
  }
  if (!ip) {
    return 0;
  }
  struct host *tmp = malloc (len + sizeof (struct host));
  assert (tmp);
  tmp->ip = ip;
  tmp->len = len;
  memcpy (tmp->name, name, len);
  return R->htable[h1] = tmp;
}

static void free_resolver_data (struct resolver_conf *R) {
  int s = R->hsize, i;
  struct host **htable = R->htable;
  if (htable) {
    assert (s > 0);
    for (i = 0; i < s; i++) {
      struct host *tmp = htable[i];
      if (tmp) {
        free (tmp);
        htable[i] = 0;
      }
    }
    free (htable);
    R->htable = 0;
    R->hsize = 0;
  }
  R->hosts_loaded = 0;
}


static char *skipspc (char *ptr) {
  while (*ptr == ' ' || *ptr == '\t') {
    ++ptr;
  }
  return ptr;
}


static char *skiptoeoln (char *ptr) {
  while (*ptr && *ptr != '\n') {
    ++ptr;
  }
  if (*ptr) {
    ++ptr;
  }
  return ptr;
}


static char *getword (char **ptr, int *len) {
  char *start = skipspc (*ptr), *tmp = start;

  while (*tmp && *tmp != ' ' && *tmp != '\t' && *tmp != '\n') {
    ++tmp;
  }

  *ptr = tmp;
  *len = tmp - start;

  if (!*len) {
    return 0;
  }

  return start;
}


static int readbyte (char **ptr) {
  char *tmp;
  unsigned val = strtoul (*ptr, &tmp, 10);
  if (tmp == *ptr || val > 255) {
    return -1;
  }
  *ptr = tmp;
  return val;
}


static int parse_hosts (struct resolver_conf *R, char *data, int mode) {
  char *ptr;
  int ans = 0;

  for (ptr = data; *ptr; ptr = skiptoeoln (ptr)) {
    ptr = skipspc (ptr);
    int i;
    unsigned ip = 0;

    for (i = 0; i < 4; i++) {
      int res = readbyte (&ptr);
      if (res < 0) {
        break;
      }
      ip = (ip << 8) | res;
      if (i < 3 && *ptr++ != '.') {
        break;
      }
    }

//fprintf (stderr, "ip = %08x, i = %d\n", ip, i);

    if (i < 4 || (*ptr != ' ' && *ptr != '\t') || !ip) {
      continue;
    }

    char *word;
    int wordlen;

    do {
      word = getword (&ptr, &wordlen);
      if (word && wordlen < 128) {
//fprintf (stderr, "word = %.*s\n", wordlen, word);
        if (mode) {
          getHash (R, word, wordlen, ip);
        }
        ++ans;
      }
    } while (word);
  }
  return ans;
}


static int kdb_load_hosts_internal (void) {
  static struct stat s;
  long long r;
  int fd;
  char *data;

  if (stat (HOSTS_FILE, &s) < 0) {
    return Hosts_new.hosts_loaded = -1;
  }
  if (!S_ISREG (s.st_mode)) {
    return Hosts_new.hosts_loaded = -1;
  }
  if (Hosts.hosts_loaded > 0 && Hosts.fsize == s.st_size && Hosts.ftime == s.st_mtime) {
    return 0;
  }
  if (s.st_size >= MAX_HOSTS_SIZE) {
    return Hosts_new.hosts_loaded = -1;
  }
  fd = open (HOSTS_FILE, O_RDONLY);
  if (fd < 0) {
    return Hosts_new.hosts_loaded = -1;
  }
  Hosts_new.fsize = s.st_size;
  Hosts_new.ftime = s.st_mtime;
  data = malloc (s.st_size + 1);
  if (!data) {
    close (fd);
    return Hosts_new.hosts_loaded = -1;
  }
  r = read (fd, data, s.st_size + 1);
  if (verbosity > 1) {
    fprintf (stderr, "read %lld of %lld bytes of "HOSTS_FILE"\n", r, Hosts_new.fsize);
  }
  close (fd);
  if (r != s.st_size) {
    free (data);
    return Hosts_new.hosts_loaded = -1;
  }
  data[s.st_size] = 0;

  int ans = parse_hosts (&Hosts_new, data, 0), i;

  for (i = 0; i < sizeof (pr) / sizeof (int); i++) {
    if (pr[i] > ans * 2) {
      break;
    }
  }

  if (i >= sizeof (pr) / sizeof (int)) {
    free (data);
    return Hosts_new.hosts_loaded = -1;
  }
  Hosts_new.hsize = pr[i];

  if (verbosity > 1) {
    fprintf (stderr, "IP table hash size: %d (for %d entries)\n", Hosts_new.hsize, ans);
  }

  Hosts_new.htable = malloc (sizeof (void *) * Hosts_new.hsize);
  assert (Hosts_new.htable);

  memset (Hosts_new.htable, 0, sizeof (void *) * Hosts_new.hsize);

  int res = parse_hosts (&Hosts_new, data, 1);
  assert (res == ans);

  free (data);
  return Hosts_new.hosts_loaded = 1;
}

int kdb_load_hosts (void) {
  int res = kdb_load_hosts_internal ();
  if (res < 0) {
    if (kdb_hosts_loaded <= 0) {
      kdb_hosts_loaded = res;
    }
    return kdb_hosts_loaded < 0 ? -1 : 0;
  }
  if (!res) {
    assert (kdb_hosts_loaded > 0);
    return 0;
  }
  assert (Hosts_new.hosts_loaded > 0);
  if (kdb_hosts_loaded > 0) {
    assert (Hosts.hosts_loaded > 0);
    free_resolver_data (&Hosts);
  }
  memcpy (&Hosts, &Hosts_new, sizeof (Hosts));
  memset (&Hosts_new, 0, sizeof (Hosts));
  kdb_hosts_loaded = Hosts.hosts_loaded;

  return 1;
}

int parse_ipv6 (unsigned short ipv6[8], char *str) {
  return -1;
}

struct hostent *kdb_gethostbyname (const char *name) {
  if (!kdb_hosts_loaded) {
    kdb_load_hosts ();
  }

  int len = strlen (name);


  if (name[0] == '[' && name[len-1] == ']' && len <= 64) {
    /*
    if (parse_ipv6 ((unsigned short *) ipv6_addr, name + 1) == len - 2) {
      hret6.h_name = (char *)name;
      return &hret6;
    }
    */
    char buf[64];
    memcpy (buf, name + 1, len - 2);
    buf[len - 2] = 0;
    return gethostbyname2 (buf, AF_INET6);
  }

  if (kdb_hosts_loaded <= 0) {
    return gethostbyname (name) ?: gethostbyname2 (name, AF_INET6);
  }

  if (len >= 128) {
    return gethostbyname (name) ?: gethostbyname2 (name, AF_INET6);
  }

  struct host *res = getHash (&Hosts, name, len, 0);


  if (!res) {
    if (strchr (name, '.') || strchr (name, ':')) {
      return gethostbyname (name) ?: gethostbyname2 (name, AF_INET6);
    } else {
      return 0;
    }
  }

  hret.h_name = (char *)name;
  ipaddr = htonl (res->ip);
  return &hret;
}

char *detect_hostname (void) {
  static char *hostname = NULL;
  static char hostname_buffer[256];
  int r, i;
  if (!hostname || !*hostname) {
    hostname = getenv ("HOSTNAME");
    if (!hostname || !*hostname) {
      int fd = open ("/etc/hostname", O_RDONLY);
      if (fd < 0) {
        kprintf ("cannot read /etc/hostname: %m\n");
        exit (2);
      }
      r = read (fd, hostname_buffer, 256);
      if (r <= 0 || r >= 256) {
        kprintf ("cannot read hostname from /etc/hostname: %d bytes read\n", r);
        exit (2);
      }
      hostname_buffer[r] = 0;
      close (fd);
      hostname = hostname_buffer;
      while (*hostname == 9 || *hostname == 32) {
        hostname++;
      }
      i = 0;
      while (hostname[i] > 32) {
        i++;
      }
      hostname[i] = 0;
    }
  }
  if (!hostname || !*hostname) {
    kprintf ("fatal: cannot detect hostname\n");
    exit (2);
  }
  i = 0;
  while ((hostname[i] >= '0' && hostname[i] <= '9') || hostname[i] == '.' || hostname[i] == '-' || hostname[i] == '_' || (hostname[i] >= 'A' && hostname[i] <= 'Z') || (hostname[i] >= 'a' && hostname[i] <= 'z')) {
    i++;
  }
  if (hostname[i] || i >= 64) {
    kprintf ("fatal: bad hostname '%s'\n", hostname);
    exit (2);
  }
  vkprintf (1, "hostname is %s\n", hostname);
  return hostname;
}
