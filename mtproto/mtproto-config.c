/*
    This file is part of MTProto-Server

    MTProto-Server is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    MTProto-Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MTProto-Server.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2012-2018 Nikolai Durov
              2012-2014 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/mman.h>

#include "md5.h"
#include "resolver.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "mtproto-common.h"
#include "mtproto-config.h"
#include "engine/engine.h"
#include "common/parse-config.h"
#include "common/server-functions.h"

/*
 *
 *  CONFIGURATION PARSER
 *
 */

struct mf_config Config[2], *CurConf = Config, *NextConf = Config + 1;


//#define MAX_CONFIG_SIZE (1 << 20)

//char config_buff[MAX_CONFIG_SIZE+4], *config_filename, *cfg_start, *cfg_end, *cfg_cur;
//int config_bytes, cfg_lno, cfg_lex = -1;

char *config_filename;

static int cfg_getlex_ext (void) {
  switch (cfg_skipspc()) {
  case ';':
  case ':':
  case '{':
  case '}':
    return cfg_lex = *cfg_cur++;
  case 'm':
    if (!memcmp (cfg_cur, "min_connections", 15)) {
      cfg_cur += 15;
      return cfg_lex = 'x';
    }
    if (!memcmp (cfg_cur, "max_connections", 15)) {
      cfg_cur += 15;
      return cfg_lex = 'X';
    }
    break;
  case 'p':
    if (!memcmp (cfg_cur, "proxy_for", 9)) {
      cfg_cur += 9;
      return cfg_lex = 'Y';
    } else if (!memcmp (cfg_cur, "proxy", 5)) {
      cfg_cur += 5;
      return cfg_lex = 'y';
    }
    break;
  case 't':
    if (!memcmp (cfg_cur, "timeout", 7)) {
      cfg_cur += 7;
      return cfg_lex = 't';
    }
    break;
  case 'd':
    if (!memcmp (cfg_cur, "default", 7)) {
      cfg_cur += 7;
      return cfg_lex = 'D';
    }
    break;
  case 0:
    return cfg_lex = 0;
  }
  return cfg_lex = -1;
}


void forget_cluster_targets (struct mf_group_stats *GS, struct mf_cluster *MFC, int do_destroy_targets) {
  if (MFC->cluster_targets) {
    MFC->cluster_targets = 0;
  }
  MFC->targets_num = MFC->write_targets_num = 0;
  MFC->targets_allocated = 0;
}

void clear_mf_cluster (struct mf_group_stats *GS, struct mf_cluster *MFC, int do_destroy_targets) {
  forget_cluster_targets (GS, MFC, do_destroy_targets);
  MFC->flags = 0;
  GS->tot_clusters --;
}

void clear_config (struct mf_config *MC, int do_destroy_targets) {
  int j;
  if (do_destroy_targets) {
    for (j = 0; j < MC->tot_targets; j++) {
      vkprintf (1, "destroying target %s:%d\n", inet_ntoa (CONN_TARGET_INFO(MC->targets[j])->target), CONN_TARGET_INFO(MC->targets[j])->port);
      destroy_target (JOB_REF_PASS (MC->targets[j]));
    }
    memset (MC->targets, 0, MC->tot_targets * sizeof (conn_target_job_t));
  }
  for (j = 0; j < MC->auth_clusters; j++) {
    clear_mf_cluster (&MC->auth_stats, &MC->auth_cluster[j], do_destroy_targets);
  }
  MC->tot_targets = 0;
  MC->auth_clusters = 0;
  memset (&MC->auth_stats, 0, sizeof (struct mf_group_stats));
}

conn_target_job_t *cfg_parse_server_port (struct mf_config *MC, int flags) {
  if (MC->tot_targets >= MAX_CFG_TARGETS) {
    syntax ("too many targets (%d)", MC->tot_targets);
    return 0;
  }

  struct hostent *h = cfg_gethost ();
  if (!h) {
    return 0;
  }
      
  if (h->h_addrtype == AF_INET) {
    default_cfg_ct.target = *((struct in_addr *) h->h_addr);
    memset (default_cfg_ct.target_ipv6, 0, 16);
  } else if (h->h_addrtype == AF_INET6) {
    default_cfg_ct.target.s_addr = 0;
    memcpy (default_cfg_ct.target_ipv6, h->h_addr, 16);      
  } else {
    syntax ("cannot resolve hostname");
    return 0;
  }

  //*(cfg_cur += l) = c;
  cfg_getlex_ext ();
  if (expect_lexem (':') < 0) {
    return 0;
  }
  default_cfg_ct.port = cfg_getint();
  if (!default_cfg_ct.port) {
    syntax ("port number expected");
    return 0;
  }
        
  if (default_cfg_ct.port <= 0 || default_cfg_ct.port >= 0x10000) {
    syntax ("port number %d out of range", default_cfg_ct.port);
    return 0;
  }

  default_cfg_ct.min_connections = MC->min_connections;
  default_cfg_ct.max_connections = MC->max_connections;
  default_cfg_ct.reconnect_timeout = 1.0 + 0.1 * drand48 ();

  if ((flags & 1)) {
    int was_created = -1;
    conn_target_job_t D = create_target (&default_cfg_ct, &was_created);
    MC->targets[MC->tot_targets] = D;
    vkprintf (3, "new target %p created (%d): ip %s, port %d\n", D, was_created, inet_ntoa (default_cfg_ct.target), default_cfg_ct.port);
  }
  return &MC->targets[MC->tot_targets++];
}


static void init_old_mf_cluster (struct mf_group_stats *GS, struct mf_cluster *MFC, conn_target_job_t *targets, int targets_num, int flags, int cluster_id) {
  MFC->flags = flags;
  MFC->targets_num = targets_num;
  MFC->write_targets_num = targets_num;
  MFC->targets_allocated = 0;
  MFC->cluster_targets = targets;
  MFC->cluster_id = cluster_id;
  GS->tot_clusters ++;
}

static int extend_old_mf_cluster (struct mf_cluster *MFC, conn_target_job_t *target, int cluster_id) {
  if (MFC->cluster_targets + MFC->targets_num != target) {
    return 0;
  }
  if (MFC->cluster_id != cluster_id) {
    return 0;
  }
  MFC->write_targets_num = ++(MFC->targets_num);
  return 1;
}

struct mf_cluster *mf_cluster_lookup (struct mf_config *MC, int cluster_id, int force) {
  int i;
  for (i = 0; i < MC->auth_clusters; i++) {
    if (MC->auth_cluster[i].cluster_id == cluster_id) {
      return &(MC->auth_cluster[i]);
    }
  }
  return force ? MC->default_cluster : 0;
}

void dump_mf_cluster (struct mf_cluster *MFC) {
  int i;
  kprintf ("Current state of cluster `%s` (N=%d, M=%d, alloc=%d):\n", "(nil)", MFC->targets_num, MFC->write_targets_num, MFC->targets_allocated);
  for (i = 0; i < MFC->targets_num; i++) {
    kprintf ("Target #%d [%c]: %s:%d\n", i, i < MFC->write_targets_num ? 'W' : 'R', show_ip (ntohl (CONN_TARGET_INFO(MFC->cluster_targets[i])->target.s_addr)), CONN_TARGET_INFO(MFC->cluster_targets[i])->port);
  }
}

static void preinit_config (struct mf_config *MC) {
  MC->tot_targets = 0;
  MC->auth_clusters = 0;
  MC->min_connections = default_cfg_min_connections;
  MC->max_connections = default_cfg_max_connections;
  MC->timeout = 0.3;
  MC->default_cluster_id = 0;
  MC->default_cluster = 0;
}

// flags = 0 -- syntax check only (first pass), flags = 1 -- create targets and points as well (second pass)
// flags: +2 = allow proxies, +4 = allow proxies only, +16 = do not load file
int parse_config (struct mf_config *MC, int flags, int config_fd) {
  conn_target_job_t *targ_ptr;
  int have_proxy = 0;

  assert (flags & 4);

  if (!(flags & 17)) {
    if (load_config (config_filename, config_fd) < 0) {
      return -2;
    }
  }

  reset_config ();

  preinit_config (MC);
  
  while (cfg_skipspc ()) {
    int t, target_dc = 0;
    switch (t = cfg_getlex_ext ()) {
    case 't':
      MC->timeout = cfg_getint ();
      if (MC->timeout < 10 || MC->timeout > 30000) {
        Syntax ("invalid timeout");
      }
      MC->timeout /= 1000;
      break;
    case 'D':
    case 'Y': {
      long long targ_dc = cfg_getint_signed_zero();
      if (targ_dc < -0x8000 || targ_dc >= 0x8000) {
	Syntax ("invalid target id (integer -32768..32767 expected)", targ_dc);
      }
      if (t == 'D') {
	MC->default_cluster_id = targ_dc;
	break;
      }
      if (*cfg_cur != ' ' && *cfg_cur != 9) {
	Syntax ("space expected after target id");
      }
      cfg_skspc ();
      target_dc = targ_dc;
    }
    case 'y': {
      have_proxy |= 1;
      if (MC->auth_clusters >= MAX_CFG_CLUSTERS) {
        Syntax ("too many auth clusters", MC->auth_clusters);
      }
      targ_ptr = cfg_parse_server_port (MC, flags);
      if (!targ_ptr) {
        return -1;
      }
      struct mf_cluster *MFC = mf_cluster_lookup (MC, target_dc, 0);
      if (!MFC) {
	vkprintf (3, "-> added target to new auth_cluster #%d\n", MC->auth_clusters);
	if (flags & 1) {
	  init_old_mf_cluster (&MC->auth_stats, &MC->auth_cluster[MC->auth_clusters], targ_ptr, 1, 1, target_dc);
	} else {
	  MC->auth_cluster[MC->auth_clusters].cluster_id = target_dc;
	}
	MC->auth_clusters ++;
      } else if (MFC == &MC->auth_cluster[MC->auth_clusters - 1]) {
	vkprintf (3, "-> added target to old auth_cluster #%d\n", MC->auth_clusters - 1);
	if (flags & 1) {
	  if (!extend_old_mf_cluster (MFC, targ_ptr, target_dc)) {
	    Syntax ("IMPOSSIBLE");
	  }
	}
      } else {
	Syntax ("proxies for dc %d intermixed", target_dc);
      }
      break;
    }
    case 'X':
      MC->max_connections = cfg_getint ();
      if (MC->max_connections < MC->min_connections || MC->max_connections > 1000) {
        Syntax ("invalid max connections");
      }
      break;
    case 'x':
      MC->min_connections = cfg_getint ();
      if (MC->min_connections < 1 || MC->min_connections > MC->max_connections) {
        Syntax ("invalid min connections");
      }
      break;
    case 0:
      break;
    default:
      Syntax ("'proxy <ip>:<port>;' expected");
    }
    if (!t) {
      break;
    }
    cfg_getlex_ext ();
    Expect (';');
  }

  if (have_proxy != 1) {
    Syntax ("expected to find a mtproto-proxy configuration with `proxy' directives");
  }
  MC->have_proxy = have_proxy & 1;
  if (!MC->auth_clusters) {
    Syntax ("no MTProto next proxy servers defined to forward queries to");
  }
  MC->default_cluster = mf_cluster_lookup (MC, MC->default_cluster_id, 0);
  return 0;
}

static int need_reload_config = 0;


// flags: +1 = create targets and connections, +2 = allow proxies, +4 = allow proxies only, +16 = do not re-load file itself, +32 = preload config + perform syntax check, do not apply
int do_reload_config (int flags) {
  int res;
  need_reload_config = 0;

  int fd = -1;
  assert (flags & 4);

  if (!(flags & 16)) {
    fd = open (config_filename, O_RDONLY);
    if (fd < 0) {
      kprintf ("cannot re-read config file %s: %m\n", config_filename);
      return -1;
    }

    res = kdb_load_hosts ();

    if (res > 0) {
      vkprintf (1, "/etc/hosts changed, reloaded\n");
    }
  }

  res = parse_config (NextConf, flags & -2, fd);

  if (fd >= 0) {
    close (fd);
  }

  //  clear_config (NextConf);
  
  if (res < 0) {
    kprintf ("error while re-reading config file %s, new configuration NOT applied\n", config_filename);
    return res;
  }

  if ((flags & 32)) {
    return 0;
  }

  res = parse_config (NextConf, flags | 1, -1);

  if (res < 0) {
    clear_config (NextConf, 0);
    kprintf ("fatal error while re-reading config file %s\n", config_filename);
    exit (-res);
  }

  struct mf_config *tmp = CurConf;
  CurConf = NextConf;
  NextConf = tmp;

  clear_config (NextConf, 1);

  if (flags & 1) {
    create_all_outbound_connections ();
  }

  CurConf->config_loaded_at = now ? now : time (0);
  CurConf->config_bytes = config_bytes;
  CurConf->config_md5_hex = malloc (33);
  md5_hex_config (CurConf->config_md5_hex);
  CurConf->config_md5_hex[32] = 0;

  kprintf ("configuration file %s re-read successfully (%d bytes parsed), new configuration active\n", config_filename, config_bytes);

  return 0;
}

