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

    Copyright 2013 Vkontakte Ltd
              2013 Vitaliy Valtman
              2013 Anton Maydell
    
    Copyright 2014 Telegram Messenger Inc             
              2014 Vitaly Valtman     
              2014 Anton Maydell
    
    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaliy Valtman
*/
#include <arpa/inet.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

#include "common/kprintf.h"
#include "common/server-functions.h"

#include "engine/engine.h"
#include "engine/engine-net.h"

#include "net/net-tcp-rpc-client.h"

void default_close_network_sockets (void) /* {{{ */ {
  engine_t *E = engine_state;
  
  if (E->sfd > 0) {
    close (E->sfd);
    E->sfd = -1;
  }
}
/* }}} */

int get_port_mod (void) /* {{{ */ {
  return -1;
}
/* }}} */

int try_open_port (int port, int quit_on_fail) /* {{{ */ {
  engine_t *E = engine_state;
  if (engine_check_tcp_enabled ()) {
    struct in_addr l;
    l.s_addr = htonl(0x7f000001);
    E->sfd = server_socket (port, l, engine_get_backlog (), 0);
    vkprintf (1, "opened tcp socket\n");
    if (E->sfd < 0) {
      if (quit_on_fail) {
        kprintf ("cannot open server socket at port %d: %m\n", port);
        exit (1);
      } else {
        return -1;
      }
    }
  }
  return 0;
}
/* }}} */

int try_open_port_range (int start_port, int end_port, int mod_port, int rem_port, int quit_on_fail) /* {{{ */ {  
  int s = start_port;
  for (;start_port <= end_port; start_port ++) {
    if (mod_port && rem_port >= 0 && (start_port % mod_port) != (rem_port % mod_port)) { continue; } 
    if (try_open_port (start_port, 0) >= 0) { 
      return start_port;
    }
  }
  if (quit_on_fail) {
    kprintf ("cannot open server socket at port %d-%d\n", s, end_port);
    exit (2);    
  }
  return -1;
}
/* }}} */

void engine_do_open_port (void) /* {{{ */ {
  int port_mod = get_port_mod ();

  int port = engine_state->port;
  int start_port = engine_state->start_port;
  int end_port = engine_state->end_port;

  if (port > 0 && port < PRIVILEGED_TCP_PORTS) {
    assert (try_open_port (port, 1) >= 0);
    return;
  }

  if (port <= 0 && start_port <= end_port && start_port < PRIVILEGED_TCP_PORTS) {
    engine_state->port = try_open_port_range (start_port, end_port, 100, port_mod, 1);
    assert (engine_state->port >= 0);
    return;
  }
}
/* }}} */

struct tcp_rpc_server_functions default_engine_tcp_rpc_methods = {
  .execute = default_tl_tcp_rpcs_execute,
  .check_ready = server_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_check_perm = tcp_rpcs_default_check_perm,
  .rpc_init_crypto = tcp_rpcs_init_crypto,
  .rpc_close = default_tl_close_conn,
};

void engine_set_tcp_methods (struct tcp_rpc_server_functions *F) {
  default_engine_tcp_rpc_methods = *F;
}

    
void engine_set_http_fallback (conn_type_t *http_type, struct http_server_functions *http_functions) {
  default_engine_tcp_rpc_methods.http_fallback_type = http_type;
  default_engine_tcp_rpc_methods.http_fallback_extra = http_functions;
}

void engine_server_init (void) {
  server_init (&ct_tcp_rpc_server, &default_engine_tcp_rpc_methods);
}

void set_maxconn (int val) {
  if (val <= 0) {
    val = MAX_CONNECTIONS;
  }
  engine_state->maxconn = val;
  tcp_set_max_connections (val);
}


static int f_parse_option_net (int val) {
  switch (val) {
    case 'b':
      engine_set_backlog (atoi (optarg));
      break;
    case 'c':
      set_maxconn (atoi (optarg));
      break;
    case 'p':
      {
        int start_port, end_port;
        int x = sscanf (optarg, "%d:%d", &start_port, &end_port);
        if (!x) { 
          usage ();
        }
        if (x == 1) {
          if (start_port <= 0) {
            usage ();
          }
          engine_state->port = start_port;
        } else {
          if (start_port <= 0 || start_port > end_port) {
            usage ();
          }
          engine_state->start_port = start_port;
          engine_state->end_port = end_port;
        }
      }
      break;        
    case '6':
      engine_enable_ipv6 ();
      break;
    case 200:
      engine_set_aes_pwd_file (optarg);
      break;
    case 214:
      engine_disable_tcp ();
      break;
    case 224:
      tcp_set_default_rpc_flags (0xffffffff, RPCF_USE_CRC32C);
      break;
    case 229:
      tcp_set_default_rpc_flags (0xffffffff, RPCF_ALLOW_SKIP_DH);
      break;
    case 230:
      tcp_force_enable_dh ();
      break;
    case 249:
      tcp_set_max_accept_rate (atoi (optarg));
      break;
    case 250:
      tcp_set_max_dh_accept_rate (atoi (optarg));
      break;
    case 372:
      if (net_add_nat_info (optarg) < 0) {
        usage ();
        exit (2);
      }
      break;
    case 373:
      {
        engine_t *E = engine_state;
        assert (E);
        if (inet_pton (AF_INET, optarg, &E->settings_addr) != 1) {
          kprintf ("Can not convert '%s' to ip addr: %m\n", optarg);
          exit (4);
        }
      }
      break;
    default:
      return -1;
  }
  return 0;
}

static void parse_option_net_builtin (const char *name, int arg, int *var, int val, unsigned flags, const char *help, ...) __attribute__ ((format (printf, 6, 7)));
static void parse_option_net_builtin (const char *name, int arg, int *var, int val, unsigned flags, const char *help, ...) {
  char *h = NULL;
  va_list ap;
  va_start (ap, help);
  assert (vasprintf (&h, help, ap) >= 0);
  va_end (ap);

  parse_option_ex (name, arg, var, val, flags, f_parse_option_net, "%s", h);
  free (h);
}

void engine_add_net_parse_options (void) {
  parse_option_net_builtin ("backlog", required_argument, 0, 'b', LONGOPT_TCP_SET, "sets backlog size");
  parse_option_net_builtin ("connections", required_argument, 0, 'c', LONGOPT_TCP_SET, "sets maximal connections number");
  parse_option_net_builtin ("port", required_argument, 0, 'p', LONGOPT_NET_SET, "<port> or <sport>:<eport> sets listening port number or port range");
  parse_option_net_builtin ("aes-pwd", required_argument, 0, 200, LONGOPT_NET_SET, "sets custom secret.conf file");
  parse_option_net_builtin ("ipv6", no_argument, 0, '6', LONGOPT_NET_SET, "enables ipv6 TCP/UDP support");
  parse_option_net_builtin ("disable-tcp", no_argument, 0, 214, LONGOPT_TCP_SET, "do not open listening tcp socket");
  parse_option_net_builtin ("crc32c", no_argument, 0, 224, LONGOPT_TCP_SET, "Try to use crc32c instead of crc32 in tcp rpc");
  parse_option_net_builtin ("allow-skip-dh", no_argument, 0, 229, LONGOPT_TCP_SET, "Allow skipping DH during RPC handshake");
  parse_option_net_builtin ("force-dh", no_argument, 0, 230, LONGOPT_TCP_SET, "Force using DH for all outbound RPC connections");
  parse_option_net_builtin ("max-accept-rate", required_argument, 0, 249, LONGOPT_TCP_SET, "max number of connections per second that is allowed to accept");
  parse_option_net_builtin ("max-dh-accept-rate", required_argument, 0, 250, LONGOPT_TCP_SET, "max number of DH connections per second that is allowed to accept");
  parse_option_net_builtin ("nat-info", required_argument, 0, 372, LONGOPT_NET_SET, "<local-addr>:<global-addr>\tsets network address translation for RPC protocol handshake");
  parse_option_net_builtin ("address", required_argument, 0, 373, LONGOPT_NET_SET, "tries to bind socket only to specified address");
}
