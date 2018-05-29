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
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman     
*/

#pragma once

#include "net/net-tcp-rpc-common.h"
#include "net/net-connections.h"

struct tcp_rpc_server_functions {
  void *info;
  void *rpc_extra;
  int (*execute)(connection_job_t c, int op, struct raw_message *raw);/* invoked from parse_execute() */
  int (*check_ready)(connection_job_t c);		/* invoked from rpc_client_check_ready() */
  int (*flush_packet)(connection_job_t c);		/* execute this to push response to client */
  int (*rpc_check_perm)(connection_job_t c);	/* 1 = allow unencrypted, 2 = allow encrypted */
  int (*rpc_init_crypto)(connection_job_t c, struct tcp_rpc_nonce_packet *P);  /* 1 = ok; -1 = no crypto */
  void *nop;
  int (*rpc_wakeup)(connection_job_t c);
  int (*rpc_alarm)(connection_job_t c);
  int (*rpc_ready)(connection_job_t c);
  int (*rpc_close)(connection_job_t c, int who);
  int max_packet_len;
  int mode_flags;  /* 1 = ignore PID mismatch */
  void *memcache_fallback_type, *memcache_fallback_extra;
  void *http_fallback_type, *http_fallback_extra;
};

#define TCP_RPC_IGNORE_PID	RPC_MF_IGNORE_PID

extern conn_type_t ct_tcp_rpc_server;
extern struct tcp_rpc_server_functions default_tcp_rpc_server;

int tcp_rpcs_wakeup (connection_job_t c);
int tcp_rpcs_parse_execute (connection_job_t c);
int tcp_rpcs_alarm (connection_job_t c);
int tcp_rpcs_do_wakeup (connection_job_t c);
int tcp_rpcs_init_accepted (connection_job_t c);
int tcp_rpcs_close_connection (connection_job_t c, int who);
int tcp_rpcs_flush (connection_job_t c);
int tcp_rpcs_init_accepted_nohs (connection_job_t c);
// int tcp_rpcs_flush_packet (connection_job_t c); -- use tcp_rpc_flush_packet () instead
int tcp_rpcs_default_check_perm (connection_job_t c);
int tcp_rpcs_init_crypto (connection_job_t c, struct tcp_rpc_nonce_packet *P);

#define	TCP_RPCS_FUNC(c)	((struct tcp_rpc_server_functions *) (CONN_INFO(c)->extra))
