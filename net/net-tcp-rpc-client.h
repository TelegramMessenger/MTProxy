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

struct tcp_rpc_client_functions {
  void *info;
  void *rpc_extra;
  int (*execute)(connection_job_t c, int op, struct raw_message *raw);	/* invoked from parse_execute() */
  int (*check_ready)(connection_job_t c);		/* invoked from rpc_client_check_ready() */
  int (*flush_packet)(connection_job_t c);		/* execute this to push query to server */
  int (*rpc_check_perm)(connection_job_t c);		/* 1 = allow unencrypted, 2 = allow encrypted */
  int (*rpc_init_crypto)(connection_job_t c);  	/* 1 = ok; -1 = no crypto */
  int (*rpc_start_crypto)(connection_job_t c, char *nonce, int key_select, unsigned char *temp_key, int temp_key_len);  /* 1 = ok; -1 = no crypto */
  int (*rpc_wakeup)(connection_job_t c);
  int (*rpc_alarm)(connection_job_t c);
  int (*rpc_ready)(connection_job_t c);
  int (*rpc_close)(connection_job_t c, int who);
  int max_packet_len;
  int mode_flags;
};
extern struct tcp_rpc_client_functions default_tcp_rpc_client;

#define TCP_RPC_IGNORE_PID	RPC_MF_IGNORE_PID

extern conn_type_t ct_tcp_rpc_client;
int tcp_rpcc_parse_execute (connection_job_t c);
int tcp_rpcc_compact_parse_execute (connection_job_t c);
int tcp_rpcc_connected (connection_job_t c);
int tcp_rpcc_connected_nohs (connection_job_t c);
int tcp_rpcc_close_connection (connection_job_t c, int who);
int tcp_rpcc_init_outbound (connection_job_t c);
int tcp_rpc_client_check_ready (connection_job_t c);
void tcp_rpcc_flush_crypto (connection_job_t c);
int tcp_rpcc_flush (connection_job_t c);
// int tcp_rpcc_flush_packet (connection_job_t c); -- use tcp_rpc_flush_packet() instead
int tcp_rpcc_default_check_perm (connection_job_t c);
int tcp_rpcc_init_crypto (connection_job_t c);
int tcp_rpcc_start_crypto (connection_job_t c, char *nonce, int key_select, unsigned char *temp_key, int temp_key_len);
int tcp_rpcc_default_check_ready (connection_job_t c);
void tcp_force_enable_dh (void);

#define	TCP_RPCC_FUNC(c)	((struct tcp_rpc_client_functions *) (CONN_INFO(c)->extra))

