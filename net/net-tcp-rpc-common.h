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

#include "pid.h"

struct tcp_message {
  connection_job_t c;
  int op;
  int packet_num;
  struct raw_message raw;
};

#pragma pack(push,4)
struct tcp_rpc_nonce_packet {
  int type;
  int key_select;        /* least significant 32 bits of key to use */
  int crypto_schema;     /* 0 = NONE, 1 = AES */
  int crypto_ts;
  char crypto_nonce[16];
};

#define RPC_MAX_EXTRA_KEYS	8

struct tcp_rpc_nonce_ext_packet {
  int type;              /* type = RPC_NONCE */
  int key_select;        /* least significant 32 bits of key to use */
  int crypto_schema;     /* 2 = AES+extra keys */
  int crypto_ts;
  char crypto_nonce[16];
  int extra_keys_count;
  int extra_key_select[RPC_MAX_EXTRA_KEYS];
};

struct tcp_rpc_nonce_dh_packet {
  int type;              /* type = RPC_NONCE */
  int key_select;        /* least significant 32 bits of key to use */
  int crypto_schema;     /* 3 = AES+extra keys+DH */
  int crypto_ts;
  char crypto_nonce[16];
  int extra_keys_count;
  int extra_key_select[RPC_MAX_EXTRA_KEYS];
  int dh_params_select;	 /* least significant 32 bits of SHA1 of DH params : g:int p:string */
  unsigned char g_a[256];
};

struct tcp_rpc_handshake_packet {
  int type;
  int flags;
  struct process_id sender_pid;
  struct process_id peer_pid;
  /* more ints? */
};

struct tcp_rpc_handshake_error_packet {
  int type;
  int error_code;
  struct process_id sender_pid;
};
#pragma pack(pop)

// Bit 1 - have to clone raw
// Bit 2 - delete reference to connection
// Bit 4 - raw is allocated pointer and it should be freed or reused
void tcp_rpc_conn_send (JOB_REF_ARG (C), struct raw_message *raw, int flags);
void tcp_rpc_conn_send_data (JOB_REF_ARG (C), int len, void *Q);
void tcp_rpc_conn_send_init (__joblocked connection_job_t C, struct raw_message *raw, int flags);
void tcp_rpc_conn_send_data_init (__joblocked connection_job_t c, int len, void *Q);
void tcp_rpc_conn_send_im (JOB_REF_ARG (C), struct raw_message *raw, int flags);
void tcp_rpc_conn_send_data_im (JOB_REF_ARG (C), int len, void *Q);
int tcp_rpc_default_execute (connection_job_t C, int op, struct raw_message *raw);

/* for crypto_flags in struct tcp_rpc_data */
#define RPCF_ALLOW_UNENC	1     // allow unencrypted
#define RPCF_ALLOW_ENC		2     // allow encrypted
#define RPCF_REQ_DH		4     // require DH
#define RPCF_ALLOW_SKIP_DH	8     // crypto NONCE packet sent
#define RPCF_ENC_SENT		16
#define RPCF_SEQNO_HOLES	256   // packet numbers not sequential
#define RPCF_QUICKACK		512   // allow quick ack packets
#define RPCF_COMPACT_OFF	1024  // compact mode off
#define RPCF_USE_CRC32C		2048  // use CRC32-C instead of CRC32

/* for flags in struct tcp_rpc_data */
#define RPC_F_PAD		0x8000000
#define RPC_F_DROPPED		0x10000000
#define RPC_F_MEDIUM		0x20000000
#define RPC_F_COMPACT		0x40000000
#define RPC_F_COMPACT_MEDIUM	(RPC_F_COMPACT | RPC_F_MEDIUM)
#define RPC_F_QUICKACK		0x80000000
#define RPC_F_EXTMODE1		0x10000
#define RPC_F_EXTMODE2		0x20000
#define RPC_F_EXTMODE3		0x30000

/* in conn->custom_data */
struct tcp_rpc_data {
  //int packet_len;
  //int packet_num;
  //int packet_type;
  //int packet_crc32;
  int flags;
  int in_packet_num;
  int out_packet_num;
  int crypto_flags;	/* RPCF_* flags */
  struct process_id remote_pid;
  char nonce[16];
  int nonce_time;
  int in_rpc_target;
  union {
    void *user_data;
    void *extra;
  };
  int extra_int;
  int extra_int2;
  int extra_int3;
  int extra_int4;
  double extra_double, extra_double2;
  crc32_partial_func_t custom_crc_partial;
};

//extern int default_rpc_flags;  /* 0 = compatibility mode, RPC_USE_CRC32C = allow both CRC32C and CRC32 */

#define RPC_NONCE 0x7acb87aa
#define RPC_HANDSHAKE 0x7682eef5
#define RPC_HANDSHAKE_ERROR 0x6a27beda

#define RPC_CRYPTO_NONE 0
#define RPC_CRYPTO_AES  1
#define RPC_CRYPTO_AES_EXT  2
#define RPC_CRYPTO_AES_DH   3

#define	RPC_MF_COMPACT_ALLOW	1
#define	RPC_MF_COMPACT_FORCE	2
#define RPC_MF_IGNORE_PID	4
#define RPC_MF_OPPORT_CRYPTO	8

#define	TCP_RPC_DATA(c)	((struct tcp_rpc_data *) (CONN_INFO(c)->custom_data))

int tcp_rpc_flush_packet (connection_job_t C);
int tcp_rpc_write_packet (connection_job_t C, struct raw_message *raw);
int tcp_rpc_write_packet_compact (connection_job_t C, struct raw_message *raw);
int tcp_rpc_flush (connection_job_t C);
void tcp_rpc_send_ping (connection_job_t C, long long ping_id);
unsigned tcp_set_default_rpc_flags (unsigned and_flags, unsigned or_flags);
unsigned tcp_get_default_rpc_flags (void);
void tcp_set_max_dh_accept_rate (int rate);
int tcp_add_dh_accept (void);

