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

    Copyright 2012-2015 Nikolai Durov
              2012-2013 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#pragma once

#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/aes.h>

#include "rpc-const.h"

#define tls_push()	{ struct tl_out_state *tlio_out = tl_out_state_alloc ();
#define tls_pop()	tl_out_state_free (tlio_out); }
#define TLS_START(C)		tls_push(); tls_init_tcp_raw_msg (tlio_out, C, 0);
#define TLS_START_UNALIGN(C)	tls_push(); tls_init_tcp_raw_msg_unaligned (tlio_out, C, 0);
#define TLS_END		tl_store_end_ext (0); tls_pop();

/* DH key exchange protocol data structures */
#define	CODE_req_pq			0x60469778
#define	CODE_req_pq_multi	       	0xbe7e8ef1
#define CODE_req_DH_params		0xd712e4be
#define CODE_set_client_DH_params	0xf5045f1f

/* RPC for front/proxy */
#define	RPC_PROXY_REQ		0x36cef1ee
#define	RPC_PROXY_ANS		0x4403da0d
#define	RPC_CLOSE_CONN		0x1fcf425d
#define	RPC_CLOSE_EXT		0x5eb634a2
#define	RPC_SIMPLE_ACK		0x3bac409b

/* not really a limit, for struct encrypted_message only */
// #define MAX_MESSAGE_INTS	16384
#define MAX_MESSAGE_INTS	1048576
#define MAX_PROTO_MESSAGE_INTS	524288

#pragma pack(push,4)
struct encrypted_message {
  // unencrypted header
  long long auth_key_id;
  char msg_key[16];
  // encrypted part, starts with encrypted header
  long long server_salt;
  long long session_id;
  // first message follows
  long long msg_id;
  int seq_no;
  int msg_len;   // divisible by 4
  int message[MAX_MESSAGE_INTS + 8];
};

#define MAX_PROXY_EXTRA_BYTES	16384

struct rpc_proxy_req {
  int type;	// RPC_PROXY_REQ
  int flags;
  long long ext_conn_id;
  unsigned char remote_ipv6[16];
  int remote_port;
  unsigned char our_ipv6[16];
  int our_port;
  union {
    int data[0];
    struct {
      int extra_bytes;
      int extra[MAX_PROXY_EXTRA_BYTES / 4];
    };
  };
};

struct rpc_proxy_ans {
  int type;	// RPC_PROXY_ANS
  int flags;	// +16 = small error packet, +8 = flush immediately
  long long ext_conn_id;
  int data[];
};

struct rpc_close_conn {
  int type;	// RPC_CLOSE_CONN
  long long ext_conn_id;
};

struct rpc_close_ext {
  int type;	// RPC_CLOSE_EXT
  long long ext_conn_id;
};

struct rpc_simple_ack {
  int type;	// RPC_SIMPLE_ACK
  long long ext_conn_id;
  int confirm_key;
};

#pragma pack(pop)
