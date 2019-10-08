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

#include <assert.h>
#include <stdio.h>
#include <sys/uio.h>

#include "common/precise-time.h"
#include "common/rpc-const.h"
#include "common/mp-queue.h"
#include "net/net-msg.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "kprintf.h"
#include "vv/vv-io.h"

// Flags:
//   Flag 1 - can not edit this message. Need to make copy.

void tcp_rpc_conn_send_init (connection_job_t C, struct raw_message *raw, int flags) {
  struct connection_info *c = CONN_INFO (C);
  vkprintf (3, "%s: sending message of size %d to conn fd=%d\n", __func__, raw->total_bytes, c->fd);
  assert (!(raw->total_bytes & 3));
  int Q[2];
  Q[0] = raw->total_bytes + 12;
  Q[1] = TCP_RPC_DATA(C)->out_packet_num ++;
  struct raw_message *r = malloc (sizeof (*r));
  if (flags & 1) {
    rwm_clone (r, raw);
  } else {
    *r = *raw;
  }
  rwm_push_data_front (r, Q, 8);
  unsigned crc32 = rwm_custom_crc32 (r, r->total_bytes, TCP_RPC_DATA(C)->custom_crc_partial);
  rwm_push_data (r, &crc32, 4);

  socket_connection_job_t S = c->io_conn;

  if (S) {
    mpq_push_w (SOCKET_CONN_INFO (S)->out_packet_queue, r, 0);
    job_signal (JOB_REF_CREATE_PASS (S), JS_RUN);
  }
}

void tcp_rpc_conn_send_im (JOB_REF_ARG (C), struct raw_message *raw, int flags) {
  struct connection_info *c = CONN_INFO (C);
  vkprintf (3, "%s: sending message of size %d to conn fd=%d\n", __func__, raw->total_bytes, c->fd);
  assert (!(raw->total_bytes & 3));
  int Q[2];
  Q[0] = raw->total_bytes + 12;
  Q[1] = TCP_RPC_DATA(C)->out_packet_num ++;
  struct raw_message *r = malloc (sizeof (*r));
  if (flags & 1) {
    rwm_clone (r, raw);
  } else {
    *r = *raw;
  }
  rwm_push_data_front (r, Q, 8);
  unsigned crc32 = rwm_custom_crc32 (r, r->total_bytes, TCP_RPC_DATA(C)->custom_crc_partial);
  rwm_push_data (r, &crc32, 4);

  rwm_union (&c->out, r);
  free (r);

  job_signal (JOB_REF_PASS (C), JS_RUN);
}

void tcp_rpc_conn_send (JOB_REF_ARG (C), struct raw_message *raw, int flags) {
  struct connection_info *c = CONN_INFO (C);
  vkprintf (3, "%s: sending message of size %d to conn fd=%d\n", __func__, raw->total_bytes, c->fd);
  if (!(flags & 8)) {
    assert (!(raw->total_bytes & 3));
  }
  struct raw_message *r;
  if (flags & 4) {
    r = raw;
    assert (!(flags & 1));
  } else {
    r = malloc (sizeof (*r));
    if (flags & 1) {
      rwm_clone (r, raw);
    } else {
      *r = *raw;
    }
  }

  mpq_push_w (c->out_queue, r, 0);
  job_signal (JOB_REF_PASS (C), JS_RUN);
}

void tcp_rpc_conn_send_data (JOB_REF_ARG (C), int len, void *Q) {
  assert (!(len & 3));
  struct raw_message r;
  assert (rwm_create (&r, Q, len) == len);
  tcp_rpc_conn_send (JOB_REF_PASS (C), &r, 0);
}

void tcp_rpc_conn_send_data_init (connection_job_t c, int len, void *Q) {
  assert (!(len & 3));
  struct raw_message r;
  assert (rwm_create (&r, Q, len) == len);
  tcp_rpc_conn_send_init (c, &r, 0);
}

void tcp_rpc_conn_send_data_im (JOB_REF_ARG (C), int len, void *Q) {
  assert (!(len & 3));
  struct raw_message r;
  assert (rwm_create (&r, Q, len) == len);
  tcp_rpc_conn_send_im (JOB_REF_PASS (C), &r, 0);
}

int tcp_rpc_default_execute (connection_job_t C, int op, struct raw_message *raw) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  vkprintf (1, "rpcc_execute: fd=%d, op=%d, len=%d\n", c->fd, op, raw->total_bytes);
  if (op == RPC_PING && raw->total_bytes == 12) {
    c->last_response_time = precise_now;    
    int P[3];
    assert (rwm_fetch_data (raw, P, 12) == 12);
    P[0] = RPC_PONG;    
    //P[1] = Q[1];
    //P[2] = Q[2];
    
    vkprintf (2, "received ping from " IP_PRINT_STR ":%d (val = %lld)\n", IP_TO_PRINT (c->remote_ip), (int)c->remote_port, *(long long *)(P + 1));
    tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (C), 12, P);
    return 0;
  }
  c->last_response_time = precise_now;    
  return 0;
}
/* }}} */

int tcp_rpc_flush_packet (connection_job_t C) {
  return CONN_INFO(C)->type->flush (C);
}

int tcp_rpc_write_packet (connection_job_t C, struct raw_message *raw) {
  int Q[2];
  if (!(TCP_RPC_DATA(C)->flags & (RPC_F_COMPACT | RPC_F_MEDIUM))) {
    Q[0] = raw->total_bytes + 12;
    Q[1] = TCP_RPC_DATA(C)->out_packet_num ++;
  
    rwm_push_data_front (raw, Q, 8);
    unsigned crc32 = rwm_custom_crc32 (raw, raw->total_bytes, TCP_RPC_DATA(C)->custom_crc_partial);
    rwm_push_data (raw, &crc32, 4);
  
    rwm_union (&CONN_INFO(C)->out, raw);
  }

  return 0;
}

int tcp_rpc_write_packet_compact (connection_job_t C, struct raw_message *raw) {
  if (raw->total_bytes == 5) {
    int flag = 0;
    assert (rwm_fetch_data (raw, &flag, 1) == 1);
    assert (flag == 0xdd);
    rwm_union (&CONN_INFO(C)->out, raw);
    return 0;
  }
  if ((CONN_INFO (C)->flags & C_IS_TLS) && CONN_INFO (C)->left_tls_packet_length == -1) {
    // uninited TLS connection
    rwm_union (&CONN_INFO(C)->out, raw);
    return 0;
  }
    
  if (!(TCP_RPC_DATA(C)->flags & (RPC_F_COMPACT | RPC_F_MEDIUM))) {
    return tcp_rpc_write_packet (C, raw);
  }

  if (TCP_RPC_DATA(C)->flags & RPC_F_PAD) {
    int x = lrand48_j();
    int y = lrand48_j() & 3;
    assert (rwm_push_data (raw, &x, y) == y);
  }

  int len = raw->total_bytes;
  assert (!(len & 0xfc000000));
  if (!(TCP_RPC_DATA(C)->flags & RPC_F_PAD)) {
    assert (!(len & 3));
  }
  if (TCP_RPC_DATA(C)->flags & RPC_F_MEDIUM) {
    rwm_push_data_front (raw, &len, 4);
  } else if (len <= 0x7e * 4) {
    len >>= 2;
    rwm_push_data_front (raw, &len, 1);
  } else {
    len = (len << 6) | 0x7f;
    rwm_push_data_front (raw, &len, 4);
  }
  rwm_union (&CONN_INFO(C)->out, raw);

  return 0;
}

int tcp_rpc_flush (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  if (c->crypto) {
    int pad_bytes = c->type->crypto_needed_output_bytes (C);
    vkprintf (2, "tcp_rpcs_flush_packet: padding with %d bytes\n", pad_bytes);    
    if (pad_bytes > 0) {
      assert (!(pad_bytes & 3));
      static const int pad_str[3] = {4, 4, 4};
      assert (pad_bytes <= 12);
      assert (rwm_push_data (&c->out, pad_str, pad_bytes) == pad_bytes);
    }
  }
  
  return 0;
}

void tcp_rpc_send_ping (connection_job_t C, long long ping_id) {
  int P[3];
  P[0] = RPC_PING;
  *(long long *)(P + 1) = ping_id;
  tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (C), 12, P);
}

static unsigned default_rpc_flags = 0;

unsigned tcp_set_default_rpc_flags (unsigned and_flags, unsigned or_flags) {
  return (default_rpc_flags = (default_rpc_flags & and_flags) | or_flags);
}

unsigned tcp_get_default_rpc_flags (void) {
  return default_rpc_flags;
}

static __thread double cur_dh_accept_rate_remaining;
static __thread double cur_dh_accept_rate_time;
static double max_dh_accept_rate;

void tcp_set_max_dh_accept_rate (int rate) {
  max_dh_accept_rate = rate;
}

int tcp_add_dh_accept (void) {
  if (max_dh_accept_rate) {
    cur_dh_accept_rate_remaining += (precise_now - cur_dh_accept_rate_time) * max_dh_accept_rate;
    cur_dh_accept_rate_time = precise_now;
    if (cur_dh_accept_rate_remaining > max_dh_accept_rate) {
      cur_dh_accept_rate_remaining = max_dh_accept_rate;
    }
    if (cur_dh_accept_rate_remaining < 1) {
      return -1;
    }
    cur_dh_accept_rate_remaining -= 1;
  }
  return 0;
}

