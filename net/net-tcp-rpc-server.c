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

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "crc32.h"
#include "crc32c.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-server.h"
#include "net/net-tcp-connections.h"
#include "net/net-thread.h"

#include "rpc-const.h"

#include "net/net-crypto-aes.h"
#include "net/net-crypto-dh.h"
#include "net/net-config.h"

#include "vv/vv-io.h"
/*
 *
 *                BASIC RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_wakeup (connection_job_t c);
int tcp_rpcs_parse_execute (connection_job_t c);
int tcp_rpcs_alarm (connection_job_t c);
int tcp_rpcs_do_wakeup (connection_job_t c);
int tcp_rpcs_init_accepted (connection_job_t c);
int tcp_rpcs_close_connection (connection_job_t c, int who);
int tcp_rpcs_init_accepted_nohs (connection_job_t c);
int tcp_rpcs_default_check_perm (connection_job_t c);
int tcp_rpcs_init_crypto (connection_job_t c, struct tcp_rpc_nonce_packet *P);

conn_type_t ct_tcp_rpc_server = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_tcp_server",
  .init_accepted = tcp_rpcs_init_accepted,
  .parse_execute = tcp_rpcs_parse_execute,
  .close = tcp_rpcs_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_alarm,
  .crypto_init = aes_crypto_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_needed_output_bytes,
};

int tcp_rpcs_default_execute (connection_job_t c, int op, struct raw_message *msg);

struct tcp_rpc_server_functions default_tcp_rpc_server = {
  .execute = tcp_rpcs_default_execute,
  .check_ready = server_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_wakeup = tcp_rpcs_do_wakeup,
  .rpc_alarm = tcp_rpcs_do_wakeup,
  .rpc_check_perm = tcp_rpcs_default_check_perm,
  .rpc_init_crypto = tcp_rpcs_init_crypto,
  .rpc_ready = server_noop,
};

int tcp_rpcs_default_execute (connection_job_t C, int op, struct raw_message *raw) {
  struct connection_info *c = CONN_INFO (C);

  vkprintf (3, "%s: fd=%d, op=%d, len=%d\n", __func__, c->fd, op, raw->total_bytes);
  if (op == RPC_PING && raw->total_bytes == 12) {
    c->last_response_time = precise_now;    
    int P[3];
    assert (rwm_fetch_data (raw, P, 12) == 12);
    P[0] = RPC_PONG;    
    vkprintf (3, "received ping from " IP_PRINT_STR ":%d (val = %lld)\n", IP_TO_PRINT (c->remote_ip), (int)c->remote_port, *(long long *)(P + 1));
    tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (C), 12, P);
    return 0;
  }
  return 0;
}

static int tcp_rpcs_process_nonce_packet (connection_job_t C, struct raw_message *msg) {
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  union {
    struct tcp_rpc_nonce_packet s;
    struct tcp_rpc_nonce_ext_packet x;
    struct tcp_rpc_nonce_dh_packet dh;
  } P;
  struct tcp_rpc_nonce_dh_packet *dh = 0;
  int res;
  
  int packet_num = D->in_packet_num;
  int packet_type;
  assert (rwm_fetch_lookup (msg, &packet_type, 4) == 4);
  int packet_len = msg->total_bytes;

  if (packet_num != -2 || packet_type != RPC_NONCE) {
    return -2;
  }
  if (packet_len < sizeof (struct tcp_rpc_nonce_packet) || packet_len > sizeof (struct tcp_rpc_nonce_dh_packet)) {
    return -3;
  }

  assert (rwm_fetch_data (msg, &P, packet_len) == packet_len);

  switch (P.s.crypto_schema) {
  case RPC_CRYPTO_NONE:
    if (packet_len != sizeof (struct tcp_rpc_nonce_packet)) {
      return -3;
    }
    break;
  case RPC_CRYPTO_AES:
    if (packet_len != sizeof (struct tcp_rpc_nonce_packet)) {
      return -3;
    }
    break;
  case RPC_CRYPTO_AES_EXT:
    if (packet_len < sizeof (struct tcp_rpc_nonce_ext_packet) - 4 * RPC_MAX_EXTRA_KEYS) {
      return -3;
    }
    if (P.x.extra_keys_count < 0 || P.x.extra_keys_count > RPC_MAX_EXTRA_KEYS || packet_len != sizeof (struct tcp_rpc_nonce_ext_packet) + 4 * (P.x.extra_keys_count - RPC_MAX_EXTRA_KEYS)) {
      return -3;
    }
    break;
  case RPC_CRYPTO_AES_DH:
    if (packet_len < sizeof (struct tcp_rpc_nonce_dh_packet) - 4 * RPC_MAX_EXTRA_KEYS) {
      return -3;
    }
    if (P.x.extra_keys_count < 0 || P.x.extra_keys_count > RPC_MAX_EXTRA_KEYS || packet_len != sizeof (struct tcp_rpc_nonce_dh_packet) + 4 * (P.x.extra_keys_count - RPC_MAX_EXTRA_KEYS)) {
      return -3;
    }
    break;
  default:
    return -3;
  }

  switch (P.s.crypto_schema) {
  case RPC_CRYPTO_NONE:
    if (P.s.key_select) {
      return -3;
    }
    if (D->crypto_flags & RPCF_ALLOW_UNENC) {
      D->crypto_flags = RPCF_ALLOW_UNENC;
    } else {
      return -5;
    }
    break;
  case RPC_CRYPTO_AES_DH: {
    dh = (struct tcp_rpc_nonce_dh_packet *)((char *) &P + 4*(P.x.extra_keys_count - RPC_MAX_EXTRA_KEYS));
    if (!dh_params_select) {
      init_dh_params ();
    }
    if (!dh->dh_params_select || dh->dh_params_select != dh_params_select) {
      dh = 0;
    }
  }
  case RPC_CRYPTO_AES_EXT:
    P.s.key_select = select_best_key_signature (P.s.key_select, P.x.extra_keys_count, P.x.extra_key_select);
  case RPC_CRYPTO_AES:
    if (!P.s.key_select || !select_best_key_signature (P.s.key_select, 0, 0)) {
      if (D->crypto_flags & RPCF_ALLOW_UNENC) {
        D->crypto_flags = RPCF_ALLOW_UNENC;
        break;
      }
      return -3;
    }
    if (!(D->crypto_flags & RPCF_ALLOW_ENC)) {
      if (D->crypto_flags & RPCF_ALLOW_UNENC) {
        D->crypto_flags = RPCF_ALLOW_UNENC;
        break;
      }
      return -5;
    }
    D->nonce_time = (now ? now : time (0));
    if (abs (P.s.crypto_ts - D->nonce_time) > 30) {
      return -6;	//less'om
    }
    D->crypto_flags &= ~RPCF_ALLOW_UNENC;
    break;
  default:
    if (D->crypto_flags & RPCF_ALLOW_UNENC) {
      D->crypto_flags = RPCF_ALLOW_UNENC;
      break;
    }
    return -4;
  }

  if ((D->crypto_flags & (RPCF_REQ_DH | RPCF_ALLOW_ENC)) == (RPCF_REQ_DH | RPCF_ALLOW_ENC) && !dh) {
    if (D->crypto_flags & RPCF_ALLOW_SKIP_DH) {
      D->crypto_flags &= ~(RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH);
    } else {
      return -7;
    }
  }

  res = TCP_RPCS_FUNC(C)->rpc_init_crypto (C, &P.s);
  if (res < 0) {
    return -6;
  }
  return 0;
}

static int tcp_rpcs_send_handshake_packet (connection_job_t c) {
  struct tcp_rpc_data *D = TCP_RPC_DATA(c);
  struct tcp_rpc_handshake_packet P;
  assert(PID.ip);
  memset (&P, 0, sizeof (P));
  P.type = RPC_HANDSHAKE;
  P.flags = D->crypto_flags & RPCF_USE_CRC32C;
  memcpy (&P.sender_pid, &PID, sizeof (struct process_id));
  memcpy (&P.peer_pid, &D->remote_pid, sizeof (struct process_id));

  tcp_rpc_conn_send_data_im (JOB_REF_CREATE_PASS (c), sizeof (P), &P);
  return 0;
}

static int tcp_rpcs_send_handshake_error_packet (connection_job_t c, int error_code) {
  struct tcp_rpc_handshake_error_packet P;
  assert (PID.pid);
  memset (&P, 0, sizeof (P));
  P.type = RPC_HANDSHAKE_ERROR;
  P.error_code = error_code;
  memcpy (&P.sender_pid, &PID, sizeof (PID));

  tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (c), sizeof (P), &P);
  return 0;
}

static int tcp_rpcs_process_handshake_packet (connection_job_t C, struct raw_message *msg) {
  struct connection_info *c = CONN_INFO (C);

  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  struct tcp_rpc_handshake_packet P;
  if (!PID.ip) {
    init_server_PID (c->our_ip, c->our_port);
    if (!PID.ip) {
      PID.ip = get_my_ipv4 ();
    }
  }
  
  int packet_num = D->in_packet_num;
  int packet_type;
  assert (rwm_fetch_lookup (msg, &packet_type, 4) == 4);
  int packet_len = msg->total_bytes;

  if (packet_num != -1 || packet_type != RPC_HANDSHAKE) {
    return -2;
  }
  if (packet_len != sizeof (struct tcp_rpc_handshake_packet)) {
    tcp_rpcs_send_handshake_error_packet (C, -3);
    return -3;
  }
  assert (rwm_fetch_data (msg, &P, packet_len) == packet_len);
  memcpy (&D->remote_pid, &P.sender_pid, sizeof (struct process_id));
  if (!matches_pid (&PID, &P.peer_pid) && !(TCP_RPCS_FUNC(C)->mode_flags & TCP_RPC_IGNORE_PID)) {
    vkprintf (1, "PID mismatch during handshake: local %08x:%d:%d:%d, remote %08x:%d:%d:%d\n",
                 PID.ip, PID.port, PID.pid, PID.utime, P.peer_pid.ip, P.peer_pid.port, P.peer_pid.pid, P.peer_pid.utime);
    tcp_rpcs_send_handshake_error_packet (C, -4);
    return -4;
  }
  if (P.flags & 0xff) {
    tcp_rpcs_send_handshake_error_packet (C, -7);
    return -7;
  }
  if (P.flags & tcp_get_default_rpc_flags () & RPCF_USE_CRC32C) {
    D->crypto_flags |= RPCF_USE_CRC32C;
  }
  return 0;
}

int tcp_rpcs_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  vkprintf (4, "%s. in_total_bytes = %d\n", __func__, c->in.total_bytes);  
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int len;

  while (1) {
    if (c->flags & C_ERROR) {
      return NEED_MORE_BYTES;
    }
    if (c->flags & C_STOPPARSE) {
      return NEED_MORE_BYTES;
    }
    len = c->in.total_bytes; 
    if (len <= 0) {
      return NEED_MORE_BYTES;
    }

    if (len < 4) {
      return 4 - len;
    }

    int packet_len;
    assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

    if (D->crypto_flags & RPCF_QUICKACK) {
      D->flags = (D->flags & ~RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
      packet_len &= ~RPC_F_QUICKACK;
    }

    if (packet_len <= 0 || (packet_len & 0xc0000003)) {
      if (D->in_packet_num <= -2 && (packet_len == *(int *)"HEAD" || packet_len == *(int *)"POST" || packet_len == *(int *)"GET " || packet_len == *(int *)"OPTI") && TCP_RPCS_FUNC(C)->http_fallback_type) {
        vkprintf (1, "switching to http fallback for connection %d\n", c->fd);
        memset (c->custom_data, 0, sizeof (c->custom_data));
        c->type = TCP_RPCS_FUNC(C)->http_fallback_type;
        c->extra = TCP_RPCS_FUNC(C)->http_fallback_extra;
        
        if (c->type->init_accepted (C) < 0) {
          vkprintf (1, "http init_accepted() returns error for connection %d\n", c->fd);
          fail_connection (C, -33);
          return 0;
        }
        //nbit_set (&c->Q, &c->In);
        return c->type->parse_execute (C);
      }
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if ((packet_len > TCP_RPCS_FUNC(C)->max_packet_len && TCP_RPCS_FUNC(C)->max_packet_len > 0))  {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }
    
    if (packet_len == 4) {
      assert (rwm_skip_data (&c->in, 4) == 4);
      continue;
    }
    
    if (packet_len < 16) {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if (len < packet_len) {
      return packet_len - len;
    }

    struct raw_message msg;
    rwm_split_head (&msg, &c->in, packet_len);

    unsigned crc32;
    assert (rwm_fetch_data_back (&msg, &crc32, 4) == 4);

    unsigned packet_crc32 = rwm_custom_crc32 (&msg, packet_len - 4, D->custom_crc_partial);
    if (crc32 != packet_crc32) {
      vkprintf (1, "error while parsing packet: crc32 = %08x != %08x\n", packet_crc32, crc32);
      rwm_dump (&msg);
      fail_connection (C, -1);
      rwm_free (&msg);
      return 0;
    }

    int packet_num;
    int packet_type;
    assert (rwm_skip_data (&msg, 4) == 4);
    assert (rwm_fetch_data (&msg, &packet_num, 4) == 4);
    assert (rwm_fetch_lookup (&msg, &packet_type, 4) == 4);
    packet_len -= 12;

    if (verbosity > 2) {
      fprintf (stderr, "received packet from connection %d (num %d)\n", c->fd, packet_num);
      rwm_dump (&msg);
    }

    int res = -1;

    if (D->in_packet_num == -3) {
      D->in_packet_num = 0;
    }

    if (!(D->crypto_flags & RPCF_SEQNO_HOLES) && packet_num != D->in_packet_num) {
      vkprintf (1, "error while parsing packet: got packet num %d, expected %d\n", packet_num, D->in_packet_num);
      fail_connection (C, -1);
      rwm_free (&msg);
      return 0;
    } else if (packet_num < 0) {
      /* this is for us */
      if (packet_num == -2) {
        res = tcp_rpcs_process_nonce_packet (C, &msg);  // if res > 0, nonce packet sent in response
      } else if (packet_num == -1) {
        res = tcp_rpcs_process_handshake_packet (C, &msg);
        if (res >= 0) {
          res = tcp_rpcs_send_handshake_packet (C);
          if (D->crypto_flags & RPCF_USE_CRC32C) {
            D->custom_crc_partial = crc32c_partial;
          }
          notification_event_insert_tcp_conn_ready (C);
        }
      }
      rwm_free (&msg);
      if (res < 0) {
        fail_connection (C, res);
        return 0;
      }
    } else {
      /* main case */
      c->last_response_time = precise_now;
      if (packet_type == RPC_PING) {
        res = tcp_rpcs_default_execute (C, packet_type, &msg);
      } else {
        res = TCP_RPCS_FUNC(C)->execute (C, packet_type, &msg);
      }
      if (res <= 0) {
        rwm_free (&msg);
      }
    }

    D->in_packet_num++;
  }
  return NEED_MORE_BYTES;
}

int tcp_rpcs_wakeup (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  notification_event_insert_tcp_conn_wakeup (C);

  if (c->out_p.total_bytes > 0) {
    __sync_fetch_and_or (&c->flags, C_WANTWR);
  }
  
  //c->generation = ++conn_generation;
  c->pending_queries = 0;
  return 0;
}

int tcp_rpcs_alarm (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  notification_event_insert_tcp_conn_alarm (C);
  
  if (c->out_p.total_bytes > 0) {
    __sync_fetch_and_or (&c->flags, C_WANTWR);
  }

  //c->generation = ++conn_generation;
  c->pending_queries = 0;
  return 0;
}

int tcp_rpcs_close_connection (connection_job_t C, int who) {
  if (TCP_RPCS_FUNC(C)->rpc_close) {
    notification_event_insert_tcp_conn_close (C);
  }

  return cpu_server_close_connection (C, who);
}


int tcp_rpcs_do_wakeup (connection_job_t c) {
  return 0;
}


int tcp_rpcs_init_accepted (connection_job_t C) {  
  struct connection_info *c = CONN_INFO (C);

  c->last_query_sent_time = precise_now;
  TCP_RPC_DATA(C)->custom_crc_partial = crc32_partial;

  if (TCP_RPCS_FUNC(C)->rpc_check_perm) {
    int res = TCP_RPCS_FUNC(C)->rpc_check_perm (C);
    vkprintf (4, "tcp_rpcs_check_perm for connection %d: [%s]:%d -> [%s]:%d = %d\n", c->fd, show_remote_ip (C), c->remote_port, show_our_ip (C), c->our_port, res);
    if (res < 0) {
      return res;
    }
    res &= RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC | RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH;
    if (!(res & (RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC))) {
      return -1;
    }

    TCP_RPC_DATA(C)->crypto_flags = res;
  } else {
    TCP_RPC_DATA(C)->crypto_flags = RPCF_ALLOW_UNENC;
  }

  TCP_RPC_DATA(C)->in_packet_num = -2;
  TCP_RPC_DATA(C)->out_packet_num = -2;
  
  return 0;
}

int tcp_rpcs_init_accepted_nohs (connection_job_t c) {
  TCP_RPC_DATA(c)->crypto_flags = RPCF_QUICKACK | RPCF_ALLOW_UNENC;
  TCP_RPC_DATA(c)->in_packet_num = -3;
  TCP_RPC_DATA(c)->custom_crc_partial = crc32_partial;
  if (TCP_RPCS_FUNC(c)->rpc_ready) {
    notification_event_insert_tcp_conn_ready (c);
  }
  return 0;
}

int tcp_rpcs_init_fake_crypto (connection_job_t c) {
  if (!(TCP_RPC_DATA(c)->crypto_flags & RPCF_ALLOW_UNENC)) {
    return -1;
  }

  struct tcp_rpc_nonce_packet buf;
  memset (&buf, 0, sizeof (buf));
  buf.type = RPC_NONCE;
  buf.crypto_schema = RPC_CRYPTO_NONE;
  
  assert ((TCP_RPC_DATA(c)->crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT)) == 0);
  TCP_RPC_DATA(c)->crypto_flags |= RPCF_ENC_SENT;
 
  tcp_rpc_conn_send_data_init (c, sizeof (buf), &buf);
 
  return 1;
}

int tcp_rpcs_default_check_perm (connection_job_t C) {
  return RPCF_ALLOW_ENC | RPCF_REQ_DH | tcp_get_default_rpc_flags();
}

int tcp_rpcs_init_crypto (connection_job_t C, struct tcp_rpc_nonce_packet *P) {
  struct connection_info *c = CONN_INFO (C);

//  fprintf (stderr, "rpcs_init_crypto (%p [fd=%d], '%.*s')\n", c, c->fd, key_len, key);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);

  if (c->crypto) {
    return -1;
  }

  if ((D->crypto_flags & (RPCF_ALLOW_ENC | RPCF_ALLOW_UNENC)) == RPCF_ALLOW_UNENC) {
    return tcp_rpcs_init_fake_crypto (C);
  }

  if ((D->crypto_flags & (RPCF_ALLOW_ENC | RPCF_ALLOW_UNENC)) != RPCF_ALLOW_ENC) {
    return -1;
  }

  if (main_secret.key_signature != P->key_select) {
    return -1;
  }

  aes_secret_t *secret = &main_secret;

  union {
    struct tcp_rpc_nonce_packet s;
    struct tcp_rpc_nonce_ext_packet x;
    struct tcp_rpc_nonce_dh_packet dh;
  } buf;

  struct tcp_rpc_nonce_dh_packet *old_dh = 0, *new_dh = 0;
  unsigned char temp_dh[256];
  int temp_dh_len = 0;

  if (D->crypto_flags & RPCF_REQ_DH) {
    new_dh = (struct tcp_rpc_nonce_dh_packet *)((char *)&buf - 4*RPC_MAX_EXTRA_KEYS);
    if (P->crypto_schema != RPC_CRYPTO_AES_DH) {
      return -1;
    }
    old_dh = (struct tcp_rpc_nonce_dh_packet *)((char *)P + 4*(((struct tcp_rpc_nonce_dh_packet *) P)->extra_keys_count - RPC_MAX_EXTRA_KEYS));
    if (old_dh->dh_params_select != dh_params_select || !dh_params_select) {
      return -1;
    }

    if (tcp_add_dh_accept () < 0) {
      return -1;
    }

    temp_dh_len = dh_second_round (temp_dh, new_dh->g_a, old_dh->g_a);
    assert (temp_dh_len == 256);

    incr_active_dh_connections ();
    __sync_fetch_and_or (&c->flags, C_ISDH);
  }
  aes_generate_nonce (D->nonce);

  struct aes_key_data aes_keys;

  if (aes_create_keys (&aes_keys, 0, D->nonce, P->crypto_nonce, P->crypto_ts, nat_translate_ip (c->our_ip), c->our_port, c->our_ipv6, nat_translate_ip (c->remote_ip), c->remote_port, c->remote_ipv6, secret, temp_dh, temp_dh_len) < 0) {
    return -1;
  }

  if (aes_crypto_init (C, &aes_keys, sizeof (aes_keys)) < 0) {
    return -1;
  }

  memcpy (buf.s.crypto_nonce, D->nonce, 16);
  buf.s.crypto_ts = D->nonce_time;
  buf.s.type = RPC_NONCE;
  buf.s.key_select = secret->key_signature;

  int buf_len;
  if (!new_dh) {
    buf.s.crypto_schema = RPC_CRYPTO_AES;
    buf_len = sizeof (struct tcp_rpc_nonce_packet);
  } else {
    buf.dh.crypto_schema = RPC_CRYPTO_AES_DH;
    buf_len = sizeof (struct tcp_rpc_nonce_dh_packet) - 4*RPC_MAX_EXTRA_KEYS;
    buf.dh.extra_keys_count = 0;
    new_dh->dh_params_select = dh_params_select;
  }

  assert ((D->crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT)) == RPCF_ALLOW_ENC);
  D->crypto_flags |= RPCF_ENC_SENT;
 
  tcp_rpc_conn_send_data_init (C, buf_len, &buf);


  return 1;
}


/*
 *
 *                END (BASIC RPC SERVER)
 *
 */
