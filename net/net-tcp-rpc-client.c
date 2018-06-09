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
#include <stddef.h>

#include "crc32.h"
#include "crc32c.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-client.h"

#include "vv/vv-io.h"

#include "rpc-const.h"
#include "net/net-config.h"
#include "net/net-crypto-aes.h"
#include "net/net-crypto-dh.h"

#include "net/net-thread.h"

/*
 *
 *                BASIC RPC CLIENT INTERFACE
 *
 */

int tcp_rpcc_parse_execute (connection_job_t c);
int tcp_rpcc_compact_parse_execute (connection_job_t c);
int tcp_rpcc_connected (connection_job_t c);
int tcp_rpcc_connected_nohs (connection_job_t c);
int tcp_rpcc_close_connection (connection_job_t c, int who);
int tcp_rpcc_init_outbound (connection_job_t c);
int tcp_rpc_client_check_ready (connection_job_t c);
int tcp_rpcc_default_check_perm (connection_job_t c);
int tcp_rpcc_init_crypto (connection_job_t c);
int tcp_rpcc_start_crypto (connection_job_t c, char *nonce, int key_select, unsigned char *temp_key, int temp_key_len);


conn_type_t ct_tcp_rpc_client = {
  .magic = CONN_FUNC_MAGIC,
  .title = "rpc_client",
  .accept = server_failed,
  .init_accepted = server_failed,
  .parse_execute = tcp_rpcc_parse_execute,
  .close = tcp_rpcc_close_connection,
  .init_outbound = tcp_rpcc_init_outbound,
  .connected = tcp_rpcc_connected,
  .wakeup = server_noop,
  .check_ready = tcp_rpc_client_check_ready,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet,
  .crypto_init = aes_crypto_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_needed_output_bytes,
  .flags = C_RAWMSG,
};

//int tcp_rpcc_default_execute (connection_job_t c, int op, struct raw_message *raw);

struct tcp_rpc_client_functions default_tcp_rpc_client = {
  .execute = tcp_rpc_default_execute,
  .check_ready = tcp_rpcc_default_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_check_perm = tcp_rpcc_default_check_perm,
  .rpc_init_crypto = tcp_rpcc_init_crypto,
  .rpc_start_crypto = tcp_rpcc_start_crypto,
  .rpc_ready = server_noop,
};

static int tcp_rpcc_process_nonce_packet (connection_job_t C, struct raw_message *msg) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  union {
    struct tcp_rpc_nonce_packet s;
    struct tcp_rpc_nonce_ext_packet x;
    struct tcp_rpc_nonce_dh_packet dh;
  } P;
  struct tcp_rpc_nonce_dh_packet *dh = 0;
  int res;

  unsigned char temp_dh[256];
  int temp_dh_len = 0;

  int packet_num = D->in_packet_num - 1;
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

  vkprintf (2, "Processing nonce packet, crypto schema: %d, key select: %d\n", P.s.crypto_schema, P.s.key_select);

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
    if (P.x.extra_keys_count < 0 || P.x.extra_keys_count > RPC_MAX_EXTRA_KEYS || packet_len != sizeof (struct tcp_rpc_nonce_ext_packet) + 4*(P.x.extra_keys_count - RPC_MAX_EXTRA_KEYS)) {
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
      if (D->crypto_flags & RPCF_ALLOW_ENC) {
        // release_all_unprocessed (&c->Out);
        assert (!c->out_p.total_bytes);
      }
      D->crypto_flags = RPCF_ALLOW_UNENC;
    } else {
      return -5;
    }
    break;
  case RPC_CRYPTO_AES_DH: {
    dh = (struct tcp_rpc_nonce_dh_packet *)((char *) &P + 4 * (P.x.extra_keys_count - RPC_MAX_EXTRA_KEYS));
    if (!dh_params_select) {
      init_dh_params ();
    }
    if (!dh->dh_params_select || dh->dh_params_select != dh_params_select) {
      return -7;
    }
    if (!(D->crypto_flags & RPCF_REQ_DH) || !c->crypto_temp) {
      return -7;
    }
  }
  case RPC_CRYPTO_AES_EXT:
    P.s.key_select = select_best_key_signature (P.s.key_select, P.x.extra_keys_count, P.x.extra_key_select);
  case RPC_CRYPTO_AES:
    if (!P.s.key_select || !select_best_key_signature (P.s.key_select, 0, 0)) {
      return -3;
    }
    if (!(D->crypto_flags & RPCF_ALLOW_ENC)) {
      return -5;
    }
    if (abs (P.s.crypto_ts - D->nonce_time) > 30) {
      return -6; 
    }
    if ((D->crypto_flags & (RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH)) == RPCF_REQ_DH && !dh) {
      return -7;
    }
    if (dh) {
      temp_dh_len = dh_third_round (temp_dh, dh->g_a, c->crypto_temp);
      if (temp_dh_len != 256) {
        return -8;
      }
      //active_dh_connections++;
      incr_active_dh_connections ();
      __sync_fetch_and_or (&c->flags, C_ISDH);
    }
    if (c->crypto_temp) {
      if (((struct crypto_temp_dh_params *) c->crypto_temp)->magic == CRYPTO_TEMP_DH_PARAMS_MAGIC) {
        free_crypto_temp (c->crypto_temp, sizeof (struct crypto_temp_dh_params));
      } else {
        free_crypto_temp (c->crypto_temp, 0);
      }
      c->crypto_temp = 0;
    }
    res = TCP_RPCC_FUNC(C)->rpc_start_crypto (C, P.s.crypto_nonce, P.s.key_select, temp_dh, temp_dh_len);
    if (res < 0) {
      return -6;
    }
    break;
  default:
    return -4;
  }

  vkprintf (2, "Processed nonce packet, crypto flags = %d\n", D->crypto_flags);
  return 0;
}
/* }}} */

static int tcp_rpcc_send_handshake_packet (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  struct tcp_rpc_handshake_packet P;
  if (!PID.ip) {
    init_client_PID (c->our_ip);
  }
  memset (&P, 0, sizeof (P));
  P.type = RPC_HANDSHAKE;
  P.flags = tcp_get_default_rpc_flags () & RPCF_USE_CRC32C;
  if (!D->remote_pid.port) {
    D->remote_pid.ip = (c->remote_ip == 0x7f000001 ? 0 : c->remote_ip);
    D->remote_pid.port = c->remote_port;
  }
  memcpy (&P.sender_pid, &PID, sizeof (struct process_id));
  memcpy (&P.peer_pid, &D->remote_pid, sizeof (struct process_id));
  
  tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (C), sizeof (P), &P);

  return 0;
}
/* }}} */

static int tcp_rpcc_send_handshake_error_packet (connection_job_t C, int error_code) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  struct tcp_rpc_handshake_error_packet P;
  if (!PID.pid) {
    init_client_PID (c->our_ip);
  }
  memset (&P, 0, sizeof (P));
  P.type = RPC_HANDSHAKE_ERROR;
  P.error_code = error_code;
  memcpy (&P.sender_pid, &PID, sizeof (PID));
  tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (C), sizeof (P), &P);

  return 0;
}
/* }}} */ 

static int tcp_rpcc_process_handshake_packet (connection_job_t C, struct raw_message *msg) /* {{{ */ {
  //struct connection_info *c = CONN_INFO (C);

  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  struct tcp_rpc_handshake_packet P;

  int packet_num = D->in_packet_num - 1;
  int packet_len = msg->total_bytes;
  int packet_type;
  assert (rwm_fetch_lookup (msg, &packet_type, 4) == 4);
  
  if (packet_num != -1 || packet_type != RPC_HANDSHAKE) {
    return -2;
  }
  if (packet_len != sizeof (struct tcp_rpc_handshake_packet)) {
    tcp_rpcc_send_handshake_error_packet (C, -3);
    return -3;
  }
  assert (rwm_fetch_data (msg, &P, packet_len) == packet_len);  
  if (!matches_pid (&P.sender_pid, &D->remote_pid) && !(TCP_RPCC_FUNC(C)->mode_flags & TCP_RPC_IGNORE_PID)) {
    vkprintf (1, "PID mismatch during client RPC handshake: local %08x:%d:%d:%d, remote %08x:%d:%d:%d\n",
                 D->remote_pid.ip, D->remote_pid.port, D->remote_pid.pid, D->remote_pid.utime, P.sender_pid.ip, P.sender_pid.port, P.sender_pid.pid, P.sender_pid.utime);
    tcp_rpcc_send_handshake_error_packet (C, -6);
    return -6;
  }
  if (!P.sender_pid.ip) {
    P.sender_pid.ip = D->remote_pid.ip;
  }
  memcpy (&D->remote_pid, &P.sender_pid, sizeof (struct process_id));
  if (!matches_pid (&PID, &P.peer_pid)) {
    tcp_rpcc_send_handshake_error_packet (C, -4);
    return -4;
  }
  if (P.flags & 0xff) {
    tcp_rpcc_send_handshake_error_packet (C, -7);
    return -7;
  }
  if (P.flags & RPCF_USE_CRC32C) {
    if (!(tcp_get_default_rpc_flags () & RPCF_USE_CRC32C)) {
      tcp_rpcc_send_handshake_error_packet (C, -8);
      return -8;
    }
    D->crypto_flags |= RPCF_USE_CRC32C;
    D->custom_crc_partial = crc32c_partial;
  }
  return 0;
}
/* }}} */

int tcp_rpcc_parse_execute (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  vkprintf (4, "%s. in_total_bytes = %d\n", __func__, c->in.total_bytes);  
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int len;

  while (1) {
    len = c->in.total_bytes; 
    if (len <= 0) {
      break;
    }
    if (len < 4) {
      return 4 - len;
    }

    int packet_len;
    assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);
    if (packet_len <= 0 || (packet_len & 3) || (packet_len > TCP_RPCC_FUNC(C)->max_packet_len && TCP_RPCC_FUNC(C)->max_packet_len > 0)) {
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
      fail_connection (C, -2);
      return 0;
    }
    
    if (len < packet_len) {
      return packet_len - len;
    }
    

    struct raw_message msg;
    if (c->in.total_bytes == packet_len) {
      msg = c->in;
      rwm_init (&c->in, 0);
    } else {
      rwm_split_head (&msg, &c->in, packet_len);
    }

    unsigned crc32;
    assert (rwm_fetch_data_back (&msg, &crc32, 4) == 4);
    
    unsigned packet_crc32 = rwm_custom_crc32 (&msg, packet_len - 4, D->custom_crc_partial);
    if (crc32 != packet_crc32) {
      vkprintf (1, "error while parsing packet: crc32 mismatch: %08x != %08x\n", packet_crc32, crc32);
      fail_connection (C, -3);
      rwm_free (&msg);
      return 0;
    }

    assert (rwm_skip_data (&msg, 4) == 4); // len
    int packet_num;
    int packet_type;
    assert (rwm_fetch_data (&msg, &packet_num, 4) == 4);
    assert (rwm_fetch_lookup (&msg, &packet_type, 4) == 4);
    packet_len -= 12;

    if (verbosity > 2) {
      fprintf (stderr, "received packet from connection %d\n", c->fd);
      rwm_dump (&msg);
    }

    if (packet_num != D->in_packet_num) {
      vkprintf (1, "error while parsing packet: got packet num %d, expected %d\n", packet_num, D->in_packet_num);
      fail_connection (C, -4);
      rwm_free (&msg);
      return 0;
    }

    if (packet_num < 0) {
      D->in_packet_num ++;
      int res;
      if (packet_num == -2) {
        res = tcp_rpcc_process_nonce_packet (C, &msg);
        if (res >= 0) {
          res = tcp_rpcc_send_handshake_packet (C);
        }
      } else if (packet_num == -1) {
        res = tcp_rpcc_process_handshake_packet (C, &msg);
        if (res >= 0 && TCP_RPCC_FUNC(C)->rpc_ready) {
          notification_event_insert_tcp_conn_ready (C);
        }
      } else {
        vkprintf (1, "bad packet num %d\n", packet_num);
        res = -5;
      }

      rwm_free (&msg);
      if (res < 0) {
        fail_connection (C, res);
        return 0;
      }
      continue;
    }
        
    D->in_packet_num ++;
   
    int res;
    if (packet_type == RPC_PING) {
      res = tcp_rpc_default_execute (C, packet_type, &msg);
    } else {
      res = TCP_RPCC_FUNC(C)->execute (C, packet_type, &msg);
    }

    if (res <= 0) {
      rwm_free (&msg);
    }
  }
  return 0;
}
/* }}} */ 

int tcp_rpcc_connected (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);

  TCP_RPC_DATA(C)->out_packet_num = -2;
  c->last_query_sent_time = precise_now;

  if (TCP_RPCC_FUNC(C)->rpc_check_perm) {
    int res = TCP_RPCC_FUNC(C)->rpc_check_perm (C);
    if (res < 0) {
      return res;
    }
    res &= RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC | RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH;
    if (!(res & (RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC))) {
      return -1;
    }
    TCP_RPC_DATA(C)->crypto_flags = res;
  } else {
    TCP_RPC_DATA(C)->crypto_flags = RPCF_ALLOW_ENC | RPCF_ALLOW_UNENC;
  }
  vkprintf (2, "RPC connection #%d: [%s]:%d -> [%s]:%d connected, crypto_flags = %d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port, TCP_RPC_DATA(C)->crypto_flags);

  assert (TCP_RPCC_FUNC(C)->rpc_init_crypto);
  int res = TCP_RPCC_FUNC(C)->rpc_init_crypto (C);

  if (res > 0) {
    assert (TCP_RPC_DATA(C)->crypto_flags & RPCF_ENC_SENT);
  } else {
    return -1;
  }

  assert (TCP_RPCC_FUNC(C)->flush_packet);
  TCP_RPCC_FUNC(C)->flush_packet (C);

  return 0;
}
/* }}} */ 

int tcp_rpcc_close_connection (connection_job_t C, int who) {
  if (TCP_RPCC_FUNC(C)->rpc_close) {
    notification_event_insert_tcp_conn_close (C);
  }

  return cpu_server_close_connection (C, who);
}


int tcp_rpc_client_check_ready (connection_job_t c) {
  return TCP_RPCC_FUNC(c)->check_ready (c);
}

int tcp_rpcc_default_check_ready (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  if (c->flags & C_ERROR) {
    return c->ready = cr_failed;
  }

  const double CONNECT_TIMEOUT = 3.0;
  if (c->status == conn_connecting || TCP_RPC_DATA(C)->in_packet_num < 0) {
    //if (TCP_RPC_DATA(C)->in_packet_num == -1 && c->status == conn_running) {
    //  return c->ready = cr_ok;
    //}

    assert (c->last_query_sent_time != 0);
    if (c->last_query_sent_time < precise_now - CONNECT_TIMEOUT) {
      fail_connection (C, -6);
      return c->ready = cr_failed;
    }
    return c->ready = cr_notyet;
  }
   
  if (c->status == conn_working) {
    return c->ready = cr_ok;
  }

  fail_connection (C, -7);
  return c->ready = cr_failed;
}


int tcp_rpcc_init_fake_crypto (connection_job_t c) {
  if (!(TCP_RPC_DATA(c)->crypto_flags & RPCF_ALLOW_UNENC)) {
    return -1;
  }

  struct tcp_rpc_nonce_packet buf;
  memset (&buf, 0, sizeof (buf));
  buf.type = RPC_NONCE;
  buf.crypto_schema = RPC_CRYPTO_NONE;

  tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (c), sizeof (buf), &buf);

  assert ((TCP_RPC_DATA(c)->crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT)) == 0);
  TCP_RPC_DATA(c)->crypto_flags |= RPCF_ENC_SENT;
 
  return 1;
}


int tcp_rpcc_init_outbound (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  vkprintf (3, "rpcc_init_outbound (%d)\n", c->fd);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  c->last_query_sent_time = precise_now;
  D->custom_crc_partial = crc32_partial;

  if (TCP_RPCC_FUNC(C)->rpc_check_perm) {
    int res = TCP_RPCC_FUNC(C)->rpc_check_perm (C);
    if (res < 0) {
      return res;
    }
    res &= RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC | RPCF_REQ_DH | RPCF_ALLOW_SKIP_DH;
    if (!(res & (RPCF_ALLOW_UNENC | RPCF_ALLOW_ENC))) {
      return -1;
    }
    if (res & RPCF_REQ_DH) {
      if (tcp_add_dh_accept () < 0) {
        return -1;
      }
    }

    D->crypto_flags = res;
  } else {
    D->crypto_flags = RPCF_ALLOW_UNENC;
  }

  D->in_packet_num = -2;

  return 0;
}

static int force_rpc_dh;

void tcp_force_enable_dh (void) {
  force_rpc_dh |= 4;
}

int tcp_rpcc_default_check_perm (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  vkprintf (3, "tcp_rpcc_default_check_perm(%d): [%s]:%d -> [%s]:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);

  return RPCF_ALLOW_ENC | tcp_get_default_rpc_flags(); 
}

int tcp_rpcc_init_crypto (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);

  if (!(TCP_RPC_DATA(C)->crypto_flags & RPCF_ALLOW_ENC)) {
    return tcp_rpcc_init_fake_crypto (C);
  }

  TCP_RPC_DATA(C)->nonce_time = time (0);

  aes_generate_nonce (TCP_RPC_DATA(C)->nonce);

  if (!dh_params_select) {
    assert (init_dh_params () >= 0);
    assert (dh_params_select);
  }

  union {
    struct tcp_rpc_nonce_packet s;
    struct tcp_rpc_nonce_ext_packet x;
    struct tcp_rpc_nonce_dh_packet dh;
  } buf;
  int len = sizeof (struct tcp_rpc_nonce_packet);

  memset (&buf, 0, sizeof (buf));
  memcpy (buf.s.crypto_nonce, TCP_RPC_DATA(C)->nonce, 16);
  buf.s.crypto_ts = TCP_RPC_DATA(C)->nonce_time;
  buf.s.type = RPC_NONCE;
  buf.s.key_select = main_secret.key_signature;
  buf.s.crypto_schema = RPC_CRYPTO_AES;
  int extra_keys = buf.x.extra_keys_count = 0;
  assert (extra_keys >= 0 && extra_keys <= RPC_MAX_EXTRA_KEYS);

  if (TCP_RPC_DATA(C)->crypto_flags & RPCF_REQ_DH) {
    buf.s.crypto_schema = RPC_CRYPTO_AES_DH;
    len = sizeof (struct tcp_rpc_nonce_dh_packet) + 4*(extra_keys - RPC_MAX_EXTRA_KEYS);
    struct tcp_rpc_nonce_dh_packet *dh = (struct tcp_rpc_nonce_dh_packet *)((char *) &buf + 4*(extra_keys - RPC_MAX_EXTRA_KEYS));
    dh->dh_params_select = dh_params_select;
    assert (!c->crypto_temp);
    c->crypto_temp = alloc_crypto_temp (sizeof (struct crypto_temp_dh_params));
    assert (c->crypto_temp);
    dh_first_round (dh->g_a, c->crypto_temp);
  } else if (extra_keys) {
    buf.s.crypto_schema = RPC_CRYPTO_AES_EXT;
    len = offsetof (struct tcp_rpc_nonce_ext_packet, extra_key_select) + 4 * extra_keys;
  }

  tcp_rpc_conn_send_data (JOB_REF_CREATE_PASS (C), len, &buf);

  assert ((TCP_RPC_DATA(C)->crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT)) == RPCF_ALLOW_ENC);
  TCP_RPC_DATA(C)->crypto_flags |= RPCF_ENC_SENT;

  assert (!c->crypto);

  return 1;
}

int tcp_rpcc_start_crypto (connection_job_t C, char *nonce, int key_select, unsigned char *temp_key, int temp_key_len) {
  struct connection_info *c = CONN_INFO (C);

  struct tcp_rpc_data *D = TCP_RPC_DATA(C);

  vkprintf (2, "rpcc_start_crypto: key_select = %d\n", key_select);

  if (c->crypto) {
    return -1;
  }

  if (c->in.total_bytes || c->out.total_bytes || !D->nonce_time) {
    return -1;
  }

  if (!key_select) {
    return -1;
  }

  aes_secret_t *secret = &main_secret;

  struct aes_key_data aes_keys;

  if (aes_create_keys (&aes_keys, 1, nonce, D->nonce, D->nonce_time, nat_translate_ip (c->remote_ip), c->remote_port, c->remote_ipv6, nat_translate_ip (c->our_ip), c->our_port, c->our_ipv6, secret, temp_key, temp_key_len) < 0) {
    return -1;
  }

  if (aes_crypto_init (C, &aes_keys, sizeof (aes_keys)) < 0) {
    return -1;
  }

  return 1;
}

/*
 *
 *                END (BASIC RPC CLIENT)
 *
 */


