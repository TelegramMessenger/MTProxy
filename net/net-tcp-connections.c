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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman     
*/

#include <errno.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "net/net-connections.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "crypto/aesni256.h"
#include "net/net-crypto-aes.h"
#include "kprintf.h"


int cpu_tcp_free_connection_buffers (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert_net_cpu_thread ();
  rwm_free (&c->in);
  rwm_free (&c->in_u);
  rwm_free (&c->out);
  rwm_free (&c->out_p);
  return 0;
}
/* }}} */


int cpu_tcp_server_writer (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();

  struct connection_info *c = CONN_INFO (C);
  
  int stop = 0;
  if (c->status == conn_write_close) {
    stop = 1;
  }
  
  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->out_queue, 4);
    if (!raw) { break; }
    //rwm_union (out, raw);
    c->type->write_packet (C, raw);
    free (raw);
  }
  
  c->type->flush (C);

  struct raw_message *raw = malloc (sizeof (*raw));

  if (c->type->crypto_encrypt_output && c->crypto) {
    c->type->crypto_encrypt_output (C);
    *raw = c->out_p;
    rwm_init (&c->out_p, 0);
  } else {
    *raw = c->out;
    rwm_init (&c->out, 0);
  }
 
  if (raw->total_bytes && c->io_conn) {        
    mpq_push_w (SOCKET_CONN_INFO(c->io_conn)->out_packet_queue, raw, 0);
    if (stop) {
      __sync_fetch_and_or (&SOCKET_CONN_INFO(c->io_conn)->flags, C_STOPWRITE);
    }
    job_signal (JOB_REF_CREATE_PASS (c->io_conn), JS_RUN);
  } else {
    rwm_free (raw);
    free (raw);
  }

  return 0;
}
/* }}} */

int cpu_tcp_server_reader (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO(C);

  while (1) {
    struct raw_message *raw = mpq_pop_nw (c->in_queue, 4);
    if (!raw) { break; }

    if (c->crypto) {
      rwm_union (&c->in_u, raw);
    } else {
      rwm_union (&c->in, raw);
    }
    free (raw);
  }
        
  if (c->crypto) {
    assert (c->type->crypto_decrypt_input (C) >= 0);
  }

  int r = c->in.total_bytes;
        
  int s = c->skip_bytes;

  if (c->type->data_received) {
    c->type->data_received (C, r);
  }

  if (c->flags & (C_FAILED | C_ERROR | C_NET_FAILED)) {
    return -1;
  }
  if (c->flags & C_STOPREAD) {
    return 0;
  }

  int r1 = r;

  if (s < 0) {
    // have to skip s more bytes
    if (r1 > -s) {
      r1 = -s;
    }
    rwm_skip_data (&c->in, r1);
    c->skip_bytes = s += r1;

    vkprintf (2, "skipped %d bytes, %d more to skip\n", r1, -s);
      
    if (s) {
      return 0;
    }
  }

  if (s > 0) {
    // need to read s more bytes before invoking parse_execute()
    if (r1 >= s) {
      c->skip_bytes = s = 0;
    }

    vkprintf (1, "fetched %d bytes, %d available bytes, %d more to load\n", r, r1, s ? s - r1 : 0);
    if (s) {
      return 0;
    }
  }


  while (!c->skip_bytes && !(c->flags & (C_ERROR | C_FAILED | C_NET_FAILED | C_STOPREAD)) && c->status != conn_error) {
    int bytes = c->in.total_bytes;
    if (!bytes) {
      break;
    }

    int res = c->type->parse_execute (C);
    
    // 0 - ok/done, >0 - need that much bytes, <0 - skip bytes, or NEED_MORE_BYTES
    if (!res) {
    } else if (res != NEED_MORE_BYTES) {
      bytes = (c->crypto ? c->in.total_bytes : c->in_u.total_bytes);
      // have to load or skip abs(res) bytes before invoking parse_execute
      if (res < 0) {
        res -= bytes;
      } else {
        res += bytes;
      }
      c->skip_bytes = res;
      break;
    } else {
      break;
    }
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_encrypt_output (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *out = &c->out;

  int l = out->total_bytes;
  l &= ~15;
  if (l) {
    assert (rwm_encrypt_decrypt_to (&c->out, &c->out_p, l, &T->write_aeskey, (void *)T->write_aeskey.type->cbc_crypt, T->write_iv, 16, 0, 0) == l);
  }

  return (-out->total_bytes) & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_decrypt_input (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *in = &c->in_u;

  int l = in->total_bytes;
  l &= ~15;
  if (l) {
    assert (rwm_encrypt_decrypt_to (&c->in_u, &c->in, l, &T->read_aeskey, (void *)T->read_aeskey.type->cbc_crypt, T->read_iv, 16, 0, 0) == l);
  }

  return (-in->total_bytes) & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_needed_output_bytes (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert (c->crypto);
  return -c->out.total_bytes & 15;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_encrypt_output (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *out = &c->out;

  int l = out->total_bytes;
  if (l) {
    assert (rwm_encrypt_decrypt_to (&c->out, &c->out_p, l, &T->write_aeskey, (void *)T->write_aeskey.type->ctr128_crypt, T->write_iv, 1, T->write_ebuf, &T->write_num) == l);
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_decrypt_input (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);
  struct aes_crypto *T = c->crypto;
  assert (c->crypto);
  struct raw_message *in = &c->in_u;

  int l = in->total_bytes;
  if (l) {
    assert (rwm_encrypt_decrypt_to (&c->in_u, &c->in, l, &T->read_aeskey, (void *)T->read_aeskey.type->ctr128_crypt, T->read_iv, 1, T->read_ebuf, &T->read_num) == l);
  }

  return 0;
}
/* }}} */

int cpu_tcp_aes_crypto_ctr128_needed_output_bytes (connection_job_t C) /* {{{ */ {
  struct connection_info *c = CONN_INFO (C);
  assert (c->crypto);
  return 0;
}
/* }}} */
