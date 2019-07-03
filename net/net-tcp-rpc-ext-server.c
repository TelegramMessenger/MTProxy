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
    
    Copyright 2014-2018 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman
                    2016-2018 Nikolai Durov
*/

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "common/kprintf.h"
#include "common/precise-time.h"
#include "common/rpc-const.h"
#include "common/sha256.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-events.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-thread.h"

#include "vv/vv-io.h"

/*
 *
 *                EXTERNAL RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_compact_parse_execute (connection_job_t c);

conn_type_t ct_tcp_rpc_ext_server = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_ext_server",
  .init_accepted = tcp_rpcs_init_accepted_nohs,
  .parse_execute = tcp_rpcs_compact_parse_execute,
  .close = tcp_rpcs_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet_compact,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

int tcp_rpcs_default_execute (connection_job_t c, int op, struct raw_message *msg);

static unsigned char ext_secret[16][16];
static int ext_secret_cnt = 0;

void tcp_rpcs_set_ext_secret(unsigned char secret[16]) {
  assert (ext_secret_cnt < 16);
  memcpy (ext_secret[ext_secret_cnt ++], secret, 16);
}

/*
struct tcp_rpc_server_functions default_tcp_rpc_ext_server = {
  .execute = tcp_rpcs_default_execute,
  .check_ready = server_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_wakeup = tcp_rpcs_do_wakeup,
  .rpc_alarm = tcp_rpcs_do_wakeup,
  .rpc_check_perm = tcp_rpcs_default_check_perm,
  .rpc_init_crypto = tcp_rpcs_init_crypto,
  .rpc_ready = server_noop,
};
*/

#define MAX_TLS_SERVER_EXTENSIONS 3
static int tls_server_extensions[MAX_TLS_SERVER_EXTENSIONS + 1] = {0x33, 0x2b, -1};

int get_tls_server_hello_encrypted_size() {
  int r = rand();
  return 2509 + ((r >> 1) & 1) - (r & 1);
}

struct client_random {
  unsigned char random[16];
  struct client_random *next_by_time;
  struct client_random *next_by_hash;
  int time;
};

#define RANDOM_HASH_BITS 14
static struct client_random *client_randoms[1 << RANDOM_HASH_BITS];

static struct client_random *first_client_random;
static struct client_random *last_client_random;

static struct client_random **get_bucket(unsigned char random[16]) {
  int i = RANDOM_HASH_BITS;
  int pos = 0;
  int id = 0;
  while (i > 0) {
    int bits = i < 8 ? i : 8;
    id = (id << bits) | (random[pos++] & ((1 << bits) - 1));
    i -= bits;
  }
  assert (0 <= id && id < (1 << RANDOM_HASH_BITS));
  return client_randoms + id;
}

static int have_client_random (unsigned char random[16]) {
  struct client_random *cur = *get_bucket (random);
  while (cur != NULL) {
    if (memcmp (random, cur->random, 16) == 0) {
      return 1;
    }
    cur = cur->next_by_hash;
  }
  return 0;
}

static void add_client_random (unsigned char random[16]) {
  struct client_random *entry = malloc (sizeof (struct client_random));
  memcpy (entry->random, random, 16);
  entry->time = now;
  entry->next_by_time = NULL;
  if (last_client_random == NULL) {
    assert (first_client_random == NULL);
    first_client_random = last_client_random = entry;
  } else {
    last_client_random->next_by_time = entry;
    last_client_random = entry;
  }

  struct client_random **bucket = get_bucket (random);
  entry->next_by_hash = *bucket;
  *bucket = entry;
}

#define MAX_CLIENT_RANDOM_CACHE_TIME 2 * 86400

static void delete_old_client_randoms() {
  while (first_client_random != last_client_random) {
    assert (first_client_random != NULL);
    if (first_client_random->time > now - MAX_CLIENT_RANDOM_CACHE_TIME) {
      return;
    }

    struct client_random *entry = first_client_random;
    assert (entry->next_by_hash == NULL);

    first_client_random = first_client_random->next_by_time;

    struct client_random **cur = get_bucket (entry->random);
    while (*cur != entry) {
      cur = &(*cur)->next_by_hash;
    }
    *cur = NULL;

    free (entry);
  }
}

static int is_allowed_timestamp (int timestamp) {
  if (timestamp > now + 3) {
    // do not allow timestamps in the future
    // after time synchronization client should always have time in the past
    vkprintf (1, "Disallow request with timestamp %d from the future\n", timestamp);
    return 0;
  }

  // first_client_random->time is an exact time when corresponding request was received
  // if the timestamp is bigger than (first_client_random->time + 3), then the current request could be accepted
  // only after the request with first_client_random, so the client random still must be cached
  // if the request wasn't accepted, then the client_random still will be cached for MAX_CLIENT_RANDOM_CACHE_TIME seconds,
  // so we can miss duplicate request only after a lot of time has passed
  if (first_client_random != NULL && timestamp > first_client_random->time + 3) {
    vkprintf (1, "Allow new request with timestamp %d\n", timestamp);
    return 1;
  }

  // allow all requests with timestamp recently in past, regardless of ability to check repeating client random
  // the allowed error must be big enough to allow requests after time synchronization
  const int MAX_ALLOWED_TIMESTAMP_ERROR = 10 * 60;
  if (timestamp > now - MAX_ALLOWED_TIMESTAMP_ERROR) {
    // this can happen only first (MAX_ALLOWED_TIMESTAMP_ERROR + 3) sceonds after first_client_random->time
    vkprintf (1, "Allow recent request with timestamp %d without full check for client random duplication\n", timestamp);
    return 1;
  }

  // the request is too old to check client random, do not allow it to force client to synchronize it's time
  vkprintf (1, "Disallow too old request with timestamp %d\n", timestamp);
  return 0;
}

int tcp_rpcs_compact_parse_execute (connection_job_t C) {
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->crypto_flags & RPCF_COMPACT_OFF) {
    return tcp_rpcs_parse_execute (C);
  }

  struct connection_info *c = CONN_INFO (C);
  int len;

  vkprintf (4, "%s. in_total_bytes = %d\n", __func__, c->in.total_bytes);  

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

    int min_len = (D->flags & RPC_F_MEDIUM) ? 4 : 1;
    if (len < min_len + 8) {
      return min_len + 8 - len;
    }

    int packet_len = 0;
    assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

    if (D->in_packet_num == -3) {
      vkprintf (1, "trying to determine connection type\n");
#if __ALLOW_UNOBFS__
      if ((packet_len & 0xff) == 0xef) {
        D->flags |= RPC_F_COMPACT;
        assert (rwm_skip_data (&c->in, 1) == 1);
        D->in_packet_num = 0;
        vkprintf (1, "Short type\n");
        continue;
      } 
      if (packet_len == 0xeeeeeeee) {
        D->flags |= RPC_F_MEDIUM;
        assert (rwm_skip_data (&c->in, 4) == 4);
        D->in_packet_num = 0;
        vkprintf (1, "Medium type\n");
        continue;
      }
      if (packet_len == 0xdddddddd) {
        D->flags |= RPC_F_MEDIUM | RPC_F_PAD;
        assert (rwm_skip_data (&c->in, 4) == 4);
        D->in_packet_num = 0;
        vkprintf (1, "Medium type\n");
        continue;
      }
        
      // http
      if ((packet_len == *(int *)"HEAD" || packet_len == *(int *)"POST" || packet_len == *(int *)"GET " || packet_len == *(int *)"OPTI") && TCP_RPCS_FUNC(C)->http_fallback_type) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "HTTP type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      // fake tls
      if (c->flags & C_IS_TLS) {
        if (len < 11) {
          return 11 - len;
        }

        vkprintf (1, "Established TLS connection\n");
        unsigned char header[11];
        assert (rwm_fetch_lookup (&c->in, header, 11) == 11);
        if (memcmp (header, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
          vkprintf (1, "error while parsing packet: bad client dummy ChangeCipherSpec\n");
          fail_connection (C, -1);
          return 0;
        }

        min_len = 11 + 256 * header[9] + header[10];
        if (len < min_len) {
          vkprintf (2, "Need %d bytes, but have only %d\n", min_len, len);
          return min_len - len;
        }

        assert (rwm_skip_data (&c->in, 11) == 11);
        len -= 11;
        c->left_tls_packet_length = 256 * header[9] + header[10]; // store left length of current TLS packet in extra_int3
        vkprintf (2, "Receive first TLS packet of length %d\n", c->left_tls_packet_length);

        if (c->left_tls_packet_length < 64) {
          vkprintf (1, "error while parsing packet: too short first TLS packet: %d\n", c->left_tls_packet_length);
          fail_connection (C, -1);
          return 0;
        }
        // now len >= c->left_tls_packet_length >= 64

        assert (rwm_fetch_lookup (&c->in, &packet_len, 4) == 4);

        c->left_tls_packet_length -= 64; // skip header length
      } else if (packet_len == *(int *)"\x16\x03\x01\x02" && ext_secret_cnt > 0) {
        unsigned char header[5];
        assert (rwm_fetch_lookup (&c->in, header, 5) == 5);
        min_len = 5 + 256 * header[3] + header[4];
        if (len < min_len) {
          return min_len - len;
        }
        if (len > min_len) {
          vkprintf (1, "Too much data in ClientHello, receive %d instead of %d\n", len, min_len);
          return (-1 << 28);
        }

        vkprintf (1, "TLS type\n");

        unsigned char client_hello[len]; // VLA
        assert (rwm_fetch_lookup (&c->in, client_hello, len) == len);

        unsigned char client_random[32];
        memcpy (client_random, client_hello + 11, 32);
        memset (client_hello + 11, '\0', 32);

        if (have_client_random (client_random)) {
          vkprintf (1, "Receive again request with the same client random\n");
          return (-1 << 28);
        }
        add_client_random (client_random);
        delete_old_client_randoms();

        unsigned char expected_random[32];
        int secret_id;
        for (secret_id = 0; secret_id < ext_secret_cnt; secret_id++) {
          sha256_hmac (ext_secret[secret_id], 16, client_hello, len, expected_random);
          if (memcmp (expected_random, client_random, 28) == 0) {
            break;
          }
        }
        if (secret_id == ext_secret_cnt) {
          vkprintf (1, "Receive request with unmatched client random\n");
          return (-1 << 28);
        }
        int timestamp = *(int *)(expected_random + 28) ^ *(int *)(client_random + 28);
        if (!is_allowed_timestamp (timestamp)) {
          return (-1 << 28);
        }

        assert (rwm_skip_data (&c->in, len) == len);
        c->flags |= C_IS_TLS;
        c->left_tls_packet_length = -1;

        int encrypted_size = get_tls_server_hello_encrypted_size();
        int response_size = 127 + 6 + 5 + encrypted_size;
        unsigned char *buffer = malloc (32 + response_size);
        assert (buffer != NULL);
        memcpy (buffer, client_random, 32);
        unsigned char *response_buffer = buffer + 32;
        memcpy (response_buffer, "\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03", 11);
        memset (response_buffer + 11, '\0', 32);
        response_buffer[43] = '\x20';
        memcpy (response_buffer + 44, client_random, 32);
        memcpy (response_buffer + 76, "\x13\x01\x00\x00\x2e", 5);
        int i;
        int pos = 81;
        for (i = 0; tls_server_extensions[i] != -1; i++) {
          if (tls_server_extensions[i] == 0x33) {
            assert (pos + 40 <= response_size);
            memcpy (response_buffer + pos, "\x00\x33\x00\x24\x00\x1d\x00\x20", 8);
            RAND_bytes (response_buffer + pos + 8, 32);
            pos += 40;
          } else if (tls_server_extensions[i] == 0x2b) {
            assert (pos + 5 <= response_size);
            memcpy (response_buffer + pos, "\x00\x2b\x00\x02\x03\x04", 6);
            pos += 6;
          } else {
            assert (0);
          }
        }
        assert (pos == 127);
        memcpy (response_buffer + 127, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9);
        pos += 9;
        response_buffer[pos++] = encrypted_size / 256;
        response_buffer[pos++] = encrypted_size % 256;
        assert (pos + encrypted_size == response_size);
        RAND_bytes (response_buffer + pos, encrypted_size);

        unsigned char server_random[32];
        sha256_hmac (ext_secret[secret_id], 16, buffer, 32 + response_size, server_random);
        memcpy (response_buffer + 11, server_random, 32);

        struct raw_message *m = calloc (sizeof (struct raw_message), 1);
        rwm_create (m, response_buffer, response_size);
        mpq_push_w (c->out_queue, m, 0);
        job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);

        free (buffer);
        return 11; // waiting for dummy ChangeCipherSpec and first packet
      }

#if __ALLOW_UNOBFS__
      int tmp[2];
      assert (rwm_fetch_lookup (&c->in, &tmp, 8) == 8);
      if (!tmp[1] && !(c->flags & C_IS_TLS)) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "Long type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      if (len < 64) {
        assert (!(c->flags & C_IS_TLS));
#if __ALLOW_UNOBFS__
        vkprintf (1, "random 64-byte header: first 0x%08x 0x%08x, need %d more bytes to distinguish\n", tmp[0], tmp[1], 64 - len);
#else
        vkprintf (1, "\"random\" 64-byte header: have %d bytes, need %d more bytes to distinguish\n", len, 64 - len);
#endif
        return 64 - len;
      }

      unsigned char random_header[64];
      unsigned char k[48];
      assert (rwm_fetch_lookup (&c->in, random_header, 64) == 64);
        
      unsigned char random_header_sav[64];
      memcpy (random_header_sav, random_header, 64);
      
      struct aes_key_data key_data;
      
      int ok = 0;
      int secret_id;
      for (secret_id = 0; secret_id < 1 || secret_id < ext_secret_cnt; secret_id++) {
        if (ext_secret_cnt > 0) {
          memcpy (k, random_header + 8, 32);
          memcpy (k + 32, ext_secret[secret_id], 16);
          sha256 (k, 48, key_data.read_key);
        } else {
          memcpy (key_data.read_key, random_header + 8, 32);
        }
        memcpy (key_data.read_iv, random_header + 40, 16);

        int i;
        for (i = 0; i < 32; i++) {
          key_data.write_key[i] = random_header[55 - i];
        }
        for (i = 0; i < 16; i++) {
          key_data.write_iv[i] = random_header[23 - i];
        }

        if (ext_secret_cnt > 0) {
          memcpy (k, key_data.write_key, 32);
          sha256 (k, 48, key_data.write_key);
        }

        aes_crypto_ctr128_init (C, &key_data, sizeof (key_data));
        assert (c->crypto);
        struct aes_crypto *T = c->crypto;

        T->read_aeskey.type->ctr128_crypt (&T->read_aeskey, random_header, random_header, 64, T->read_iv, T->read_ebuf, &T->read_num);
        unsigned tag = *(unsigned *)(random_header + 56);

        if (tag == 0xdddddddd || tag == 0xeeeeeeee || tag == 0xefefefef) {
          assert (rwm_skip_data (&c->in, 64) == 64);
          rwm_union (&c->in_u, &c->in);
          rwm_init (&c->in, 0);
          // T->read_pos = 64;
          D->in_packet_num = 0;
          switch (tag) {
            case 0xeeeeeeee:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2;
              break;
            case 0xdddddddd:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2 | RPC_F_PAD;
              break;
            case 0xefefefef:
              D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE2;
              break;
          }
          assert (c->type->crypto_decrypt_input (C) >= 0);

          int target = *(short *)(random_header + 60);
          D->extra_int4 = target;
          vkprintf (1, "tcp opportunistic encryption mode detected, tag = %08x, target=%d\n", tag, target);
          ok = 1;
          break;
        } else {
          aes_crypto_free (C);
          memcpy (random_header, random_header_sav, 64);
        }
      }

      if (ok) {
        continue;
      }

      if (ext_secret_cnt > 0) {
        vkprintf (1, "invalid \"random\" 64-byte header, entering global skip mode\n");
        return (-1 << 28);
      }

#if __ALLOW_UNOBFS__
      vkprintf (1, "short type with 64-byte header: first 0x%08x 0x%08x\n", tmp[0], tmp[1]);
      D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE1;
      D->in_packet_num = 0;

      assert (len >= 64);
      assert (rwm_skip_data (&c->in, 64) == 64);
      continue;
#else
      vkprintf (1, "invalid \"random\" 64-byte header, entering global skip mode\n");
      return (-1 << 28);
#endif
    }

    int packet_len_bytes = 4;
    if (D->flags & RPC_F_MEDIUM) {
      // packet len in `medium` mode
      //if (D->crypto_flags & RPCF_QUICKACK) {
        D->flags = (D->flags & ~RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
        packet_len &= ~RPC_F_QUICKACK;
      //}
    } else {
      // packet len in `compact` mode
      if (packet_len & 0x80) {
        D->flags |= RPC_F_QUICKACK;
        packet_len &= ~0x80;
      } else {
        D->flags &= ~RPC_F_QUICKACK;
      }
      if ((packet_len & 0xff) == 0x7f) {
        packet_len = ((unsigned) packet_len >> 8);
        if (packet_len < 0x7f) {
          vkprintf (1, "error while parsing compact packet: got length %d in overlong encoding\n", packet_len);
          fail_connection (C, -1);
          return 0;
        }
      } else {
        packet_len &= 0x7f;
        packet_len_bytes = 1;
      }
      packet_len <<= 2;
    }

    if (packet_len <= 0 || (packet_len & 0xc0000000) || (!(D->flags & RPC_F_PAD) && (packet_len & 3))) {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if ((packet_len > TCP_RPCS_FUNC(C)->max_packet_len && TCP_RPCS_FUNC(C)->max_packet_len > 0))  {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if (len < packet_len + packet_len_bytes) {
      return packet_len + packet_len_bytes - len;
    }

    assert (rwm_skip_data (&c->in, packet_len_bytes) == packet_len_bytes);
    
    struct raw_message msg;
    int packet_type;

    rwm_split_head (&msg, &c->in, packet_len);
    if (D->flags & RPC_F_PAD) {
      rwm_trunc (&msg, packet_len & -4);
    }

    assert (rwm_fetch_lookup (&msg, &packet_type, 4) == 4);

    if (D->in_packet_num < 0) {
      assert (D->in_packet_num == -3);
      D->in_packet_num = 0;
    }

    if (verbosity > 2) {
      fprintf (stderr, "received packet from connection %d (length %d, num %d, type %08x)\n", c->fd, packet_len, D->in_packet_num, packet_type);
      rwm_dump (&msg);
    }

    int res = -1;

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

    D->in_packet_num++;
  }
  return NEED_MORE_BYTES;
}

/*
 *
 *                END (EXTERNAL RPC SERVER)
 *
 */
