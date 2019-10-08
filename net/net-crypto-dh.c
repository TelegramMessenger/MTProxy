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

    Copyright 2014 Telegram Messenger Inc             
              2014 Nikolai Durov
              2014 Andrey Lopatin
    
*/
#define	_FILE_OFFSET_BITS	64
#define _XOPEN_SOURCE 500


#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "crc32.h"
#include "net/net-events.h"
#include "server-functions.h"
#include "kprintf.h"
#include "precise-time.h"
#include "net/net-connections.h"
#include "jobs/jobs.h"

#include "net/net-crypto-dh.h"
#include "common/common-stats.h"

#define MODULE crypto_dh

MODULE_STAT_TYPE {
  long long tot_dh_rounds[3];
};

MODULE_INIT

MODULE_STAT_FUNCTION
  sb_printf (sb,
    "tot_dh_rounds\t%lld %lld %lld\n", SB_SUM_LL(tot_dh_rounds[0]), SB_SUM_LL(tot_dh_rounds[1]), SB_SUM_LL(tot_dh_rounds[2])
  );
MODULE_STAT_FUNCTION_END

void fetch_tot_dh_rounds_stat (long long _tot_dh_rounds[3]) {
  int i;
  for (i = 0; i < 3; i++) {
    _tot_dh_rounds[i] = SB_SUM_LL(tot_dh_rounds[i]);
  }
}

const unsigned char rpc_dh_prime_bin[256] = {0x89, 0x52, 0x13, 0x1b, 0x1e, 0x3a, 0x69, 0xba, 0x5f, 0x85, 0xcf, 0x8b, 0xd2, 0x66, 0xc1, 0x2b, 0x13, 0x83, 0x16, 0x13, 0xbd, 0x2a, 0x4e, 0xf8, 0x35, 0xa4, 0xd5, 0x3f, 0x9d, 0xbb, 0x42, 0x48, 0x2d, 0xbd, 0x46, 0x2b, 0x31, 0xd8, 0x6c, 0x81, 0x6c, 0x59, 0x77, 0x52, 0x0f, 0x11, 0x70, 0x73, 0x9e, 0xd2, 0xdd, 0xd6, 0xd8, 0x1b, 0x9e, 0xb6, 0x5f, 0xaa, 0xac, 0x14, 0x87, 0x53, 0xc9, 0xe4, 0xf0, 0x72, 0xdc, 0x11, 0xa4, 0x92, 0x73, 0x06, 0x83, 0xfa, 0x00, 0x67, 0x82, 0x6b, 0x18, 0xc5, 0x1d, 0x7e, 0xcb, 0xa5, 0x2b, 0x82, 0x60, 0x75, 0xc0, 0xb9, 0x55, 0xe5, 0xac, 0xaf, 0xdd, 0x74, 0xc3, 0x79, 0x5f, 0xd9, 0x52, 0x0b, 0x48, 0x0f, 0x3b, 0xe3, 0xba, 0x06, 0x65, 0x33, 0x8a, 0x49, 0x8c, 0xa5, 0xda, 0xf1, 0x01, 0x76, 0x05, 0x09, 0xa3, 0x8c, 0x49, 0xe3, 0x00, 0x74, 0x64, 0x08, 0x77, 0x4b, 0xb3, 0xed, 0x26, 0x18, 0x1a, 0x64, 0x55, 0x76, 0x6a, 0xe9, 0x49, 0x7b, 0xb9, 0xc3, 0xa3, 0xad, 0x5c, 0xba, 0xf7, 0x6b, 0x73, 0x84, 0x5f, 0xbb, 0x96, 0xbb, 0x6d, 0x0f, 0x68, 0x4f, 0x95, 0xd2, 0xd3, 0x9c, 0xcb, 0xb4, 0xa9, 0x04, 0xfa, 0xb1, 0xde, 0x43, 0x49, 0xce, 0x1c, 0x20, 0x87, 0xb6, 0xc9, 0x51, 0xed, 0x99, 0xf9, 0x52, 0xe3, 0x4f, 0xd1, 0xa3, 0xfd, 0x14, 0x83, 0x35, 0x75, 0x41, 0x47, 0x29, 0xa3, 0x8b, 0xe8, 0x68, 0xa4, 0xf9, 0xec, 0x62, 0x3a, 0x5d, 0x24, 0x62, 0x1a, 0xba, 0x01, 0xb2, 0x55, 0xc7, 0xe8, 0x38, 0x5d, 0x16, 0xac, 0x93, 0xb0, 0x2d, 0x2a, 0x54, 0x0a, 0x76, 0x42, 0x98, 0x2d, 0x22, 0xad, 0xa3, 0xcc, 0xde, 0x5c, 0x8d, 0x26, 0x6f, 0xaa, 0x25, 0xdd, 0x2d, 0xe9, 0xf6, 0xd4, 0x91, 0x04, 0x16, 0x2f, 0x68, 0x5c, 0x45, 0xfe, 0x34, 0xdd, 0xab};
#define RPC_DH_GEN	3

#define RPC_PARAM_HASH	0x00620b93

int dh_params_select;

BIGNUM *rpc_dh_prime, *rpc_dh_generator;

__thread BN_CTX *rpc_BN_ctx;



static int is_good_rpc_dh_bin (const unsigned char *data) {
  int i;
  int ok = 0;
  for (i = 0; i < 8; i++) {
    if (data[i]) {
      ok = 1;
      break;
    }
  }
  if (!ok) {
    return 0;
  }
  for (i = 0; i < 8; i++) {
    if (data[i] > rpc_dh_prime_bin[i]) {
      return 0;
    }
    if (data[i] < rpc_dh_prime_bin[i]) {
      return 1;
    }
  }
  return 0;
}


pthread_mutex_t DhInitLock = PTHREAD_MUTEX_INITIALIZER;

// result: 1 = OK, 0 = already done, -1 = error
int init_dh_params (void) {
  if (dh_params_select) {
    return 0;
  }
  pthread_mutex_lock (&DhInitLock);
  if (dh_params_select) {
    pthread_mutex_unlock (&DhInitLock);
    return 0;
  }

  rpc_dh_prime = BN_new(); 
  assert (BN_bin2bn (rpc_dh_prime_bin, sizeof (rpc_dh_prime_bin), rpc_dh_prime));

  rpc_dh_generator = BN_new();
  BN_set_word (rpc_dh_generator, RPC_DH_GEN);

  static unsigned char buf[264], shabuf[20];
  *(int *)buf = RPC_DH_GEN;
  *(int *)(buf + 4) = 0x000100fe;
  assert (sizeof (rpc_dh_prime_bin) == sizeof (buf) - 8);
  memcpy (buf + 8, rpc_dh_prime_bin, sizeof (rpc_dh_prime_bin));
  SHA1 (buf, sizeof (buf), shabuf);

  rpc_BN_ctx = BN_CTX_new ();

  dh_params_select = *(int *)shabuf;
  assert (dh_params_select == RPC_PARAM_HASH);
  
  pthread_mutex_unlock (&DhInitLock);
  return 1;
}


void create_g_a (unsigned char g_a[256], unsigned char a[256]) {
  if (!rpc_BN_ctx) {
    rpc_BN_ctx = BN_CTX_new ();
  }
  do {
    assert (RAND_bytes (a, 256) >= 0); /* if you write '>0', the assert will fail. It's very sad */

    BIGNUM *dh_power = BN_new ();
    assert (BN_bin2bn (a, 256, dh_power) == dh_power);
    BIGNUM *value = BN_new ();
    assert (BN_mod_exp (value, rpc_dh_generator, dh_power, rpc_dh_prime, rpc_BN_ctx) == 1);
    BN_clear_free (dh_power);

    int len = BN_num_bytes (value);
    assert (len > 240 && len <= 256);
  
    memset (g_a, 0, 256 - len);
    assert (BN_bn2bin (value, g_a + (256 - len)) == len);

    BN_free (value);
  } while (!is_good_rpc_dh_bin (g_a));
}


int dh_first_round (unsigned char g_a[256], struct crypto_temp_dh_params *dh_params) {
  dh_params->dh_params_select = dh_params_select;
  create_g_a (g_a, dh_params->a);
  dh_params->magic = CRYPTO_TEMP_DH_PARAMS_MAGIC;
  MODULE_STAT->tot_dh_rounds[0] ++;
  
  return 1;
}


static void dh_inner_round (unsigned char g_ab[256], const unsigned char g_b[256], const unsigned char a[256]) {
  if (!rpc_BN_ctx) {
    rpc_BN_ctx = BN_CTX_new ();
  }
  BIGNUM *dh_base = BN_new ();
  assert (BN_bin2bn (g_b, 256, dh_base) == dh_base);

  BIGNUM *dh_power = BN_new ();
  assert (BN_bin2bn (a, 256, dh_power) == dh_power);

  BIGNUM *key = BN_new ();
  assert (BN_mod_exp (key, dh_base, dh_power, rpc_dh_prime, rpc_BN_ctx) == 1);
  
  BN_free (dh_base);
  BN_clear_free (dh_power);

  int len = BN_num_bytes (key);
  assert (len > 240 && len <= 256);
  
  memset (g_ab, 0, 256 - len);
  assert (BN_bn2bin (key, g_ab + (256 - len)) == len);

  BN_clear_free (key);
}


int dh_second_round (unsigned char g_ab[256], unsigned char g_a[256], const unsigned char g_b[256]) {
  unsigned char a[256];

  if (!is_good_rpc_dh_bin (g_b)) {
    return 0;
  }

  create_g_a (g_a, a);

  dh_inner_round (g_ab, g_b, a);

  memset (a, 0, sizeof (a));

  vkprintf (2, "DH key is %02x%02x%02x...%02x%02x%02x\n", g_ab[0], g_ab[1], g_ab[2], g_ab[253], g_ab[254], g_ab[255]);
  MODULE_STAT->tot_dh_rounds[1]++;
  
  return 256;
}

int dh_third_round (unsigned char g_ab[256], const unsigned char g_b[256], struct crypto_temp_dh_params *dh_params) {
  if (!is_good_rpc_dh_bin (g_b)) {
    return 0;
  }

  dh_inner_round (g_ab, g_b, dh_params->a);

  vkprintf (2, "DH key is %02x%02x%02x...%02x%02x%02x\n", g_ab[0], g_ab[1], g_ab[2], g_ab[253], g_ab[254], g_ab[255]);
  MODULE_STAT->tot_dh_rounds[2]++;

  return 256;
}
