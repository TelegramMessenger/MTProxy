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
              2014-2016 Nikolai Durov
              2014-2016 Vitaliy Valtman
*/

#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// #include <openssl/aes.h>

#include "kprintf.h"
#include "precise-time.h"

#include "net/net-crypto-aes.h"
#include "net/net-config.h"

#include "net/net-connections.h"
#include "md5.h"
#include "sha1.h"

#include "jobs/jobs.h"
#include "common/common-stats.h"

#define MODULE crypto_aes

MODULE_STAT_TYPE {
  int allocated_aes_crypto, allocated_aes_crypto_temp;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_I (allocated_aes_crypto);
  SB_SUM_ONE_I (allocated_aes_crypto_temp);

  sb_printf (sb,
    "aes_pwd_hash\t%s\n",
    pwd_config_md5);
MODULE_STAT_FUNCTION_END

void fetch_aes_crypto_stat (int *allocated_aes_crypto_ptr, int *allocated_aes_crypto_temp_ptr) {
  if (allocated_aes_crypto_ptr) {
    *allocated_aes_crypto_ptr = SB_SUM_I (allocated_aes_crypto);
  }
  if (allocated_aes_crypto_temp_ptr) {
    *allocated_aes_crypto_temp_ptr = SB_SUM_I (allocated_aes_crypto_temp);
  }
}

aes_secret_t main_secret;

int aes_crypto_init (connection_job_t c, void *key_data, int key_data_len) {
  assert (key_data_len == sizeof (struct aes_key_data));
  struct aes_crypto *T = NULL;
  assert (!posix_memalign ((void **)&T, 16, sizeof (struct aes_crypto)));
  struct aes_key_data *D = key_data;
  assert (T);

  MODULE_STAT->allocated_aes_crypto ++;
  
  T->read_aeskey = evp_cipher_ctx_init (EVP_aes_256_cbc(), D->read_key, D->read_iv, 0);
  T->write_aeskey = evp_cipher_ctx_init (EVP_aes_256_cbc(), D->write_key, D->write_iv, 1);
  CONN_INFO(c)->crypto = T;
  return 0;
}

int aes_crypto_ctr128_init (connection_job_t c, void *key_data, int key_data_len) {
  assert (key_data_len == sizeof (struct aes_key_data));
  struct aes_crypto *T = NULL;
  assert (!posix_memalign ((void **)&T, 16, sizeof (struct aes_crypto)));
  struct aes_key_data *D = key_data;
  assert (T);

  MODULE_STAT->allocated_aes_crypto ++;
  
  T->read_aeskey = evp_cipher_ctx_init (EVP_aes_256_ctr(), D->read_key, D->read_iv, 1); // NB: is_encrypt == 1 here!
  T->write_aeskey = evp_cipher_ctx_init (EVP_aes_256_ctr(), D->write_key, D->write_iv, 1);
  CONN_INFO(c)->crypto = T;
  return 0;
}

int aes_crypto_free (connection_job_t c) {
  struct aes_crypto *crypto = CONN_INFO(c)->crypto;
  if (crypto) {
    EVP_CIPHER_CTX_free (crypto->read_aeskey);
    EVP_CIPHER_CTX_free (crypto->write_aeskey);

    free (crypto);
    CONN_INFO(c)->crypto = 0;
    MODULE_STAT->allocated_aes_crypto --;
  }
  if (CONN_INFO(c)->crypto_temp) {
    free (CONN_INFO(c)->crypto_temp);
    CONN_INFO(c)->crypto_temp = 0;
    MODULE_STAT->allocated_aes_crypto_temp --;
  }
  return 0;
}


int aes_initialized;
static char rand_buf[64];

// filename = 0 -- use DEFAULT_PWD_FILE
// 1 = init ok, else < 0
int aes_load_pwd_file (const char *filename) {
  int h = open ("/dev/random", O_RDONLY | O_NONBLOCK);
  int r = 0;

  if (h >= 0) {
    r = read (h, rand_buf, 16);
    if (r < 0) {
      perror ("READ");
      r = 0;
    }
    if (r > 0) {
      vkprintf (2, "added %d bytes of real entropy to the AES security key\n", r);
    }
    if (r < 0) {
      perror ("read from random");
      r = 0;
    }
    close (h);
  }

  if (r < 16) {
    h = open ("/dev/urandom", O_RDONLY);
    if (h < 0) {
      main_secret.secret_len = 0;
      return -1;
    }
    int s = read (h, rand_buf + r, 16 - r);
    if (r + s != 16) {
      main_secret.secret_len = 0;
      return -1;
    }
    close (h);
  }

  *(long *) rand_buf ^= lrand48_j();

  srand48 (*(long *)rand_buf);

  if (!filename) {
    filename = DEFAULT_PWD_FILE;
  }

  h = open (filename, O_RDONLY);

  if (h < 0) {
    vkprintf (1, "cannot open password file %s: %m\n", filename);
    return -0x80000000;
  }

  r = read (h, pwd_config_buf, MAX_PWD_CONFIG_LEN + 1);

  close (h);

  if (r < 0) {
    vkprintf (1, "error reading password file %s: %m\n", filename);
    return -1;
  }

  vkprintf (1, "loaded %d bytes from password file %s\n", r, filename);

  if (r > MAX_PWD_CONFIG_LEN) {
    pwd_config_len = 0;
    return -1;
  }

  pwd_config_len = r;
  memset (pwd_config_buf + r, 0, 4);

  if (r < MIN_PWD_LEN || r > MAX_PWD_LEN) {
    vkprintf (1, "secret file %s too long or too short: loaded %d bytes, expected %d..%d\n", filename, r, MIN_PWD_LEN, MAX_PWD_LEN);
    return -1;
  }

  md5_hex (pwd_config_buf, pwd_config_len, pwd_config_md5);
  
  memcpy (main_secret.secret, pwd_config_buf, r);
  main_secret.secret_len = r;

  aes_initialized = 1;

  return 1;
}

int aes_generate_nonce (char res[16]) {
  *(int *)(rand_buf + 16) = lrand48_j ();
  *(int *)(rand_buf + 20) = lrand48_j ();
  *(long long *)(rand_buf + 24) = rdtsc ();
  struct timespec T;
  assert (clock_gettime(CLOCK_REALTIME, &T) >= 0);
  *(int *)(rand_buf + 32) = T.tv_sec;
  *(int *)(rand_buf + 36) = T.tv_nsec;
  (*(int *)(rand_buf + 40))++;

  md5 ((unsigned char *)rand_buf, 44, (unsigned char *)res);
  return 0;
} 


// str := nonce_server.nonce_client.client_timestamp.server_ip.client_port.("SERVER"/"CLIENT").client_ip.server_port.master_key.nonce_server.[client_ipv6.server_ipv6].nonce_client
// key := SUBSTR(MD5(str+1),0,12).SHA1(str)
// iv  := MD5(str+2)

int aes_create_keys (struct aes_key_data *R, int am_client, const char nonce_server[16], const char nonce_client[16], int client_timestamp,
		     unsigned server_ip, unsigned short server_port, const unsigned char server_ipv6[16], 
		     unsigned client_ip, unsigned short client_port, const unsigned char client_ipv6[16],
		     const aes_secret_t *key, const unsigned char *temp_key, int temp_key_len) {
  unsigned char str[16+16+4+4+2+6+4+2+MAX_PWD_LEN+16+16+4+16*2 + 256];
  int i, str_len;

  if (!key->secret_len) {
    return -1;
  }

  assert (key->secret_len >= MIN_PWD_LEN && key->secret_len <= MAX_PWD_LEN);

  memcpy (str, nonce_server, 16);
  memcpy (str + 16, nonce_client, 16);
  *((int *) (str + 32)) = client_timestamp;
  *((unsigned *) (str + 36)) = server_ip;
  *((unsigned short *) (str + 40)) = client_port;
  memcpy (str + 42, am_client ? "CLIENT" : "SERVER", 6);
  *((unsigned *) (str + 48)) = client_ip;
  *((unsigned short *) (str + 52)) = server_port;
  memcpy (str + 54, key->secret, key->secret_len);
  memcpy (str + 54 + key->secret_len, nonce_server, 16);
  str_len = 70 + key->secret_len;

  if (!server_ip) {
    assert (!client_ip);
    memcpy (str + str_len, client_ipv6, 16);
    memcpy (str + str_len + 16, server_ipv6, 16);
    str_len += 32;
  } else {
    assert (client_ip);
  }

  memcpy (str + str_len, nonce_client, 16);
  str_len += 16;

  if (temp_key_len > sizeof (str)) {
    temp_key_len = sizeof (str);
  }

  int first_len = str_len < temp_key_len ? str_len : temp_key_len;

  for (i = 0; i < first_len; i++) {
    str[i] ^= temp_key[i];
  }

  for (i = first_len; i < temp_key_len; i++) {
    str[i] = temp_key[i];
  }

  if (str_len < temp_key_len) {
    str_len = temp_key_len;
  }

  md5 (str + 1, str_len - 1, R->write_key);
  sha1 (str, str_len, R->write_key + 12);
  md5 (str + 2, str_len - 2, R->write_iv);

  //memcpy (str + 42, !am_client ? "CLIENT" : "SERVER", 6);
  str[42] ^= 'C' ^ 'S';
  str[43] ^= 'L' ^ 'E';
  str[44] ^= 'I' ^ 'R';
  str[45] ^= 'E' ^ 'V';
  str[46] ^= 'N' ^ 'E';
  str[47] ^= 'T' ^ 'R';

  md5 (str + 1, str_len - 1, R->read_key);
  sha1 (str, str_len, R->read_key + 12);
  md5 (str + 2, str_len - 2, R->read_iv);

  memset (str, 0, str_len);

  return 1;
}

int get_crypto_key_id (void) {
  if (main_secret.secret_len >= 4) {
    return main_secret.key_signature;
  } else {
    return 0;
  }
}

int get_extra_crypto_key_ids (int *buf, int max) {
  return 0;
}

int is_valid_crypto_key_id (int x) {
  return x && x == main_secret.key_signature && main_secret.secret_len >= 4;
}

void free_crypto_temp (void *crypto, int len) {
  memset (crypto, 0, len);
  free (crypto);
  MODULE_STAT->allocated_aes_crypto_temp --;
}

void *alloc_crypto_temp (int len) {
  void *res = malloc (len);
  assert (res);
  MODULE_STAT->allocated_aes_crypto_temp ++;
  return res;
}
