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

#pragma once

#include <openssl/aes.h>

#include "net/net-connections.h"
#include "crypto/aesni256.h"
#include "pid.h"

#define	MIN_PWD_LEN 32
#define MAX_PWD_LEN 256

#define	DEFAULT_PWD_FILE	"secret"

int aes_crypto_init (connection_job_t c, void *key_data, int key_data_len);  /* < 0 = error */
int aes_crypto_ctr128_init (connection_job_t c, void *key_data, int key_data_len);
int aes_crypto_free (connection_job_t c);
int aes_crypto_encrypt_output (connection_job_t c);  /* 0 = all ok, >0 = so much more bytes needed to encrypt last block */
int aes_crypto_decrypt_input (connection_job_t c);   /* 0 = all ok, >0 = so much more bytes needed to decrypt last block */
int aes_crypto_needed_output_bytes (connection_job_t c);	/* returns # of bytes needed to complete last output block */

void fetch_aes_crypto_stat (int *allocated_aes_crypto_ptr, int *allocated_aes_crypto_temp_ptr);

typedef struct aes_secret {
  int refcnt;
  int secret_len;
  union {
    char secret[MAX_PWD_LEN+4];
    int key_signature;
  };
} aes_secret_t;

extern aes_secret_t main_secret;

/* for aes_crypto_init */
struct aes_key_data {
  unsigned char read_key[32];
  unsigned char read_iv[16];
  unsigned char write_key[32];
  unsigned char write_iv[16];
};

#define	AES_KEY_DATA_LEN	sizeof (struct aes_key_data)

/* for c->crypto */
struct aes_crypto {
  EVP_CIPHER_CTX *read_aeskey;
  EVP_CIPHER_CTX *write_aeskey;
};

extern int aes_initialized;

int aes_load_pwd_data (void *data, int len);
int aes_load_pwd_file (const char *filename);
int aes_load_random (void);
int aes_get_pwd_data (void *data, int len);
int aes_generate_nonce (char res[16]);

int aes_create_keys (struct aes_key_data *R, int am_client, const char nonce_server[16], const char nonce_client[16], int client_timestamp,
		     unsigned server_ip, unsigned short server_port, const unsigned char server_ipv6[16],
		     unsigned client_ip, unsigned short client_port, const unsigned char client_ipv6[16],
		     const aes_secret_t *key, const unsigned char *temp_key, int temp_key_len);

int aes_create_udp_keys (struct aes_key_data *R, struct process_id *local_pid, struct process_id *remote_pid, int generation, const aes_secret_t *key);

void free_aes_secret (aes_secret_t *secret);
aes_secret_t *alloc_aes_secret (const char *key, int key_len);
static inline void aes_secret_decref (aes_secret_t *secret) { if (__sync_add_and_fetch (&secret->refcnt, -1) <= 0) { free_aes_secret (secret); } }
static inline void aes_secret_incref (aes_secret_t *secret) { __sync_fetch_and_add (&secret->refcnt, 1); }
void free_crypto_temp (void *crypto, int len);
void *alloc_crypto_temp (int len);
