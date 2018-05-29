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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Anton Maydell

    Copyright 2014-2016 Telegram Messenger Inc
              2014-2016 Anton Maydell
*/

#include "crypto/aesni256.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "common/cpuid.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/modes.h>
void AES_ctr128_encrypt(
		const unsigned char *in, 
		unsigned char *out,
		size_t length, 
		const AES_KEY *key,
		unsigned char ivec[AES_BLOCK_SIZE],
		unsigned char ecount_buf[AES_BLOCK_SIZE],
		unsigned int *num) {
	CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num, (block128_f)AES_encrypt);
}
#endif

void tg_ssl_aes_ctr_crypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16], unsigned long long offset) {
  unsigned char iv_copy[16];
  memcpy (iv_copy, iv, 16);
  unsigned long long *p = (unsigned long long *) (iv_copy + 8);
  (*p) += offset >> 4;
  union {
    unsigned char c[16];
    unsigned long long d[2];
  } u;
  int i = offset & 15, l;
  if (i) {
    AES_encrypt (iv_copy, u.c, &ctx->u.key);
    (*p)++;
    l = i + size;
    if (l > 16) {
      l = 16;
    }
    size -= l - i;
    do {
      *out++ = (*in++) ^ u.c[i++];
    } while (i < l);
  }
  const unsigned long long *I = (const unsigned long long *) in;
  unsigned long long *O = (unsigned long long *) out;
  int n = size >> 4;
  while (--n >= 0) {
    AES_encrypt (iv_copy, (unsigned char *) u.d, &ctx->u.key);
    (*p)++;
    *O++ = (*I++) ^ u.d[0];
    *O++ = (*I++) ^ u.d[1];
  }
  l = size & 15;
  if (l) {
    AES_encrypt (iv_copy, u.c, &ctx->u.key);
    in = (const unsigned char *) I;
    out = (unsigned char *) O;
    i = 0;
    do {
      *out++ = (*in++) ^ u.c[i++];
    } while (i < l);
  }
}


static void tg_ssl_aes_cbc_encrypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16]) {
  AES_cbc_encrypt (in, out, size, &ctx->u.key, iv, AES_ENCRYPT);
}

static void tg_ssl_aes_cbc_decrypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16]) {
  AES_cbc_encrypt (in, out, size, &ctx->u.key, iv, AES_DECRYPT);
}

static void tg_ssl_aes_ige_encrypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[32]) {
  AES_ige_encrypt (in, out, size, &ctx->u.key, iv, AES_ENCRYPT);
}

static void tg_ssl_aes_ige_decrypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[32]) {
  AES_ige_encrypt (in, out, size, &ctx->u.key, iv, AES_DECRYPT);
}

void tg_ssl_aes_ctr128_crypt (struct tg_aes_ctx *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16], unsigned char ecount_buf[16], unsigned int *num) {
  AES_ctr128_encrypt (in, out, size, &ctx->u.key, iv, ecount_buf, num);
}

static const struct tg_aes_methods ssl_aes_encrypt_methods = {
  .cbc_crypt = tg_ssl_aes_cbc_encrypt,
  .ige_crypt = tg_ssl_aes_ige_encrypt,
  .ctr_crypt = tg_ssl_aes_ctr_crypt,
  .ctr128_crypt = tg_ssl_aes_ctr128_crypt
};

void tg_aes_set_encrypt_key (tg_aes_ctx_t *ctx, unsigned char *key, int bits) {
  AES_set_encrypt_key (key, bits, &ctx->u.key);
  ctx->type = &ssl_aes_encrypt_methods;
}

static const struct tg_aes_methods ssl_aes_decrypt_methods = {
  .cbc_crypt = tg_ssl_aes_cbc_decrypt,
  .ige_crypt = tg_ssl_aes_ige_decrypt,
  .ctr_crypt = NULL,
  .ctr128_crypt = NULL
};

void tg_aes_set_decrypt_key (tg_aes_ctx_t *ctx, unsigned char *key, int bits) {
  AES_set_decrypt_key (key, bits, &ctx->u.key);
  ctx->type = &ssl_aes_decrypt_methods;
}

void tg_aes_ctx_cleanup (tg_aes_ctx_t *ctx) {
  memset (ctx, 0, sizeof (tg_aes_ctx_t));
}
