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

#ifdef USE_AESNI
void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
#endif

void AES_ctr128_encrypt(
		const unsigned char *in, 
		unsigned char *out,
		size_t length, 
		const AES_KEY *key,
		unsigned char ivec[AES_BLOCK_SIZE],
		unsigned char ecount_buf[AES_BLOCK_SIZE],
		unsigned int *num) {
    block128_f block_func = (block128_f)
#ifdef USE_AESNI
        aesni_encrypt;
#else
        AES_encrypt;
#endif

	CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num, block_func);
}
#endif

static void handle_errors() {
  assert(0);
}

static void tg_ssl_aes_cbc_encrypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16]) {
  int len;

  if(EVP_EncryptUpdate(ctx->evp_enc_ctx, out, &len, in, size) != 1) {
    handle_errors();
  }

  if(EVP_EncryptFinal_ex(ctx->evp_enc_ctx, out + len, &len) != 1) {
    handle_errors();
  }
}

static void tg_ssl_aes_cbc_decrypt (tg_aes_ctx_t *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16]) {
  int len;

  if(EVP_DecryptUpdate(ctx->evp_dec_ctx, out, &len, in, size) != 1) {
    handle_errors();
  }

  if(EVP_DecryptFinal_ex(ctx->evp_dec_ctx, out + len, &len) != 1) {
    handle_errors();
  }
}

void tg_ssl_aes_ctr128_crypt (struct tg_aes_ctx *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16], 
                                unsigned char ecount_buf[16], unsigned int *num) {
    AES_ctr128_encrypt (in, out, size, &ctx->u.key, iv, ecount_buf, num);
}

static const struct tg_aes_methods ssl_aes_encrypt_methods = {
  .cbc_crypt = tg_ssl_aes_cbc_encrypt,
  .ctr128_crypt = tg_ssl_aes_ctr128_crypt
};

void tg_aes_set_encrypt_key_cbc (tg_aes_ctx_t *ctx, unsigned char *key, unsigned char iv[16], int bits) {
  ctx->evp_enc_ctx = EVP_CIPHER_CTX_new();
  assert(ctx->evp_enc_ctx);

  if(EVP_EncryptInit(ctx->evp_enc_ctx, EVP_aes_256_cbc(), key, iv) != 1) {
    handle_errors();
  }

  ctx->type = &ssl_aes_encrypt_methods;
}

void tg_aes_set_encrypt_key_ctr (tg_aes_ctx_t *ctx, unsigned char *key, unsigned char iv[16], int bits) {
#ifdef USE_AESNI
  aesni_set_encrypt_key(key, bits, &ctx->u.key);
#else
  AES_set_encrypt_key (key, bits, &ctx->u.key);
#endif

  ctx->type = &ssl_aes_encrypt_methods;
}

static const struct tg_aes_methods ssl_aes_decrypt_methods = {
  .cbc_crypt = tg_ssl_aes_cbc_decrypt,
  .ctr128_crypt = NULL
};

void tg_aes_set_decrypt_key_cbc (tg_aes_ctx_t *ctx, unsigned char *key, unsigned char iv[16], int bits) {
  ctx->evp_dec_ctx = EVP_CIPHER_CTX_new();
  assert(ctx->evp_dec_ctx);

  if(EVP_DecryptInit(ctx->evp_dec_ctx, EVP_aes_256_cbc(), key, iv) != 1) {
    handle_errors();
  }

  ctx->type = &ssl_aes_decrypt_methods;
}

void tg_aes_set_decrypt_key_ctr (tg_aes_ctx_t *ctx, unsigned char *key, unsigned char iv[16], int bits) {
#ifdef USE_AESNI
  aesni_set_decrypt_key(key, bits, &ctx->u.key);
#else
  AES_set_decrypt_key (key, bits, &ctx->u.key);
#endif

  ctx->type = &ssl_aes_decrypt_methods;
}

void tg_aes_ctx_cleanup (tg_aes_ctx_t *ctx) {
  if (ctx->evp_enc_ctx) {
    EVP_CIPHER_CTX_free(ctx->evp_enc_ctx);
  }

  if (ctx->evp_dec_ctx) {
    EVP_CIPHER_CTX_free(ctx->evp_dec_ctx);
  }

  memset (ctx, 0, sizeof (tg_aes_ctx_t));
}
