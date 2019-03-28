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

void tg_aes_encrypt_init (tg_aes_ctx_t *ctx, unsigned char *key, unsigned char iv[16], const EVP_CIPHER *cipher) {
  ctx->evp_ctx = EVP_CIPHER_CTX_new();
  assert(ctx->evp_ctx);

  assert(EVP_EncryptInit(ctx->evp_ctx, cipher, key, iv) == 1);
  assert(EVP_CIPHER_CTX_set_padding(ctx->evp_ctx, 0) == 1);
}

void tg_aes_decrypt_init (tg_aes_ctx_t *ctx, unsigned char *key, unsigned char iv[16], const EVP_CIPHER *cipher) {
  ctx->evp_ctx = EVP_CIPHER_CTX_new();
  assert(ctx->evp_ctx);

  assert(EVP_DecryptInit(ctx->evp_ctx, cipher, key, iv) == 1);
  assert(EVP_CIPHER_CTX_set_padding(ctx->evp_ctx, 0) == 1);
}

void tg_aes_crypt(tg_aes_ctx_t *ctx, const void *in, void *out, int size) {
  int len;

  if (EVP_CIPHER_CTX_encrypting(ctx->evp_ctx)) {
    assert(EVP_EncryptUpdate(ctx->evp_ctx, out, &len, in, size) == 1);
    assert(EVP_EncryptFinal_ex(ctx->evp_ctx, out + len, &len) == 1);
  } else {
    assert(EVP_DecryptUpdate(ctx->evp_ctx, out, &len, in, size) == 1);
    assert(EVP_DecryptFinal_ex(ctx->evp_ctx, out + len, &len) == 1);
  }
}

void tg_aes_ctx_cleanup (tg_aes_ctx_t *ctx) {
  EVP_CIPHER_CTX_free(ctx->evp_ctx);
  memset (ctx, 0, sizeof (tg_aes_ctx_t));
}
