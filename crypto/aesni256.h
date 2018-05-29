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

#pragma once

#include <openssl/aes.h>

struct aesni256_ctx {
  unsigned char a[256];
};

//TODO: move cbc_crypt, ige_crypt, ctr_crypt to the virtual method table
struct tg_aes_ctx;

struct tg_aes_methods {
  void (*cbc_crypt) (struct tg_aes_ctx *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16]);
  void (*ige_crypt) (struct tg_aes_ctx *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[32]);
  void (*ctr_crypt) (struct tg_aes_ctx *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16], unsigned long long offset);
  void (*ctr128_crypt) (struct tg_aes_ctx *ctx, const unsigned char *in, unsigned char *out, int size, unsigned char iv[16], unsigned char ecount_buf[16], unsigned int *num);
};

typedef struct tg_aes_ctx {
  union {
    AES_KEY key;
    struct aesni256_ctx ctx;
  } u;
  const struct tg_aes_methods *type;
} tg_aes_ctx_t;

void tg_aes_set_encrypt_key (tg_aes_ctx_t *ctx, unsigned char *key, int bits);
void tg_aes_set_decrypt_key (tg_aes_ctx_t *ctx, unsigned char *key, int bits);
void tg_aes_ctx_cleanup (tg_aes_ctx_t *ctx);
