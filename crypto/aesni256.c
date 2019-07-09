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

EVP_CIPHER_CTX *evp_cipher_ctx_init (const EVP_CIPHER *cipher, unsigned char *key, unsigned char iv[16], int is_encrypt) {
  EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
  assert(evp_ctx);

  assert(EVP_CipherInit(evp_ctx, cipher, key, iv, is_encrypt) == 1);
  assert(EVP_CIPHER_CTX_set_padding(evp_ctx, 0) == 1);
  return evp_ctx;
}

void evp_crypt (EVP_CIPHER_CTX *evp_ctx, const void *in, void *out, int size) {
  int len;
  assert (EVP_CipherUpdate(evp_ctx, out, &len, in, size) == 1);
  assert (len == size);
}
