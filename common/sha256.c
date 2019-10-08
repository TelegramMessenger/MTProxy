/*
    This file is part of KittenDB/Engine Library.

    KittenDB/Engine Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    KittenDB/Engine Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with KittenDB/Engine Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2016 Telegram Messenger Inc
              2016 Nikolai Durov
*/

#include "sha256.h"

#include <assert.h>

#include <openssl/hmac.h>

void sha256_starts (sha256_context *ctx) {
  EVP_MD_CTX_init (ctx);
  EVP_DigestInit_ex (ctx, EVP_sha256(), NULL); 
}

void sha256_update (sha256_context *ctx, const unsigned char *input, int ilen) {
  EVP_DigestUpdate (ctx, input, ilen);
}

void sha256_finish (sha256_context *ctx, unsigned char output[32]) {
  unsigned olen = 0;
  EVP_DigestFinal_ex (ctx, output, &olen);
  assert (olen == 32);
}

void sha256 (const unsigned char *input, int ilen, unsigned char output[32]) {
  sha256_context *ctx = EVP_MD_CTX_new();
  sha256_starts (ctx);
  sha256_update (ctx, input, ilen);
  sha256_finish (ctx, output);
  EVP_MD_CTX_free (ctx);
}

void sha256_two_chunks (const unsigned char *input1, int ilen1, const unsigned char *input2, int ilen2, unsigned char output[32]) {
  sha256_context *ctx = EVP_MD_CTX_new();
  sha256_starts (ctx);
  sha256_update (ctx, input1, ilen1);
  sha256_update (ctx, input2, ilen2);
  sha256_finish (ctx, output);
  EVP_MD_CTX_free (ctx);
}

void sha256_hmac (unsigned char *key, int keylen, unsigned char *input, int ilen, unsigned char output[32]) {
  unsigned int len = 0;
  unsigned char *result = HMAC(EVP_sha256(), key, keylen, input, ilen, output, &len);
  assert (result == output);
  assert (len == 32);
}
