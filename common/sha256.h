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

#pragma once

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

typedef EVP_MD_CTX sha256_context;

void sha256_starts (sha256_context *ctx);
void sha256_update (sha256_context *ctx, const unsigned char *input, int ilen);
void sha256_finish (sha256_context *ctx, unsigned char output[32]);
void sha256 (const unsigned char *input, int ilen, unsigned char output[32]);
void sha256_two_chunks (const unsigned char *input1, int ilen1, const unsigned char *input2, int ilen2, unsigned char output[32]);

void sha256_hmac (unsigned char *key, int keylen, unsigned char *input, int ilen, unsigned char output[32]);
