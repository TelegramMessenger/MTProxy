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

    Copyright 2014-2016 Telegram Messenger Inc             
              2014-2016 Nikolai Durov
*/

#pragma once

#include "net/net-crypto-aes.h"

#define MAX_PWD_CONFIG_LEN	16384

#define RPCF_ALLOW_UNENC        1
#define RPCF_ALLOW_ENC          2
#define RPCF_REQ_DH             4
#define RPCF_ALLOW_SKIP_DH      8
#define RPCF_DISABLE_RPC	0x1000
#define RPCF_ALLOW_MC		0x2000
#define RPCF_ALLOW_SQL		0x4000
#define RPCF_ALLOW_HTTP		0x8000
#define RPCF_RESULT_VALID	0x80000000

extern char pwd_config_buf[MAX_PWD_CONFIG_LEN + 128];
extern int pwd_config_len;
extern char pwd_config_md5[33];

int select_best_key_signature (int key_signature, int extra_num, const int *extra_key_signatures);
