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

    Copyright 2014 Telegram Messenger Inc             
              2014 Nikolai Durov
              2014 Andrey Lopatin
*/

#pragma once

#define CRYPTO_TEMP_DH_PARAMS_MAGIC	0xab45ccd3

struct crypto_temp_dh_params {
  int magic;
  int dh_params_select;
  unsigned char a[256];
};

extern int dh_params_select;

int init_dh_params (void);   // result: 1 = OK, 0 = already done, -1 = error
int dh_first_round (unsigned char g_a[256], struct crypto_temp_dh_params *dh_params);
int dh_second_round (unsigned char g_ab[256], unsigned char g_a[256], const unsigned char g_b[256]);
int dh_third_round (unsigned char g_ab[256], const unsigned char g_b[256], struct crypto_temp_dh_params *dh_params);

void fetch_tot_dh_rounds_stat (long long _tot_dh_rounds[3]);
