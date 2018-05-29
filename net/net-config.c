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

#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// #include <openssl/aes.h>

#include "kprintf.h"
#include "precise-time.h"
#include "net/net-events.h"   // for show_ipv6()

#include "net/net-config.h"

char pwd_config_buf[MAX_PWD_CONFIG_LEN + 128];
int pwd_config_len;
char pwd_config_md5[33] = {'n', 'o', 'n', 'e', 0};


int select_best_key_signature (int key_signature, int extra_num, const int *extra_key_signatures) {
  assert (extra_num >= 0 && extra_num <= 16);
  if (main_secret.secret_len < 4) {
    return 0;
  }
  int main_key_id = main_secret.key_signature;
  if (main_key_id == key_signature) {
    return main_key_id;
  }
  int i;
  for (i = 0; i < extra_num; i++) {
    if (main_key_id == extra_key_signatures[i]) {
      return main_key_id;
    }
  }
  return 0;
}

