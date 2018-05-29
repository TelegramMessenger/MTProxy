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

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#pragma once

#include "common/crc32.h"

#ifdef __cplusplus
extern "C" {
#endif

//extern unsigned int crc32c_table[256];
extern crc32_partial_func_t crc32c_partial;
extern crc32_combine_func_t compute_crc32c_combine;

static inline unsigned compute_crc32c (const void *data, int len) {
  return crc32c_partial (data, len, -1) ^ -1;
}

unsigned crc32c_partial_four_tables (const void *data, long len, unsigned crc);

#ifdef __cplusplus
}
#endif
