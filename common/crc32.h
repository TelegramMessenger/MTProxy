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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned (*crc32_partial_func_t) (const void *data, long len, unsigned crc);
typedef unsigned (*crc32_combine_func_t) (unsigned crc1, unsigned crc2, int64_t len2);
typedef uint64_t (*crc64_partial_func_t) (const void *data, long len, uint64_t crc);
typedef uint64_t (*crc64_combine_func_t) (uint64_t crc1, uint64_t crc2, int64_t len2);

extern crc32_partial_func_t crc32_partial;
extern crc64_partial_func_t crc64_partial;
extern crc32_combine_func_t compute_crc32_combine;
extern crc64_combine_func_t compute_crc64_combine;

static inline unsigned compute_crc32 (const void *data, long len) {
  return crc32_partial (data, len, -1) ^ -1;
}

static inline uint64_t compute_crc64 (const void *data, long len) {
  return crc64_partial (data, len, -1LL) ^ -1LL;
}

/* crc32_check_and_repair returns
   0 : Cyclic redundancy check is ok
   1 : Cyclic redundancy check fails, but we fix one bit in input
   2 : Cyclic redundancy check fails, but we fix one bit in input_crc32
  -1 : Cyclic redundancy check fails, no repair possible. 
       In this case *input_crc32 will be equal crc32 (input, l)

  Case force_exit == 1 (case 1, 2: kprintf call, case -1: assert fail).
*/
int crc32_check_and_repair (void *input, int l, unsigned *input_crc32, int force_exit);
int crc32_find_corrupted_bit (int size, unsigned d);
int crc32_repair_bit (unsigned char *input, int l, int k);

/* these functions are exported only for testing purpose */
unsigned crc32_partial_generic (const void *data, long len, unsigned crc);
unsigned crc32_partial_clmul (const void *data, long len, unsigned crc);
uint64_t crc64_partial_one_table (const void *data, long len, uint64_t crc);
uint64_t crc64_partial_clmul (const void *data, long len, uint64_t crc);

uint64_t crc64_feed_byte (uint64_t crc, unsigned char b);


void gf32_compute_powers_generic (unsigned *P, int size, unsigned poly);
void gf32_compute_powers_clmul (unsigned *P, unsigned poly);
unsigned gf32_combine_generic (unsigned *powers, unsigned crc1, int64_t len2);
uint64_t gf32_combine_clmul (unsigned *powers, unsigned crc1, int64_t len2);


#ifdef __cplusplus
}
#endif
