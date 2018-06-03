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
              2014 Anton Maydell
*/

#include <assert.h>
#include <cpuid.h>

#include "cpuid.h"


#define CPUID_MAGIC 0x280147b8

kdb_cpuid_t *kdb_cpuid (void) {
  static kdb_cpuid_t cached = { .magic = 0 };
  if (cached.magic) {
    assert (cached.magic == CPUID_MAGIC);
    return &cached;
  }

  unsigned int a;
  assert(
    __get_cpuid(1,
        &a,
        (unsigned int*) &cached.ebx,
        (unsigned int*) &cached.ecx,
        (unsigned int*) &cached.edx
    ) != 0
  );

  cached.magic = CPUID_MAGIC;
  return &cached;
}
