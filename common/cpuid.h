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

#pragma once

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)

typedef long long v2di __attribute__ ((vector_size (16)));
typedef char v16qi __attribute__ ((vector_size (16)));
typedef short v8hi __attribute__ ((vector_size (16)));
typedef int v4si __attribute__ ((vector_size (16)));
typedef double v2df __attribute__ ((vector_size (16)));
typedef float v4sf __attribute__ ((vector_size (16)));

typedef struct {
  int magic;
  int ebx, ecx, edx;
} kdb_cpuid_t;

kdb_cpuid_t *kdb_cpuid (void);
