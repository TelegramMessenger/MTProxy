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

    Copyright 2011-2013 Vkontakte Ltd
              2011-2013 Nikolai Durov
              2011-2013 Andrey Lopatin

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include "common/pid.h"

npid_t PID;

void init_common_PID (void) {
  if (!PID.pid) {
    int p = getpid ();
    assert (!(p & 0xffff0000));
    PID.pid = p;
  }
  if (!PID.utime) {
    PID.utime = time (0);
  }
}

void init_client_PID (unsigned ip) {
  if (ip && ip != 0x7f000001) {
    PID.ip = ip;
  }
  // PID.port = 0;
  init_common_PID ();
};

void init_server_PID (unsigned ip, int port) {
  if (ip && ip != 0x7f000001) {
    PID.ip = ip;
  }
  if (!PID.port) {
    PID.port = port;
  }
  init_common_PID ();
};

/* returns 1 if X is a special case of Y, 2 if they match completely */
int matches_pid (npid_t *X, npid_t *Y) {
  if (!memcmp (X, Y, sizeof (struct process_id))) {
    return 2;
  } else if ((!Y->ip || X->ip == Y->ip) && (!Y->port || X->port == Y->port) && (!Y->pid || X->pid == Y->pid) && (!Y->utime || X->utime == Y->utime)) {
    return 1;
  } else {
    return 0;
  }
}

int process_id_is_newer (struct process_id *a, struct process_id *b) {
  assert (!memcmp (a, b, 6));
  if (a->utime < b->utime) { return 0; }
  if (a->utime > b->utime) { return 1; }
  int x = (a->pid - b->pid) & 0x7fff;
  if (x && x <= 0x3fff) { return 1; }
  return 0;
}

