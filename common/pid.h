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

#pragma once

#pragma pack(push,4)

struct process_id {
  unsigned ip;
  short port;
  unsigned short pid;
  int utime;
};

struct process_id_ext {
  unsigned ip;
  short port;
  unsigned short pid;
  int utime;
  int actor_id;
};

#pragma pack(pop)

typedef struct process_id npid_t;
typedef struct process_id_ext npidx_t;

extern npid_t PID;

void init_common_PID (void);
void init_client_PID (unsigned ip);
void init_server_PID (unsigned ip, int port);

/* returns 1 if X is a special case of Y, 2 if they match completely */
int matches_pid (struct process_id *X, struct process_id *Y);

int process_id_is_newer (struct process_id *a, struct process_id *b);
