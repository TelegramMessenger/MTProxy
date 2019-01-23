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

    Copyright 2016-2018 Telegram Messenger Inc                 
              2016-2018 Nikolai Durov
*/

#pragma once

#define __ALLOW_UNOBFS__ 0

#include "net/net-tcp-rpc-server.h"
#include "net/net-connections.h"

extern conn_type_t ct_tcp_rpc_ext_server;
// extern struct tcp_rpc_server_functions default_tcp_rpc_server;

int tcp_rpcs_compact_parse_execute (connection_job_t c);
void tcp_rpcs_set_ext_secret(unsigned char secret[16]);
void tcp_rpcs_set_ext_rand_pad_only(int set);
