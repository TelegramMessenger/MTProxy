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

    Copyright 2013 Vkontakte Ltd
              2013 Vitaliy Valtman
              2013 Anton Maydell
    
    Copyright 2014 Telegram Messenger Inc             
              2014 Vitaly Valtman     
              2014 Anton Maydell
    
    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaliy Valtman
*/
#pragma once

void default_close_network_sockets (void);
void engine_do_open_port (void);
int try_open_port_range (int start_port, int end_port, int mod_port, int rem_port, int quit_on_fail);
int try_open_port (int port, int quit_on_fail);
int get_port_mod (void);
void engine_server_init (void);
void engine_set_tcp_methods (struct tcp_rpc_server_functions *F);
void engine_set_http_fallback (conn_type_t *http_type, struct http_server_functions *http_functions);
