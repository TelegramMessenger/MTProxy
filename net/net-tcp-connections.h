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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman     
*/

#pragma once

#include "net/net-connections.h"
int cpu_tcp_server_writer (connection_job_t c);
int cpu_tcp_free_connection_buffers (connection_job_t c);
int cpu_tcp_server_reader (connection_job_t c);
int cpu_tcp_aes_crypto_decrypt_input (connection_job_t c);
int cpu_tcp_aes_crypto_encrypt_output (connection_job_t c);
int cpu_tcp_aes_crypto_needed_output_bytes (connection_job_t c);
int cpu_tcp_aes_crypto_ctr128_decrypt_input (connection_job_t c);
int cpu_tcp_aes_crypto_ctr128_encrypt_output (connection_job_t c);
int cpu_tcp_aes_crypto_ctr128_needed_output_bytes (connection_job_t c);
