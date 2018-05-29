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

    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman     
    
*/
#pragma once 

#include "net/net-msg.h"
#include "net/net-connections.h"

void notification_event_insert_tcp_conn_alarm (connection_job_t C);
void notification_event_insert_tcp_conn_wakeup (connection_job_t C);
void notification_event_insert_tcp_conn_close (connection_job_t C);
void notification_event_insert_tcp_conn_ready (connection_job_t C);
void notification_event_job_create (void);
