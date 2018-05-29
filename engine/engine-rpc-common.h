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

#define TL_ENGINE_STAT 0xefb3c36b
struct tl_act_extra *tl_default_parse_function (struct tl_in_state *tlio_in, long long actor_id);
