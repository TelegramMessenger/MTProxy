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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Nikolai Durov
              2012-2013 Andrey Lopatin
              2012-2013 Vitaliy Valtman

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#pragma once

#define TL_STAT 0x9d56e6b2


#define RPC_INVOKE_REQ			0x2374df3d
#define RPC_INVOKE_KPHP_REQ		0x99a37fda
#define RPC_REQ_RUNNING			0x346d5efa
#define RPC_REQ_ERROR			0x7ae432f5
#define RPC_REQ_RESULT			0x63aeda4e
#define	RPC_READY			0x6a34cac7
#define	RPC_STOP_READY			0x59d86654
#define	RPC_SEND_SESSION_MSG		0x1ed5a3cc
#define RPC_RESPONSE_INDIRECT		0x2194f56e
#define RPC_PING 0x5730a2df
#define RPC_PONG 0x8430eaa7


#define RPC_DEST_ACTOR 0x7568aabd
#define RPC_DEST_ACTOR_FLAGS 0xf0a5acf7
#define RPC_DEST_FLAGS 0xe352035e
#define RPC_REQ_RESULT_FLAGS 0x8cc84ce1

#define MAX_TL_STRING_LENGTH 0xffffff

#define TL_ERROR_RETRY 503

#define TL_BOOL_TRUE 0x997275b5
#define TL_BOOL_FALSE 0xbc799737

#define TL_BOOL_STAT 0x92cbcbfa

#define TL_TRUE 0x3fedd339

#define TL_INT 0xa8509bda
#define TL_LONG 0x22076cba
#define TL_DOUBLE 0x2210c154
#define TL_STRING 0xb5286e24

#define TL_MAYBE_TRUE 0x3f9c8ef8
#define TL_MAYBE_FALSE 0x27930a7b

#define TL_VECTOR 0x1cb5c415
#define TL_VECTOR_TOTAL 0x10133f47 
#define TL_TUPLE 0x9770768a

#define TL_DICTIONARY 0x1f4c618f

//
// Error codes
//

//
// Query syntax errors -1000...-1999
//

#define TL_ERROR_SYNTAX -1000
#define TL_ERROR_EXTRA_DATA -1001
#define TL_ERROR_HEADER -1002
#define TL_ERROR_WRONG_QUERY_ID -1003
#define TL_ERROR_NOT_ENOUGH_DATA -1004

//
// Syntax ok, bad can not start query. -2000...-2999
//
#define TL_ERROR_UNKNOWN_FUNCTION_ID -2000
#define TL_ERROR_PROXY_NO_TARGET -2001
#define TL_ERROR_WRONG_ACTOR_ID -2002
#define TL_ERROR_TOO_LONG_STRING -2003
#define TL_ERROR_VALUE_NOT_IN_RANGE -2004
#define TL_ERROR_QUERY_INCORRECT -2005
#define TL_ERROR_BAD_VALUE -2006
#define TL_ERROR_BINLOG_DISABLED -2007
#define TL_ERROR_FEATURE_DISABLED -2008
#define TL_ERROR_QUERY_IS_EMPTY	-2009
#define TL_ERROR_INVALID_CONNECTION_ID -2010
#define TL_ERROR_WRONG_SPLIT -2011
#define TL_ERROR_TOO_BIG_OFFSET -2012

//
// Error processing query -3000...-3999
//
#define TL_ERROR_QUERY_TIMEOUT -3000
#define TL_ERROR_PROXY_INVALID_RESPONSE -3001
#define TL_ERROR_NO_CONNECTIONS -3002
#define TL_ERROR_INTERNAL -3003
#define TL_ERROR_AIO_FAIL -3004
#define TL_ERROR_AIO_TIMEOUT -3005
#define TL_ERROR_BINLOG_WAIT_TIMEOUT -3006
#define TL_ERROR_AIO_MAX_RETRY_EXCEEDED -3007
#define TL_ERROR_TTL -3008
#define TL_ERROR_BAD_METAFILE -3009
#define TL_ERROR_NOT_READY -3010

#define TL_ERROR_STORAGE_CACHE_MISS -3500
#define TL_ERROR_STORAGE_CACHE_NO_MTPROTO_CONN -3501

//
// Different errors -4000...-4999
//
#define TL_ERROR_UNKNOWN -4000

#define TL_IS_USER_ERROR(x) ((x) <= -1000 && (x) > -3000)

#define TL_NAMESPACE TL_

#define CONCAT(a,b) a ## b
#define TLN(nspc,name) CONCAT (nspc, name)
#define TLG(name) TL_ ## name
#define TL(x) TLN (TL_NAMESPACE, x)
