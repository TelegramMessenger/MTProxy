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
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

//#include "net/net-buffers.h"
#include "net/net-events.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
//#include "net/net-rpc-server.h"
#include "net/net-rpc-targets.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-server.h"

#include "common/cpuid.h"
#include "common/crc32.h"
#include "common/kprintf.h"
#include "common/server-functions.h"

#include "vv/vv-io.h"

//#include "TL/constants.h"

#include "engine/engine.h"
#include "engine/engine-rpc-common.h"

#include "common/tl-parse.h"


static int tl_act_nop (job_t job, struct tl_act_extra *extra) {
  tls_int (extra->tlio_out, TL_TRUE);
  return 0;
}

static int tl_act_stat (job_t job, struct tl_act_extra *extra) {
  tl_engine_store_stats (extra->tlio_out);
  return 0;
}

static inline struct tl_act_extra *tl_simple_parse_function (struct tl_in_state *tlio_in, int (*act)(job_t job, struct tl_act_extra *data)) {
  tl_fetch_int ();
  tl_fetch_end ();
  if (tl_fetch_error ()) {
    return 0;
  }
  struct tl_act_extra *extra = calloc (sizeof (*extra), 1);
  assert (extra);
  extra->flags = 3;
  extra->start_rdtsc = rdtsc ();
  extra->size = sizeof (*extra);
  extra->act = act;
  extra->type = QUERY_ALLOW_REPLICA_GET | QUERY_ALLOW_REPLICA_SET | QUERY_ALLOW_UNINIT;
  return extra;
}

struct tl_act_extra *tl_default_parse_function (struct tl_in_state *tlio_in, long long actor_id) {
  if (actor_id) { 
    return 0; 
  }
  int f = tl_fetch_lookup_int ();
  if (tl_fetch_error ()) {
    return 0;
  }

  switch (f) {
  case TL_ENGINE_STAT: return tl_simple_parse_function (tlio_in, tl_act_stat);
  case TL_ENGINE_NOP: return tl_simple_parse_function (tlio_in, tl_act_nop);
  }
  return 0;
}
