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
              2012-2013 Vitaliy Valtman              
    
    Copyright 2014 Telegram Messenger Inc             
              2014 Vitaly Valtman     
*/

#include "common/tl-parse.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "net/net-events.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "net/net-rpc-targets.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-server.h"


#include "common/cpuid.h"
#include "common/kprintf.h"
#include "common/server-functions.h"

#include "vv/vv-io.h"
#include "vv/vv-tree.h"

//#include "auto/TL/common.h"
//#include "auto/TL/tl-names.h"

#include "engine/engine.h"
#include "jobs/jobs.h"
#include "common/common-stats.h"

#define MODULE tl_parse

MODULE_STAT_TYPE {
  long long rpc_queries_received, rpc_answers_error, rpc_answers_received;
  long long rpc_sent_errors, rpc_sent_answers, rpc_sent_queries;
  int tl_in_allocated, tl_out_allocated;
/*  #ifdef TIME_DEBUG
  long long tl_udp_flush_rdtsc;
  long long tl_udp_flush_cnt;
  #endif*/
};

MODULE_INIT

MODULE_STAT_FUNCTION
  double uptime = time (0) - start_time;
  SB_SUM_ONE_LL (rpc_queries_received);
  SB_SUM_ONE_LL (rpc_answers_error);
  SB_SUM_ONE_LL (rpc_answers_received);
  SB_SUM_ONE_LL (rpc_sent_errors);
  SB_SUM_ONE_LL (rpc_sent_answers);
  SB_SUM_ONE_LL (rpc_sent_queries);
  SB_SUM_ONE_I (tl_in_allocated);
  SB_SUM_ONE_I (tl_out_allocated);
  /*#ifdef TIME_DEBUG
  SB_SUM_ONE_LL (tl_udp_flush_rdtsc);
  SB_SUM_ONE_LL (tl_udp_flush_cnt);
  #endif*/
  sb_printf (sb,
    "rpc_qps\t%lf\n"
    "default_rpc_flags\t%u\n",
    safe_div (SB_SUM_LL (rpc_queries_received), uptime), tcp_get_default_rpc_flags ()
  );
MODULE_STAT_FUNCTION_END



void tl_query_header_delete (struct tl_query_header *h) {
  if (__sync_fetch_and_add (&h->ref_cnt, -1) > 1) { return; }
  assert (!h->ref_cnt);
  free (h);
}
  
struct tl_query_header *tl_query_header_dup (struct tl_query_header *h) {
  __sync_fetch_and_add (&h->ref_cnt, 1);
  return h;
}
  
struct tl_query_header *tl_query_header_clone (struct tl_query_header *h_old) {
  struct tl_query_header *h = malloc (sizeof (*h));
  memcpy (h, h_old, sizeof (*h));
  h->ref_cnt = 1;
  return h;
}

int tlf_set_error_format (struct tl_in_state *tlio_in, int errnum, const char *format, ...) {
  if (TL_ERROR) {
    return 0;
  }
  assert (format);
  char s[1000];
  va_list l;
  va_start (l, format);
  vsnprintf (s, sizeof (s), format, l);
  va_end (l);
  vkprintf (2, "Error %s\n", s);
  TL_ERRNUM = errnum;
  TL_ERROR = strdup (s);
  return 0;
}

int tls_set_error_format (struct tl_out_state *tlio_out, int errnum, const char *format, ...) {
  if (tlio_out->error) {
    return 0;
  }
  assert (format);
  char s[1000];
  va_list l;
  va_start (l, format);
  vsnprintf (s, sizeof (s), format, l);
  va_end (l);
  vkprintf (2, "Error %s\n", s);
  tlio_out->errnum = errnum;
  tlio_out->error = strdup (s);
  return 0;
}

/* {{{ Raw msg methods */
static inline void __tl_raw_msg_fetch_raw_data (struct tl_in_state *tlio_in, void *buf, int len) {
  assert (rwm_fetch_data (TL_IN_RAW_MSG, buf, len) == len);
}

static inline void __tl_raw_msg_fetch_move (struct tl_in_state *tlio_in, int len) {
  assert (len >= 0);
  assert (rwm_skip_data (TL_IN_RAW_MSG, len) == len);
}

static inline void __tl_raw_msg_fetch_lookup (struct tl_in_state *tlio_in, void *buf, int len) {
  assert (rwm_fetch_lookup (TL_IN_RAW_MSG, buf, len) == len);
}

static inline void __tl_raw_msg_fetch_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int len) {
  rwm_split_head (raw, TL_IN_RAW_MSG, len);
}

static inline void __tl_raw_msg_fetch_lookup_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int len) {
  rwm_clone (raw, TL_IN_RAW_MSG);
  rwm_trunc (raw, len);
}
  
static inline void __tl_raw_msg_fetch_mark (struct tl_in_state *tlio_in) {
  assert (!TL_IN_MARK);
  struct raw_message *T = malloc (sizeof (*T));
  rwm_clone (T, TL_IN_RAW_MSG);
  TL_IN_MARK = T;
  TL_IN_MARK_POS = TL_IN_POS;
}

static inline void __tl_raw_msg_fetch_mark_restore (struct tl_in_state *tlio_in) {
  assert (TL_IN_MARK);
  rwm_free (TL_IN_RAW_MSG);
  *TL_IN_RAW_MSG = *(struct raw_message *)TL_IN_MARK;
  free (TL_IN_MARK);
  TL_IN_MARK = 0;
  int x = TL_IN_POS - TL_IN_MARK_POS;
  TL_IN_POS -= x;
  TL_IN_REMAINING += x;
}

static inline void __tl_raw_msg_fetch_mark_delete (struct tl_in_state *tlio_in) {
  assert (TL_IN_MARK);
  rwm_free (TL_IN_MARK);
  free (TL_IN_MARK);
  TL_IN_MARK = 0;
}

static inline void *__tl_raw_msg_store_get_ptr (struct tl_out_state *tlio_out, int len) {
  return rwm_postpone_alloc (TL_OUT_RAW_MSG, len);
}

static inline void *__tl_raw_msg_store_get_prepend_ptr (struct tl_out_state *tlio_out, int len) {
  return rwm_prepend_alloc (TL_OUT_RAW_MSG, len);
}

static inline void __tl_raw_msg_store_raw_data (struct tl_out_state *tlio_out, const void *buf, int len) {
  assert (rwm_push_data (TL_OUT_RAW_MSG, buf, len) == len);
}

static inline void __tl_raw_msg_store_raw_msg (struct tl_out_state *tlio_out, struct raw_message *raw) {
  rwm_union (TL_OUT_RAW_MSG, raw);
}

static inline void __tl_raw_msg_store_read_back (struct tl_out_state *tlio_out, int len) {
  assert (rwm_fetch_data_back (TL_OUT_RAW_MSG, 0, len) == len);
}

static inline void __tl_raw_msg_store_read_back_nondestruct (struct tl_out_state *tlio_out, void *buf, int len) {
  struct raw_message r;
  rwm_clone (&r, TL_OUT_RAW_MSG);
  assert (rwm_fetch_data_back (&r, buf, len) == len);
  rwm_free (&r);
}

static inline void __tl_raw_msg_raw_msg_copy_through (struct tl_in_state *tlio_in, struct tl_out_state *tlio_out, int len, int advance) {
  if (!advance) {
    struct raw_message r;
    rwm_clone (&r, TL_IN_RAW_MSG);
    rwm_trunc (&r, len);
    rwm_union (TL_OUT_RAW_MSG, &r);
  } else {
    struct raw_message r;
    rwm_split_head (&r, TL_IN_RAW_MSG, len);
    rwm_union (TL_OUT_RAW_MSG, &r);
    assert (TL_IN_RAW_MSG->magic == RM_INIT_MAGIC);
  }
}

static inline void __tl_raw_msg_str_copy_through (struct tl_in_state *tlio_in, struct tl_out_state *tlio_out, int len, int advance) {
  if (advance) {
    assert (rwm_fetch_data (TL_IN_RAW_MSG, TL_OUT_STR, len) == len);
    TL_OUT += len;
  } else {
    assert (rwm_fetch_lookup (TL_IN_RAW_MSG, TL_OUT_STR, len) == len);
    TL_OUT += len;
  }
}

static inline void __tl_raw_msg_fetch_clear (struct tl_in_state *tlio_in) {
  if (TL_IN_RAW_MSG) {
    rwm_free (TL_IN_RAW_MSG);
    free (TL_IN_RAW_MSG);
    TL_IN = 0;
  }
}

static inline void __tl_raw_msg_store_clear (struct tl_out_state *tlio_out) {
  if (TL_OUT_RAW_MSG) {
    rwm_free (TL_OUT_RAW_MSG);
    free (TL_OUT_RAW_MSG);
    TL_OUT = 0;
  }
}

static inline void __tl_raw_msg_store_flush (struct tl_out_state *tlio_out) {
//  struct udp_target *S = (struct udp_target *)TL_OUT_EXTRA;
  assert (TL_OUT_RAW_MSG);
  /*#ifdef TIME_DEBUG
  long long r = rdtsc ();
  #endif*/
  assert (0);
  /*#ifdef TIME_DEBUG
  MODULE_STAT->tl_udp_flush_rdtsc += (rdtsc () - r);
  MODULE_STAT->tl_udp_flush_cnt ++;
  #endif*/
  free (TL_OUT_RAW_MSG);
  TL_OUT = 0;
  //udp_target_flush ((struct udp_target *)TL_OUT_EXTRA);
}


/* }}} */

/* {{{ Tcp raw msg methods */

static inline void __tl_tcp_raw_msg_store_clear (struct tl_out_state *tlio_out) {
  if (TL_OUT_RAW_MSG) {
    rwm_free (TL_OUT_RAW_MSG);
    free (TL_OUT_RAW_MSG);
    job_decref (JOB_REF_PASS (TL_OUT_EXTRA));
    TL_OUT = NULL;
    TL_OUT_EXTRA = NULL;
  }
}


static inline void __tl_tcp_raw_msg_store_flush (struct tl_out_state *tlio_out) {
  assert (TL_OUT_RAW_MSG);
  assert (TL_OUT_EXTRA);
  tcp_rpc_conn_send (JOB_REF_PASS (TL_OUT_EXTRA), TL_OUT_RAW_MSG, 4);
  TL_OUT = NULL;
}

static inline void __tl_tcp_raw_msg_store_flush_unaligned (struct tl_out_state *tlio_out) {
  assert (TL_OUT_RAW_MSG);
  assert (TL_OUT_EXTRA);
  tcp_rpc_conn_send (JOB_REF_PASS (TL_OUT_EXTRA), TL_OUT_RAW_MSG, 12);
  TL_OUT = NULL;
}
/* }}} */

/* {{{ Str methods */
static inline void __tl_str_fetch_raw_data (struct tl_in_state *tlio_in, void *buf, int len) {
  memcpy (buf, TL_IN_STR, len);
  TL_IN += len;
}

static inline void __tl_str_fetch_move (struct tl_in_state *tlio_in, int len) {
  TL_IN += len;
}

static inline void __tl_str_fetch_lookup (struct tl_in_state *tlio_in, void *buf, int len) {
  memcpy (buf, TL_IN_STR, len);
}

static inline void __tl_str_fetch_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int len) {
  rwm_init (raw, 0);
  rwm_push_data (raw, TL_IN, len);
  TL_IN += len;
}

static inline void __tl_str_fetch_lookup_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int len) {
  rwm_init (raw, 0);
  rwm_push_data (raw, TL_IN, len);
}

static inline void *__tl_str_store_get_ptr (struct tl_out_state *tlio_out, int len) {
  void *r = TL_OUT_STR;
  TL_OUT += len;
  return r;
}

static inline void *__tl_str_store_get_prepend_ptr (struct tl_out_state *tlio_out, int len) {
  return TL_OUT_STR - TL_OUT_POS - len;
}


static inline void __tl_str_store_raw_data (struct tl_out_state *tlio_out, const void *buf, int len) {
  memcpy (TL_OUT_STR, buf, len);
  TL_OUT += len;
}

static inline void __tl_str_store_raw_msg (struct tl_out_state *tlio_out, struct raw_message *raw) {
  int len = raw->total_bytes;
  rwm_fetch_data (raw, TL_OUT_STR, raw->total_bytes);
  TL_OUT += len;
}


static inline void __tl_str_store_read_back (struct tl_out_state *tlio_out, int len) {
  TL_OUT -= len;
}

static inline void __tl_str_store_read_back_nondestruct (struct tl_out_state *tlio_out, void *buf, int len) {
  memcpy (TL_OUT_STR - len, buf, len);
}

static inline void __tl_str_raw_msg_copy_through (struct tl_in_state *tlio_in, struct tl_out_state *tlio_out, int len, int advance) {
  assert (rwm_push_data (TL_OUT_RAW_MSG, TL_IN_STR, len) == len);
  if (advance) {
    TL_IN += advance;
  }
}

static inline void __tl_str_str_copy_through (struct tl_in_state *tlio_in, struct tl_out_state *tlio_out, int len, int advance) {
  memcpy (TL_OUT_STR, TL_IN_STR, len);
  TL_OUT += len;
  if (advance) {
    TL_IN += advance;
  }
}
  
static inline void __tl_str_fetch_mark (struct tl_in_state *tlio_in) {
  assert (!TL_IN_MARK);
  TL_IN_MARK = TL_IN_STR;
  TL_IN_MARK_POS = TL_IN_POS;
}

static inline void __tl_str_fetch_mark_restore (struct tl_in_state *tlio_in) {
  TL_IN = TL_IN_MARK;
  TL_IN_MARK = 0;
  int x = TL_IN_POS - TL_IN_MARK_POS;
  TL_IN_POS -= x;
  TL_IN_REMAINING += x;
}

static inline void __tl_str_fetch_mark_delete (struct tl_in_state *tlio_in) {
  TL_IN_MARK = 0;
}


static inline void __tl_str_store_clear (struct tl_out_state *tlio_out) {
  TL_OUT = 0;
}

static inline void __tl_str_store_flush (struct tl_out_state *tlio_out) {
  TL_OUT = 0;
}
/* }}} */

const struct tl_in_methods tl_in_raw_msg_methods = {
  .fetch_raw_data = __tl_raw_msg_fetch_raw_data,
  .fetch_move = __tl_raw_msg_fetch_move,
  .fetch_lookup = __tl_raw_msg_fetch_lookup,
  .fetch_raw_message = __tl_raw_msg_fetch_raw_message,
  .fetch_lookup_raw_message = __tl_raw_msg_fetch_lookup_raw_message,
  .fetch_clear = __tl_raw_msg_fetch_clear,
  .fetch_mark = __tl_raw_msg_fetch_mark,
  .fetch_mark_restore = __tl_raw_msg_fetch_mark_restore,
  .fetch_mark_delete = __tl_raw_msg_fetch_mark_delete,
  .flags = 0,
};

const struct tl_in_methods tl_in_str_methods = {
  .fetch_raw_data = __tl_str_fetch_raw_data,
  .fetch_move = __tl_str_fetch_move,
  .fetch_lookup = __tl_str_fetch_lookup,
  .fetch_raw_message = __tl_str_fetch_raw_message,
  .fetch_lookup_raw_message = __tl_str_fetch_lookup_raw_message,
//  .fetch_clear = __tl_str_fetch_clear,
  .fetch_mark = __tl_str_fetch_mark,
  .fetch_mark_restore = __tl_str_fetch_mark_restore,
  .fetch_mark_delete = __tl_str_fetch_mark_delete,
  .flags = 0,
  .prepend_bytes = 0,
};
/*
const struct tl_out_methods tl_out_conn_simple_methods = {
  .store_get_ptr = __tl_conn_store_get_ptr,
  .store_raw_data = __tl_conn_store_raw_data,
  .store_raw_msg = __tl_conn_store_raw_msg,
  .store_read_back =  __tl_conn_store_read_back,
  .store_read_back_nondestruct = __tl_conn_store_read_back_nondestruct,
  // .store_flush = __tl_conn_store_flush,
  .store_clear = __tl_conn_store_clear,
  .copy_through = 
    {
      0, // none
      __tl_str_conn_copy_through, // str
      __tl_raw_msg_conn_copy_through, // raw_msg
      __tl_raw_msg_conn_copy_through, // tcp raw msg
      __tl_raw_msg_conn_copy_through, // gms msg
      __tl_raw_msg_conn_copy_through  // gms bcast
    },
  .flags = TLF_PERMANENT | TLF_DISABLE_PREPEND | TLF_NO_AUTOFLUSH | TLF_NOALIGN,
  .prepend_bytes = 0
};*/

const struct tl_out_methods tl_out_raw_msg_methods = {
  .store_get_ptr = __tl_raw_msg_store_get_ptr,
  .store_get_prepend_ptr = __tl_raw_msg_store_get_prepend_ptr,
  .store_raw_msg = __tl_raw_msg_store_raw_msg,
  .store_raw_data = __tl_raw_msg_store_raw_data,
  .store_read_back = __tl_raw_msg_store_read_back,
  .store_read_back_nondestruct = __tl_raw_msg_store_read_back_nondestruct,
  .store_clear = __tl_raw_msg_store_clear,
  .store_flush = __tl_raw_msg_store_flush,
  .copy_through = 
    {
      0, // none
      __tl_str_raw_msg_copy_through, // str
      __tl_raw_msg_raw_msg_copy_through, // raw_msg
      __tl_raw_msg_raw_msg_copy_through, // tcp conn
    },
  .flags = TLF_ALLOW_PREPEND
};

const struct tl_out_methods tl_out_raw_msg_methods_nosend = {
  .store_get_ptr = __tl_raw_msg_store_get_ptr,
  .store_get_prepend_ptr = __tl_raw_msg_store_get_prepend_ptr,
  .store_raw_msg = __tl_raw_msg_store_raw_msg,
  .store_raw_data = __tl_raw_msg_store_raw_data,
  .store_read_back = __tl_raw_msg_store_read_back,
  .store_read_back_nondestruct = __tl_raw_msg_store_read_back_nondestruct,
  .store_clear = __tl_raw_msg_store_clear,
  .copy_through = 
    {
      0, // none
      __tl_str_raw_msg_copy_through, // str
      __tl_raw_msg_raw_msg_copy_through, // tcp conn
    },
  .flags = TLF_ALLOW_PREPEND
};

const struct tl_out_methods tl_out_tcp_raw_msg_methods = {
  .store_get_ptr = __tl_raw_msg_store_get_ptr,
  .store_get_prepend_ptr = __tl_raw_msg_store_get_prepend_ptr,
  .store_raw_data = __tl_raw_msg_store_raw_data,
  .store_raw_msg = __tl_raw_msg_store_raw_msg,
  .store_read_back = __tl_raw_msg_store_read_back,
  .store_read_back_nondestruct = __tl_raw_msg_store_read_back_nondestruct,
  .store_clear = __tl_tcp_raw_msg_store_clear,
  .store_flush = __tl_tcp_raw_msg_store_flush,
  .copy_through = 
    {
      0, // none
      __tl_str_raw_msg_copy_through, // str
      __tl_raw_msg_raw_msg_copy_through, // raw_msg
      __tl_raw_msg_raw_msg_copy_through, // tcp conn
    },
  .flags = TLF_ALLOW_PREPEND
};

const struct tl_out_methods tl_out_tcp_raw_msg_unaligned_methods = {
  .store_get_ptr = __tl_raw_msg_store_get_ptr,
  .store_get_prepend_ptr = __tl_raw_msg_store_get_prepend_ptr,
  .store_raw_data = __tl_raw_msg_store_raw_data,
  .store_raw_msg = __tl_raw_msg_store_raw_msg,
  .store_read_back = __tl_raw_msg_store_read_back,
  .store_read_back_nondestruct = __tl_raw_msg_store_read_back_nondestruct,
  .store_clear = __tl_tcp_raw_msg_store_clear,
  .store_flush = __tl_tcp_raw_msg_store_flush_unaligned,
  .copy_through = 
    {
      0, // none
      __tl_str_raw_msg_copy_through, // str
      __tl_raw_msg_raw_msg_copy_through, // raw_msg
      __tl_raw_msg_raw_msg_copy_through, // tcp conn
    },
  .flags = TLF_ALLOW_PREPEND | TLF_NOALIGN
};

const struct tl_out_methods tl_out_str_methods = {
  .store_get_ptr = __tl_str_store_get_ptr,
  .store_get_prepend_ptr = __tl_str_store_get_prepend_ptr,
  .store_raw_data = __tl_str_store_raw_data,
  .store_raw_msg = __tl_str_store_raw_msg,
  .store_read_back = __tl_str_store_read_back,
  .store_read_back_nondestruct = __tl_str_store_read_back_nondestruct,
  .store_clear = __tl_str_store_clear,
  .store_flush = __tl_str_store_flush,
  .copy_through = 
    {
      0, // none
      __tl_str_str_copy_through, // str
      __tl_raw_msg_str_copy_through, // raw_msg
      __tl_raw_msg_str_copy_through, // tcp raw_msg
    },
  .flags = TLF_PERMANENT | TLF_ALLOW_PREPEND,
  .prepend_bytes = 0
};

int tlf_set_error (struct tl_in_state *tlio_in, int errnum, const char *s) {
  assert (s);
  if (TL_ERROR) {
    return 0;
  }
  vkprintf (2, "Error %s\n", s);
  TL_ERROR = strdup (s);
  TL_ERRNUM = errnum;
  return 0;
}

int __tl_fetch_init (struct tl_in_state *tlio_in, void *in, void *in_extra, enum tl_type type, const struct tl_in_methods *methods, int size) {
  assert (TL_IN_TYPE == tl_type_none);
  assert (in);
  TL_IN_TYPE = type;
  TL_IN = in;
  TL_IN_REMAINING = size;
  TL_IN_POS = 0;
  TL_IN_CUR_FLAGS = 0;

  TL_IN_METHODS = methods;
  if (TL_ERROR) {
    free (TL_ERROR);
    TL_ERROR = 0;
  }
  TL_ERRNUM = 0;
  return 0;
}

int tlf_init_raw_message (struct tl_in_state *tlio_in, struct raw_message *msg, int size, int dup) {
  struct raw_message *r = (struct raw_message *)malloc (sizeof (*r));
  if (dup == 0) {
    rwm_move (r, msg);
  } else if (dup == 1) {
    rwm_move (r, msg);
    rwm_init (msg, 0);
  } else {
    rwm_clone (r, msg);
  }
  return __tl_fetch_init (tlio_in, r, 0, tl_type_raw_msg, &tl_in_raw_msg_methods, size);
}

int tlf_init_str (struct tl_in_state *tlio_in, const char *s, int size) {
  return __tl_fetch_init (tlio_in, (void *)s, 0, tl_type_str, &tl_in_str_methods, size);
}

int tlf_query_flags (struct tl_in_state *tlio_in, struct tl_query_header *header) {
  int flags = tl_fetch_int ();
  if (tl_fetch_error ()) {
    return -1;
  }
  if (header->flags & flags) {
    tl_fetch_set_error_format (TL_ERROR_HEADER, "Duplicate flags in header 0x%08x", header->flags & flags);
    return -1;
  }
  if (flags) {
    tl_fetch_set_error_format (TL_ERROR_HEADER, "Unsupported flags in header 0x%08x", flags);
    return -1;
  }
  header->flags |= flags;

  return 0;
}

int tlf_query_header (struct tl_in_state *tlio_in, struct tl_query_header *header) {
  assert (header);
  memset (header, 0, sizeof (*header));
  int t = tl_fetch_unread ();
  if (TL_IN_METHODS->prepend_bytes) {
    tl_fetch_skip (TL_IN_METHODS->prepend_bytes);
  }
  header->op = tl_fetch_int ();
  header->real_op = header->op;
  header->ref_cnt = 1;
  if (header->op != (int)RPC_INVOKE_REQ && header->op != (int)RPC_INVOKE_KPHP_REQ) {
    tl_fetch_set_error (TL_ERROR_HEADER, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
    return -1;
  }
  header->qid = tl_fetch_long ();
  if (header->op == (int)RPC_INVOKE_KPHP_REQ) {
    //tl_fetch_raw_data (header->invoke_kphp_req_extra, 24);
    if (tl_fetch_error ()) {
      return -1;
    }
    MODULE_STAT->rpc_queries_received ++;
    return t - tl_fetch_unread ();
  }
  while (1) {
    int op = tl_fetch_lookup_int ();
    int ok = 1;
    switch (op) {
    case RPC_DEST_ACTOR:
      assert (tl_fetch_int () == (int)RPC_DEST_ACTOR);
      header->actor_id = tl_fetch_long ();
      break;
    case RPC_DEST_ACTOR_FLAGS:
      assert (tl_fetch_int () == (int)RPC_DEST_ACTOR_FLAGS);
      header->actor_id = tl_fetch_long ();
      tlf_query_flags (tlio_in, header);
      break;
    case RPC_DEST_FLAGS:
      assert (tl_fetch_int () == (int)RPC_DEST_FLAGS);      
      tlf_query_flags (tlio_in, header);
      break;
    default:
      ok = 0;
      break;
    }
    if (tl_fetch_error ()) {
      return -1;
    }
    if (!ok) { 
      MODULE_STAT->rpc_queries_received ++;
      return t - tl_fetch_unread ();
    }
  }
}

int tlf_query_answer_flags (struct tl_in_state *tlio_in, struct tl_query_header *header) {
  int flags = tl_fetch_int ();
  if (tl_fetch_error ()) {
    return -1;
  }
  if (header->flags & flags) {
    tl_fetch_set_error_format (TL_ERROR_HEADER, "Duplicate flags in header 0x%08x", header->flags & flags);
    return -1;
  }
  if (flags) {
    tl_fetch_set_error_format (TL_ERROR_HEADER, "Unsupported flags in header 0x%08x", flags);
    return -1;
  }
  header->flags |= flags;
  return 0;
}

int tlf_query_answer_header (struct tl_in_state *tlio_in, struct tl_query_header *header) {
  assert (header);
  memset (header, 0, sizeof (*header));
  int t = tl_fetch_unread ();
  if (TL_IN_METHODS->prepend_bytes) {
    tl_fetch_skip (TL_IN_METHODS->prepend_bytes);
  }
  header->op = tl_fetch_int ();
  header->real_op = header->op;
  header->ref_cnt = 1;
  if (header->op != RPC_REQ_ERROR && header->op != RPC_REQ_RESULT ) {
    tl_fetch_set_error (TL_ERROR_HEADER, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
    return -1;
  }
  header->qid = tl_fetch_long ();
  while (1) {
    int ok = 1;
    if (header->op != RPC_REQ_ERROR) {
      int op = tl_fetch_lookup_int ();
      switch (op) {
      case RPC_REQ_ERROR:
        assert (tl_fetch_int () == RPC_REQ_ERROR);
        header->op = RPC_REQ_ERROR_WRAPPED;
        tl_fetch_long ();
        break;
      case RPC_REQ_ERROR_WRAPPED:
        header->op = RPC_REQ_ERROR_WRAPPED;
        break;
      case RPC_REQ_RESULT_FLAGS:
        assert (tl_fetch_int () == (int)RPC_REQ_RESULT_FLAGS);
        tlf_query_answer_flags (tlio_in, header);
        break;
      default:
        ok = 0;
        break;
      }
    } else {
      ok = 0;
    }
    if (tl_fetch_error ()) {
      return -1;
    }
    if (!ok) {
      if (header->op == RPC_REQ_ERROR || header->op == RPC_REQ_ERROR_WRAPPED) {
        MODULE_STAT->rpc_answers_error ++;
      } else {
        MODULE_STAT->rpc_answers_received ++;
      }
      return t - tl_fetch_unread ();
    }
  }
}

static inline int __tl_store_init (struct tl_out_state *tlio_out, void *out, void *out_extra, enum tl_type type, const struct tl_out_methods *methods, int size, long long qid) {
  assert (tlio_out);
  assert (!TL_OUT_METHODS); 
  
  TL_OUT = out;
  TL_OUT_EXTRA = out_extra;
  if (out) {
    TL_OUT_METHODS = methods;
    TL_OUT_TYPE = type;
    if (type != tl_type_none && !(methods->flags & (TLF_ALLOW_PREPEND | TLF_DISABLE_PREPEND))) {
      TL_OUT_SIZE = (int *) methods->store_get_ptr (tlio_out, methods->prepend_bytes + (qid ? 12 : 0));
    }
  } else {
    TL_OUT_TYPE = tl_type_none;
  }

  TL_OUT_POS = 0;
  TL_OUT_QID = qid;
  TL_OUT_REMAINING = size;

  tlio_out->errnum = 0;
  tlio_out->error = NULL;

  return 0;
}

/*int tls_init_simple (struct tl_out_state *tlio_out, connection_job_t c) {
  if (c) {
    TL_OUT_PID = &(RPCS_DATA(c)->remote_pid);
  } else {
    TL_OUT_PID = 0;
  }
  return __tl_store_init (tlio_out, job_incref (c), 0, tl_type_conn, &tl_out_conn_simple_methods, (1 << 27), 0);
}*/

int tls_init_raw_msg (struct tl_out_state *tlio_out, struct process_id *pid, long long qid) {
  if (pid) {
    memcpy (&tlio_out->out_pid_buf, pid, 12);
    TL_OUT_PID = &tlio_out->out_pid_buf;
  } else {
    TL_OUT_PID = 0;
  }
  struct raw_message *d = 0;
  if (pid) {
    d = (struct raw_message *)malloc (sizeof (*d));
    rwm_init (d, 0);
  }
  return __tl_store_init (tlio_out, d, NULL, tl_type_raw_msg, &tl_out_raw_msg_methods, (1 << 27), qid);
}

int tls_init_tcp_raw_msg (struct tl_out_state *tlio_out, JOB_REF_ARG(c), long long qid) {
  if (c) {
    TL_OUT_PID = &(TCP_RPC_DATA(c)->remote_pid);
  } else {
    TL_OUT_PID = 0;
  }
  struct raw_message *d = 0;
  if (c) {
    d = (struct raw_message *)malloc (sizeof (*d));
    rwm_init (d, 0);
  }
  return __tl_store_init (tlio_out, d, c, tl_type_tcp_raw_msg, &tl_out_tcp_raw_msg_methods, (1 << 27), qid);
}

int tls_init_tcp_raw_msg_unaligned (struct tl_out_state *tlio_out, JOB_REF_ARG(c), long long qid) {
  if (c) {
    TL_OUT_PID = &(TCP_RPC_DATA(c)->remote_pid);
  } else {
    TL_OUT_PID = 0;
  }
  struct raw_message *d = 0;
  if (c) {
    d = (struct raw_message *)malloc (sizeof (*d));
    rwm_init (d, 0);
  }
  return __tl_store_init (tlio_out, d, c, tl_type_tcp_raw_msg, &tl_out_tcp_raw_msg_unaligned_methods, (1 << 27), qid);
}

int tls_init_str (struct tl_out_state *tlio_out, char *s, long long qid, int size) {
  TL_OUT_PID = 0;
  return __tl_store_init (tlio_out, s, s, tl_type_str, &tl_out_str_methods, size, qid);
}

int tls_init_raw_msg_nosend (struct tl_out_state *tlio_out) {
  struct raw_message *d = (struct raw_message *)malloc (sizeof (*d));  
  rwm_init (d, 0);
  return __tl_store_init (tlio_out, d, d, tl_type_raw_msg, &tl_out_raw_msg_methods_nosend, (1 << 27), 0);
}
/*
int tls_init_any (struct tl_out_state *tlio_out, enum tl_type type, void *out, long long qid) {
  switch (type) {
  case tl_type_conn:
    return tls_init_connection (tlio_out, (connection_job_t )out, qid);
  case tl_type_tcp_raw_msg:
    return tls_init_tcp_raw_msg (tlio_out, out, qid);
  default:
    assert (0);
  }
}*/

int tls_header (struct tl_out_state *tlio_out, struct tl_query_header *header) {
  assert (tls_check (tlio_out, 0) >= 0);  
  assert (header->op == (int)RPC_REQ_ERROR || header->op == (int)RPC_REQ_RESULT || header->op == (int)RPC_INVOKE_REQ || header->op == (int)RPC_REQ_ERROR_WRAPPED);
  if (header->op == (int)RPC_INVOKE_REQ) {
    if (header->flags) {
      tl_store_int (RPC_DEST_ACTOR_FLAGS);
      tl_store_long (header->actor_id);
      tl_store_int (header->flags);
    } else if (header->actor_id) {
      tl_store_int (RPC_DEST_ACTOR);
      tl_store_long (header->actor_id);
    }
  } else if (header->op == RPC_REQ_ERROR_WRAPPED) {
    tl_store_int (RPC_REQ_ERROR);
    tl_store_long (TL_OUT_QID);    
  } else if (header->op == RPC_REQ_RESULT) {
    if (header->flags) {
      tl_store_int (RPC_REQ_RESULT_FLAGS);
      tl_store_int (header->flags);
    }
  }
  return 0;
}

int tls_end_ext (struct tl_out_state *tlio_out, int op) {
  if (TL_OUT_TYPE == tl_type_none) {
    return 0;
  }
  assert (TL_OUT);  
  assert (TL_OUT_TYPE);
  if (tlio_out->error) {
//    tl_store_clear ();    
    tl_store_clean ();
    vkprintf (1, "tl_store_end: "PID_PRINT_STR" writing error %s, errnum %d, tl.out_pos = %d\n", PID_TO_PRINT(TL_OUT_PID), tlio_out->error, tlio_out->errnum, TL_OUT_POS);
    //tl_store_clear ();
    tl_store_int (RPC_REQ_ERROR);
    tl_store_long (TL_OUT_QID);
    tl_store_int (tlio_out->errnum);
    tl_store_string0 (tlio_out->error);

    MODULE_STAT->rpc_sent_errors ++;
  } else {
    if (op == RPC_REQ_RESULT) {
      MODULE_STAT->rpc_sent_answers ++;
    } else {
      MODULE_STAT->rpc_sent_queries ++;
    }
  }
  if (!(TL_OUT_FLAGS & TLF_NOALIGN)) {
    assert (!(TL_OUT_POS & 3));
  }

  {
    int *p;
    if (TL_OUT_FLAGS & TLF_ALLOW_PREPEND) {
      p = TL_OUT_SIZE = tl_store_get_prepend_ptr (TL_OUT_METHODS->prepend_bytes + (TL_OUT_QID ? 12 : 0));
    } else {
      p = TL_OUT_SIZE;
    }

    if (TL_OUT_QID) {
      assert (op);
      p += (TL_OUT_METHODS->prepend_bytes) / 4;
      *p = op;
      *(long long *)(p + 1) = TL_OUT_QID;
    }
  }

  if (TL_OUT_METHODS->store_prefix) {
    TL_OUT_METHODS->store_prefix (tlio_out);
  }

  if (!(TL_OUT_FLAGS & TLF_NO_AUTOFLUSH)) {
    TL_OUT_METHODS->store_flush (tlio_out);
  }
  vkprintf (2, "tl_store_end: written %d bytes, qid = %lld, PID = " PID_PRINT_STR "\n", TL_OUT_POS, TL_OUT_QID, PID_TO_PRINT (TL_OUT_PID));
  TL_OUT = 0;
  TL_OUT_TYPE = tl_type_none;
  TL_OUT_METHODS = 0;
  TL_OUT_EXTRA = 0;
  return 0;
}

int tls_init (struct tl_out_state *tlio_out, enum tl_type type, struct process_id *pid, long long qid) {
  switch (type) {
  case tl_type_raw_msg:
    {
      tls_init_raw_msg (tlio_out, pid, qid);
      return 1;
    }
  case tl_type_tcp_raw_msg:
    {
      connection_job_t d = rpc_target_choose_connection (rpc_target_lookup (pid), pid);
      if (d) {
        vkprintf (2, "%s: Good connection " PID_PRINT_STR "\n", __func__, PID_TO_PRINT (pid));
        tls_init_tcp_raw_msg (tlio_out, JOB_REF_PASS (d), qid);
        return 1;
      } else {
        vkprintf (2, "%s: Bad connection " PID_PRINT_STR "\n", __func__, PID_TO_PRINT (pid));
        return -1;
      }
    }
  case tl_type_none:
    vkprintf (2, "Trying to tl_init_store() with type tl_type_none, qid=%lld\n" , qid);
    return -1;
  default:
    fprintf (stderr, "type = %d\n", type);
    assert (0);
    return 0;
  }
}


struct tl_in_state *tl_in_state_alloc (void) {
  MODULE_STAT->tl_in_allocated ++;
  return calloc (sizeof (struct tl_in_state), 1);
}

void tl_in_state_free (struct tl_in_state *tlio_in) {
  MODULE_STAT->tl_in_allocated --;
  if (tlio_in->in_methods && tlio_in->in_methods->fetch_clear) {
    tlio_in->in_methods->fetch_clear (tlio_in);
  }
  if (tlio_in->error) {
    free (PTR_MOVE (tlio_in->error));
  }
  free (tlio_in);
}

struct tl_out_state *tl_out_state_alloc (void) {
  MODULE_STAT->tl_out_allocated ++;
  return calloc (sizeof (struct tl_out_state), 1);
}

void tl_out_state_free (struct tl_out_state *tlio_out) {
  MODULE_STAT->tl_out_allocated --;
  if (tlio_out->out_methods && tlio_out->out_methods->store_clear) {
    tlio_out->out_methods->store_clear (tlio_out);
  }
  if (tlio_out->error) {
    free (PTR_MOVE (tlio_out->error));
  }
  free (tlio_out);
}
