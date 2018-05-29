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

#pragma once

#include <assert.h>
#include <string.h>

#include "net/net-connections.h"

#include "rpc-const.h"
#include "jobs/jobs.h"

//#define RPC_INVOKE_REQ 0x2374df3d
//#define RPC_REQ_RESULT 0x63aeda4e
//#define RPC_REQ_ERROR 0x7ae432f5

#define TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY 1

#define TL_ENGINE_NOP 0x166bb7c6

#define TLF_CRC32 1
#define TLF_PERMANENT 2
#define TLF_ALLOW_PREPEND 4
#define TLF_DISABLE_PREPEND 8
#define TLF_NOALIGN 16
#define TLF_NO_AUTOFLUSH 32


struct tl_query_header;
struct tl_query_header *tl_query_header_dup (struct tl_query_header *h);
struct tl_query_header *tl_query_header_clone (struct tl_query_header *h_old);
void tl_query_header_delete (struct tl_query_header *h);


#define RPC_REQ_ERROR_WRAPPED (RPC_REQ_ERROR + 1)

extern long long rpc_queries_received, rpc_queries_ok, rpc_queries_error;

struct tl_in_state;
struct tl_out_state;
struct tl_in_methods {
  void (*fetch_raw_data)(struct tl_in_state *tlio, void *buf, int len);
  void (*fetch_move)(struct tl_in_state *tlio, int len);
  void (*fetch_lookup)(struct tl_in_state *tlio, void *buf, int len);
  void (*fetch_clear)(struct tl_in_state *tlio);
  void (*fetch_mark)(struct tl_in_state *tlio);
  void (*fetch_mark_restore)(struct tl_in_state *tlio);
  void (*fetch_mark_delete)(struct tl_in_state *tlio);
  void (*fetch_raw_message)(struct tl_in_state *tlio, struct raw_message *raw, int len);
  void (*fetch_lookup_raw_message)(struct tl_in_state *tlio, struct raw_message *raw, int len);
  int flags;
  int prepend_bytes;
};

struct tl_out_methods {
  void *(*store_get_ptr)(struct tl_out_state *tlio, int len);
  void *(*store_get_prepend_ptr)(struct tl_out_state *tlio, int len);
  void (*store_raw_data)(struct tl_out_state *tlio, const void *buf, int len);
  void (*store_raw_msg)(struct tl_out_state *tlio, struct raw_message *raw);
  void (*store_read_back)(struct tl_out_state *tlio, int len);
  void (*store_read_back_nondestruct)(struct tl_out_state *tlio, void *buf, int len);
  unsigned (*store_crc32_partial)(struct tl_out_state *tlio, int len, unsigned start);
  void (*store_flush)(struct tl_out_state *tlio);
  void (*store_clear)(struct tl_out_state *tlio);
  void (*copy_through[10])(struct tl_in_state *tlio_src, struct tl_out_state *tlio_dst, int len, int advance);
  void (*store_prefix)(struct tl_out_state *tlio);
  int flags;
  int prepend_bytes;
};

enum tl_type {
  tl_type_none,
  tl_type_str,
  //tl_type_conn,
  //tl_type_nbit,
  tl_type_raw_msg,
  tl_type_tcp_raw_msg,
};

struct tl_in_state {
  enum tl_type in_type;
  const struct tl_in_methods *in_methods;
  
  void *in;
  void *in_mark;

  int in_remaining;
  int in_pos;
  int in_mark_pos;
  int in_flags;

  char *error;
  int errnum;

  struct process_id in_pid_buf;
  struct process_id *in_pid;
};

struct tl_out_state {
  enum tl_type out_type;
  const struct tl_out_methods *out_methods;
  void *out;
  void *out_extra;
  int out_pos;
  int out_remaining;
  int *out_size;

  char *error;
  int errnum;

  long long out_qid;

  struct process_id out_pid_buf;
  struct process_id *out_pid;
};

struct query_work_params;

struct tl_query_header {
  long long qid;
  long long actor_id;
  int flags;
  int op;
  int real_op;
  int ref_cnt;
  struct query_work_params *qw_params;
};

extern const struct tl_in_methods tl_in_conn_methods;
extern const struct tl_in_methods tl_in_nbit_methods;
extern const struct tl_in_methods tl_in_raw_msg_methods;
extern const struct tl_out_methods tl_out_conn_methods;
extern const struct tl_out_methods tl_out_raw_msg_methods;

#define TL_IN (tlio_in->in)
#define TL_IN_CONN ((connection_job_t)(tlio_in->in))
#define TL_IN_NBIT ((nb_iterator_t *)(tlio_in->in))
#define TL_IN_RAW_MSG ((struct raw_message *)(tlio_in->in))
#define TL_IN_STR ((char *)(tlio_in->in))
#define TL_IN_TYPE (tlio_in->in_type)
#define TL_IN_REMAINING (tlio_in->in_remaining)
#define TL_IN_POS (tlio_in->in_pos)
#define TL_IN_METHODS (tlio_in->in_methods)
#define TL_IN_MARK (tlio_in->in_mark)
#define TL_IN_MARK_POS (tlio_in->in_mark_pos)
#define TL_IN_PID (tlio_in->in_pid)
#define TL_IN_FLAGS (tlio_in->in_methods->flags)
#define TL_IN_CUR_FLAGS (tlio_in->in_flags)

#define TL_OUT ((tlio_out->out))
#define TL_OUT_TYPE (tlio_out->out_type)
#define TL_OUT_SIZE (tlio_out->out_size)
#define TL_OUT_CONN ((connection_job_t)(tlio_out->out))
#define TL_OUT_RAW_MSG ((struct raw_message *)(tlio_out->out))
#define TL_OUT_STR ((char *)(tlio_out->out))
#define TL_OUT_POS (tlio_out->out_pos)
#define TL_OUT_REMAINING (tlio_out->out_remaining)
#define TL_OUT_METHODS (tlio_out->out_methods)
#define TL_OUT_QID (tlio_out->out_qid)
#define TL_OUT_EXTRA (tlio_out->out_extra)
#define TL_OUT_PID (tlio_out->out_pid)
#define TL_OUT_FLAGS (tlio_out->out_methods->flags)

#define TL_ERROR (tlio_in->error)
#define TL_ERRNUM (tlio_in->errnum)

//#define TL_COPY_THROUGH (tlio->copy_through)

//#define TL_ATTEMPT_NUM (tlio)->attempt_num


int tlf_set_error_format (struct tl_in_state *tlio_in, int errnum, const char *format, ...) __attribute__ (( format(printf,3,4) ));
#define tl_fetch_set_error_format(...) tlf_set_error_format (tlio_in, ## __VA_ARGS__)
int tlf_set_error (struct tl_in_state *tlio_in,  int errnum, const char *s);
#define tl_fetch_set_error(...) tlf_set_error (tlio_in, ## __VA_ARGS__)

int tls_set_error_format (struct tl_out_state *tlio_out, int errnum, const char *format, ...) __attribute__ (( format(printf,3,4) ));
#define tl_store_set_error_format(...) tls_set_error_format (tlio_out, ## __VA_ARGS__)

//int tlf_init_connection (struct tl_in_state *tlio_in, connection_job_t c, int size);
//int tlf_init_iterator (struct tl_in_state *tlio_in, nb_iterator_t *it, int size);
//int tlf_init_iterator_noskip (struct tl_in_state *tlio_in, nb_iterator_t *it, int size);
// dup = 0 - delete reference
// dup = 1 - make msg valid raw message of size 0
// dup = 2 - clone message
int tlf_init_raw_message (struct tl_in_state *tlio_in, struct raw_message *msg, int size, int dup);

int tlf_init_str (struct tl_in_state *tlio_in, const char *s, int size);

//int tls_init_connection (struct tl_out_state *tlio_out, connection_job_t c, long long qid);
//int tls_init_connection_keep_error (struct tl_out_state *tlio_out, connection_job_t c, long long qid);
int tls_init_raw_msg (struct tl_out_state *tlio_out, struct process_id *pid, long long qid);
//int tls_init_raw_msg_keep_error (struct tl_out_state *tlio_out, struct process_id *pid, long long qid);
int tls_init_tcp_raw_msg (struct tl_out_state *tlio_out, JOB_REF_ARG (c), long long qid);
int tls_init_tcp_raw_msg_unaligned (struct tl_out_state *tlio_out, JOB_REF_ARG (c), long long qid);
//int tls_init_tcp_raw_msg_keep_error (struct tl_out_state *tlio_out, connection_job_t c, long long qid);
//int tls_init_simple (struct tl_out_state *tlio_out, connection_job_t c);
int tls_init_str (struct tl_out_state *tlio_out, char *s, long long qid, int size);
//int tls_init_str_keep_error (struct tl_out_state *tlio_out, char *s, long long qid, int size);
//int tls_init_any_keep_error (struct tl_out_state *tlio_out, enum tl_type type, void *out, long long qid);
int tls_init_raw_msg_nosend (struct tl_out_state *tlio_out);
//int tls_init_any (struct tl_out_state *tlio, enum tl_type type, void *out, long long qid);
int tls_init (struct tl_out_state *tlio_out, enum tl_type type, struct process_id *pid, long long qid);
//int tls_init_keep_error (struct tl_out_state *tlio_out, enum tl_type type, struct process_id *pid, long long qid);


int tlf_query_flags (struct tl_in_state *tlio_in, struct tl_query_header *header);
int tlf_query_header (struct tl_in_state *tlio_in, struct tl_query_header *header);
int tlf_query_answer_flags (struct tl_in_state *tlio_in, struct tl_query_header *header);
int tlf_query_answer_header (struct tl_in_state *tlio_in, struct tl_query_header *header);
int tls_header (struct tl_out_state *tlio_out, struct tl_query_header *header);

int tls_end_ext (struct tl_out_state *tlio_out, int op);

static inline int tlf_init_empty (struct tl_in_state *tlio_in) {
  return tlf_init_str (tlio_in, "", 0);
}

static inline int tl_store_end_simple (struct tl_out_state *tlio_out) {
  return tls_end_ext (tlio_out, 0);
}
#define tl_store_end_ext(type) tls_end_ext(tlio_out,type)

static inline int tlf_check (struct tl_in_state *tlio_in, int nbytes) /* {{{ */ {
  if (!TL_IN_TYPE) {
    tlf_set_error (tlio_in, TL_ERROR_INTERNAL, "Trying to read from unitialized in buffer");
    return -1;
  }
  if (nbytes >= 0) {
    if (TL_IN_REMAINING < nbytes) {
      tlf_set_error_format (tlio_in, TL_ERROR_NOT_ENOUGH_DATA, "Trying to read %d bytes at position %d (size = %d)", nbytes, TL_IN_POS, TL_IN_POS + TL_IN_REMAINING);
      return -1;
    }
  } else {
    if (TL_IN_POS < -nbytes) {
      tlf_set_error_format (tlio_in, TL_ERROR_NOT_ENOUGH_DATA, "Trying to read %d bytes at position %d (size = %d)", nbytes, TL_IN_POS, TL_IN_POS + TL_IN_REMAINING);
      return -1;
    }
  }
  if (TL_ERROR) {
    return -1;
  }
  return 0;
}
/* }}} */

inline static void __tlf_raw_data (struct tl_in_state *tlio_in, void *buf, int size) /* {{{ */ {
  TL_IN_METHODS->fetch_raw_data (tlio_in, buf, size);
  TL_IN_POS += size;
  TL_IN_REMAINING -= size;
}
/* }}} */

inline static void __tlf_skip_raw_data (struct tl_in_state *tlio_in, int size) /* {{{ */ {
  TL_IN_METHODS->fetch_move (tlio_in, size);
  TL_IN_POS += size;
  TL_IN_REMAINING -= size;
}
/* }}} */

static inline int tlf_lookup_int (struct tl_in_state *tlio_in) /* {{{ */ {
  if (tlf_check (tlio_in, 4) < 0) {
    return -1;
  }
  int x;
  TL_IN_METHODS->fetch_lookup (tlio_in, &x, 4);
  return x;
}
/* }}} */
#define tl_fetch_lookup_int(...) tlf_lookup_int (tlio_in, ## __VA_ARGS__)

static inline int tlf_lookup_second_int (struct tl_in_state *tlio_in) /* {{{ */ {
  if (tlf_check (tlio_in, 8) < 0) {
    return -1;
  }
  int x[2];
  TL_IN_METHODS->fetch_lookup (tlio_in, x, 8);
  return x[1];
}
/* }}} */
#define tl_fetch_lookup_second_int(...) tlf_lookup_second_int (tlio_in, ## __VA_ARGS__)

static inline long long tlf_lookup_long (struct tl_in_state *tlio_in) /* {{{ */ {
  if (tlf_check (tlio_in, 8) < 0) {
    return -1;
  }
  long long x;
  TL_IN_METHODS->fetch_lookup (tlio_in, &x, 8);
  return x;
}
/* }}} */
#define tl_fetch_lookup_long(...) tlf_lookup_long (tlio_in, ## __VA_ARGS__)

static inline int tlf_lookup_data (struct tl_in_state *tlio_in, void *data, int len) /* {{{ */ {
  if (tlf_check (tlio_in, len) < 0) {
    return -1;
  }
  TL_IN_METHODS->fetch_lookup (tlio_in, data, len);
  return len;
}
/* }}} */
#define tl_fetch_lookup_data(...) tlf_lookup_data (tlio_in, ## __VA_ARGS__)

static inline int tlf_int (struct tl_in_state *tlio_in) /* {{{ */ {
  if (__builtin_expect (tlf_check (tlio_in, 4) < 0, 0)) {
    return -1;
  }
  int x;
  __tlf_raw_data (tlio_in, &x, 4);
  return x;
}
/* }}} */
#define tl_fetch_int(...) tlf_int (tlio_in, ## __VA_ARGS__)

static inline double tlf_double (struct tl_in_state *tlio_in) /* {{{ */ {
  if (__builtin_expect (tlf_check (tlio_in, sizeof (double)) < 0, 0)) {
    return -1;
  }
  double x;
  __tlf_raw_data (tlio_in, &x, sizeof (x));
  return x;
}
/* }}} */
#define tl_fetch_double(...) tlf_double (tlio_in, ## __VA_ARGS__)

static inline long long tlf_long (struct tl_in_state *tlio_in) /* {{{ */ {
  if (__builtin_expect (tlf_check (tlio_in, 8) < 0, 0)) {
    return -1;
  }
  long long x;
  __tlf_raw_data (tlio_in, &x, 8);
  return x;
}
/* }}} */
#define tl_fetch_long(...) tlf_long (tlio_in, ## __VA_ARGS__)

static inline void tlf_mark (struct tl_in_state *tlio_in) /* {{{ */ {
  TL_IN_METHODS->fetch_mark (tlio_in);
}
/* }}} */
#define tl_fetch_mark(...) tlf_mark (tlio_in, ## __VA_ARGS__)

static inline void tlf_mark_restore (struct tl_in_state *tlio_in) /* {{{ */ {
  TL_IN_METHODS->fetch_mark_restore (tlio_in);
}
/* }}} */
#define tl_fetch_mark_restore(...) tlf_mark_restore (tlio_in, ## __VA_ARGS__)

static inline void tlf_mark_delete (struct tl_in_state *tlio_in) /* {{{ */ {
  TL_IN_METHODS->fetch_mark_delete (tlio_in);
}
/* }}} */
#define tl_fetch_mark_delete(...) tlf_mark_delete (tlio_in, ## __VA_ARGS__)

static inline int tlf_string_len (struct tl_in_state *tlio_in, int max_len) /* {{{ */ {
  if (tlf_check (tlio_in, 4) < 0) {
    return -1;
  }
  int x = 0;
  __tlf_raw_data (tlio_in, &x, 1);
  if (x == 255) {
    tlf_set_error (tlio_in, TL_ERROR_SYNTAX, "String len can not start with 0xff");
    return -1;
  }
  if (x == 254) {
    __tlf_raw_data (tlio_in, &x, 3);
  }
  if (x > max_len) {
    tlf_set_error_format (tlio_in, TL_ERROR_TOO_LONG_STRING, "string is too long: max_len = %d, len = %d", max_len, x);
    return -1;
  }
  if (x > TL_IN_REMAINING) {
    tlf_set_error_format (tlio_in, TL_ERROR_NOT_ENOUGH_DATA, "string is too long: remaining_bytes = %d, len = %d", TL_IN_REMAINING, x);
    return -1;
  }
  return x;
}
/* }}} */
#define tl_fetch_string_len(...) tlf_string_len (tlio_in, ## __VA_ARGS__)

static inline int tlf_pad (struct tl_in_state *tlio_in) /* {{{ */ {
  int pad = (-TL_IN_POS) & 3;
  if (tlf_check (tlio_in, pad) < 0) {
    return -1;
  }
  int t = 0;
  assert (TL_IN_REMAINING >= pad);
  __tlf_raw_data (tlio_in, &t, pad);
  if (t) {
    tlf_set_error (tlio_in,  TL_ERROR_SYNTAX, "Padding with non-zeroes");
    return -1;
  }
  return pad;  
}
/* }}} */
#define tl_fetch_pad(...) tlf_pad (tlio_in, ## __VA_ARGS__)

static inline int tlf_raw_data (struct tl_in_state *tlio_in, void *buf, int len) /* {{{ */ {
  assert (!(len & 3));
  if (tlf_check (tlio_in, len) < 0) {
    return -1;
  }
  __tlf_raw_data (tlio_in, buf, len);
  return len;
}
/* }}} */
#define tl_fetch_raw_data(...) tlf_raw_data (tlio_in, ## __VA_ARGS__)

static inline int tlf_string_data (struct tl_in_state *tlio_in, char *buf, int len) /* {{{ */ {
  if (tlf_check (tlio_in, len) < 0) {
    return -1;
  }
  __tlf_raw_data (tlio_in, buf, len);
  if (tlf_pad (tlio_in) < 0) {
    return -1;
  }
  return len;
}
/* }}} */
#define tl_fetch_string_data(...) tlf_string_data (tlio_in, ## __VA_ARGS__)

static inline int tlf_skip_string_data (struct tl_in_state *tlio_in, int len) /* {{{ */ {
  if (tlf_check (tlio_in, len) < 0) {
    return -1;
  }
  __tlf_skip_raw_data (tlio_in, len);
  if (tlf_pad (tlio_in) < 0) {
    return -1;
  }
  return len;
}
/* }}} */
#define tl_fetch_skip_string_data(...) tlf_skip_string_data (tlio_in, ## __VA_ARGS__)

static inline int tlf_string (struct tl_in_state *tlio_in, char *buf, int max_len) /* {{{ */ {
  int l = tlf_string_len (tlio_in, max_len);
  if (l < 0) {
    return -1;
  }
  if (tlf_string_data (tlio_in, buf, l) < 0) {
    return -1;
  }
  return l;
}
/* }}} */
#define tl_fetch_string(...) tlf_string (tlio_in, ## __VA_ARGS__)

static inline int tlf_skip_string (struct tl_in_state *tlio_in, int max_len) /* {{{ */ {
  int l = tlf_string_len (tlio_in, max_len);
  if (l < 0) {
    return -1;
  }
  if (tlf_skip_string_data (tlio_in, l) < 0) {
    return -1;
  }
  return l;
}
/* }}} */
#define tl_fetch_skip_string(...) tlf_skip_string (tlio_in, ## __VA_ARGS__)

static inline int tlf_string0 (struct tl_in_state *tlio_in, char *buf, int max_len) /* {{{ */ {
  int l = tlf_string_len (tlio_in, max_len);
  if (l < 0) {
    return -1;
  }
  if (tlf_string_data (tlio_in, buf, l) < 0) {
    return -1;
  }
  buf[l] = 0;
  return l;
}
/* }}} */
#define tl_fetch_string0(...) tlf_string0 (tlio_in, ## __VA_ARGS__)

static inline int tlf_error (struct tl_in_state *tlio_in) /* {{{ */{
  return TL_ERROR != 0;
}
/* }}} */
#define tl_fetch_error(...) tlf_error (tlio_in, ## __VA_ARGS__)

static inline int tlf_end (struct tl_in_state *tlio_in) /* {{{ */ {
  if (TL_IN_REMAINING && !(TL_IN_CUR_FLAGS & (TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY))) {
    tlf_set_error_format (tlio_in, TL_ERROR_EXTRA_DATA, "extra %d bytes after query", TL_IN_REMAINING);
    return -1;
  }
  return 1;
}
/* }}} */
#define tl_fetch_end(...) tlf_end (tlio_in, ## __VA_ARGS__)

static inline int tlf_check_str_end (struct tl_in_state *tlio_in, int size) /* {{{ */ {
  if (TL_IN_REMAINING != size + ((-size - TL_IN_POS) & 3)) {
    tlf_set_error_format (tlio_in, TL_ERROR_EXTRA_DATA, "extra %d bytes after query", TL_IN_REMAINING - size - ((-size - TL_IN_POS) & 3));    
    return -1;
  }
  return 1;
}
/* }}} */
#define tl_fetch_check_str_end(...) tlf_check_str_end (tlio_in, ## __VA_ARGS__)

static inline int tlf_unread (struct tl_in_state *tlio_in) /* {{{ */ {
  return TL_IN_REMAINING;
}
/* }}} */
#define tl_fetch_unread(...) tlf_unread (tlio_in, ## __VA_ARGS__)

static inline int tlf_skip (struct tl_in_state *tlio_in, int len) /* {{{ */ {
  if (tlf_check (tlio_in, len) < 0) {
    return -1;
  }
  __tlf_skip_raw_data (tlio_in, len);
  return len;
}
/* }}} */
#define tl_fetch_skip(...) tlf_skip (tlio_in, ## __VA_ARGS__)
/*
static inline int tl_fetch_move (int offset) {
  if (tl_fetch_check (offset) < 0) {
    return -1;
  }
  TL_IN_METHODS->fetch_move (offset);
  TL_IN_POS += offset;
  TL_IN_REMAINING -= offset;
  return offset;
}*/

static inline int tls_check (struct tl_out_state *tlio_out, int size) /* {{{ */ {
  if (TL_OUT_TYPE == tl_type_none) { return -1; }
  if (TL_OUT_REMAINING < size) { return -1; }
  return 0;
}
/* }}} */

static inline void __tls_raw_data (struct tl_out_state *tlio_out, const void *buf, int len) /* {{{ */ {
  TL_OUT_METHODS->store_raw_data (tlio_out, buf, len);
  TL_OUT_POS += len;
  TL_OUT_REMAINING -= len;
}
/* }}} */

static inline void *tls_get_ptr (struct tl_out_state *tlio_out, int size) /* {{{ */ {
  assert (tls_check (tlio_out, size) >= 0);
  if (!size) { return 0; }
  assert (size >= 0);
  void *x = TL_OUT_METHODS->store_get_ptr (tlio_out, size);
  TL_OUT_POS += size;
  TL_OUT_REMAINING -= size;
  return x;
}
/* }}} */
#define tl_store_get_ptr(...) tls_get_ptr (tlio_out, ## __VA_ARGS__)

static inline void *tls_get_prepend_ptr (struct tl_out_state *tlio_out, int size) /* {{{ */ {
  assert (tls_check (tlio_out, size) >= 0);
  if (!size) { return 0; }
  assert (size >= 0);
  void *x = TL_OUT_METHODS->store_get_prepend_ptr (tlio_out, size);
  TL_OUT_POS += size;
  TL_OUT_REMAINING -= size;
  return x;
}
/* }}} */
#define tl_store_get_prepend_ptr(...) tls_get_prepend_ptr (tlio_out, ## __VA_ARGS__)

static inline int tls_int (struct tl_out_state *tlio_out, int x) /* {{{ */ {
  assert (tls_check (tlio_out, 4) >= 0);
  __tls_raw_data (tlio_out, &x, 4);
  return 0;
}
/* }}} */
#define tl_store_int(...) tls_int (tlio_out, ## __VA_ARGS__)

static inline int tls_long (struct tl_out_state *tlio_out, long long x) /* {{{ */ {
  assert (tls_check (tlio_out, 8) >= 0);
  __tls_raw_data (tlio_out, &x, 8);
  return 0;
}
/* }}} */
#define tl_store_long(...) tls_long (tlio_out, ## __VA_ARGS__)

static inline int tls_double (struct tl_out_state *tlio_out, double x) /* {{{ */ {
  assert (tls_check (tlio_out, 8) >= 0);
  __tls_raw_data (tlio_out, &x, 8);
  return 0;
}
/* }}} */
#define tl_store_double(...) tls_double (tlio_out, ## __VA_ARGS__)

static inline int tls_string_len (struct tl_out_state *tlio_out, int len) /* {{{ */ {
  assert (tls_check (tlio_out, 4) >= 0);
  assert (len >= 0);
  if (len < 254) {
    __tls_raw_data (tlio_out, &len, 1);
  } else {
    assert (len < (1 << 24));
    int x = (len << 8) + 0xfe;
    __tls_raw_data (tlio_out, &x, 4);
  }
  return 0;
}
/* }}} */
#define tl_store_string_len(...) tls_string_len (tlio_out, ## __VA_ARGS__)

static inline int tls_raw_msg (struct tl_out_state *tlio_out, struct raw_message *raw, int dup) /* {{{ */ {
  assert (tls_check (tlio_out, raw->total_bytes) >= 0);
  int len = raw->total_bytes;
  if (!dup) {
    TL_OUT_METHODS->store_raw_msg (tlio_out, raw);
  } else {
    struct raw_message r;
    rwm_clone (&r, raw);
    TL_OUT_METHODS->store_raw_msg (tlio_out, &r);
  }
  TL_OUT_POS += len;
  TL_OUT_REMAINING -= len;
  return 0;
}
/* }}} */
#define tl_store_raw_msg(...) tls_raw_msg (tlio_out, ## __VA_ARGS__)

static inline int tls_pad (struct tl_out_state *tlio_out) /* {{{ */ {
  assert (tls_check (tlio_out, 0) >= 0);
  int x = 0;
  int pad = (-TL_OUT_POS) & 3;
  __tls_raw_data (tlio_out, &x, pad);
  return 0;
}
/* }}} */
#define tl_store_pad(...) tls_pad (tlio_out, ## __VA_ARGS__)

static inline int tls_raw_data (struct tl_out_state *tlio_out, const void *s, int len) /* {{{ */ {
  //assert (!(len & 3));
  assert (tls_check (tlio_out, len) >= 0);
  __tls_raw_data (tlio_out, s, len);
  return len;
}
/* }}} */
#define tl_store_raw_data(...) tls_raw_data (tlio_out, ## __VA_ARGS__)

static inline int tls_string_data (struct tl_out_state *tlio_out, const char *s, int len) /* {{{ */ {
  assert (tls_check (tlio_out, len) >= 0);
  __tls_raw_data (tlio_out, s, len);
  tls_pad (tlio_out);
  return 0;
}
/* }}} */
#define tl_store_string_data(...) tls_string_data (tlio_out, ## __VA_ARGS__)

static inline int tls_string (struct tl_out_state *tlio_out, const char *s, int len) /* {{{ */ {
  tls_string_len (tlio_out, len);
  tls_string_data (tlio_out, s, len);
  return 0;
}
/* }}} */
#define tls_string0(tlio_out,_s) tls_string (tlio_out, _s, strlen (_s))
#define tl_store_string(...) tls_string (tlio_out, ## __VA_ARGS__)
#define tl_store_string0(s) tl_store_string(s, strlen (s))

static inline int tls_clear (struct tl_out_state *tlio_out) /* {{{ */ {
  assert (TL_OUT);
  TL_OUT_METHODS->store_clear (tlio_out);
  TL_OUT = 0;
  TL_OUT_TYPE = tl_type_none;
  TL_OUT_EXTRA = 0;
  return 0; 
}
/* }}} */ 
#define tl_store_clear(...) tls_clear (tlio_out, ## __VA_ARGS__)

static inline int tls_clean (struct tl_out_state *tlio_out) /* {{{ */ {
  assert (TL_OUT);
  TL_OUT_METHODS->store_read_back (tlio_out, TL_OUT_POS);
  TL_OUT_REMAINING += TL_OUT_POS;
  TL_OUT_POS = 0;
  return 0; 
}
/* }}} */
#define tl_store_clean(...) tls_clean (tlio_out, ## __VA_ARGS__)

/*static inline int tl_store_read_back_nondestruct (struct tchar *buf, int size) {
  assert (size <= TL_OUT_POS);
  TL_OUT_METHODS->store_read_back_nondestruct (buf, size);
  return size;
}*/

#define tl_store_end() tl_store_end_ext(RPC_REQ_RESULT)

static inline int tl_copy_through (struct tl_in_state *tlio_in, struct tl_out_state *tlio_out, int len, int advance) /* {{{ */ {
  if (TL_IN_TYPE == tl_type_none || TL_OUT_TYPE == tl_type_none) {
    return -1;
  }
  if (tlf_check (tlio_in, len) < 0 || tls_check (tlio_out, len) < 0) {
    return -1;
  }
  tlio_out->out_methods->copy_through[tlio_in->in_type](tlio_in, tlio_out, len, advance);
  if (advance) {
    TL_IN_POS += len;
    TL_IN_REMAINING -= len;
  }
  TL_OUT_POS += len;
  TL_OUT_REMAINING -= len;
  return len;
}
/* }}} */

static inline int tlf_int_range (struct tl_in_state *tlio_in, int min, int max) /* {{{ */ {
  int x = tlf_int (tlio_in);
  if (x < min || x > max) {
    tlf_set_error_format (tlio_in, TL_ERROR_VALUE_NOT_IN_RANGE, "Expected int32 in range [%d,%d], %d presented", min, max, x);
  }
  return x;
}
/* }}} */
#define tl_fetch_int_range(...) tlf_int_range (tlio_in, ## __VA_ARGS__)

static inline int tlf_positive_int (struct tl_in_state *tlio_in) {
  return tlf_int_range (tlio_in, 1, 0x7fffffff);
}
#define tl_fetch_positive_int(...) tlf_positive_int (tlio_in, ## __VA_ARGS__)

static inline int tlf_nonnegative_int (struct tl_in_state *tlio_in) {
  return tlf_int_range (tlio_in, 0, 0x7fffffff);
}
#define tl_fetch_nonnegative_int(...) tlf_nonnegative_int (tlio_in, ## __VA_ARGS__)

static inline int tlf_int_subset (struct tl_in_state *tlio_in, int set) /* {{{ */ {
  int x = tlf_int (tlio_in);
  if (x & ~set) {
    tlf_set_error_format (tlio_in, TL_ERROR_VALUE_NOT_IN_RANGE, "Expected int32 with only bits 0x%02x allowed, 0x%02x presented", set, x);
  }
  return x;
}
/* }}} */
#define tl_fetch_int_subset(...) tlf_int_subset (tlio_in, ## __VA_ARGS__)

static inline long long tlf_long_range (struct tl_in_state *tlio_in, long long min, long long max) /* {{{ */ {
  long long x = tlf_long (tlio_in);
  if (x < min || x > max) {
    tlf_set_error_format (tlio_in, TL_ERROR_VALUE_NOT_IN_RANGE, "Expected int64 in range [%lld,%lld], %lld presented", min, max, x);
  }
  return x;
}
/* }}} */

static inline long long tlf_positive_long (struct tl_in_state *tlio_in) {
  return tlf_long_range (tlio_in, 1, 0x7fffffffffffffffll);
}
#define tl_fetch_positive_long(...) tlf_positive_long (tlio_in, ## __VA_ARGS__)

static inline long long tlf_nonnegative_long (struct tl_in_state *tlio_in) {
  return tlf_long_range (tlio_in, 0, 0x7fffffffffffffffll);
}
#define tl_fetch_nonnegative_long(...) tlf_nonnegative_long (tlio_in, ## __VA_ARGS__)

static int _tlf_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int len, int advance) {
  if (__builtin_expect (tlf_check (tlio_in, len) < 0, 0)) {
    return -1;
  }

  if (advance) {
    TL_IN_METHODS->fetch_raw_message (tlio_in, raw, len);
    TL_IN_POS += len;
    TL_IN_REMAINING -= len;
  } else {
    TL_IN_METHODS->fetch_lookup_raw_message (tlio_in, raw, len);
  }

  return 0;
}

static inline int tlf_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int bytes) {
  return _tlf_raw_message (tlio_in, raw, bytes, 1);
}
#define tl_fetch_raw_message(...) tlf_raw_message (tlio_in, ## __VA_ARGS__)

static inline int tlf_lookup_raw_message (struct tl_in_state *tlio_in, struct raw_message *raw, int bytes) {
  return _tlf_raw_message (tlio_in, raw, bytes, 0);
}
#define tl_fetch_lookup_raw_message(...) tlf_lookup_raw_message (tlio_in, ## __VA_ARGS__)

static inline void tlf_copy_error (struct tl_in_state *tlio_in, struct tl_out_state *tlio_out) {
  if (!tlio_out->error) {
    if (tlio_in->error) {
      tlio_out->error = strdup (tlio_in->error);
      tlio_out->errnum = tlio_in->errnum;
    }
  }
}
#define tl_copy_error(...) tlf_copy_error (tlio_in, tlio_out, ## __VA_ARGS__)

struct tl_in_state *tl_in_state_alloc (void);
void tl_in_state_free (struct tl_in_state *tlio_in);
struct tl_out_state *tl_out_state_alloc (void);
void tl_out_state_free (struct tl_out_state *tlio_out);
