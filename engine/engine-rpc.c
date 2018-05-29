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
#include "engine/engine-rpc.h"
#include "common/tl-parse.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

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

#include "engine/engine-rpc-common.h"

#include "vv/vv-io.h"
#include "vv/vv-tree.h"

//#include "auto/TL/tl-names.h"

#include "engine/engine.h"
#include "common/common-stats.h"

double tl_aio_timeout;

struct tl_out_state *tl_aio_init_store (enum tl_type type, struct process_id *pid, long long qid) {
  if (type == tl_type_raw_msg) {
    struct tl_out_state *IO = tl_out_state_alloc ();
    tls_init_raw_msg (IO, pid, qid);
    return IO;
  } else if (type == tl_type_tcp_raw_msg) {
    connection_job_t d = rpc_target_choose_connection (rpc_target_lookup (pid), pid);
    if (d) {
      vkprintf (2, "%s: Good connection #%d for " PID_PRINT_STR "\n", __func__, CONN_INFO(d)->fd, PID_TO_PRINT (pid));
      struct tl_out_state *IO = tl_out_state_alloc ();
      tls_init_tcp_raw_msg (IO, JOB_REF_PASS (d), qid);
      return IO;
    } else {
      vkprintf (2, "%s: Bad connection " PID_PRINT_STR "\n", __func__, PID_TO_PRINT (pid));
      return NULL;
    }
  } else {
    assert (0);
    return NULL;
  }
}

#define ENGINE_JOB_CLASS JF_CLASS_MAIN

static long long queries_allocated;

long long engine_get_allocated_queries (void) {
  return queries_allocated;
}


#define rpc_custom_op_cmp(a,b) (a->op < b->op ? -1 : a->op > b->op ? 1 : 0)

#define X_TYPE struct rpc_custom_op *
#define X_CMP rpc_custom_op_cmp
#define TREE_NAME rpc_custom_op
#define TREE_MALLOC
#include "vv/vv-tree.c"
static struct tree_rpc_custom_op *rpc_custom_op_tree;

void register_custom_op_cb (unsigned op, void (*func)(struct tl_in_state *tlio_in, struct query_work_params *params)) {
  struct rpc_custom_op *O = malloc (sizeof (*O));
  O->op = op;
  O->func = func;
  rpc_custom_op_tree = tree_insert_rpc_custom_op (rpc_custom_op_tree, O, lrand48 ());
}

static struct tl_act_extra *(*tl_parse_function)(struct tl_in_state *tlio_in, long long actor_id);
static int (*tl_get_op_function)(struct tl_in_state *tlio_in);
static void (*tl_stat_function)(struct tl_out_state *tlio_out);

int tl_result_new_flags (int old_flags) {
  return old_flags & 0xffff;
}

int tl_result_get_header_len (struct tl_query_header *h) {
  if (!h->flags) { return 0; }
  int s = 8;
  return s;
}

int tl_result_make_header (int *ptr, struct tl_query_header *h) {
  int *p = ptr;
  if (!h->flags) { return 0; }
  int new_flags = tl_result_new_flags (h->flags);
  *p = RPC_REQ_RESULT_FLAGS; 
  p++;
  *p = new_flags;
  p ++;
  return (p - ptr) * 4;
}

void tl_default_act_free (struct tl_act_extra *extra) {
  if (extra->header) {
    tl_query_header_delete (extra->header);
  }
  if (!(extra->flags & 1)) {
    return;
  }
  free (extra);
}

struct tl_act_extra *tl_default_act_dup (struct tl_act_extra *extra) {
  struct tl_act_extra *new = malloc (extra->size);
  memcpy (new, extra, extra->size);
  new->flags = new->flags | 3;
  return new;
}

int need_dup (struct tl_act_extra *extra) {
  return !(extra->flags & 1);
}


static tl_query_result_fun_t *tl_query_result_functions = NULL;

void tl_query_result_fun_set (tl_query_result_fun_t func, int query_type_id) {
  if (!tl_query_result_functions) {
    tl_query_result_functions = calloc (sizeof (void *), 16);
  }
  tl_query_result_functions[query_type_id] = func;
}

long long tl_generate_next_qid (int query_type_id) {
  assert (((unsigned) query_type_id) < 16);
  static unsigned int last_qid = 0;
  if (!last_qid) {
    last_qid = lrand48_j ();
  }
  return ((unsigned long long) ((query_type_id << 28) + (lrand48_j () & 0x0fffffff)) << 32) | (++last_qid);
}

long long tl_generate_next_qid (int query_type_id);

void engine_work_rpc_req_result (struct tl_in_state *tlio_in, struct query_work_params *params) {
  if (!tl_query_result_functions) {
    return;
  }
  struct tl_query_header *h = malloc (sizeof (*h));
  if (tlf_query_answer_header (tlio_in, h) < 0) {
    tl_query_header_delete (h);
    return;
  }
  h->qw_params = params;
  int query_type_id = (((unsigned long long) h->qid) >> 60);
  tl_query_result_fun_t fun = tl_query_result_functions[query_type_id];
  if (likely (fun != NULL)) {
    fun (tlio_in, h);
  } else {
    vkprintf (1, "Unknown query type %d (qid = 0x%016llx). Skipping query result.\n", query_type_id, h->qid);
  }
  tl_query_header_delete (h);
}

int __tl_query_act_custom (struct tl_in_state *tlio_in, struct query_work_params *P) {
  unsigned op = tl_fetch_lookup_int ();
  struct rpc_custom_op *O = tree_lookup_ptr_rpc_custom_op (rpc_custom_op_tree, (void *)&op);
  if (O) {
    O->func (tlio_in, P);
  }
  
  return 0;
}

struct colon_extra {
  struct raw_message *left;
  char *left_error;
  int left_error_code;
  struct raw_message *right;
  char *right_error;
  int right_error_code;
  struct raw_message **result;
  char **error;
  int *error_code;
  job_t extra_ref;
};

struct ifeq_extra {
  struct raw_message *left;
  char *left_error;
  int left_error_code;
  struct raw_message *right;
  char *right_error;
  int right_error_code;
  struct raw_message *check;
  int check_result;
  struct raw_message **result;
  char **error;
  int *error_code;
  job_t extra_ref;
  job_t right_job;
};

static int process_act_atom_subjob (job_t job, int op, struct job_thread *JT);

/* {{{ auto TL parse functions weak declaration */

struct paramed_type *skip_function_any (struct tl_in_state *tlio_in) __attribute__ ((weak));
struct paramed_type *skip_function_any (struct tl_in_state *tlio_in) { return NULL; }
struct paramed_type *fetch_function_any (struct tl_in_state *tlio_in) __attribute__ ((weak));
struct paramed_type *fetch_function_any (struct tl_in_state *tlio_in) { return NULL; }

int skip_type_any (struct tl_in_state *tlio_in, struct paramed_type *P) __attribute__ ((weak));
int skip_type_any (struct tl_in_state *tlio_in, struct paramed_type *P) { return -1; }
int fetch_type_any (struct tl_in_state *tlio_in, struct paramed_type *P) __attribute__ ((weak));
int fetch_type_any (struct tl_in_state *tlio_in, struct paramed_type *P) { return -1; }

void free_vars_to_be_freed (void) __attribute__ ((weak));
void free_vars_to_be_freed (void) {}
void tl_printf_clear (void) __attribute__ ((weak));
void tl_printf_clear (void) {}

static inline struct paramed_type *do_skip_function_any (struct tl_in_state *tlio_in) {
  free_vars_to_be_freed ();
  return skip_function_any (tlio_in);
}

static inline struct paramed_type *do_fetch_function_any (struct tl_in_state *tlio_in) {
  free_vars_to_be_freed ();
  tl_printf_clear ();
  return fetch_function_any (tlio_in);
}

static inline int do_fetch_type_any (struct tl_in_state *tlio_in, struct paramed_type *P) {
  tl_printf_clear ();
  return fetch_type_any (tlio_in, P);
}

void paramed_type_free (struct paramed_type *P) __attribute__ ((weak));
void paramed_type_free (struct paramed_type *P) {}

struct paramed_type *paramed_type_dup (struct paramed_type *P) __attribute__ ((weak));
struct paramed_type *paramed_type_dup (struct paramed_type *P) { return 0; }

/* }}} */

static job_t fetch_query (job_t parent, struct tl_in_state *IO, struct raw_message **raw, char **error, int *error_code, long long actor_id, job_t extra_ref, job_t all_list, int status, struct tl_query_header *h) /* {{{ */ {
  int fop = tl_get_op_function (IO);

  struct tl_act_extra *extra = tl_default_parse_function (IO, actor_id);    
  if (!extra && tlf_error (IO)) {
    *error = strdup (IO->error);
    *error_code = IO->errnum;
    return NULL;
  }
  if (!extra && tl_parse_function) {
    extra = tl_parse_function (IO, actor_id);
  }
  if (!extra) {
    tlf_set_error_format (IO, TL_ERROR_UNKNOWN_FUNCTION_ID, "Unknown op 0x%08x", tlf_lookup_int (IO));
    *error = strdup (IO->error);
    *error_code = IO->errnum;
    return NULL;
  }  
  if (!extra->free) {
    extra->free = tl_default_act_free;
  }
  if (!extra->dup) {
    extra->dup = tl_default_act_dup;
  }
  extra->op = fop;
  assert (extra->act);
  assert (extra->free);
  assert (extra->dup);
  extra->error = error;
  extra->error_code = error_code;
  extra->raw = raw;
  extra->extra_ref = extra_ref ? job_incref (extra_ref) : 0;
    
  extra = need_dup (extra) ? extra->dup (extra) : extra;
  
  job_t job = create_async_job (process_act_atom_subjob, status | JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ABORT) | JSC_ALLOW (JC_ENGINE, JS_FINISH), extra->subclass, sizeof (void *), 0, JOB_REF_CREATE_PASS_N (parent));  
  
  *(void **)job->j_custom = extra;

  if (all_list) {
    insert_job_into_job_list (all_list, JOB_REF_CREATE_PASS (job), JSP_PARENT_ERROR);
  }

  queries_allocated ++;

  return job;
}
/* }}} */


static int fetch_all_queries (job_t parent, struct tl_in_state *tlio_in) /* {{{ */ {
  struct query_work_params *P = (struct query_work_params *) parent->j_custom;


  struct tl_query_header *h = P->h;

  job_t root = fetch_query (parent, tlio_in, &P->result, &P->error, &P->error_code, h->actor_id, 0, P->all_list, JSP_PARENT_RWE, h);

  if (root == (void *)-1l) {
    return -2;
  } else if (root) {
    schedule_job (JOB_REF_PASS (root));
    
    return 0;
  } else {
    return -1;
  }
}
/* }}} */ 

static int process_act_atom_subjob (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  if (op != JS_FINISH) {
    if (parent_job_aborted (job)) {
      return job_fatal (job, ECANCELED);
    }
  }

  struct tl_act_extra *E = *(void **)job->j_custom;
  
  switch (op) {
  case JS_RUN: {
    int ok = 1;
    if (!ok && !(E->type & (QUERY_ALLOW_REPLICA_GET | QUERY_ALLOW_UNINIT))) {        
      if (E->raw) {
        *E->error = strdup ("not coord anymore");
        *E->error_code = TL_ERROR_BINLOG_DISABLED;
        E->raw = 0;
        if (E->extra_ref) {
          job_decref (JOB_REF_PASS (E->extra_ref));
        }
      }
      return job_fatal (job, EIO);
    } else {
      if (!E->raw) {
        if (E->extra_ref) {
          job_decref (JOB_REF_PASS (E->extra_ref));
        }
        return JOB_COMPLETED;
      }

      struct tl_out_state *IO = tl_out_state_alloc ();
      tls_init_raw_msg_nosend (IO);
      E->tlio_out = IO;

      long long old_rdtsc = rdtsc ();
      int res = E->act (job, E);
      E->tlio_out = NULL;
      long long rdtsc_delta = rdtsc () - old_rdtsc;
      //vv_incr_stat_counter (STAT_QPS_TIME, rdtsc_delta);     
      //vv_op_stat_insert_rdtsc (E->op, rdtsc_delta);
      //if (rdtsc_delta > (int)(0.05 * 2e9)) {
      //  long_queries_cpu_cnt ++;
      //}
      E->cpu_rdtsc += rdtsc_delta;

      if (res >= 0 && !IO->error) {
        //assert (TL_OUT_RAW_MSG);
        struct raw_message *raw = malloc (sizeof (*raw));
        rwm_clone (raw, (struct raw_message *)IO->out);
        tl_out_state_free (IO);
        if (E->raw) {
          *E->raw = raw;
          E->raw = 0;
          if (E->extra_ref) {
            job_decref (JOB_REF_PASS (E->extra_ref));
          }
        }

        return JOB_COMPLETED;
      } else if (res == -2 && E->attempt < 5 && !IO->error && job->j_children > 0) {
        tl_out_state_free (IO);

        E->attempt ++;

        return 0; 
      } else {
        if (!IO->error) {
          if (res == -2 && E->attempt >= 5) {
            tls_set_error_format (IO, TL_ERROR_AIO_MAX_RETRY_EXCEEDED, "Maximum number of retries exceeded");
          } else if (res == -2) {
            tls_set_error_format (IO, TL_ERROR_BAD_METAFILE, "Error loading metafile");
          } else {
            tls_set_error_format (IO, TL_ERROR_UNKNOWN, "Unknown error");
          }
        }

        assert (IO->error);
        if (E->raw) {
          *E->error = strdup (IO->error);
          *E->error_code = IO->errnum;
          E->raw = 0;
          if (E->extra_ref) {
            job_decref (JOB_REF_PASS (E->extra_ref));
          }
        }
        tl_out_state_free (IO);

        return job_fatal (job, EIO);
      }
    }
    assert (0);
  }
  case JS_ABORT:
    if (!job->j_error) {
      job->j_error = ECANCELED;
    
      if (E->raw) {
        *E->error = strdup ("Job cancelled");
        *E->error_code = TL_ERROR_UNKNOWN;
        E->raw = 0;
      }
    }
    if (E->extra_ref) {
      job_decref (JOB_REF_PASS (E->extra_ref));
    }
    return JOB_COMPLETED;
  case JS_FINISH:
    queries_allocated --;
    if (E->extra_ref) {
      job_decref (JOB_REF_PASS (E->extra_ref));
    }    
    E->free (E);
    assert (job->j_refcnt == 1);
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }
}
/* }}} */ 

static int process_query_job (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  struct query_work_params *P = (struct query_work_params *) job->j_custom;
  struct tl_out_state *IO = NULL;
  switch (op) {
  case JS_RUN:
    assert (!job->j_children);
    assert (!P->wait_pos);
    //assert (!P->wait_time);

    if (!P->result && !P->error) {
      P->error = strdup ("Unknown error");
      P->error_code = TL_ERROR_UNKNOWN;
    }
    if (!P->answer_sent) {
      if (P->fd && P->type == tl_type_raw_msg) {
        connection_job_t C = connection_get_by_fd (P->fd);
        if (C && CONN_INFO(C)->generation != P->generation) {
          job_decref (JOB_REF_PASS (C));
        }
        if (C) {
          IO = tl_out_state_alloc ();
          tls_init_tcp_raw_msg (IO, JOB_REF_PASS (C), P->h->qid);
        }
      }
      if (!IO) {
        IO = tl_aio_init_store (P->type, &P->pid, P->h->qid);
      }
    }
    if (IO) {
      assert (!P->answer_sent);
      //long long rdtsc_delta = rdtsc () - P->start_rdtsc;
      //if (rdtsc_delta > engine_get_long_query_thres () * 2e9) {
      //  long_queries_cnt ++;
      //}
      if (P->error_code) {
        tls_set_error_format (IO, P->error_code, "%s", P->error);
        free (P->error);
        P->error = 0;
      } else {
        int z = tl_result_get_header_len (P->h);
        int *hptr = tls_get_ptr (IO, z);
        assert (z == tl_result_make_header (hptr, P->h));
        tls_raw_msg (IO, P->result, 0);
        free (P->result);
        P->result = NULL;
      }
      tls_end_ext (IO, RPC_REQ_RESULT);
      tl_out_state_free (IO);
      IO = NULL;
    }
    P->answer_sent ++;
    job_timer_remove (job);
    if (P->all_list) {
      job_signal (JOB_REF_PASS (P->all_list), JS_ABORT);
    }
    return JOB_COMPLETED;
  case JS_ALARM:
    if (!job_timer_check (job)) {
      return 0;
    }
    if (!P->answer_sent) {
      IO = tl_aio_init_store (P->type, &P->pid, P->h->qid);
    }
    if (IO) {
      if (P->error_code) {
        tls_set_error_format (IO, P->error_code, "%s", P->error);
        free (P->error);
        P->error = NULL;
      } else {
        if (P->wait_pos/* || P->wait_time*/) {
          tls_set_error_format (IO, TL_ERROR_AIO_TIMEOUT, "Binlog wait error");
        } else {
          tls_set_error_format (IO, TL_ERROR_AIO_TIMEOUT, "Aio wait error");
        }
      }

      tls_end_ext (IO, RPC_REQ_RESULT);
      tl_out_state_free (IO);
      P->answer_sent ++;
    }
    //P->wait_time = job_delete_wait (P->wait_time);
    if (!job->j_error) {
      job->j_error = ETIMEDOUT;
    }
    if (P->all_list) {
      job_signal (JOB_REF_PASS (P->all_list), JS_ABORT);
    }
    return JOB_COMPLETED;
  case JS_ABORT:
    //P->wait_time = job_delete_wait (P->wait_time);
    if (!P->answer_sent) {
      IO = tl_aio_init_store (P->type, &P->pid, P->h->qid);
    }
    if (IO) {
      if (P->error_code) {
        tls_set_error_format (IO, P->error_code, "%s", P->error);
        free (P->error);
        P->error = 0;
      } else {
        tls_set_error_format (IO, TL_ERROR_UNKNOWN, "Cancelled");
      }
      tls_end_ext (IO, RPC_REQ_RESULT);
      P->answer_sent ++;
      tl_out_state_free (IO);
      IO = NULL;
    }
    job_timer_remove (job);
    if (P->all_list) {
      job_signal (JOB_REF_PASS (P->all_list), JS_ABORT);
    }
    return JOB_COMPLETED;
  case JS_FINISH:
    assert (!P->wait_pos);
    //assert (!P->wait_time);
    assert (!P->all_list);
    assert (job->j_refcnt == 1);
    if (P->P) {
      paramed_type_free (P->P);
      P->P = 0;
    }
    if (P->error) { free (P->error); }
    if (P->result) {
      rwm_free (P->result);
      free (P->result);
    }
    if (P->src.magic) {
      rwm_free (&P->src);
    }
    tl_query_header_delete (P->h);
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }
}
/* }}} */ 

static int process_parse_subjob (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  struct query_work_params *P = (struct query_work_params *) job->j_custom;
  
  switch (op) {
  case JS_RUN: {
    job->j_execute = process_query_job;

    struct raw_message raw_copy;
    rwm_clone (&raw_copy, &P->src);

    struct tl_in_state *IO = tl_in_state_alloc ();
    tlf_init_raw_message (IO, &P->src, P->src.total_bytes, 0);
    
    int r = fetch_all_queries (job, IO);
    tl_in_state_free (IO);
    IO = NULL;
  
    rwm_free (&raw_copy);
    if (r < 0) {
      return JOB_SENDSIG (JS_ABORT);
      //return JOB_COMPLETED;
    } else {
      return 0;
    }
  }
  case JS_ABORT:
  case JS_ALARM:
  case JS_FINISH:
    return process_query_job (job, op, JT);
  default:
    return JOB_ERROR;
  }
}
/* }}} */

static int process_query_custom_subjob (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  struct query_work_params *P = (struct query_work_params *) job->j_custom;
  if (op == JS_RUN) {
    struct tl_in_state *IO = tl_in_state_alloc ();
    tlf_init_raw_message (IO, &P->src, P->src.total_bytes, 0);
    __tl_query_act_custom (IO, P);
    tl_in_state_free (IO);
   
    job_timer_remove (job);
    return JOB_COMPLETED;
  }
  switch (op) {
  case JS_ABORT: 
    job_timer_remove (job);
    if (!job->j_error) {
      job->j_error = ECANCELED;
    }
    return JOB_COMPLETED;
  case JS_ALARM:
    if (!job->j_error) {
      job->j_error = ETIMEDOUT;
    }
    return JOB_COMPLETED;
  case JS_FINISH:
    assert (job->j_refcnt == 1);
    if (P->src.magic) {
      rwm_free (&P->src);
    }
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }  
}
/* }}} */ 

int create_query_job (job_t job, struct raw_message *raw, struct tl_query_header *h, double timeout, struct process_id *remote_pid, enum tl_type out_type, int fd, int generation) /* {{{ */ {
  job->j_execute = process_parse_subjob;
  struct process_id pd = *remote_pid;
  remote_pid = &pd;

  struct query_work_params *P = (struct query_work_params *) job->j_custom;

  memset (P, 0, sizeof (*P));
  P->h = tl_query_header_dup (h);
  P->start_rdtsc = rdtsc ();
  if (P->wait_coord) {
    vkprintf (1, "wait coord query\n");
  }
  P->fd = fd;
  P->generation = generation;

  P->pid = *remote_pid;
  P->type = out_type;
  
  job_timer_insert (job, precise_now + timeout);  
  rwm_clone (&P->src, raw);
  
  return JOB_SENDSIG (JS_RUN);
}
/* }}} */

int create_query_custom_job (job_t job, struct raw_message *raw, double timeout, int fd, int generation) /* {{{ */ {
  job->j_execute = process_query_custom_subjob;
  
  struct query_info *q = QUERY_INFO (job);
  struct process_id p = q->src_pid;
  enum tl_type type = q->src_type;
  struct query_work_params *P = (struct query_work_params *) job->j_custom;
  memset (P, 0, sizeof (*P));
  P->pid = p;
  P->type = type;
  P->fd = fd;
  P->generation = generation;
  
  if (timeout > 0) {
    job_timer_insert (job, precise_now + timeout);  
  }
  
  rwm_clone (&P->src, raw);
  
  return JOB_SENDSIG (JS_RUN);
}
/* }}} */ 

int query_job_run (job_t job, int fd, int generation) /* {{{ */  {
  struct query_info *q = QUERY_INFO (job);
 
  struct tl_in_state *IO = tl_in_state_alloc ();
  tlf_init_raw_message (IO, &q->raw, q->raw.total_bytes, 0);

  int op = tlf_lookup_int (IO);
  struct tl_query_header *h = NULL;

  int res;
  if (op != RPC_INVOKE_REQ) {
    if (rpc_custom_op_tree) {
      struct raw_message r;
      rwm_clone (&r, (struct raw_message *)IO->in);

      res = create_query_custom_job (job, &r, 0, fd, generation);
      rwm_free (&r);
    } else {
      res = JOB_COMPLETED; 
    }
  } else {
    //vv_incr_stat_counter (STAT_QPS_CNT, 1); 
    h = malloc (sizeof (*h));
    tlf_query_header (IO, h);
  
    if (tlf_error (IO)) {
      struct tl_out_state *OUT = tl_aio_init_store (q->src_type, &q->src_pid, h ? h->qid : 0);
      if (OUT) {
        tls_set_error_format (OUT, IO->errnum, "%s", IO->error);
        tls_end_ext (OUT, RPC_REQ_RESULT);
        tl_out_state_free (OUT);
      }
      res = JOB_COMPLETED;
    } else {
      //tl_aio_init_store (q->src_type, &q->src_pid, h ? h->qid : 0);
      struct raw_message r;
      rwm_clone (&r, (struct raw_message *)IO->in);
      res = create_query_job (job, &r, h, tl_aio_timeout, &q->src_pid, q->src_type, fd, generation);
      rwm_free (&r);
    }
  }
  if (h) {
    tl_query_header_delete (h);
  }
  tl_in_state_free (IO);
  return res;
}
/* }}} */ 

static int do_query_job_run (job_t job, int op, struct job_thread *JT) /* {{{ */ {
  struct query_info *q = QUERY_INFO (job);
  int fd = 0;
  int generation = 0;
  if (q->conn) {
    rpc_target_insert_conn (q->conn);
    fd = CONN_INFO((job_t)q->conn)->fd;
    generation = CONN_INFO((job_t)q->conn)->generation;
    job_decref (JOB_REF_PASS (q->conn));
  }
  if (op == JS_RUN) {
    return query_job_run (job, fd, generation);
  }
  assert (!job_timer_active (job));
  switch (op) {
  case JS_ALARM:
    if (!job->j_error) {
      job->j_error = ETIMEDOUT;
    }
    return JOB_COMPLETED;
  case JS_ABORT:
    if (!job->j_error) {
      job->j_error = ECANCELED;
    }
    return JOB_COMPLETED;
  case JS_FINISH:
    if (q->raw.magic) {
      rwm_free (&q->raw);
    }
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }  
}
/* }}} */ 

int do_create_query_job (struct raw_message *raw, int type, struct process_id *pid, void *conn) /* {{{ */ {
  job_t job = create_async_job (do_query_job_run, JSP_PARENT_RWE | JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ABORT) | JSC_ALLOW (JC_ENGINE, JS_ALARM) | JSC_ALLOW (JC_ENGINE, JS_FINISH), -2, sizeof (struct query_work_params), JT_HAVE_TIMER, JOB_REF_NULL); 
  
  struct query_info *q = QUERY_INFO (job);

  q->raw = *raw;
  q->src_type = type;
  q->src_pid = *pid;
  q->conn = conn;

  schedule_job (JOB_REF_PASS (job));
  return 0;
}
/* }}} */



/* }}} */

int default_tl_close_conn (connection_job_t c, int who) {
  rpc_target_delete_conn (c);
  return 0;
}

int default_tl_tcp_rpcs_execute (connection_job_t c, int op, struct raw_message *raw) /* {{{ */ {
  CONN_INFO(c)->last_response_time = precise_now;    
  //rpc_target_insert_conn (c);

  if (op == RPC_PONG) {
    do_create_query_job (raw, tl_type_tcp_raw_msg, &TCP_RPC_DATA(c)->remote_pid, NULL);
  } else {
    do_create_query_job (raw, tl_type_tcp_raw_msg, &TCP_RPC_DATA(c)->remote_pid, job_incref (c));
  }
  return 1;
}
/* }}} */ 

int tl_store_stats (struct tl_out_state *tlio_out, const char *s, int raw) /* {{{ */  {
  int i, key_start = 0, value_start = -1;
  if (!raw) {
    tl_store_int (TL_STAT);
  }
  int *cnt_ptr = tl_store_get_ptr (4);
  *cnt_ptr = 0;
  for (i = 0; s[i]; i++) {
    if (s[i] == '\n') {
      if (value_start - key_start > 1 && value_start < i) {
        tl_store_string (s + key_start, value_start - key_start - 1); /* - 1 (trim tabular) */
        tl_store_string (s + value_start, i - value_start);
        ++*cnt_ptr;
      }
      key_start = i + 1;
      value_start = -1;
    } else if (s[i] == '\t') {
      value_start = value_start == -1 ? i + 1 : -2;
    }
  }
  return *cnt_ptr;
}
/* }}} */


static void default_stat_function (struct tl_out_state *tlio_out) {
  static char buf[(1 << 12)];
  prepare_stats (buf, (1 << 12) - 2);
  tl_store_stats (tlio_out, buf, 0);
}

void tl_engine_store_stats (struct tl_out_state *tlio_out) {
  if (tl_stat_function) {
    tl_stat_function (tlio_out);
  } else {
    default_stat_function (tlio_out);
  }
}

void engine_tl_init (struct tl_act_extra *(*parse)(struct tl_in_state *,long long), void (*stat)(), int (get_op)(struct tl_in_state *), double timeout, const char *name) {
  tl_parse_function = parse;
  tl_stat_function = stat;
  tl_aio_timeout = timeout;
  tl_get_op_function = get_op;
}

