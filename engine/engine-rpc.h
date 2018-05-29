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

#include "common/tl-parse.h"
#include "common/precise-time.h"

struct stats_buffer;
struct tl_act_extra;

struct query_work_params {
  struct event_timer ev;
  enum tl_type type;
  struct process_id pid;
  struct raw_message src;
  struct tl_query_header *h;
  struct raw_message *result;
  int error_code;
  int answer_sent;
  int wait_coord;
  char *error;
  void *wait_pos;
  //void *wait_time;
  struct paramed_type *P;
  long long start_rdtsc;
  long long total_work_rdtsc;
  job_t all_list;
  int fd;
  int generation;
};

//extern struct tl_act_extra *(*tl_parse_function)(struct tl_in_state *tlio_in, long long actor_id);
typedef void (*tl_query_result_fun_t)(struct tl_in_state *tlio_in, struct tl_query_header *h);
//extern void (*tl_stat_function)(struct tl_out_state *tlio_out);
//extern int (*tl_get_op_function)(struct tl_in_state *tlio_in);

void tl_query_result_fun_set (tl_query_result_fun_t func, int query_type_id);
long long tl_generate_next_qid (int query_type_id);

int default_tl_rpcs_execute (connection_job_t c, int op, int len);
int default_tl_tcp_rpcs_execute (connection_job_t c, int op, struct raw_message *raw);
int default_tl_close_conn (connection_job_t c, int who);
int tl_store_stats (struct tl_out_state *tlio_out, const char *s, int raw);
extern char *tl_engine_name;
void register_custom_op_cb (unsigned op, void (*func)(struct tl_in_state *tlio_in, struct query_work_params *params));
void engine_work_rpc_req_result (struct tl_in_state *tlio_in, struct query_work_params *params);
void tl_engine_store_stats (struct tl_out_state *tlio_out);

const char *op_to_string (int op);

void tl_restart_all_ready (void);
void tl_default_act_free (struct tl_act_extra *extra);


int engine_check_allow_query (unsigned flags);
int tl_query_act (connection_job_t c, int op, int len);
int tl_query_act_tcp (connection_job_t c, int op, struct raw_message *raw);

struct tl_act_extra {
  int size;
  int flags;  
  int attempt;
  int type;
  int op;
  int subclass;
  unsigned long long hash;
  long long start_rdtsc;
  long long cpu_rdtsc;
  struct tl_out_state *tlio_out;
  int (*act)(job_t, struct tl_act_extra *data);
  void (*free)(struct tl_act_extra *data);
  struct tl_act_extra *(*dup)(struct tl_act_extra *data);
  struct tl_query_header *header;
  struct raw_message **raw;  
  char **error;
  job_t extra_ref;
  int *error_code;
  int extra[0];
};

static inline struct tl_act_extra *tl_act_extra_init (void *buf, int size, int (*act)(job_t, struct tl_act_extra *)) {
  struct tl_act_extra *extra = (struct tl_act_extra *)buf;
  memset (extra, 0, sizeof (*extra));
  extra->size = size + (int)sizeof (*extra);
  extra->flags = 0;
  extra->act = act;
  extra->free = 0;
  extra->dup = 0;
  extra->start_rdtsc = rdtsc ();
  extra->cpu_rdtsc = 0;
  return extra;
}

#define QUERY_ALLOW_REPLICA_GET 1
#define QUERY_ALLOW_REPLICA_SET 2
#define QUERY_ALLOW_UNINIT 4

#define TL_PARSE_FUN_EX(tname,fname,dname,qtype,...) \
static struct tl_act_extra *fname (struct tl_in_state *tlio_in, ## __VA_ARGS__) { \
  struct tl_act_extra *extra = tl_act_extra_init (stats_buff, sizeof (tname), dname); \
  tname *e __attribute__ ((unused)); \
  e = (void *)extra->extra;  \
  extra->type = qtype; \
  extra->subclass = -1; \

#define TL_PARSE_FUN(name,...) TL_PARSE_FUN_EX(struct tl_ ## name,tl_ ## name,tl_do_ ## name,__VA_ARGS__)
#define TL_PARSE_FUN_GET(name,...) TL_PARSE_FUN_EX(struct tl_ ## name,tl_ ## name,tl_do_ ## name, QUERY_ALLOW_REPLICA_GET | QUERY_ALLOW_REPLICA_SET, ## __VA_ARGS__)
#define TL_PARSE_FUN_GET_ONLY(name,...) TL_PARSE_FUN_EX(struct tl_ ## name,tl_ ## name,tl_do_ ## name, QUERY_ALLOW_REPLICA_GET, ## __VA_ARGS__)
#define TL_PARSE_FUN_SET(name,...) TL_PARSE_FUN_EX(struct tl_ ## name,tl_ ## name,tl_do_ ## name, QUERY_ALLOW_REPLICA_SET, ## __VA_ARGS__)

#define TL_PARSE_FUN_END \
  tl_fetch_end (); \
  if (tl_fetch_error ()) { \
    return 0; \
  } \
  return extra; \
}

/* ${engine}-interface-structures.h must contain #pragma pack(push,4) for use TL_DEFAULT_PARSE_FUN macro */
#define TL_DEFAULT_PARSE_FUN(name,qtype) \
  TL_PARSE_FUN(name, qtype) \
  if (tlf_check (tlio_in, sizeof (*e)) < 0) { tl_fetch_set_error_format (TL_ERROR_NOT_ENOUGH_DATA, "Not enougth data"); return 0; } \
  tl_fetch_raw_data (e, sizeof (*e)); \
  TL_PARSE_FUN_END

#define TL_DEFAULT_PARSE_FUN_GET_ONLY(name) TL_DEFAULT_PARSE_FUN(name,QUERY_ALLOW_REPLICA_GET)
#define TL_DEFAULT_PARSE_FUN_GET(name) TL_DEFAULT_PARSE_FUN(name,QUERY_ALLOW_REPLICA_GET | QUERY_ALLOW_REPLICA_SET)
#define TL_DEFAULT_PARSE_FUN_SET(name) TL_DEFAULT_PARSE_FUN(name,QUERY_ALLOW_REPLICA_SET)

#define TL_DO_FUN_EX(tname,dname) \
  static int dname (job_t this_query_job, struct tl_act_extra *extra) { \
    tname *e = (void *)extra->extra; \
    struct tl_out_state *tlio_out __attribute__ ((unused)); \
    tlio_out = extra->tlio_out; \

#define TL_DO_FUN_DECL_EX(tname,dname) \
  static int dname (job_t this_query_job, struct tl_act_extra *extra);

#define TL_DO_FUN(name) TL_DO_FUN_EX(struct tl_ ## name __attribute__ ((unused)), tl_do_ ## name);
#define TL_DO_FUN_DECL(name) TL_DO_FUN_DECL_EX(struct tl_ ## name __attribute__ ((unused)), tl_do_ ## name);

#define TL_DO_PUBLIC_FUN_EX(tname,dname) \
  int dname (job_t this_query_job, struct tl_act_extra *extra) { \
    tname *e = (void *)extra->extra; \
    struct tl_out_state *tlio_out = extra->tlio_out; \

#define TL_DO_PUBLIC_FUN_DECL_EX(tname,dname) \
  int dname (job_t this_query_job, struct tl_act_extra *extra);

#define TL_DO_PUBLIC_FUN(name) TL_DO_PUBLIC_FUN_EX(struct tl_ ## name __attribute__ ((unused)), tl_do_ ## name);
#define TL_DO_PUBLIC_FUN_DECL(name) TL_DO_PUBLIC_FUN_DECL_EX(struct tl_ ## name __attribute__ ((unused)), tl_do_ ## name);

#define TL_DO_FUN_END \
  return 0; \
}
