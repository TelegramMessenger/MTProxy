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
    
    Copyright 2014-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman     
    
*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net/net-rpc-targets.h"
#include "vv/vv-tree.h"
//#include "net/net-rpc-common.h"
//#include "net/net-rpc-server.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-common.h"
#include "kprintf.h"
#include "net/net-connections.h"
#include "vv/vv-io.h"

#include "common/common-stats.h"
#include "common/mp-queue.h"
#include "common/server-functions.h"

#define rpc_target_cmp(a,b) (RPC_TARGET_INFO(a)->PID.port ? memcmp (&RPC_TARGET_INFO(a)->PID, &RPC_TARGET_INFO(b)->PID, 6) : memcmp (&RPC_TARGET_INFO(a)->PID, &RPC_TARGET_INFO(b)->PID, 8)) 

//DEFINE_TREE(rpc_target, rpc_target_job_t, rpc_target_cmp, MALLOC)

//DEFINE_TREE(rpc_target, struct rpc_target *, rpc_target_cmp)
#define X_TYPE rpc_target_job_t
#define X_CMP rpc_target_cmp
#define TREE_NAME rpc_target
#define TREE_PTHREAD
#define TREE_MALLOC
#include "vv/vv-tree.c"

#define X_TYPE connection_job_t
#define X_CMP(a,b) (((a) < (b)) ? -1 : ((a) > (b)) ? 1 : 0)
#define TREE_NAME connection
#define TREE_PTHREAD
#define TREE_MALLOC
#define TREE_INCREF job_incref
#define TREE_DECREF job_decref_f
#include "vv/vv-tree.c"

static struct tree_rpc_target *rpc_target_tree;
struct tree_rpc_target *get_rpc_target_tree_ptr (struct tree_rpc_target **T);
void free_rpc_target_tree_ptr (struct tree_rpc_target *T);


/* {{{ STAT */
#define MODULE rpc_targets

MODULE_STAT_TYPE {
  long long total_rpc_targets;
  long long total_connections_in_rpc_targets;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_LL (total_rpc_targets);
  SB_SUM_ONE_LL (total_connections_in_rpc_targets);
MODULE_STAT_FUNCTION_END
/* }}} */

static rpc_target_job_t rpc_target_alloc (struct process_id PID) {
  assert_engine_thread ();
  rpc_target_job_t SS = calloc (sizeof (struct async_job) + sizeof (struct rpc_target_info), 1);
  struct rpc_target_info *S = RPC_TARGET_INFO (SS);
  
  S->PID = PID;

  struct tree_rpc_target *old = rpc_target_tree;
  
  if (old) {
    __sync_fetch_and_add (&old->refcnt, 1);
  }

  rpc_target_tree = tree_insert_rpc_target (rpc_target_tree, SS, lrand48_j ());
  MODULE_STAT->total_rpc_targets ++;
  //hexdump ((void *)rpc_target_tree, (void *)(rpc_target_tree + 1));
  free_tree_ptr_rpc_target (old);

  return SS;
}

void rpc_target_insert_conn (connection_job_t C) {
  assert_engine_thread ();
  struct connection_info *c = CONN_INFO (C);
  
  if (c->flags & (C_ERROR | C_NET_FAILED | C_FAILED)) {
    return;
  }
  if (TCP_RPC_DATA(C)->in_rpc_target) { return; }

  assert_net_cpu_thread ();
  //st_update_host ();
  struct rpc_target_info t;
  t.PID = TCP_RPC_DATA(C)->remote_pid;
  assert (t.PID.ip);
  
  vkprintf (2, "rpc_target_insert_conn: ip = " IP_PRINT_STR ", port = %d, fd = %d\n", IP_TO_PRINT (t.PID.ip), (int) t.PID.port, c->fd);
  rpc_target_job_t fake_target = ((void *)&t) - offsetof (struct async_job, j_custom);

  
  rpc_target_job_t SS = tree_lookup_ptr_rpc_target (rpc_target_tree, fake_target);
  
  if (!SS) {
    SS = rpc_target_alloc (t.PID);
  }

  struct rpc_target_info *S = RPC_TARGET_INFO (SS);

  connection_job_t D = tree_lookup_ptr_connection (S->conn_tree, C);
  assert (!D);

  struct tree_connection *old = S->conn_tree;

  if (old) {
    __sync_fetch_and_add (&old->refcnt, 1);
  }

  S->conn_tree = tree_insert_connection (S->conn_tree, job_incref (C), lrand48_j ());
  MODULE_STAT->total_connections_in_rpc_targets ++;

  __sync_synchronize ();
  free_tree_ptr_connection (old);

  TCP_RPC_DATA(C)->in_rpc_target = 1;
}

void rpc_target_delete_conn (connection_job_t C) {
  assert_engine_thread ();
  struct connection_info *c = CONN_INFO (C);
  
  if (!TCP_RPC_DATA(C)->in_rpc_target) { return; }

  assert_net_cpu_thread ();
  //st_update_host ();
  struct rpc_target_info t;
  t.PID = TCP_RPC_DATA(C)->remote_pid;
  if (!t.PID.ip) {
    t.PID.ip = PID.ip;
  }
  
  vkprintf (2, "rpc_target_insert_conn: ip = " IP_PRINT_STR ", port = %d, fd = %d\n", IP_TO_PRINT (t.PID.ip), (int) t.PID.port, c->fd);
  rpc_target_job_t fake_target = ((void *)&t) - offsetof (struct async_job, j_custom);

  
  rpc_target_job_t SS = tree_lookup_ptr_rpc_target (rpc_target_tree, fake_target);
  
  if (!SS) {
    SS = rpc_target_alloc (t.PID);
  }

  struct rpc_target_info *S = RPC_TARGET_INFO (SS);

  connection_job_t D = tree_lookup_ptr_connection (S->conn_tree, C);
  assert (D);

  struct tree_connection *old = S->conn_tree;
  if (old) {
    __sync_fetch_and_add (&old->refcnt, 1);
  }
  S->conn_tree = tree_delete_connection (S->conn_tree, C);
  MODULE_STAT->total_connections_in_rpc_targets --;
  
  __sync_synchronize ();

  free_tree_ptr_connection (old);
  
  TCP_RPC_DATA(C)->in_rpc_target = 0;
}

rpc_target_job_t rpc_target_lookup (struct process_id *pid) {
  assert (pid);
  struct rpc_target_info t;
  t.PID = *pid;
  if (!t.PID.ip) { t.PID.ip = PID.ip; }
  rpc_target_job_t fake_target = ((void *)&t) - offsetof (struct async_job, j_custom);
  assert (RPC_TARGET_INFO(fake_target) == &t);
 
  int fast = this_job_thread && this_job_thread->thread_class == JC_ENGINE;

  struct tree_rpc_target *T = fast ? rpc_target_tree : get_tree_ptr_rpc_target (&rpc_target_tree);
  rpc_target_job_t S = tree_lookup_ptr_rpc_target (T, fake_target);
  if (!fast) {
    tree_free_rpc_target (T);
  }
  return S;
}

rpc_target_job_t rpc_target_lookup_hp (unsigned ip, int port) {
  struct process_id p;
  p.ip = ip;
  p.port = port;
  return rpc_target_lookup (&p);
}

rpc_target_job_t rpc_target_lookup_target (conn_target_job_t SS) {
  struct conn_target_info *S = CONN_TARGET_INFO (SS);
  if (S->custom_field == -1) {
    return 0;
  }
  return rpc_target_lookup_hp (S->custom_field, S->port);
}

void check_connection (connection_job_t C, void *ex, void *ex2, void *ex3) {
  int *best_unr = ex2;
  if (*best_unr < 0) { return; }
  connection_job_t *R = ex;
  struct process_id *PID = ex3;

  struct connection_info *c = CONN_INFO (C);
  int r = c->type->check_ready (C);

  if ((c->flags & (C_ERROR | C_FAILED | C_NET_FAILED)) || c->error) { 
    return;
  }
      
  if (r == cr_ok) {
    if (!PID || matches_pid (&TCP_RPC_DATA(C)->remote_pid, PID) >= 1) {
      *best_unr = -1;
      *R = C;
    }
  } else if (r == cr_stopped && c->unreliability < *best_unr) {
    if (!PID || matches_pid (&TCP_RPC_DATA(C)->remote_pid, PID) >= 1) {
      *best_unr = c->unreliability;
      *R = C;
    }
  }
}

struct connection_choose_extra {
  connection_job_t *Arr;
  int limit;
  int pos;
  int count;
};

void check_connection_arr (connection_job_t C, void *ex, void *ex2) {
  struct connection_choose_extra *E = ex;
  struct process_id *PID = ex2;

  struct connection_info *c = CONN_INFO (C);
  int r = c->type->check_ready (C);

  if ((c->flags & (C_ERROR | C_FAILED | C_NET_FAILED)) || c->error || r != cr_ok) { 
    return;
  }
  if (PID && matches_pid (&TCP_RPC_DATA(C)->remote_pid, PID) < 1) {
    return;
  }
      
  if (E->pos < E->limit) {
    E->Arr[E->pos ++] = C;
  } else {
    int t = lrand48_j () % (E->count + 1);
    if (t < E->limit) {
      E->Arr[t] = C;
    }
  }
  E->count ++;
}

connection_job_t rpc_target_choose_connection (rpc_target_job_t S, struct process_id *pid) {
  if (!S) {
    return 0;
  }

  int fast = this_job_thread && this_job_thread->thread_class == JC_ENGINE;

  struct tree_connection *T = fast ? RPC_TARGET_INFO (S)->conn_tree : get_tree_ptr_connection (&RPC_TARGET_INFO (S)->conn_tree);
  if (!T) {
    if (!fast) {
      tree_free_connection (T);
    }
    return NULL;
  }
  
  connection_job_t C = NULL;

  int best_unr = 10000;
  tree_act_ex3_connection (T, check_connection, &C, &best_unr, pid);

  if (C) {
    job_incref (C);
  }
  if (!fast) {
    tree_free_connection (T);
  }

  return C;
}

int rpc_target_choose_random_connections (rpc_target_job_t S, struct process_id *pid, int limit, connection_job_t buf[]) {
  if (!S) {
    return 0;
  }
  
  struct connection_choose_extra E;
  E.Arr = buf;
  E.count = 0;
  E.pos = 0;
  E.limit = limit;

  int fast = this_job_thread && this_job_thread->thread_class == JC_ENGINE;

  struct tree_connection *T = fast ? RPC_TARGET_INFO (S)->conn_tree : get_tree_ptr_connection (&RPC_TARGET_INFO (S)->conn_tree);
  if (!T) { 
    if (!fast) {
      tree_free_connection (T);
    }
    return 0;
  }
  
  tree_act_ex2_connection (T, check_connection_arr, &E, pid);

  int i;
  for (i = 0; i < E.pos; i++) {
    job_incref (buf[i]);
  }

  if (!fast) {
    tree_free_connection (T);
  }

  return E.pos;
}

int rpc_target_get_state (rpc_target_job_t S, struct process_id *pid) {
  connection_job_t C = rpc_target_choose_connection (S, pid);
  if (!C) {
    return -1;
  }

  int r = CONN_INFO(C)->type->check_ready (C);
  job_decref (JOB_REF_PASS (C));

  if (r == cr_ok) { return 1; }
  else { return 0; }
}

void rpc_target_delete (rpc_target_job_t RT) {}
