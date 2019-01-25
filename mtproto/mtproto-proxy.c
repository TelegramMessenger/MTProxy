/*
    This file is part of MTProto-proxy

    MTProto-proxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    MTProto-Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MTProto-Server.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2012-2018 Nikolai Durov
              2012-2014 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netdb.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "crc32.h"
#include "md5.h"
#include "resolver.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "net/net-tcp-connections.h"
#include "net/net-rpc-targets.h"
#include "net/net-http-server.h"
#include "net/net-tcp-rpc-server.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-crypto-aes.h"
#include "net/net-crypto-dh.h"
#include "mtproto-common.h"
#include "mtproto-config.h"
#include "common/tl-parse.h"
#include "engine/engine.h"
#include "engine/engine-net.h"

#ifndef COMMIT
#define COMMIT "unknown"
#endif

#define VERSION_STR	"mtproxy-0.01"
const char FullVersionStr[] = VERSION_STR " compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__ " "
#ifdef __LP64__
  "64-bit"
#else
  "32-bit"
#endif
" after commit " COMMIT;

#define EXT_CONN_TABLE_SIZE	(1 << 22)
#define EXT_CONN_HASH_SHIFT	20
#define EXT_CONN_HASH_SIZE	(1 << EXT_CONN_HASH_SHIFT)

#define	RPC_TIMEOUT_INTERVAL	5.0

#define	MAX_HTTP_LISTEN_PORTS	128

#define	HTTP_MAX_WAIT_TIMEOUT	960.0

#define PING_INTERVAL 5.0
#define STOP_INTERVAL (2 * ping_interval)
#define FAIL_INTERVAL (20 * ping_interval)
#define RESPONSE_FAIL_TIMEOUT 5
#define CONNECT_TIMEOUT 3

#define	MAX_POST_SIZE	(262144 * 4 - 4096)

#define	DEFAULT_WINDOW_CLAMP	131072

// #define DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE	1000000

#if 0
#define	MAX_CONNECTION_BUFFER_SPACE	(1 << 10) //(1 << 25)
#define MAX_MTFRONT_NB			1 //((NB_max * 3) >> 2)
#else
#define	MAX_CONNECTION_BUFFER_SPACE	(1 << 25)
#define MAX_MTFRONT_NB			((NB_max * 3) >> 2)
#endif

double ping_interval = PING_INTERVAL;
int window_clamp = DEFAULT_WINDOW_CLAMP;

#define	PROXY_MODE_OUT	2
int proxy_mode;

#define IS_PROXY_IN	0
#define IS_PROXY_OUT	1
#define IS_PROXY_INOUT	1

#define TL_HTTP_QUERY_INFO 0xd45ab381
#define TL_PROXY_TAG	0xdb1e26ae

conn_type_t ct_http_server_mtfront, ct_tcp_rpc_ext_server_mtfront, ct_tcp_rpc_server_mtfront;

long long connections_failed_lru, connections_failed_flood;
long long api_invoke_requests;

volatile int sigpoll_cnt;

#define STATS_BUFF_SIZE	(1 << 20)

int stats_buff_len;
char stats_buff[STATS_BUFF_SIZE];


// current HTTP query headers
char cur_http_origin[1024], cur_http_referer[1024], cur_http_user_agent[1024];
int cur_http_origin_len, cur_http_referer_len, cur_http_user_agent_len;

int check_conn_buffers (connection_job_t c);
void lru_insert_conn (connection_job_t c);

/*
 *
 *	CONFIGURATION PARSER SETUP
 *
 */

#define	DEFAULT_CFG_MIN_CONNECTIONS	4
#define	DEFAULT_CFG_MAX_CONNECTIONS	8

int default_cfg_min_connections = DEFAULT_CFG_MIN_CONNECTIONS;
int default_cfg_max_connections = DEFAULT_CFG_MAX_CONNECTIONS;

struct tcp_rpc_client_functions mtfront_rpc_client;

conn_type_t ct_tcp_rpc_client_mtfront;

struct conn_target_info default_cfg_ct = {
.min_connections = DEFAULT_CFG_MIN_CONNECTIONS,
.max_connections = DEFAULT_CFG_MAX_CONNECTIONS,
.type = &ct_tcp_rpc_client_mtfront,
.extra = (void *)&mtfront_rpc_client,
.reconnect_timeout = 17
};


/*
 *
 *		EXTERNAL CONNECTIONS TABLE
 *
 */

struct ext_connection {
  struct ext_connection *o_prev, *o_next; // list of all with same out_fd
  struct ext_connection *i_prev, *i_next; // list of all with same in_fd
  struct ext_connection *h_next; // next in hash on (in_fd, in_conn_id)
  int in_fd, in_gen;
  int out_fd, out_gen;
  long long in_conn_id;
  long long out_conn_id;
  long long auth_key_id;
  struct ext_connection *lru_prev, *lru_next;
};

struct ext_connection_ref {
  struct ext_connection *ref;
  long long out_conn_id;
};

long long ext_connections, ext_connections_created;

struct ext_connection_ref OutExtConnections[EXT_CONN_TABLE_SIZE];
struct ext_connection *InExtConnectionHash[EXT_CONN_HASH_SIZE];
struct ext_connection ExtConnectionHead[MAX_CONNECTIONS];

void lru_delete_ext_conn (struct ext_connection *Ext);

static inline void check_engine_class (void) {
  check_thread_class (JC_ENGINE);
}

static inline int ext_conn_hash (int in_fd, long long in_conn_id) {
  unsigned long long h = (unsigned long long) in_fd * 11400714819323198485ULL + (unsigned long long) in_conn_id * 13043817825332782213ULL;
  return (h >> (64 - EXT_CONN_HASH_SHIFT));
}

// makes sense only for !IS_PROXY_IN
// returns the only ext_connection with given in_fd
struct ext_connection *get_ext_connection_by_in_fd (int in_fd) {
  check_engine_class ();
  assert ((unsigned) in_fd < MAX_CONNECTIONS);
  struct ext_connection *H = &ExtConnectionHead[in_fd];
  struct ext_connection *Ex = H->i_next;
  assert (H->i_next == H->i_prev);
  if (!Ex || Ex == H) {
    return 0;
  }
  assert (Ex->in_fd == in_fd);
  return Ex;
}

// mode: 0 = find, 1 = delete, 2 = create if not found, 3 = find or create
struct ext_connection *get_ext_connection_by_in_conn_id (int in_fd, int in_gen, long long in_conn_id, int mode, int *created) {
  check_engine_class ();
  int h = ext_conn_hash (in_fd, in_conn_id);
  struct ext_connection **prev = &InExtConnectionHash[h], *cur = *prev;
  for (; cur; cur = *prev) {
    if (cur->in_fd == in_fd && cur->in_conn_id == in_conn_id) {
      assert (cur->out_conn_id);
      if (mode == 0 || mode == 3) {
	return cur;
      }
      if (mode != 1) {
	return 0;
      }
      if (cur->i_next) {
	cur->i_next->i_prev = cur->i_prev;
	cur->i_prev->i_next = cur->i_next;
	cur->i_next = cur->i_prev = 0;
      }
      if (cur->o_next) {
	cur->o_next->o_prev = cur->o_prev;
	cur->o_prev->o_next = cur->o_next;
	cur->o_next = cur->o_prev = 0;
      }
      lru_delete_ext_conn (cur);
      *prev = cur->h_next;
      cur->h_next = 0;
      int h = cur->out_conn_id & (EXT_CONN_TABLE_SIZE - 1);
      assert (OutExtConnections[h].ref == cur);
      assert (OutExtConnections[h].out_conn_id == cur->out_conn_id);
      OutExtConnections[h].ref = 0;
      cur->out_conn_id = 0;
      memset (cur, 0, sizeof (struct ext_connection));
      free (cur);
      ext_connections--;
      return (void *) -1L;
    }
    prev = &(cur->h_next);
  }
  if (mode != 2 && mode != 3) {
    return 0;
  }
  assert (ext_connections < EXT_CONN_TABLE_SIZE / 2);
  cur = calloc (sizeof (struct ext_connection), 1);
  assert (cur);
  cur->h_next = InExtConnectionHash[h];
  InExtConnectionHash[h] = cur;
  cur->in_fd = in_fd;
  cur->in_gen = in_gen;
  cur->in_conn_id = in_conn_id;
  assert ((unsigned) in_fd < MAX_CONNECTIONS);
  if (in_fd) {
    struct ext_connection *H = &ExtConnectionHead[in_fd];
    if (!H->i_next) {
      H->i_next = H->i_prev = H;
    }
    assert (H->i_next == H);
    cur->i_next = H;
    cur->i_prev = H->i_prev;
    H->i_prev->i_next = cur;
    H->i_prev = cur;
  }
  h = in_conn_id ? lrand48() : in_fd;
  while (OutExtConnections[h &= (EXT_CONN_TABLE_SIZE - 1)].ref) {
    h = lrand48();
  }
  OutExtConnections[h].ref = cur;
  cur->out_conn_id = OutExtConnections[h].out_conn_id = (OutExtConnections[h].out_conn_id | (EXT_CONN_TABLE_SIZE - 1)) + 1 + h;
  assert (cur->out_conn_id);
  if (created) {
    ++*created;
  }
  ext_connections++;
  ext_connections_created++;
  return cur;
}

struct ext_connection *find_ext_connection_by_out_conn_id (long long out_conn_id) {
 check_engine_class ();
  int h = out_conn_id & (EXT_CONN_TABLE_SIZE - 1);
  struct ext_connection *cur = OutExtConnections[h].ref;
  if (!cur || OutExtConnections[h].out_conn_id != out_conn_id) {
    return 0;
  }
  assert (cur->out_conn_id == out_conn_id);
  return cur;
}

// MUST be new
struct ext_connection *create_ext_connection (connection_job_t CI, long long in_conn_id, connection_job_t CO, long long auth_key_id) {
  check_engine_class ();
  struct ext_connection *Ex = get_ext_connection_by_in_conn_id (CONN_INFO(CI)->fd, CONN_INFO(CI)->generation, in_conn_id, 2, 0);
  assert (Ex && "ext_connection already exists");
  assert (!Ex->out_fd && !Ex->o_next && !Ex->auth_key_id);
  assert (!CO || (unsigned) CONN_INFO(CO)->fd < MAX_CONNECTIONS);
  assert (CO != CI);
  if (CO) {
    struct ext_connection *H = &ExtConnectionHead[CONN_INFO(CO)->fd];
    assert (H->o_next);
    Ex->o_next = H;
    Ex->o_prev = H->o_prev;
    H->o_prev->o_next = Ex;
    H->o_prev = Ex;
    Ex->out_fd = CONN_INFO(CO)->fd;
    Ex->out_gen = CONN_INFO(CO)->generation;
  }
  Ex->auth_key_id = auth_key_id;
  return Ex;
}

static int _notify_remote_closed (JOB_REF_ARG(C), long long out_conn_id);

void remove_ext_connection (struct ext_connection *Ex, int send_notifications) {
  assert (Ex);
  assert (Ex->out_conn_id);
  assert (Ex == find_ext_connection_by_out_conn_id (Ex->out_conn_id));
  if (Ex->out_fd) {
    assert ((unsigned) Ex->out_fd < MAX_CONNECTIONS);
    assert (Ex->o_next);
    if (send_notifications & 1) {
      connection_job_t CO = connection_get_by_fd_generation (Ex->out_fd, Ex->out_gen);
      if (CO) {
	_notify_remote_closed (JOB_REF_PASS (CO), Ex->out_conn_id);
      }
    }
  }
  if (Ex->in_fd) {
    assert ((unsigned) Ex->in_fd < MAX_CONNECTIONS);
    assert (Ex->i_next);
    if (send_notifications & 2) {
      connection_job_t CI = connection_get_by_fd_generation (Ex->in_fd, Ex->in_gen);
      if (Ex->in_conn_id) {
	assert (0);
      } else {
	if (CI) {
	  fail_connection (CI, -33);
	  job_decref (JOB_REF_PASS (CI));
	}
      }
    }
  }
  assert (get_ext_connection_by_in_conn_id (Ex->in_fd, Ex->in_gen, Ex->in_conn_id, 1, 0) == (void *) -1L);
}

/*
 *
 *	MULTIPROCESS STATISTICS
 *
 */

#define MAX_WORKERS	256

struct worker_stats {
  int cnt;
  int updated_at;

  struct buffers_stat bufs;
  struct connections_stat conn;
  int allocated_aes_crypto, allocated_aes_crypto_temp;
  long long tot_dh_rounds[3];

  int ev_heap_size;
  int http_connections;

  long long get_queries;
  int pending_http_queries;

  long long accept_calls_failed, accept_nonblock_set_failed, accept_connection_limit_failed,
            accept_rate_limit_failed, accept_init_accepted_failed;

  long long active_rpcs, active_rpcs_created;
  long long rpc_dropped_running, rpc_dropped_answers;
  long long tot_forwarded_queries, expired_forwarded_queries;
  long long tot_forwarded_responses;
  long long dropped_queries, dropped_responses;
  long long tot_forwarded_simple_acks, dropped_simple_acks;
  long long mtproto_proxy_errors;

  long long connections_failed_lru, connections_failed_flood;

  long long ext_connections, ext_connections_created;
  long long http_queries, http_bad_headers;
};

struct worker_stats *WStats, SumStats;
int worker_id, workers, slave_mode, parent_pid;
int pids[MAX_WORKERS];

long long get_queries;
long long http_queries;
int pending_http_queries;

long long active_rpcs, active_rpcs_created;
long long rpc_dropped_running, rpc_dropped_answers;
long long tot_forwarded_queries, expired_forwarded_queries, dropped_queries;
long long tot_forwarded_responses, dropped_responses;
long long tot_forwarded_simple_acks, dropped_simple_acks;
long long mtproto_proxy_errors;

char proxy_tag[16];
int proxy_tag_set;

static void update_local_stats_copy (struct worker_stats *S) {
  S->cnt++;
  __sync_synchronize();
  S->updated_at = now;
#define UPD(x)	S->x = x;
  fetch_tot_dh_rounds_stat (S->tot_dh_rounds);
  fetch_connections_stat (&S->conn);
  fetch_aes_crypto_stat (&S->allocated_aes_crypto, &S->allocated_aes_crypto_temp);
  fetch_buffers_stat (&S->bufs);

  UPD (ev_heap_size); 

  UPD (get_queries);
  UPD (http_connections);
  UPD (pending_http_queries); 
  UPD (active_rpcs);
  UPD (active_rpcs_created); 
  UPD (rpc_dropped_running);
  UPD (rpc_dropped_answers);
  UPD (tot_forwarded_queries); 
  UPD (expired_forwarded_queries); 
  UPD (dropped_queries); 
  UPD (tot_forwarded_responses); 
  UPD (dropped_responses); 
  UPD (tot_forwarded_simple_acks);
  UPD (dropped_simple_acks);
  UPD (mtproto_proxy_errors);
  UPD (connections_failed_lru);
  UPD (connections_failed_flood);
  UPD (ext_connections); 
  UPD (ext_connections_created); 
  UPD (http_queries); 
  UPD (http_bad_headers);
#undef UPD
  __sync_synchronize();
  S->cnt++;
  __sync_synchronize();
}

static inline void add_stats (struct worker_stats *W) {
#define UPD(x)	SumStats.x += W->x;
  UPD (tot_dh_rounds[0]);
  UPD (tot_dh_rounds[1]);
  UPD (tot_dh_rounds[2]);

  UPD (conn.active_connections); 
  UPD (conn.active_dh_connections); 
  UPD (conn.outbound_connections); 
  UPD (conn.active_outbound_connections); 
  UPD (conn.ready_outbound_connections); 
  UPD (conn.active_special_connections);
  UPD (conn.max_special_connections);
  UPD (conn.allocated_connections);
  UPD (conn.allocated_outbound_connections);
  UPD (conn.allocated_inbound_connections);
  UPD (conn.allocated_socket_connections);
  UPD (conn.allocated_targets); 
  UPD (conn.ready_targets); 
  UPD (conn.active_targets); 
  UPD (conn.inactive_targets); 
  UPD (conn.tcp_readv_calls);
  UPD (conn.tcp_readv_intr);
  UPD (conn.tcp_readv_bytes);
  UPD (conn.tcp_writev_calls);
  UPD (conn.tcp_writev_intr);
  UPD (conn.tcp_writev_bytes);
  UPD (conn.accept_calls_failed);
  UPD (conn.accept_nonblock_set_failed);
  UPD (conn.accept_rate_limit_failed);
  UPD (conn.accept_init_accepted_failed);

  UPD (allocated_aes_crypto); 
  UPD (allocated_aes_crypto_temp); 

  UPD (bufs.total_used_buffers_size); 
  UPD (bufs.allocated_buffer_bytes); 
  UPD (bufs.total_used_buffers); 
  UPD (bufs.allocated_buffer_chunks);
  UPD (bufs.max_allocated_buffer_chunks);
  UPD (bufs.max_allocated_buffer_bytes);
  UPD (bufs.max_buffer_chunks);
  UPD (bufs.buffer_chunk_alloc_ops);

  UPD (ev_heap_size); 

  UPD (get_queries);
  UPD (http_connections);
  UPD (pending_http_queries); 
  UPD (active_rpcs);
  UPD (active_rpcs_created); 
  UPD (rpc_dropped_running);
  UPD (rpc_dropped_answers);
  UPD (tot_forwarded_queries); 
  UPD (expired_forwarded_queries); 
  UPD (dropped_queries); 
  UPD (tot_forwarded_responses); 
  UPD (dropped_responses); 
  UPD (tot_forwarded_simple_acks);
  UPD (dropped_simple_acks);
  UPD (mtproto_proxy_errors);
  UPD (connections_failed_lru);
  UPD (connections_failed_flood);
  UPD (ext_connections); 
  UPD (ext_connections_created); 
  UPD (http_queries); 
  UPD (http_bad_headers);
#undef UPD
}

void update_local_stats (void) {
  if (!slave_mode) {
    return;
  }
  update_local_stats_copy (WStats + worker_id * 2);
  update_local_stats_copy (WStats + worker_id * 2 + 1);
}

void compute_stats_sum (void) {
  if (!workers) {
    return;
  }
  memset (&SumStats, 0, sizeof (SumStats));
  int i;
  for (i = 0; i < workers; i++) {
    static struct worker_stats W;
    struct worker_stats *F;
    int s_cnt;
    do {
      F = WStats + i * 2;
      do {
	barrier ();
        s_cnt = (++F)->cnt;
        if (!(s_cnt & 1)) {
          break;
        }
        s_cnt = (--F)->cnt;
      } while (s_cnt & 1);
      barrier ();
      memcpy (&W, F, sizeof (W));
      barrier ();
    } while (s_cnt != F->cnt);
    add_stats (&W);
  }
}

/*
 *
 *		SERVER
 *
 */


void mtfront_prepare_stats (stats_buffer_t *sb) {
  struct connections_stat conn;
  struct buffers_stat bufs;
  long long tot_dh_rounds[3];
  int allocated_aes_crypto, allocated_aes_crypto_temp;
  int uptime = now - start_time;
  compute_stats_sum ();
  fetch_connections_stat (&conn);
  fetch_buffers_stat (&bufs);
  fetch_tot_dh_rounds_stat (tot_dh_rounds);
  fetch_aes_crypto_stat (&allocated_aes_crypto, &allocated_aes_crypto_temp);

  sb_prepare (sb);
  sb_memory (sb, AM_GET_MEMORY_USAGE_SELF);

#define S(x)	((x)+(SumStats.x))
#define S1(x)	(SumStats.x)
#define SW(x)	(workers ? S1(x) : S(x))
  sb_printf (sb,
	     "config_filename\t%s\n"
	     "config_loaded_at\t%d\n"
	     "config_size\t%d\n"
	     "config_md5\t%s\n"
	     "config_auth_clusters\t%d\n"
	     "workers\t%d\n"
	     "queries_get\t%lld\n"
	     "qps_get\t%.3f\n"
	     "tot_forwarded_queries\t%lld\n"
	     "expired_forwarded_queries\t%lld\n"
	     "dropped_queries\t%lld\n"
	     "tot_forwarded_responses\t%lld\n"
	     "dropped_responses\t%lld\n"
	     "tot_forwarded_simple_acks\t%lld\n"
	     "dropped_simple_acks\t%lld\n"
	     "active_rpcs_created\t%lld\n"
	     "active_rpcs\t%lld\n"
	     "rpc_dropped_answers\t%lld\n"
	     "rpc_dropped_running\t%lld\n"
	     "window_clamp\t%d\n"
	     "total_ready_targets\t%d\n"
	     "total_allocated_targets\t%d\n"
	     "total_declared_targets\t%d\n"
	     "total_inactive_targets\t%d\n"
	     "total_connections\t%d\n"
	     "total_encrypted_connections\t%d\n"
	     "total_allocated_connections\t%d\n"
	     "total_allocated_outbound_connections\t%d\n"
	     "total_allocated_inbound_connections\t%d\n"
	     "total_allocated_socket_connections\t%d\n"
	     "total_dh_connections\t%d\n"
	     "total_dh_rounds\t%lld %lld %lld\n"
	     "total_special_connections\t%d\n"
	     "total_max_special_connections\t%d\n"
	     "total_accept_connections_failed\t%lld %lld %lld %lld %lld\n"
	     "ext_connections\t%lld\n"
	     "ext_connections_created\t%lld\n"
	     "total_active_network_events\t%d\n"
	     "total_network_buffers_used_size\t%lld\n"
	     "total_network_buffers_allocated_bytes\t%lld\n"
	     "total_network_buffers_used\t%d\n"
	     "total_network_buffer_chunks_allocated\t%d\n"
	     "total_network_buffer_chunks_allocated_max\t%d\n"
	     "mtproto_proxy_errors\t%lld\n"
	     "connections_failed_lru\t%lld\n"
	     "connections_failed_flood\t%lld\n"
	     "http_connections\t%d\n"
	     "pending_http_queries\t%d\n"
	     "http_queries\t%lld\n"
	     "http_bad_headers\t%lld\n"
	     "http_qps\t%.6f\n"
	     "proxy_mode\t%d\n"
	     "proxy_tag_set\t%d\n"
	     "version\t" VERSION_STR " compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__ " "
#ifdef __LP64__
	     "64-bit"
#else
	     "32-bit"
#endif
	     " after commit " COMMIT "\n",
	     config_filename,
	     CurConf->config_loaded_at,
	     CurConf->config_bytes,
	     CurConf->config_md5_hex,
	     CurConf->auth_stats.tot_clusters,
	     workers,
	     S(get_queries),
	     safe_div (S(get_queries), uptime),
	     S(tot_forwarded_queries),
	     S(expired_forwarded_queries),
	     S(dropped_queries),
	     S(tot_forwarded_responses),
	     S(dropped_responses),
	     S(tot_forwarded_simple_acks),
	     S(dropped_simple_acks),
	     S(active_rpcs_created),
	     S(active_rpcs),
	     S(rpc_dropped_answers),
	     S(rpc_dropped_running),
	     window_clamp,
	     SW(conn.ready_targets),
	     SW(conn.allocated_targets),
	     SW(conn.active_targets),
	     SW(conn.inactive_targets),
	     S(conn.active_connections),
	     S(allocated_aes_crypto),
	     S(conn.allocated_connections),
	     S(conn.allocated_outbound_connections),
	     S(conn.allocated_inbound_connections),
	     S(conn.allocated_socket_connections),
	     S(conn.active_dh_connections),
	     S(tot_dh_rounds[0]),
	     S(tot_dh_rounds[1]),
	     S(tot_dh_rounds[2]),
	     SW(conn.active_special_connections),
	     SW(conn.max_special_connections),
	     S(conn.accept_init_accepted_failed), 
	     S(conn.accept_calls_failed),
	     S(conn.accept_connection_limit_failed),
	     S(conn.accept_rate_limit_failed),
	     S(conn.accept_nonblock_set_failed),
	     S(ext_connections),
	     S(ext_connections_created),
	     S(ev_heap_size),
	     SW(bufs.total_used_buffers_size),
	     SW(bufs.allocated_buffer_bytes),
	     SW(bufs.total_used_buffers),
	     SW(bufs.allocated_buffer_chunks),
	     SW(bufs.max_allocated_buffer_chunks),
	     S(mtproto_proxy_errors),
	     S(connections_failed_lru),
	     S(connections_failed_flood),
	     S(http_connections),
	     S(pending_http_queries),
	     S(http_queries),
	     S(http_bad_headers),
	     safe_div (S(http_queries), uptime),
	     proxy_mode,
	     proxy_tag_set
  );
#undef S
#undef S1
#undef SW
}

/*
 *
 *      JOB UTILS
 *
 */

typedef int (*job_callback_func_t)(void *data, int len);
void schedule_job_callback (int context, job_callback_func_t func, void *data, int len);

struct job_callback_info {
  job_callback_func_t func;
  void *data[0];
};

int callback_job_run (job_t job, int op, struct job_thread *JT) {
  struct job_callback_info *D = (struct job_callback_info *)(job->j_custom);
  switch (op) {
  case JS_RUN:
    return D->func (D->data, job->j_custom_bytes - offsetof (struct job_callback_info, data));
    // return JOB_COMPLETED;
  case JS_FINISH:
    return job_free (JOB_REF_PASS (job));
  default:
    assert (0);
  }
}

void schedule_job_callback (int context, job_callback_func_t func, void *data, int len) {
  job_t job = create_async_job (callback_job_run, JSP_PARENT_RWE | JSC_ALLOW (context, JS_RUN) | JSIG_FAST (JS_FINISH), -2, offsetof (struct job_callback_info, data) + len, 0, JOB_REF_NULL);
  assert (job);
  struct job_callback_info *D = (struct job_callback_info *)(job->j_custom);
  D->func = func;
  memcpy (D->data, data, len);
  schedule_job (JOB_REF_PASS (job));
}


/*
 *
 *	RPC CLIENT
 *
 */

int client_send_message (JOB_REF_ARG (C), long long in_conn_id, struct tl_in_state *tlio_in, int flags);

int mtfront_client_ready (connection_job_t C);
int mtfront_client_close (connection_job_t C, int who);
int rpcc_execute (connection_job_t C, int op, struct raw_message *msg);
int tcp_rpcc_check_ready (connection_job_t C);

struct tcp_rpc_client_functions mtfront_rpc_client = {
  .execute = rpcc_execute,
  .check_ready = tcp_rpcc_default_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_check_perm = tcp_rpcc_default_check_perm,
  .rpc_init_crypto = tcp_rpcc_init_crypto,
  .rpc_start_crypto = tcp_rpcc_start_crypto,
  .rpc_ready = mtfront_client_ready,
  .rpc_close = mtfront_client_close
};

int rpcc_exists;

static int _notify_remote_closed (JOB_REF_ARG(C), long long out_conn_id) {
  TLS_START (JOB_REF_PASS(C)) {
    tl_store_int (RPC_CLOSE_CONN);
    tl_store_long (out_conn_id);
  } TLS_END;
  return 1;
}

void push_rpc_confirmation (JOB_REF_ARG (C), int confirm) {

  if ((lrand48_j() & 1) || !(TCP_RPC_DATA(C)->flags & RPC_F_PAD)) {
    struct raw_message *msg = malloc (sizeof (struct raw_message));
    rwm_create (msg, "\xdd", 1);
    rwm_push_data (msg, &confirm, 4);
    mpq_push_w (CONN_INFO(C)->out_queue, msg, 0);
    job_signal (JOB_REF_PASS (C), JS_RUN);
  } else {
    int x = -1;
    struct raw_message m;
    assert (rwm_create (&m, &x, 4) == 4);
    assert (rwm_push_data (&m, &confirm, 4) == 4);

    int z = lrand48_j() & 1;
    while (z-- > 0) {
      int t = lrand48_j();
      assert (rwm_push_data (&m, &t, 4) == 4);
    }

    tcp_rpc_conn_send (JOB_REF_CREATE_PASS (C), &m, 0);

    x = 0;
    assert (rwm_create (&m, &x, 4) == 4);

    z = lrand48_j() & 1;
    while (z-- > 0) {
      int t = lrand48_j();
      assert (rwm_push_data (&m, &t, 4) == 4);
    }

    tcp_rpc_conn_send (JOB_REF_PASS (C), &m, 0);
  }
}

struct client_packet_info {
  struct event_timer ev;
  struct raw_message msg;
  connection_job_t conn;
  int type;
};

int process_client_packet (struct tl_in_state *tlio_in, int op, connection_job_t C) {
  int len = tl_fetch_unread ();
  assert (op == tl_fetch_int ());

  switch (op) {
  case RPC_PONG:
    return 1;
  case RPC_PROXY_ANS:
    if (len >= 16) {
      int flags = tl_fetch_int ();
      long long out_conn_id = tl_fetch_long ();
      assert (tl_fetch_unread () == len - 16);
      vkprintf (2, "got RPC_PROXY_ANS from connection %d:%llx, data size = %d, flags = %d\n", CONN_INFO(C)->fd, out_conn_id, tl_fetch_unread (), flags);
      struct ext_connection *Ex = find_ext_connection_by_out_conn_id (out_conn_id);
      connection_job_t D = 0;
      if (Ex && Ex->out_fd == CONN_INFO(C)->fd && Ex->out_gen == CONN_INFO(C)->generation) {
	D = connection_get_by_fd_generation (Ex->in_fd, Ex->in_gen);
      }
      if (D) {
	vkprintf (2, "proxying answer into connection %d:%llx\n", Ex->in_fd, Ex->in_conn_id);
	tot_forwarded_responses++;
	client_send_message (JOB_REF_PASS(D), Ex->in_conn_id, tlio_in, flags);
      } else {
	vkprintf (2, "external connection not found, dropping proxied answer\n");
	dropped_responses++;
	_notify_remote_closed (JOB_REF_CREATE_PASS(C), out_conn_id);
      }
      return 1;
    }
    break;
  case RPC_SIMPLE_ACK:
    if (len == 16) {
      long long out_conn_id = tl_fetch_long ();
      int confirm = tl_fetch_int ();
      vkprintf (2, "got RPC_SIMPLE_ACK for connection = %llx, value %08x\n", out_conn_id, confirm);
      struct ext_connection *Ex = find_ext_connection_by_out_conn_id (out_conn_id);
      connection_job_t D = 0;
      if (Ex && Ex->out_fd == CONN_INFO(C)->fd && Ex->out_gen == CONN_INFO(C)->generation) {
	D = connection_get_by_fd_generation (Ex->in_fd, Ex->in_gen);
      }
      if (D) {
	vkprintf (2, "proxying simple ack %08x into connection %d:%llx\n", confirm, Ex->in_fd, Ex->in_conn_id);
	if (Ex->in_conn_id) {
	  assert (0);
	} else {
	  if (TCP_RPC_DATA(D)->flags & RPC_F_COMPACT) {
	    confirm = __builtin_bswap32 (confirm);
	  }
	  push_rpc_confirmation (JOB_REF_PASS (D), confirm);
	}
	tot_forwarded_simple_acks++;
      } else {
	vkprintf (2, "external connection not found, dropping simple ack\n");
	dropped_simple_acks++;
	_notify_remote_closed (JOB_REF_CREATE_PASS (C), out_conn_id);
      }
      return 1;
    }
    break;
  case RPC_CLOSE_EXT:
    if (len == 12) { 
      long long out_conn_id = tl_fetch_long ();
      vkprintf (2, "got RPC_CLOSE_EXT for connection = %llx\n", out_conn_id);
      struct ext_connection *Ex = find_ext_connection_by_out_conn_id (out_conn_id);
      if (Ex) {
	remove_ext_connection (Ex, 2);
      }
      return 1;
    }
    break;
  default:
    vkprintf (1, "unknown RPC operation %08x, ignoring\n", op);
  }

  return 0;
}

int client_packet_job_run (job_t job, int op, struct job_thread *JT) {
  struct client_packet_info *D = (struct client_packet_info *)(job->j_custom);
  
  switch (op) {
  case JS_RUN: {
    struct tl_in_state *tlio_in = tl_in_state_alloc ();
    tlf_init_raw_message (tlio_in, &D->msg, D->msg.total_bytes, 0);
    process_client_packet (tlio_in, D->type, D->conn);
    tl_in_state_free (tlio_in);
    return JOB_COMPLETED;
  }
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
    if (D->conn) {
      job_decref (JOB_REF_PASS (D->conn));
    }
    if (D->msg.magic) {
      rwm_free (&D->msg);
    }
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }
}

int rpcc_execute (connection_job_t C, int op, struct raw_message *msg) {
  vkprintf (2, "rpcc_execute: fd=%d, op=%08x, len=%d\n", CONN_INFO(C)->fd, op, msg->total_bytes);
  CONN_INFO(C)->last_response_time = precise_now;

  switch (op) {
  case RPC_PONG:
    break;
  case RPC_PROXY_ANS:
  case RPC_SIMPLE_ACK:
  case RPC_CLOSE_EXT: {
    job_t job = create_async_job (client_packet_job_run, JSP_PARENT_RWE | JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ABORT) | JSC_ALLOW (JC_ENGINE, JS_ALARM) | JSC_ALLOW (JC_ENGINE, JS_FINISH), -2, sizeof (struct client_packet_info), JT_HAVE_TIMER, JOB_REF_NULL);
    struct client_packet_info *D = (struct client_packet_info *)(job->j_custom);
    D->msg = *msg;
    D->type = op;
    D->conn = job_incref (C);
    schedule_job (JOB_REF_PASS (job));
    return 1;
  }
  default:
    vkprintf (1, "unknown RPC operation %08x, ignoring\n", op);
  }
  return 0;
}

static inline int get_conn_tag (connection_job_t C) {
  return 1 + (CONN_INFO(C)->generation & 0xffffff);
}

int mtfront_client_ready (connection_job_t C) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  assert (!D->extra_int);
  D->extra_int = get_conn_tag (C);
  vkprintf (1, "Connected to RPC Middle-End (fd=%d)\n", fd);
  rpcc_exists++;

  struct ext_connection *H = &ExtConnectionHead[fd];
  assert (!H->o_prev);
  H->o_prev = H->o_next = H;
  H->out_fd = fd;

  CONN_INFO(C)->last_response_time = precise_now;
  return 0;
}

int mtfront_client_close (connection_job_t C, int who) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  vkprintf (1, "Disconnected from RPC Middle-End (fd=%d)\n", fd);
  if (D->extra_int) {
    assert (D->extra_int == get_conn_tag (C));
    struct ext_connection *H = &ExtConnectionHead[fd], *Ex, *Ex_next;
    assert (H->o_next);
    for (Ex = H->o_next; Ex != H; Ex = Ex_next) {
      Ex_next = Ex->o_next;
      assert (Ex->out_fd == fd);
      remove_ext_connection (Ex, 2);
    }
    assert (H->o_next == H && H->o_prev == H);
    H->o_next = H->o_prev = 0;
    H->out_fd = 0;
  }
  D->extra_int = 0;
  return 0;
}

/*
 *
 *	HTTP INTERFACE
 *
 */

int hts_execute (connection_job_t C, struct raw_message *msg, int op);
int mtproto_http_alarm (connection_job_t C);
int mtproto_http_close (connection_job_t C, int who);

int hts_stats_execute (connection_job_t C, struct raw_message *msg, int op);

struct http_server_functions http_methods = {
  .execute = hts_execute,
  .ht_alarm = mtproto_http_alarm,
  .ht_close = mtproto_http_close
};

struct http_server_functions http_methods_stats = {
  .execute = hts_stats_execute
};

int ext_rpcs_execute (connection_job_t C, int op, struct raw_message *msg);

int mtproto_ext_rpc_ready (connection_job_t C);
int mtproto_ext_rpc_close (connection_job_t C, int who);

struct tcp_rpc_server_functions ext_rpc_methods = {
  .execute = ext_rpcs_execute,
  .check_ready = server_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_ready = mtproto_ext_rpc_ready,
  .rpc_close = mtproto_ext_rpc_close,
  //.http_fallback_type = &ct_http_server_mtfront,
  //.http_fallback_extra = &http_methods,
  .max_packet_len = MAX_POST_SIZE,
};

int mtproto_proxy_rpc_ready (connection_job_t C);
int mtproto_proxy_rpc_close (connection_job_t C, int who);

// ENGINE context
int do_close_in_ext_conn (void *_data, int s_len) {
  assert (s_len == 4);
  int fd = *(int *)_data;
  struct ext_connection *Ex = get_ext_connection_by_in_fd (fd);
  if (Ex) {
    remove_ext_connection (Ex, 1);
  }
  return JOB_COMPLETED;
}

// NET_CPU context
int mtproto_http_close (connection_job_t C, int who) {
  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "http connection closing (%d) by %d, %d queries pending\n", CONN_INFO(C)->fd, who, CONN_INFO(C)->pending_queries);
  if (CONN_INFO(C)->pending_queries) {
    assert (CONN_INFO(C)->pending_queries == 1);
    pending_http_queries--;
    CONN_INFO(C)->pending_queries = 0;
  }
  schedule_job_callback (JC_ENGINE, do_close_in_ext_conn, &CONN_INFO(C)->fd, 4);
  return 0;
}

int mtproto_ext_rpc_ready (connection_job_t C) {
  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "ext_rpc connection ready (%d)\n", CONN_INFO(C)->fd);
  lru_insert_conn (C);
  return 0;
}

int mtproto_ext_rpc_close (connection_job_t C, int who) {
  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "ext_rpc connection closing (%d) by %d\n", CONN_INFO(C)->fd, who);
  struct ext_connection *Ex = get_ext_connection_by_in_fd (CONN_INFO(C)->fd);
  if (Ex) {
    remove_ext_connection (Ex, 1);
  }
  return 0;
}

int mtproto_proxy_rpc_ready (connection_job_t C) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  vkprintf (3, "proxy_rpc connection ready (%d)\n", fd);
  struct ext_connection *H = &ExtConnectionHead[fd];
  assert (!H->i_prev);
  H->i_prev = H->i_next = H;
  H->in_fd = fd;
  assert (!D->extra_int);
  D->extra_int = -get_conn_tag(C);
  lru_insert_conn (C);
  return 0;
}

int mtproto_proxy_rpc_close (connection_job_t C, int who) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  vkprintf (3, "proxy_rpc connection closing (%d) by %d\n", fd, who);
  if (D->extra_int) {
    assert (D->extra_int == -get_conn_tag (C));
    struct ext_connection *H = &ExtConnectionHead[fd], *Ex, *Ex_next;
    assert (H->i_next);
    for (Ex = H->i_next; Ex != H; Ex = Ex_next) {
      Ex_next = Ex->i_next;
      assert (Ex->in_fd == fd);
      remove_ext_connection (Ex, 1);
    }
    assert (H->i_next == H && H->i_prev == H);
    H->i_next = H->i_prev = 0;
    H->in_fd = 0;
  }
  D->extra_int = 0;
  return 0;
}

char mtproto_cors_http_headers[] =
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Methods: POST, OPTIONS\r\n"
	"Access-Control-Allow-Headers: origin, content-type\r\n"
	"Access-Control-Max-Age: 1728000\r\n";

int forward_mtproto_packet (struct tl_in_state *tlio_in, connection_job_t C, int len, int remote_ip_port[5], int rpc_flags);
int forward_tcp_query (struct tl_in_state *tlio_in, connection_job_t C, conn_target_job_t S, int flags, long long auth_key_id, int remote_ip_port[5], int our_ip_port[5]);

unsigned parse_text_ipv4 (char *str) {
  int a, b, c, d;
  if (sscanf (str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return 0;
  }
  if ((a | b | c | d) & -0x100) {
    return 0;
  }
  return (a << 24) | (b << 16) | (c << 8) | d;
}

int parse_text_ipv6 (unsigned char ip[16], const char *str) {
  const char *ptr = str;
  int i, k = -1;
  if (*ptr == ':' && ptr[1] == ':') {
    k = 0;
    ptr += 2;
  }
  for (i = 0; i < 8; i++) {
    int c = *ptr;
    if (i > 0) {
      if (c == ':') {
	c = *++ptr;
      } else if (k >= 0) {
	break;
      } else {
	return -1; // ':' expected
      }
      if (c == ':') {
	if (k >= 0) {
	  return -1; // second '::'
	}
	k = i;
	c = *++ptr;
      }
    }
    int j = 0, v = 0;
    while ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
      c |= 0x20;
      v = (v << 4) + (c <= '9' ? c - '0' : c - 'a' + 10);
      if (++j > 4) {
	return -1; // more than 4 hex digits in component
      }
      c = *++ptr;
    }
    if (!j) {
      if (k == i) {
	break;
      }
      return -1; // hex digit or ':' expected
    }
    ip[2*i] = (v >> 8);
    ip[2*i+1] = (v & 0xff);
  }
  if (*ptr) {
    return -1;
  }
  /*
  if (*ptr && *ptr != '/' && *ptr != ' ' && *ptr != '\n' && *ptr != '\r' && *ptr != '\t') {
    return -1; // extra characters
  }
  */
  if (i < 8) {
    assert (k >= 0 && k <= i);
    int gap = 2 * (8 - i);
    memmove (ip + 2*k + gap, ip + 2*k, 2 * (i - k));
    memset (ip + 2*k, 0, gap);
  }
  return ptr - str;
}

struct http_query_info {
  struct event_timer ev;
  connection_job_t conn;
  struct raw_message msg;
  int conn_fd;
  int conn_generation;
  int flags;
  int query_type;
  int header_size;
  int data_size;
  int first_line_size;
  int host_offset;
  int host_size;
  int uri_offset;
  int uri_size;
  char header[0];
};

int process_http_query (struct tl_in_state *tlio_in, job_t HQJ) {
  struct http_query_info *D = (struct http_query_info *) HQJ->j_custom;
  connection_job_t c = D->conn;
  char *qHeaders = D->header + D->first_line_size;
  int qHeadersLen = D->header_size - D->first_line_size;

  assert (D->first_line_size > 0 && D->first_line_size <= D->header_size);

  if (verbosity > 1) {
    fprintf (stderr, "===============\n%.*s\n==============\n", D->header_size, D->header);
    fprintf (stderr, "%d,%d,%d,%d\n", D->host_offset, D->host_size, D->uri_offset, D->uri_size);

    fprintf (stderr, "hostname: '%.*s'\n", D->host_size, D->header + D->host_offset);
    fprintf (stderr, "URI: '%.*s'\n", D->uri_size, D->header + D->uri_offset);
  }

  if (verbosity >= 2) {
    char PostPreview[81];
    int preview_len = (D->data_size < sizeof (PostPreview) ? D->data_size : sizeof(PostPreview) - 1);
    tl_fetch_lookup_data (PostPreview, preview_len);
    PostPreview[preview_len] = 0;
    kprintf ("have %d POST bytes: `%.80s`\n", D->data_size, PostPreview);
  }

  char *qUri = D->header + D->uri_offset;
  int qUriLen = D->uri_size;

  char *get_qm_ptr = memchr (qUri, '?', D->uri_size);
  if (get_qm_ptr) {
    // qGet = get_qm_ptr + 1;
    // qGetLen = qUri + qUriLen - qGet;
    qUriLen = get_qm_ptr - qUri;
  } else {
    // qGet = 0;
    // qGetLen = 0;
  }

  if (qUriLen >= 20) {
    return -414;
  }

  if (qUriLen >= 4 && !memcmp (qUri, "/api", 4)) {
    if (qUriLen >= 5 && qUri[4] == 'w') {
      HTS_DATA(c)->query_flags |= QF_EXTRA_HEADERS;
      extra_http_response_headers = mtproto_cors_http_headers;
    } else {
      HTS_DATA(c)->query_flags &= ~QF_EXTRA_HEADERS;
    }
    if (D->query_type == htqt_options) {
      char response_buffer[512];
      int len = snprintf (response_buffer, 511, "HTTP/1.1 200 OK\r\nConnection: %s\r\nContent-type: text/plain\r\nPragma: no-cache\r\nCache-control: no-store\r\n%sContent-length: 0\r\n\r\n", (HTS_DATA(c)->query_flags & QF_KEEPALIVE) ? "keep-alive" : "close", HTS_DATA(c)->query_flags & QF_EXTRA_HEADERS ? mtproto_cors_http_headers : "");
      assert (len < 511);
      struct raw_message *m = calloc (sizeof (struct raw_message), 1);
      rwm_create (m, response_buffer, len);
      http_flush (c, m);
      return 0;
    }
    if (D->data_size & 3) {
      return -404;
    }
    cur_http_origin_len = get_http_header (qHeaders, qHeadersLen, cur_http_origin, sizeof (cur_http_origin) - 1, "Origin", 6);
    cur_http_referer_len = get_http_header (qHeaders, qHeadersLen, cur_http_referer, sizeof (cur_http_referer) - 1, "Referer", 7);
    cur_http_user_agent_len = get_http_header (qHeaders, qHeadersLen, cur_http_user_agent, sizeof (cur_http_user_agent) - 1, "User-Agent", 10);

    int tmp_ip_port[5], *remote_ip_port = 0;
    if ((CONN_INFO(c)->remote_ip & 0xff000000) == 0x0a000000 || (CONN_INFO(c)->remote_ip & 0xff000000) == 0x7f000000) {
      char x_real_ip[64], x_real_port[16];
      int x_real_ip_len = get_http_header (qHeaders, qHeadersLen, x_real_ip, sizeof (x_real_ip) - 1, "X-Real-IP", 9);
      int x_real_port_len = get_http_header (qHeaders, qHeadersLen, x_real_port, sizeof (x_real_port) - 1, "X-Real-Port", 11);
      if (x_real_ip_len > 0) {
	unsigned real_ip = parse_text_ipv4 (x_real_ip);
	if (real_ip >= (1 << 24) || parse_text_ipv6 ((unsigned char *)tmp_ip_port, x_real_ip) > 0) {
	  if (real_ip >= (1 << 24)) {
	    tmp_ip_port[0] = 0;
	    tmp_ip_port[1] = 0;
	    tmp_ip_port[2] = 0xffff0000;
	    tmp_ip_port[3] = htonl (real_ip);
	  }
	  int port = (x_real_port_len > 0 ? atoi (x_real_port) : 0);
	  tmp_ip_port[4] = (port > 0 && port < 65536 ? port : 0);
	  remote_ip_port = tmp_ip_port;
	  vkprintf (3, "set remote IPv6:port to %08x:%08x:%08x:%08x:%08x according to X-Real-Ip '%s', X-Real-Port '%s'\n", tmp_ip_port[0], tmp_ip_port[1], tmp_ip_port[2], tmp_ip_port[3], tmp_ip_port[4], x_real_ip, x_real_port_len > 0 ? x_real_port : "");
	}
      }
    }
    
    int res = forward_mtproto_packet (tlio_in, c, D->data_size, remote_ip_port, 0);
    return res ? 1 : -404;
  }

  return -404;
}

int http_query_job_run (job_t job, int op, struct job_thread *JT) {
  struct http_query_info *HQ = (struct http_query_info *)(job->j_custom);
  
  switch (op) {
  case JS_RUN: { // ENGINE context
    lru_insert_conn (HQ->conn);
    struct tl_in_state *tlio_in = tl_in_state_alloc ();
    tlf_init_raw_message (tlio_in, &HQ->msg, HQ->msg.total_bytes, 0);
    int res = process_http_query (tlio_in, job);
    tl_in_state_free (tlio_in);
    assert (!HQ->msg.magic);
    //rwm_free (&HQ->msg);
    if (res < 0) {
      write_http_error (HQ->conn, -res);
    } else if (res > 0) {
      assert (HQ->flags & 1);
      HQ->flags &= ~1;
    }
    return JOB_COMPLETED;
  }
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
  case JS_FINISH: // NET-CPU
    if (HQ->flags & 1) {
      connection_job_t c = HQ->conn ? job_incref (HQ->conn): connection_get_by_fd_generation (HQ->conn_fd, HQ->conn_generation);
      if (c) {
	assert (CONN_INFO(c)->pending_queries == 1);
	CONN_INFO(c)->pending_queries--;
	if (!(HTS_DATA(c)->query_flags & QF_KEEPALIVE) && CONN_INFO(c)->status == conn_working) {
	  connection_write_close (c);
	}
	job_decref (JOB_REF_PASS (c));
      }
      --pending_http_queries;
      HQ->flags &= ~1;
    }
    if (HQ->conn) {
      job_decref (JOB_REF_PASS (HQ->conn));
    }
    if (HQ->msg.magic) {
      rwm_free (&HQ->msg);
    }
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }
}

int hts_stats_execute (connection_job_t c, struct raw_message *msg, int op) {
  struct hts_data *D = HTS_DATA(c);

  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers (c) < 0) {
    return -429;
  }

  if (op != htqt_get || D->data_size != -1) {
    D->query_flags &= ~QF_KEEPALIVE;
    return -501;
  }
  if (CONN_INFO(c)->remote_ip != 0x7f000001) {
    return -404;
  }

  if (D->uri_size != 6) {
    return -404;
  }
  
  char ReqHdr[MAX_HTTP_HEADER_SIZE];
  assert (rwm_fetch_data (msg, &ReqHdr, D->header_size) == D->header_size);
  
  if (memcmp (ReqHdr + D->uri_offset, "/stats", 6)) {
    return -404;
  }

  stats_buffer_t sb;
  sb_alloc(&sb, 1 << 20);
  mtfront_prepare_stats(&sb);

  struct raw_message *raw = calloc (sizeof (*raw), 1);
  rwm_init (raw, 0);
  write_basic_http_header_raw (c, raw, 200, 0, sb.pos, 0, "text/plain");
  assert (rwm_push_data (raw, sb.buff, sb.pos) == sb.pos);
  mpq_push_w (CONN_INFO(c)->out_queue, raw, 0);
  job_signal (JOB_REF_CREATE_PASS (c), JS_RUN);

  sb_release (&sb);
  
  return 0;
}

// NET-CPU context
int hts_execute (connection_job_t c, struct raw_message *msg, int op) {
  struct hts_data *D = HTS_DATA(c);
  vkprintf (2, "in hts_execute: connection #%d, op=%d, header_size=%d, data_size=%d, http_version=%d\n",
	    CONN_INFO(c)->fd, op, D->header_size, D->data_size, D->http_ver);
  rwm_dump(msg);

  fail_connection(c, -1);
  return 0;
  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers (c) < 0) {
    return -429;
  }

  if (D->data_size >= MAX_POST_SIZE) {
    return -413;
  }

  if (!((D->query_type == htqt_post && D->data_size > 0) || (D->query_type == htqt_options && D->data_size < 0))) {
    D->query_flags &= ~QF_KEEPALIVE;
    return -501;
  }

  if (D->data_size < 0) {
    D->data_size = 0;
  }

  if (D->uri_size > 14 || D->header_size > MAX_HTTP_HEADER_SIZE) {
    return -414;
  }

  if (D->data_size > 0) {
    int need_bytes = D->data_size + D->header_size - msg->total_bytes;
    if (need_bytes > 0) {
      vkprintf (2, "-- need %d more bytes, waiting\n", need_bytes);
      return need_bytes;
    }
  }

  assert (msg->total_bytes == D->header_size + D->data_size);

  // create http query job here
  job_t job = create_async_job (http_query_job_run, JSP_PARENT_RWE | JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ABORT) | JSC_ALLOW (JC_ENGINE, JS_ALARM) | JSC_ALLOW (JC_CONNECTION, JS_FINISH), -2, sizeof (struct http_query_info) + D->header_size + 1, JT_HAVE_TIMER, JOB_REF_NULL);
  assert (job);
  struct http_query_info *HQ = (struct http_query_info *)(job->j_custom);

  rwm_clone (&HQ->msg, msg);
  HQ->conn = job_incref (c);
  HQ->conn_fd = CONN_INFO(c)->fd;
  HQ->conn_generation = CONN_INFO(c)->generation;
  HQ->flags = 1;  // pending_queries
  assert (!CONN_INFO(c)->pending_queries);
  CONN_INFO(c)->pending_queries++;
  ++pending_http_queries;
  HQ->query_type = D->query_type;
  HQ->header_size = D->header_size;
  HQ->data_size = D->data_size;
  HQ->first_line_size = D->first_line_size;
  HQ->host_offset = D->host_offset;
  HQ->host_size = D->host_size;
  HQ->uri_offset = D->uri_offset;
  HQ->uri_size = D->uri_size;
  assert (rwm_fetch_data (&HQ->msg, HQ->header, HQ->header_size) == HQ->header_size);
  HQ->header[HQ->header_size] = 0;
  assert (HQ->msg.total_bytes == HQ->data_size);

  schedule_job (JOB_REF_PASS (job));
  return 0;
}

struct rpcs_exec_data {
  struct raw_message msg;
  connection_job_t conn;
  int op;
  int rpc_flags;
};

int do_rpcs_execute (void *_data, int s_len) {
  struct rpcs_exec_data *data = _data;
  assert (s_len == sizeof (struct rpcs_exec_data));
  assert (data);

  lru_insert_conn (data->conn);

  int len = data->msg.total_bytes;
  struct tl_in_state *tlio_in = tl_in_state_alloc ();
  tlf_init_raw_message (tlio_in, &data->msg, len, 0);

  int res = forward_mtproto_packet (tlio_in, data->conn, len, 0, data->rpc_flags);
  tl_in_state_free (tlio_in);
  job_decref (JOB_REF_PASS (data->conn));

  if (!res) {
    vkprintf (1, "ext_rpcs_execute: cannot forward mtproto packet\n");
  }
  return JOB_COMPLETED;
}
  

int ext_rpcs_execute (connection_job_t c, int op, struct raw_message *msg) {
  int len = msg->total_bytes;

  vkprintf (2, "ext_rpcs_execute: fd=%d, op=%08x, len=%d\n", CONN_INFO(c)->fd, op, len);

  if (len > MAX_POST_SIZE) {
    vkprintf (1, "ext_rpcs_execute: packet too long (%d bytes), skipping\n", len);
    return SKIP_ALL_BYTES;
  }

  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers (c) < 0) {
    return SKIP_ALL_BYTES;
  }

  struct rpcs_exec_data data;
  rwm_move (&data.msg, msg);
  data.conn = job_incref (c);
  data.rpc_flags = TCP_RPC_DATA(c)->flags & (RPC_F_QUICKACK | RPC_F_DROPPED | RPC_F_COMPACT_MEDIUM | RPC_F_EXTMODE3);

  schedule_job_callback (JC_ENGINE, do_rpcs_execute, &data, sizeof (struct rpcs_exec_data));

  return 1;
}

// NET-CPU context
int mtproto_http_alarm (connection_job_t C) {
  vkprintf (2, "http_alarm() for connection %d\n", CONN_INFO(C)->fd);

  assert (CONN_INFO(C)->status == conn_working);
  HTS_DATA(C)->query_flags &= ~QF_KEEPALIVE;

  write_http_error (C, 500);

  if (CONN_INFO(C)->pending_queries) {
    assert (CONN_INFO(C)->pending_queries == 1);
    --pending_http_queries;
    CONN_INFO(C)->pending_queries = 0;
  }

  HTS_DATA(C)->parse_state = -1;
  connection_write_close (C);

  return 0;
}

// NET-CPU context
int finish_postponed_http_response (void *_data, int len) {
  assert (len == sizeof (connection_job_t));
  connection_job_t C = *(connection_job_t *)_data;
  if (!check_job_completion (C)) {
    assert (CONN_INFO(C)->pending_queries >= 0);
    assert (CONN_INFO(C)->pending_queries > 0);
    assert (CONN_INFO(C)->pending_queries == 1);
    CONN_INFO(C)->pending_queries = 0;
    --pending_http_queries; 
    // check_conn_buffers (C);
    http_flush (C, 0);
  } else {
    assert (!CONN_INFO(C)->pending_queries);
  }
  job_decref (JOB_REF_PASS (C));
  return JOB_COMPLETED;
}

// ENGINE context
// problem: mtproto_http_alarm() may be invoked in parallel in NET-CPU context
int http_send_message (JOB_REF_ARG (C), struct tl_in_state *tlio_in, int flags) {
  clear_connection_timeout (C);
  struct hts_data *D = HTS_DATA(C);

  if ((flags & 0x10) && TL_IN_REMAINING == 4) {
    int error_code = tl_fetch_int ();
    D->query_flags &= ~QF_KEEPALIVE;
    write_http_error (C, -error_code);
  } else {
    char response_buffer[512];
    TLS_START_UNALIGN (JOB_REF_CREATE_PASS (C)) {
      int len = TL_IN_REMAINING;
      tl_store_raw_data (response_buffer, snprintf (response_buffer, sizeof (response_buffer) - 1, "HTTP/1.1 200 OK\r\nConnection: %s\r\nContent-type: application/octet-stream\r\nPragma: no-cache\r\nCache-control: no-store\r\n%sContent-length: %d\r\n\r\n", (D->query_flags & QF_KEEPALIVE) ? "keep-alive" : "close", D->query_flags & QF_EXTRA_HEADERS ? mtproto_cors_http_headers : "", len));
      assert (tl_copy_through (tlio_in, tlio_out, len, 1) == len);
    } TLS_END;
  }

  assert (CONN_INFO(C)->status == conn_working && CONN_INFO(C)->pending_queries == 1);

  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "detaching http connection (%d)\n", CONN_INFO(C)->fd);

  struct ext_connection *Ex = get_ext_connection_by_in_fd (CONN_INFO(C)->fd);
  if (Ex) {
    remove_ext_connection (Ex, 1);
  }

  // reference to C is passed to the new job
  schedule_job_callback (JC_CONNECTION, finish_postponed_http_response, &C, sizeof (connection_job_t));

  return 1;
}

int client_send_message (JOB_REF_ARG(C), long long in_conn_id, struct tl_in_state *tlio_in, int flags) {
  if (check_conn_buffers (C) < 0) {
    job_decref (JOB_REF_PASS (C));
    return -1;
  }
  if (in_conn_id) {
    assert (0);
    return 1;
  }

  if (CONN_INFO(C)->type == &ct_http_server_mtfront) {
    return http_send_message (JOB_REF_PASS(C), tlio_in, flags);
  }
  TLS_START (JOB_REF_CREATE_PASS (C)) {
    assert (tl_copy_through (tlio_in, tlio_out, TL_IN_REMAINING, 1) >= 0);
  } TLS_END;

  if (check_conn_buffers (C) < 0) { 
    job_decref (JOB_REF_PASS (C));
    return -1; 
  } else {
    job_decref (JOB_REF_PASS (C));
    return 1; 
  }
}

/* ------------- process normal (encrypted) packet ----------------- */

// connection_job_t get_target_connection (conn_target_job_t S, int rotate);

conn_target_job_t choose_proxy_target (int target_dc) {
  assert (CurConf->auth_clusters > 0);
  struct mf_cluster *MFC = mf_cluster_lookup (CurConf, target_dc, 1);
  if (!MFC) {
    return 0;
  }
  int attempts = 5;
  while (attempts --> 0) {
    assert (MFC->targets_num > 0);
    conn_target_job_t S = MFC->cluster_targets[lrand48() % MFC->targets_num];
    connection_job_t C = 0;
    rpc_target_choose_random_connections (S, 0, 1, &C);
    if (C && TCP_RPC_DATA(C)->extra_int == get_conn_tag (C)) {
      job_decref (JOB_REF_PASS (C));
      return S;
    }
  }
  return 0;
}

static int forward_mtproto_enc_packet (struct tl_in_state *tlio_in, connection_job_t C, long long auth_key_id, int len, int remote_ip_port[5], int rpc_flags) {
  if (len < offsetof (struct encrypted_message, message) /*|| (len & 15) != (offsetof (struct encrypted_message, server_salt) & 15)*/) {
    return 0;
  }
  vkprintf (2, "received mtproto encrypted packet of %d bytes from connection %p (#%d~%d), key=%016llx\n", len, C, CONN_INFO(C)->fd, CONN_INFO(C)->generation, auth_key_id);

  CONN_INFO(C)->query_start_time = get_utime_monotonic ();

  conn_target_job_t S = choose_proxy_target (TCP_RPC_DATA(C)->extra_int4);

  assert (TL_IN_REMAINING == len);
  return forward_tcp_query (tlio_in, C, S, rpc_flags, auth_key_id, remote_ip_port, 0);
}

int forward_mtproto_packet (struct tl_in_state *tlio_in, connection_job_t C, int len, int remote_ip_port[5], int rpc_flags) {
  int header[7];
  if (len < sizeof (header) || (len & 3)) {
    return 0;
  }
  assert (tl_fetch_lookup_data (header, sizeof (header)) == sizeof (header));
  long long auth_key_id = *(long long *)header;
  if (auth_key_id) {
    return forward_mtproto_enc_packet (tlio_in, C, auth_key_id, len, remote_ip_port, rpc_flags);
  }
  vkprintf (2, "received mtproto packet of %d bytes\n", len);
  int inner_len = header[4];
  if (inner_len + 20 > len) {
    vkprintf (1, "received packet with bad inner length: %d (%d expected)\n", inner_len, len - 20);
    return 0;
  }
  if (inner_len < 20) {
    //must have at least function id and nonce
    return 0;
  }
  int function = header[5];
  if (function != CODE_req_pq && function != CODE_req_pq_multi && function != CODE_req_DH_params && function != CODE_set_client_DH_params) {
    return 0;
  }
  conn_target_job_t S = choose_proxy_target (TCP_RPC_DATA(C)->extra_int4);

  assert (len == TL_IN_REMAINING);
  return forward_tcp_query (tlio_in, C, S, 2 | rpc_flags, 0, remote_ip_port, 0);
}

/*
 *
 *	QUERY FORWARDING
 *
 */

/* ----------- query rpc forwarding ------------ */
 
int forward_tcp_query (struct tl_in_state *tlio_in, connection_job_t c, conn_target_job_t S, int flags, long long auth_key_id, int remote_ip_port[5], int our_ip_port[5]) {
  connection_job_t d = 0;
  int c_fd = CONN_INFO(c)->fd;
  struct ext_connection *Ex = get_ext_connection_by_in_fd (c_fd);

  if (CONN_INFO(c)->type == &ct_tcp_rpc_ext_server_mtfront) {
    flags |= TCP_RPC_DATA(c)->flags & RPC_F_DROPPED;
    flags |= 0x1000;
  } else if (CONN_INFO(c)->type == &ct_http_server_mtfront) {
    flags |= 0x3005;
  }

  if (Ex && Ex->auth_key_id != auth_key_id) {
    Ex->auth_key_id = auth_key_id;
  }

  if (Ex) {
    assert (Ex->out_fd > 0 && Ex->out_fd < MAX_CONNECTIONS);
    d = connection_get_by_fd_generation (Ex->out_fd, Ex->out_gen);
    if (!d || !CONN_INFO(d)->target) {
      if (d) {
	job_decref (JOB_REF_PASS (d));
      }
      remove_ext_connection (Ex, 1);
      Ex = 0;
    }
  }

  if (!d) {
    int attempts = 5;
    while (S && attempts --> 0) {
      rpc_target_choose_random_connections (S, 0, 1, &d);
      if (d) {
	if (TCP_RPC_DATA(d)->extra_int == get_conn_tag (d)) {
	  break;
	} else {
	  job_decref (JOB_REF_PASS (d));
	}
      }
    }
    if (!d) {
      vkprintf (2, "nowhere to forward user query from connection %d, dropping\n", CONN_INFO(c)->fd);
      dropped_queries++;
      if (CONN_INFO(c)->type == &ct_tcp_rpc_ext_server_mtfront) {
	__sync_fetch_and_or (&TCP_RPC_DATA(c)->flags, RPC_F_DROPPED);
      }
      return 0;
    }
    if (flags & RPC_F_DROPPED) {
      // there was at least one dropped inbound packet on this connection, have to close it now instead of forwarding next queries
      fail_connection (c, -35);
      return 0;
    }
    Ex = create_ext_connection (c, 0, d, auth_key_id);
  }

  tot_forwarded_queries++;

  assert (Ex);

  vkprintf (3, "forwarding user query from connection %d~%d (ext_conn_id %llx) into connection %d~%d (ext_conn_id %llx)\n", Ex->in_fd, Ex->in_gen, Ex->in_conn_id, Ex->out_fd, Ex->out_gen, Ex->out_conn_id);

  if (proxy_tag_set) {
    flags |= 8;
  }

  TLS_START (JOB_REF_PASS (d)); // open tlio_out context

  tl_store_int (RPC_PROXY_REQ);
  tl_store_int (flags);
  tl_store_long (Ex->out_conn_id);

  if (remote_ip_port) {
    tl_store_raw_data (remote_ip_port, 20);
  } else {
    if (CONN_INFO(c)->remote_ip) {
      tl_store_long (0);
      tl_store_int (-0x10000);
      tl_store_int (htonl (CONN_INFO(c)->remote_ip));
    } else {
      tl_store_raw_data (CONN_INFO(c)->remote_ipv6, 16);
    }
    tl_store_int (CONN_INFO(c)->remote_port);
  }

  if (our_ip_port) {
    tl_store_raw_data (our_ip_port, 20);
  } else {
    if (CONN_INFO(c)->our_ip) {
      tl_store_long (0);
      tl_store_int (-0x10000);
      tl_store_int (htonl (nat_translate_ip (CONN_INFO(c)->our_ip)));
    } else {
      tl_store_raw_data (CONN_INFO(c)->our_ipv6, 16);
    }
    tl_store_int (CONN_INFO(c)->our_port);
  }

  if (flags & 12) {
    int *extra_size_ptr = tl_store_get_ptr (4);
    int pos = TL_OUT_POS;
    if (flags & 8) {
      tl_store_int (TL_PROXY_TAG);
      tl_store_string (proxy_tag, sizeof (proxy_tag));
    }
    if (flags & 4) {
      tl_store_int (TL_HTTP_QUERY_INFO);
      tl_store_string (cur_http_origin, cur_http_origin_len >= 0 ? cur_http_origin_len : 0);
      tl_store_string (cur_http_referer, cur_http_referer_len >= 0 ? cur_http_referer_len : 0);
      tl_store_string (cur_http_user_agent, cur_http_user_agent_len >= 0 ? cur_http_user_agent_len : 0);
    }
    *extra_size_ptr = TL_OUT_POS - pos;
  }

  int len = TL_IN_REMAINING;
  assert (tl_copy_through (tlio_in, tlio_out, len, 1) == len);

  TLS_END;   // close tlio_out context

  if (CONN_INFO(c)->type == &ct_http_server_mtfront) {
    assert (CONN_INFO(c)->pending_queries >= 0);
    assert (CONN_INFO(c)->pending_queries > 0);
    assert (CONN_INFO(c)->pending_queries == 1);
    set_connection_timeout (c, HTTP_MAX_WAIT_TIMEOUT);
  }

  return 1;
}

/* -------------------------- EXTERFACE ---------------------------- */

struct tl_act_extra *mtfront_parse_function (struct tl_in_state *tlio_in, long long actor_id) {
  ++api_invoke_requests;
  if (actor_id != 0) {
    tl_fetch_set_error (TL_ERROR_WRONG_ACTOR_ID, "MTProxy only supports actor_id = 0");
    return 0;
  }
  int op = tl_fetch_int ();
  if (tl_fetch_error ()) {
    return 0;
  }
  switch (op) {
  default:
    tl_fetch_set_error_format (TL_ERROR_UNKNOWN_FUNCTION_ID, "Unknown op %08x", op);
    return 0;
  }
}


/* ------------------------ FLOOD CONTROL -------------------------- */

struct ext_connection ConnLRU = { .lru_prev = &ConnLRU, .lru_next = &ConnLRU };

void lru_delete_ext_conn (struct ext_connection *Ext) {
  if (Ext->lru_next) {
    Ext->lru_next->lru_prev = Ext->lru_prev;
    Ext->lru_prev->lru_next = Ext->lru_next;
  }
  Ext->lru_next = Ext->lru_prev = 0;
}

void lru_insert_ext_conn (struct ext_connection *Ext) {
  lru_delete_ext_conn (Ext);
  Ext->lru_prev = ConnLRU.lru_prev;
  Ext->lru_next = &ConnLRU;
  Ext->lru_next->lru_prev = Ext;
  Ext->lru_prev->lru_next = Ext;
}

void lru_delete_conn (connection_job_t c) {
  struct ext_connection *Ext = get_ext_connection_by_in_fd (CONN_INFO(c)->fd);
  if (Ext && Ext->in_fd == CONN_INFO(c)->fd) {
    lru_delete_ext_conn (Ext);
  }
}

void lru_insert_conn (connection_job_t c) {
  struct ext_connection *Ext = get_ext_connection_by_in_fd (CONN_INFO(c)->fd);
  if (Ext && Ext->in_fd == CONN_INFO(c)->fd && Ext->in_gen == CONN_INFO(c)->generation) {
    lru_insert_ext_conn (Ext);
  }
}

void check_all_conn_buffers (void) {
  struct buffers_stat bufs;
  fetch_buffers_stat (&bufs);
  long long max_buffer_memory = bufs.max_buffer_chunks * (long long) MSG_BUFFERS_CHUNK_SIZE;
  long long to_free = bufs.total_used_buffers_size - max_buffer_memory * 3/4;
  while (to_free > 0 && ConnLRU.lru_next != &ConnLRU) {
    struct ext_connection *Ext = ConnLRU.lru_next;
    vkprintf (2, "check_all_conn_buffers(): closing connection %d because of %lld total used buffer vytes (%lld max, %lld bytes to free)\n", Ext->in_fd, bufs.total_used_buffers_size, max_buffer_memory, to_free);
    connection_job_t d = connection_get_by_fd_generation (Ext->in_fd, Ext->in_gen);
    if (d) {
      int tot_used_bytes = CONN_INFO(d)->in.total_bytes + CONN_INFO(d)->in_u.total_bytes + CONN_INFO(d)->out.total_bytes + CONN_INFO(d)->out_p.total_bytes;
      to_free -= tot_used_bytes * 2;
      fail_connection (d, -500);
      job_decref (JOB_REF_PASS (d));
    }
    lru_delete_ext_conn (Ext);
    ++connections_failed_lru;
  }
}

int check_conn_buffers (connection_job_t c) {
  int tot_used_bytes = CONN_INFO(c)->in.total_bytes + CONN_INFO(c)->in_u.total_bytes + CONN_INFO(c)->out.total_bytes + CONN_INFO(c)->out_p.total_bytes;
  if (tot_used_bytes > MAX_CONNECTION_BUFFER_SPACE) {
    vkprintf (2, "check_conn_buffers(): closing connection %d because of %d buffer bytes used (%d max)\n", CONN_INFO(c)->fd, tot_used_bytes, MAX_CONNECTION_BUFFER_SPACE);
    fail_connection (c, -429);
    ++connections_failed_flood;
    return -1;
  }
  return 0;
}

// invoked in NET-CPU context!
int mtfront_data_received (connection_job_t c, int bytes_received) {
  // check_conn_buffers (c);
  return 0;
}

// invoked in NET-CPU context!
int mtfront_data_sent (connection_job_t c, int bytes_sent) {
  // lru_insert_conn (c);
  return 0;
}

void init_ct_server_mtfront (void) {
  assert (check_conn_functions (&ct_http_server, 1) >= 0);
  memcpy (&ct_http_server_mtfront, &ct_http_server, sizeof (conn_type_t));
  memcpy (&ct_tcp_rpc_ext_server_mtfront, &ct_tcp_rpc_ext_server, sizeof (conn_type_t));
  memcpy (&ct_tcp_rpc_server_mtfront, &ct_tcp_rpc_server, sizeof (conn_type_t));
  memcpy (&ct_tcp_rpc_client_mtfront, &ct_tcp_rpc_client, sizeof (conn_type_t));
  ct_http_server_mtfront.data_received = &mtfront_data_received;
  ct_tcp_rpc_ext_server_mtfront.data_received = &mtfront_data_received;
  ct_tcp_rpc_server_mtfront.data_received = &mtfront_data_received;
  ct_http_server_mtfront.data_sent = &mtfront_data_sent;
  ct_tcp_rpc_ext_server_mtfront.data_sent = &mtfront_data_sent;
  ct_tcp_rpc_server_mtfront.data_sent = &mtfront_data_sent;
}

/*
 *
 *	PARSE ARGS & INITIALIZATION
 *
 */

static void check_children_dead (void) {
  int i, j;
  for (j = 0; j < 11; j++) {
    for (i = 0; i < workers; i++) {
      if (pids[i]) {
        int status = 0;
        int res = waitpid (pids[i], &status, WNOHANG);
        if (res == pids[i]) {
          if (WIFEXITED (status) || WIFSIGNALED (status)) {
            pids[i] = 0;
          } else {
            break;
          }
        } else if (res == 0) {
          break;
        } else if (res != -1 || errno != EINTR) {
          pids[i] = 0;
        } else {
          break;
        }
      }
    }
    if (i == workers) {
      break;
    }
    if (j < 10) {
      usleep (100000);
    }
  }
  if (j == 11) {
    int cnt = 0;
    for (i = 0; i < workers; i++) {
      if (pids[i]) {
        ++cnt;
        kill (pids[i], SIGKILL);
      }
    }
    kprintf ("WARNING: %d children unfinished --> they are now killed\n", cnt);
  }
}

static void kill_children (int signal) {
  int i;
  assert (workers);
  for (i = 0; i < workers; i++) {
    if (pids[i]) {
      kill (pids[i], signal);
    }
  }
}

// SIGCHLD
void on_child_termination (void) {
}

void check_children_status (void) {
  if (workers) {
    int i;
    for (i = 0; i < workers; i++) {
      int status = 0;
      int res = waitpid (pids[i], &status, WNOHANG);
      if (res == pids[i]) {
        if (WIFEXITED (status) || WIFSIGNALED (status)) {
          kprintf ("Child %d terminated, aborting\n", pids[i]);
          pids[i] = 0;
          kill_children (SIGTERM);
          check_children_dead ();
          exit (EXIT_FAILURE);
        }
      } else if (res == 0) {
      } else if (res != -1 || errno != EINTR) {
        kprintf ("Child %d: unknown result during wait (%d, %m), aborting\n", pids[i], res);
        pids[i] = 0;
        kill_children (SIGTERM);
        check_children_dead ();
        exit (EXIT_FAILURE);
      }
    }
  } else if (slave_mode) {
    if (getppid () != parent_pid) {
      kprintf ("Parent %d is changed to %d, aborting\n", parent_pid, getppid ());
      exit (EXIT_FAILURE);
    }
  }
}

void check_special_connections_overflow (void) {
  if (max_special_connections && !slave_mode) {
    int max_user_conn = workers ? SumStats.conn.max_special_connections : max_special_connections;
    int cur_user_conn = workers ? SumStats.conn.active_special_connections : active_special_connections;
    if (cur_user_conn * 10 > max_user_conn * 9) {
      vkprintf (0, "CRITICAL: used %d user connections out of %d\n", cur_user_conn, max_user_conn);
    }
  }
}

void cron (void) {
  check_children_status ();
  compute_stats_sum ();
  check_special_connections_overflow ();
  check_all_conn_buffers ();
}

int sfd;
int http_ports_num;
int http_sfd[MAX_HTTP_LISTEN_PORTS], http_port[MAX_HTTP_LISTEN_PORTS];

// static double next_create_outbound;
// int outbound_connections_per_second = DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE;

void mtfront_pre_loop (void) {
  int i, enable_ipv6 = engine_check_ipv6_enabled () ? SM_IPV6 : 0;
  tcp_maximize_buffers = 1;
  if (!workers) {
    for (i = 0; i < http_ports_num; i++) {
      init_listening_tcpv6_connection (http_sfd[i], &ct_tcp_rpc_ext_server_mtfront, &ext_rpc_methods, enable_ipv6 | SM_LOWPRIO | SM_NOQACK | (max_special_connections ? SM_SPECIAL : 0));
      //     assert (setsockopt (http_sfd[i], IPPROTO_TCP, TCP_MAXSEG, (int[]){1410}, sizeof (int)) >= 0);
      //     assert (setsockopt (http_sfd[i], IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof (int)) >= 0);
      listening_connection_job_t LC = Events[http_sfd[i]].data;
      assert (LC);
      CONN_INFO(LC)->window_clamp = window_clamp;
      if (setsockopt (http_sfd[i], IPPROTO_TCP, TCP_WINDOW_CLAMP, &window_clamp, 4) < 0) {
	vkprintf (0, "error while setting window size for socket %d to %d: %m\n", http_sfd[i], window_clamp);
      }
    }
    // create_all_outbound_connections ();
  }
}

void precise_cron (void) {
  update_local_stats ();
}

void mtfront_sigusr1_handler (void) {
  reopen_logs_ext (slave_mode);
  if (workers) {
    kill_children (SIGUSR1);
  }
}

/*
 *
 *		MAIN
 *
 */

void usage (void) {
  printf ("usage: %s [-v] [-6] [-p<port>] [-H<http-port>{,<http-port>}] [-M<workers>] [-u<username>] [-b<backlog>] [-c<max-conn>] [-l<log-name>] [-W<window-size>] <config-file>\n", progname);
  printf ("%s\n", FullVersionStr);
  printf ("\tSimple MT-Proto proxy\n");
  parse_usage ();
  exit (2);
}

server_functions_t mtproto_front_functions;
int f_parse_option (int val) {
  char *colon, *ptr;
  switch (val) {
  case 'C':
    max_special_connections = atoi (optarg);
    if (max_special_connections < 0) {
      max_special_connections = 0;
    }
    break;
  case 'W':
    window_clamp = atoi (optarg);
    break;
  case 'H':
    ptr = optarg;
    if (!*ptr) {
      usage ();
      return 2;
    }
    while (*ptr >= '1' && *ptr <= '9' && http_ports_num < MAX_HTTP_LISTEN_PORTS) {
      int i = http_port[http_ports_num++] = strtol (ptr, &colon, 10);
      assert (colon > ptr && i > 0 && i < 65536);
      ptr = colon;
      if (*ptr != ',') {
	break;
      } else {
	ptr++;
      }
    }
    if (*ptr) {
      usage ();
      return 2;
    }
    break;
    /*
  case 'o':
    outbound_connections_per_second = atoi (optarg);
    if (outbound_connections_per_second <= 0) {
      outbound_connections_per_second = 1;
    }
    break;
    */
  case 'M':
    workers = atoi (optarg);
    assert (workers >= 0 && workers <= MAX_WORKERS);
    break;
  case 'T':
    ping_interval = atof (optarg);
    if (ping_interval <= 0) {
      ping_interval = PING_INTERVAL;
    }
    break;
  case 2000:
    engine_set_http_fallback (&ct_http_server, &http_methods_stats);
    mtproto_front_functions.flags &= ~ENGINE_NO_PORT;
    break;
  case 'S':
  case 'P':
    {
      if (strlen (optarg) != 32) {
        kprintf ("'%c' option requires exactly 32 hex digits\n", val);
        usage ();
      }

      unsigned char secret[16];
      int i;
      unsigned char b = 0;
      for (i = 0; i < 32; i++) {
        if (optarg[i] >= '0' && optarg[i] <= '9')  {
          b = b * 16 + optarg[i] - '0';
        } else if (optarg[i] >= 'a' && optarg[i] <= 'f') {
          b = b * 16 + optarg[i] - 'a' + 10;
        } else if (optarg[i] >= 'A' && optarg[i] <= 'F') {
          b = b * 16 + optarg[i] - 'A' + 10;
        } else {
          kprintf ("'S' option requires exactly 32 hex digits. '%c' is not hexdigit\n", optarg[i]);
          usage ();
        }
        if (i & 1) {
          secret[i / 2] = b;
          b = 0;
        }
      }
      if (val == 'S') {
	tcp_rpcs_set_ext_secret (secret);
      } else {
	memcpy (proxy_tag, secret, sizeof (proxy_tag));
	proxy_tag_set = 1;
      }
    }
    break;
  case 'R':
    tcp_rpcs_set_ext_rand_pad_only(1);
    break;
  default:
    return -1;
  }
  return 0;
}

void mtfront_prepare_parse_options (void) {
  parse_option ("http-stats", no_argument, 0, 2000, "allow http server to answer on stats queries");
  parse_option ("mtproto-secret", required_argument, 0, 'S', "16-byte secret in hex mode");
  parse_option ("proxy-tag", required_argument, 0, 'P', "16-byte proxy tag in hex mode to be passed along with all forwarded queries");
  parse_option ("max-special-connections", required_argument, 0, 'C', "sets maximal number of accepted client connections per worker");
  parse_option ("window-clamp", required_argument, 0, 'W', "sets window clamp for client TCP connections");
  parse_option ("http-ports", required_argument, 0, 'H', "comma-separated list of client (HTTP) ports to listen");
  // parse_option ("outbound-connections-ps", required_argument, 0, 'o', "limits creation rate of outbound connections to mtproto-servers (default %d)", DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE);
  parse_option ("slaves", required_argument, 0, 'M', "spawn several slave workers");
  parse_option ("ping-interval", required_argument, 0, 'T', "sets ping interval in second for local TCP connections (default %.3lf)", PING_INTERVAL);
  parse_option ("random-padding-only", no_argument, 0, 'R', "allow only clients with random padding option enabled");
}

void mtfront_parse_extra_args (int argc, char *argv[]) /* {{{ */ {
  if (argc != 1) {
    usage ();
    exit (2);
  }
  config_filename = argv[0];
  vkprintf (0, "config_filename = '%s'\n", config_filename);
}

// executed BEFORE dropping privileges
void mtfront_pre_init (void) {
  init_ct_server_mtfront ();

  int res = do_reload_config (0x26);

  if (res < 0) {
    fprintf (stderr, "config check failed! (code %d)\n", res);
    exit (-res);
  }

  vkprintf (1, "config loaded!\n");

  int i, enable_ipv6 = engine_check_ipv6_enabled () ? SM_IPV6 : 0;

  for (i = 0; i < http_ports_num; i++) {
    http_sfd[i] = server_socket (http_port[i], engine_state->settings_addr, engine_get_backlog (), enable_ipv6);
    if (http_sfd[i] < 0) {
      fprintf (stderr, "cannot open http/tcp server socket at port %d: %m\n", http_port[i]);
      exit (1);
    }
  }

  if (workers) {
    if (!kdb_hosts_loaded) {
      kdb_load_hosts ();
    }
    WStats = mmap (0, 2 * workers * sizeof (struct worker_stats), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert (WStats);
    // kprintf_multiprocessing_mode_enable ();
    int real_parent_pid = getpid();
    vkprintf (0, "creating %d workers\n", workers);
    for (i = 0; i < workers; i++) {
      int pid = fork ();
      assert (pid >= 0);
      if (!pid) {
        worker_id = i;
        workers = 0;
        slave_mode = 1;
        parent_pid = getppid ();
        assert (parent_pid == real_parent_pid);
	engine_enable_slave_mode ();
	engine_state->do_not_open_port = 1;
        break;
      } else {
        pids[i] = pid;
      }
    }
  }
}

void mtfront_pre_start (void) {
  int res = do_reload_config (0x17);

  if (res < 0) {
    fprintf (stderr, "config check failed! (code %d)\n", res);
    exit (-res);
  }

  assert (CurConf->have_proxy);

  proxy_mode |= PROXY_MODE_OUT;
  mtfront_rpc_client.mode_flags |= TCP_RPC_IGNORE_PID;
  ct_tcp_rpc_client_mtfront.flags |= C_EXTERNAL;

  assert (proxy_mode == PROXY_MODE_OUT);
}

void mtfront_on_exit (void) {
  if (workers) {
    if (signal_check_pending (SIGTERM)) {
      kill_children (SIGTERM);
    }
    check_children_dead ();
  }
}

server_functions_t mtproto_front_functions = {
  .default_modules_disabled = 0,
  .cron = cron,
  .precise_cron = precise_cron,
  .pre_init = mtfront_pre_init,
  .pre_start = mtfront_pre_start,
  .pre_loop = mtfront_pre_loop,
  .on_exit = mtfront_on_exit,
  .prepare_stats = mtfront_prepare_stats,
  .parse_option = f_parse_option,
  .prepare_parse_options = mtfront_prepare_parse_options,
  .parse_extra_args = mtfront_parse_extra_args,
  .epoll_timeout = 1,
  .FullVersionStr = FullVersionStr,
  .ShortVersionStr = "mtproxy",
  .parse_function = mtfront_parse_function,
  .flags = ENGINE_NO_PORT
  //.http_functions = &http_methods_stats
};

int main (int argc, char *argv[]) {
  mtproto_front_functions.allowed_signals |= SIG2INT (SIGCHLD);
  mtproto_front_functions.signal_handlers[SIGCHLD] = on_child_termination;
  mtproto_front_functions.signal_handlers[SIGUSR1] = mtfront_sigusr1_handler;
  return default_main (&mtproto_front_functions, argc, argv);
}
