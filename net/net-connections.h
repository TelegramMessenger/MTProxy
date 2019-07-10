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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
    
    Copyright 2014      Telegram Messenger Inc             
              2014      Nikolai Durov
              2014      Andrey Lopatin

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#pragma once

//#include "net/net-buffers.h"
#include "net/net-events.h"
#include "net/net-msg.h"
#include "jobs/jobs.h"
#include "common/mp-queue.h"
#include "common/pid.h"

#define MAX_CONNECTIONS	65536
#define MAX_TARGETS	65536
#define PRIME_TARGETS	99961
#define MAX_SPECIAL_LISTEN_SOCKETS	64

#define MAX_TCP_RECV_BUFFERS 128
#define TCP_RECV_BUFFER_SIZE 1024

#define MAX_NET_RES	(1L << 16)

//#define BUFF_SIZE	2048

#define	CONN_CUSTOM_DATA_BYTES	256

#define	NEED_MORE_BYTES	(~(-1 << 31))
#define	SKIP_ALL_BYTES	(-1 << 31)


/* for connection flags */
#define C_WANTRD	1
#define C_WANTWR	2
#define C_WANTRW	(C_WANTRD | C_WANTWR)
#define C_INCONN	4
#define C_ERROR		8
#define C_NORD		0x10
#define C_NOWR		0x20
#define C_NORW		(C_NORD | C_NOWR)
#define C_INQUERY	0x40
#define C_FAILED	0x80
#define C_ALARM		0x100
#define C_AIO		0x200
#define C_INTIMEOUT	0x400
#define C_STOPREAD	0x800
#define C_REPARSE	0x1000
#define C_DFLUSH	0x2000
#define C_IPV6		0x4000
#define C_EXTERNAL     	0x8000
#define C_SPECIAL	0x10000
#define C_NOQACK	0x20000
#define C_RAWMSG	0x40000
#define C_NET_FAILED	0x80000
#define C_CRYPTOIN	0x100000
#define C_CRYPTOOUT	0x200000
#define C_STOPPARSE	0x400000
#define C_ISDH		0x800000
#define C_READY_PENDING 0x1000000
#define C_CONNECTED	0x2000000
#define C_STOPWRITE	0x4000000
#define C_IS_TLS	0x8000000

#define C_PERMANENT (C_IPV6 | C_RAWMSG)
/* for connection status */
enum {
  conn_none,		// closed/uninitialized
  conn_connecting,
  conn_working,
  conn_error,		// connection in bad state (it will be probably closed)
  conn_listen,		// listening for inbound connections
  conn_write_close,	// write all output buffer, then close; don't read input
  conn_total_states	// total number of connection states
};

/* for connection basic_type */
enum {
  ct_none,		// no connection (closed)
  ct_listen,		// listening socket
  ct_inbound,		// inbound connection
  ct_outbound,		// outbound connection
  ct_pipe,  		// used for pipe reading
  ct_job		// used for async jobs ( net-jobs.h )
};

/* for connection->ready of outbound connections */
enum {
  cr_notyet,		// not ready yet (e.g. logging in)
  cr_ok,		// working
  cr_stopped,		// stopped (don't send more queries)
  cr_busy,		// busy (sending queries not allowed by protocol)
  cr_failed		// failed (possibly timed out)
};


typedef job_t connection_job_t; 
typedef job_t socket_connection_job_t; 
typedef job_t listening_connection_job_t; 
typedef job_t conn_target_job_t; 
typedef job_t query_job_t;


/* connection function table */

#define	CONN_FUNC_MAGIC	0x11ef55aa

typedef struct conn_functions {
  int magic;
  int flags;					/* may contain for example C_RAWMSG; (partially) inherited by inbound/outbound connections */
  char *title;
  int (*accept)(connection_job_t c);		 /* invoked for listen/accept connections of this type */
  int (*init_accepted)(connection_job_t c);	 /* initialize a new accept()'ed connection */
  int (*reader)(connection_job_t c);		 /* invoked from run() for reading network data */
  int (*writer)(connection_job_t c);		 /* invoked from run() for writing data */
  int (*close)(connection_job_t c, int who);	 /* invoked from run() whenever we need to close connection */
  int (*parse_execute)(connection_job_t c);	 /* invoked from reader() for parsing and executing one query */
  int (*init_outbound)(connection_job_t c);	 /* initializes newly created outbound connection */
  int (*connected)(connection_job_t c);	 /* invoked from run() when outbound connection is established */
  int (*check_ready)(connection_job_t c);	 /* updates conn->ready if necessary and returns it */
  int (*wakeup_aio)(connection_job_t c, int r);/* invoked from net_aio.c::check_aio_completion when aio read operation is complete */
  int (*write_packet)(connection_job_t c, struct raw_message *raw);		 /* adds necessary headers to packet */ 
  int (*flush)(connection_job_t c);		 /* generates necessary padding and writes as much bytes as possible */

  // CPU-NET METHODS
  int (*free)(connection_job_t c);
  int (*free_buffers)(connection_job_t c);	 /* invoked from close() to free all buffers */
  int (*read_write)(connection_job_t c);		 /* invoked when an event related to connection of this type occurs */
  int (*wakeup)(connection_job_t c);		 /* invoked from run() when pending_queries == 0 */
  int (*alarm)(connection_job_t c);		 /* invoked when timer is out */

  // NET-NET METHODS
  int (*socket_read_write)(connection_job_t c);		 /* invoked when an event related to connection of this type occurs */
  int (*socket_reader)(connection_job_t c);		 /* invoked from run() for reading network data */
  int (*socket_writer)(connection_job_t c);		 /* invoked from run() for writing data */
  int (*socket_connected)(connection_job_t c);	 /* invoked from run() when outbound connection is established */
  int (*socket_free)(connection_job_t c);
  int (*socket_close)(connection_job_t c);

  // INLINE FUNCTIONS
  int (*data_received)(connection_job_t c, int r);	/* invoked after r>0 bytes are read from socket */
  int (*data_sent)(connection_job_t c, int w);	/* invoked after w>0 bytes are written into socket */
  int (*ready_to_write)(connection_job_t c);   /* invoked from server_writer when Out.total_bytes crosses write_low_watermark ("greater or equal" -> "less") */
  
  // INLINE METHODS
  int (*crypto_init)(connection_job_t c, void *key_data, int key_data_len);  /* < 0 = error */
  int (*crypto_free)(connection_job_t c);
  int (*crypto_encrypt_output)(connection_job_t c);  /* 0 = all ok, >0 = so much more bytes needed to encrypt last block */
  int (*crypto_decrypt_input)(connection_job_t c);   /* 0 = all ok, >0 = so much more bytes needed to decrypt last block */
  int (*crypto_needed_output_bytes)(connection_job_t c);	/* returns # of bytes needed to complete last output block */
} conn_type_t;

struct conn_target_info {
  struct event_timer timer;
  int min_connections;
  int max_connections;

  struct tree_connection *conn_tree;
  //connection_job_t first_conn, last_conn;
  conn_type_t *type;
  void *extra;
  struct in_addr target;
  unsigned char target_ipv6[16];
  int port;
  int active_outbound_connections, outbound_connections;
  int ready_outbound_connections;
  double next_reconnect, reconnect_timeout, next_reconnect_timeout;
  int custom_field;
  conn_target_job_t next_target, prev_target;
  conn_target_job_t hnext;

  int global_refcnt;
};

struct pseudo_conn_target_info {
  struct event_timer timer;
  int pad1;
  int pad2;

  void *pad3;
  conn_type_t *type;
  void *extra;
  struct in_addr target;
  unsigned char target_ipv6[16];
  int port;
  int active_outbound_connections, outbound_connections;
  int ready_outbound_connections;

  connection_job_t in_conn;
  connection_job_t out_conn;
};

struct connection_info {
  struct event_timer timer;
  int fd;
  int generation;
  int flags;
  // connection_job_t next, prev;
  conn_type_t *type;
  void *extra;
  conn_target_job_t target;
  connection_job_t io_conn;
  int basic_type;
  int status;
  int error;
  int unread_res_bytes;
  int skip_bytes;
  int pending_queries;
  int queries_ok;
  char custom_data[CONN_CUSTOM_DATA_BYTES];
  unsigned our_ip, remote_ip;
  unsigned our_port, remote_port;
  unsigned char our_ipv6[16], remote_ipv6[16];
  double query_start_time;
  double last_query_time;
  double last_query_sent_time;
  double last_response_time;
  double last_query_timeout;
  //event_timer_t timer;
  //event_timer_t write_timer;
  int limit_per_write, limit_per_sec;
  int last_write_time, written_per_sec;
  int unreliability;
  int ready;
  //int parse_state;
  int write_low_watermark;
  void *crypto;
  void *crypto_temp;
  int listening, listening_generation;
  int window_clamp;
  int left_tls_packet_length;

  struct raw_message in_u, in, out, out_p;

  struct mp_queue *in_queue;
  struct mp_queue *out_queue;

  //netbuffer_t *Tmp, In, Out;
  //char in_buff[BUFF_SIZE];
  //char out_buff[BUFF_SIZE];
};

struct socket_connection_info {
  struct event_timer timer;
  int fd;
  int pad;
  int flags;
  int current_epoll_status;
  conn_type_t *type;
  event_t *ev;
  connection_job_t conn;
  struct mp_queue *out_packet_queue;
  struct raw_message out;
  unsigned our_ip, remote_ip;
  unsigned our_port, remote_port;
  unsigned char our_ipv6[16], remote_ipv6[16];
  int write_low_watermark;
  int eagain_count;
};

struct listening_connection_info {
  struct event_timer timer;
  int fd;
  int generation;
  int flags;
  int current_epoll_status;
  conn_type_t *type;
  event_t *ev;
  void *extra;
  int window_clamp;
};

struct connections_stat {
  int active_connections;
  int active_dh_connections;
  int outbound_connections;
  int active_outbound_connections;
  int ready_outbound_connections;
  int active_special_connections;
  int max_special_connections;
  int allocated_connections;
  int allocated_outbound_connections;
  int allocated_inbound_connections;
  int allocated_socket_connections;
  int allocated_targets;
  int ready_targets;
  int active_targets;
  int inactive_targets;
  long long tcp_readv_calls;
  long long tcp_readv_intr;
  long long tcp_readv_bytes;
  long long tcp_writev_calls;
  long long tcp_writev_intr;
  long long tcp_writev_bytes;
  long long accept_calls_failed;
  long long accept_nonblock_set_failed;
  long long accept_rate_limit_failed;
  long long accept_init_accepted_failed;
  long long accept_connection_limit_failed;
};

#define QUERY_INFO(_c) ((struct query_info *)(_c)->j_custom)

#define CONN_INFO(_conn) ((struct connection_info *)((_conn)->j_custom))
#define LISTEN_CONN_INFO(_conn) ((struct listening_connection_info *)((_conn)->j_custom))
#define SOCKET_CONN_INFO(_conn) ((struct socket_connection_info *)((_conn)->j_custom))
#define CONN_TARGET_INFO(_conn_target) ((struct conn_target_info *)((_conn_target)->j_custom))

static inline const char *show_ip46 (unsigned ip, const unsigned char ipv6[16]) { return ip ? show_ip (ip) : show_ipv6 (ipv6); }
static inline const char *show_our_ip (connection_job_t c) { return show_ip46 (CONN_INFO(c)->our_ip, CONN_INFO(c)->our_ipv6); }
static inline const char *show_remote_ip (connection_job_t c) { return show_ip46 (CONN_INFO(c)->remote_ip, CONN_INFO(c)->remote_ipv6); }
static inline const char *show_our_socket_ip (socket_connection_job_t c) { return show_ip46 (SOCKET_CONN_INFO(c)->our_ip, SOCKET_CONN_INFO(c)->our_ipv6); }
static inline const char *show_remote_socket_ip (socket_connection_job_t c) { return show_ip46 (SOCKET_CONN_INFO(c)->remote_ip, SOCKET_CONN_INFO(c)->remote_ipv6); }

void fetch_connections_stat (struct connections_stat *st);

void compute_next_reconnect (conn_target_job_t CT);
int create_all_outbound_connections (void);
int clean_unused_target (conn_target_job_t S);
int create_new_connections (conn_target_job_t S);

int set_connection_timeout (connection_job_t C, double timeout);
int clear_connection_timeout (connection_job_t C);
  
int prepare_stats (char *buf, int size);
void fail_connection (connection_job_t C, int who);
void fail_socket_connection (socket_connection_job_t C, int who);


int destroy_target (JOB_REF_ARG (CTJ));
conn_target_job_t create_target (struct conn_target_info *source, int *was_created);
void compute_next_reconnect (conn_target_job_t CT);


static inline connection_job_t connection_incref (connection_job_t C) { return job_incref (C); }
static inline void connection_decref (connection_job_t C) { job_decref (JOB_REF_PASS (C)); }

connection_job_t connection_get_by_fd (int fd);
connection_job_t connection_get_by_fd_generation (int fd, int generation);

int cpu_server_reader (connection_job_t C);
int cpu_server_writer (connection_job_t C);
int cpu_server_read_write (connection_job_t C);
//int cpu_free_tmp_buffers (connection_job_t C);
int cpu_server_free_connection (connection_job_t C);
int cpu_free_connection_buffers (connection_job_t C);
int cpu_server_close_connection (connection_job_t C, int who);


int net_server_socket_reader (connection_job_t C);
int net_server_socket_writer (connection_job_t C);
int net_server_socket_read_write (connection_job_t C);

int net_accept_new_connections (connection_job_t C);

int set_connection_timeout (connection_job_t C, double timeout);
int clear_connection_timeout (connection_job_t C);

int server_check_ready (connection_job_t C);
int server_noop (connection_job_t C);
int server_failed (connection_job_t C);

void connection_write_close (connection_job_t C);
#define write_out_chk(c,data,len) assert(write_out (&CONN_INFO(c)->Out, data, len) == len);
#define write_out_old(c,data,len) write_out(&CONN_INFO(c)->Out, data, len)
#define read_in_old(c,data,len) read_in(&CONN_INFO(c)->In, data, len)

static inline int is_ipv6_localhost (unsigned char ipv6[16]) {
  return !*(long long *)ipv6 && ((long long *)ipv6)[1] == 1LL << 56;
}

void assert_net_cpu_thread (void);
void assert_net_net_thread (void);
void assert_engine_thread (void);

connection_job_t conn_target_get_connection (conn_target_job_t CT, int allow_stopped);
      
void insert_connection_into_target (conn_target_job_t SS, connection_job_t C);
struct tree_connection *get_connection_tree (conn_target_job_t SS);
//void wakeup_main_thread (void);

void delete_connection_tree_ptr (struct tree_connection *T);

int init_listening_connection_ext (int fd, conn_type_t *type, void *extra, int mode, int prio);
int init_listening_connection (int fd, conn_type_t *type, void *extra);
int init_listening_tcpv6_connection (int fd, conn_type_t *type, void *extra, int mode);

//struct tree_connection *get_connection_tree_ptr (struct tree_connection **);
//void free_connection_tree_ptr (struct tree_connection *);

struct free_later {
  void *ptr;
  void (*free)(void *);
};


struct query_info {
  struct event_timer ev;
  struct raw_message raw;
  int src_type;
  struct process_id src_pid;
  void *conn;
};

void free_later_act (void);

void incr_active_dh_connections (void);
int check_conn_functions (conn_type_t *type, int listening);

#define QUERY_INFO(_c) ((struct query_info *)(_c)->j_custom)
void insert_free_later_struct (struct free_later *F);
int new_conn_generation (void);
int get_cur_conn_generation (void);

void tcp_set_max_accept_rate (int rate);
void tcp_set_max_connections (int maxconn);

extern int max_special_connections, active_special_connections;

#define MAX_NAT_INFO_RULES	16
extern int nat_info_rules;
extern unsigned nat_info[MAX_NAT_INFO_RULES][2];

int net_add_nat_info (char *str);
unsigned nat_translate_ip (unsigned local_ip);

connection_job_t alloc_new_connection (int cfd, conn_target_job_t CTJ, listening_connection_job_t LCJ, int basic_type, conn_type_t *conn_type, void *conn_extra, unsigned peer, unsigned char peer_ipv6[16], int peer_port);
