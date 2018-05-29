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

    Copyright 2014-2015 Telegram Messenger Inc
              2014-2015 Nikolai Durov
              2014      Andrey Lopatin
*/

#pragma once

#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include "net/net-events.h"
#include "net/net-msg.h"
#include "net/net-timers.h"

#define __joblocked
#define __jobref

#define MAX_SUBCLASS_THREADS 16

//#include "net/net-connections.h"

// verbosity level for jobs
#define JOBS_DEBUG 3

#define CONCAT(a,b) a ## b

#define PTR_MOVE(__ptr_v) \
  ({ typeof(__ptr_v) __ptr_v_save = __ptr_v; __ptr_v = NULL; __ptr_v_save; })

#define JOB_REF_ARG(__name) int __name ## _tag_int, job_t __name
#define JOB_REF_PASS(__ptr) 1, PTR_MOVE (__ptr)
#define JOB_REF_NULL 1, NULL
#define JOB_REF_CREATE_PASS(__ptr) 1, job_incref (__ptr)
#define JOB_REF_CREATE_PASS_N(__ptr) 1, __ptr ? job_incref (__ptr) : NULL

struct job_thread;
struct async_job;
typedef struct async_job *job_t;

typedef int (*job_function_t)(job_t job, int op, struct job_thread *JT);

extern __thread struct job_thread *this_job_thread;
extern __thread job_t this_job;

#define JOB_DESTROYED	-0x80000000
#define	JOB_COMPLETED	0x100
#define JOB_FINISH	0x80
#define JOB_ERROR	-1

/* job signal numbers (0..7) */
#define	JS_FREE	-1		/* pseudo-signal, invoked to free job structure ("destructor") */
#define JS_RUN	0
#define JS_AUX	1
#define JS_MSG 2
#define	JS_ALARM	4	/* usually sent by timer */
#define	JS_ABORT	5	/* used for error propagation, especially from children */
#define	JS_KILL	6
#define	JS_FINISH	7
#define	JS_SIG0	0
#define	JS_SIG1	1
#define	JS_SIG2	2
#define	JS_SIG3	3
#define	JS_SIG4	4
#define	JS_SIG5	5
#define	JS_SIG6	6
#define	JS_SIG7	7

extern int engine_multithread_mode;

#define JC_EPOLL JC_MAIN
#define JC_METAFILE_READ JC_IO
#define JC_METAFILE_PREPARE JC_CPU
#define JC_CONNECTION 4
#define JC_CONNECTION_IO 5
#define JC_UDP 6
#define JC_UDP_IO 7
#define JC_ENGINE 8
#define JC_GMS JC_ENGINE
#define JC_GMS_CPU 10
#define JC_ENGINE_MULT 11


#define DEFAULT_IO_JOB_THREADS	16
#define DEFAULT_CPU_JOB_THREADS	8
#define DEFAULT_GMS_CPU_JOB_THREADS 8

// fake class
// no signals should be allowed
#define JC_MP_QUEUE 9


#define JC_NONE	0	// no signal (unless used with "fast" flag; then it means "any context")
#define JC_IO	1	// signal must be processed in I/O thread
#define JC_CPU	2	// signal must be processed in CPU thread
#define JC_MAIN	3	// signal must be processed in main thread (unless specified otherwise)
#define JC_MAX	0xf
#define JC_MASK	JC_MAX

#define	JF_LOCKED	0x10000	// job is "locked" (usually this means that a signal is being processed)
#define	JF_SIGINT	0x20000	// signal interruption: if job is "locked" and we send a new signal to it, invoke pthread_signal() as well
#define JF_COMPLETED	0x40000	// used to signal job "completion" to outside observers

#define JF_QUEUED_CLASS(__c)	(1 << (__c))
#define	JF_QUEUED_MAIN	JF_QUEUED_CLASS(JC_MAIN)	// job is in MAIN execution queue
#define	JF_QUEUED_IO	JF_QUEUED_CLASS(JC_IO)		// job is in IO execution queue
#define	JF_QUEUED_CPU	JF_QUEUED_CLASS(JC_CPU)		// job is in CPU execution queue
#define	JF_QUEUED	0xffff	// job is in some execution queue

#define JT_HAVE_TIMER 1
#define JT_HAVE_MSG_QUEUE 2

#define	JFS_SET(__s)	(0x1000000U << (__s))	// j_flags: signal __s is awaiting delivery
#define	JSS_ALLOW(__s)	(0x1000000U << (__s))	// j_status: signal __s is allowed for delivery
#define	JSS_FAST(__s)	(0x10000U << (__s))	// j_status: signal __s is "fast" -- may be processed recursively in specified or in any context, not necessarily in order
#define	JSS_ALLOW_FAST(__s)	(0x1010000U << (__s))


#define JOB_SENDSIG(__s)	(1 << (__s))

#define JSC_TYPE(__c,__s)	(((unsigned long long)(__c) << ((__s) * 4 + 32)))
#define JSC_ALLOW(__c,__s)	(JSC_TYPE(__c,__s) | JSS_ALLOW(__s))
#define JSC_FAST(__c,__s)	(JSC_TYPE(__c,__s) | JSS_ALLOW_FAST(__s))
#define JSIG_MAIN(__s)	JSC_ALLOW(JC_MAIN,__s)
#define JSIG_IO(__s)	JSC_ALLOW(JC_IO,__s)
#define JSIG_CPU(__s)	JSC_ALLOW(JC_CPU,__s)
#define JSIG_FAST(__s)	JSC_FAST(JC_NONE,__s)
#define JSIG_ENGINE(__s)	JSC_ALLOW(JC_ENGINE,__s)

#define	JSP_PARENT_ERROR	1		// j_status: propagate error to j_error field in j_parent, and send ABORT to parent
#define	JSP_PARENT_RUN		2		// j_status: send RUN to j_parent after job completion
#define	JSP_PARENT_WAKEUP	4		// j_status: decrease j_parent's j_children; if it becomes 0, maybe send RUN
#define	JSP_PARENT_RESPTR	8		// j_status: (result) pointer(s) kept in j_custom actually point inside j_parent; use them only if j_parent is still valid
#define JSP_PARENT_INCOMPLETE	0x10		// abort job if parent already completed
#define	JSP_PARENT_RWE	7
#define	JSP_PARENT_RWEP	0xf
#define	JSP_PARENT_RWEI	0x17
#define	JSP_PARENT_RWEPI	0x1f

#define JMC_UPDATE 1
#define JMC_FORCE_UPDATE 2
#define JMC_RPC_QUERY 3
#define JMC_TYPE_MASK 31

#define JMC_CONTINUATION 8

#define JMC_EXTRACT_ANSWER(__type) (((__type) >> 8) & 255)
#define JMC_ANSWER(__type) ((__type) << 8)

/* all fields here, with the exception of bits 24..31 and JF_LOCKED of j_flags, j_error, j_refcnt, j_children, may be changed only
   by somebody who already owns a lock to this job, or has the only pointer to it. */
struct async_job {  // must be partially compatible with `struct connection`
  int j_flags;  // bits 0..15: queue flags; bits 16..23: status; bits 24..31: received signals (only bits that can be changed without having lock)
  int j_status;	// bits 24..31: allowed signals; bits 16..23: corresponding signal is "fast"; bits 0..4: relation to parent
  int j_sigclass;  // bits (4*n)..(4*n-3): queue class of signal n, n=0..7
  int j_refcnt;	// reference counter, changed by job_incref() and job_decref(); when becomes zero, j_execute is invoked with op = JS_FREE
  int j_error;  // if non-zero, error code; may be overwritten by children (unless already non-zero: remembers first error only)
  int j_children;   // number of jobs to complete before scheduling this job
  int j_align;  // align of real allocated pointer
  int j_custom_bytes;

  unsigned int j_type; // Bit 0 - have event_timer (must be first bytes of j_custom)
                       // Bit 1 - have message queue (must be after event_timer or first, if there is no event_timer)
  int j_subclass;

  struct job_thread *j_thread;  // thread currently processing this job
  // maybe: reference to queue, position in queue -- if j_flags & JF_QUEUED -- to remove from queue if necessary
  job_function_t j_execute;	// invoked in correct context to process signals
  job_t j_parent;   // parent (dependent) job or 0
  long long j_custom[0] __attribute__((aligned(64)));
} __attribute__((aligned(64)));

struct job_subclass {
  int subclass_id;

  int total_jobs;
  int allowed_to_run_jobs;
  int processed_jobs;

  int locked;

  struct mp_queue *job_queue;
};

struct job_subclass_list {
  int subclass_cnt;

  sem_t sem;

  struct job_subclass *subclasses;
};

struct job_class {
  int thread_class;

  int min_threads;
  int max_threads;
  int cur_threads;

  struct mp_queue *job_queue;

  struct job_subclass_list *subclasses;
};

struct job_thread {
  pthread_t pthread_id;
  int id;
  int thread_class; 
  int job_class_mask;  // job classes allowed to run in this thread
  int status;  // 0 = absent; +1 = created, +2 = running/waiting, +4 = performing job
  long long jobs_performed;
  struct mp_queue *job_queue;
  struct async_job *current_job;  // job currently performed or 0 (for DEBUG only)
  double current_job_start_time, last_job_time, tot_jobs_time;
  int jobs_running[JC_MAX+1];
  long long jobs_created;
  long long jobs_active;
  int thread_system_id;
  struct drand48_data rand_data;
  job_t timer_manager;
  double wakeup_time;
  struct job_class *job_class;
} __attribute__((aligned(128)));

struct job_message {
  unsigned int type;  
  unsigned int flags;
  unsigned int payload_ints;
  job_t src;
  void (*destructor)(struct job_message *M);
  struct raw_message message;   
  struct job_message *next;
  unsigned int payload[0];
};

struct job_message_queue {
  struct mp_queue *unsorted;
  struct job_message *first, *last;
  unsigned int payload_magic;
};

struct job_timer_info {
  struct event_timer ev;
  void *extra;
  double (*wakeup)(void *);
};

#define MAX_JOB_THREADS		256

long int lrand48_j (void);
long int mrand48_j (void);
double drand48_j (void);

int init_async_jobs (void);
int create_job_class (int job_class, int min_threads, int max_threads, int excl);
int create_job_class_sub (int job_class, int min_threads, int max_threads, int excl, int subclass_cnt);
job_t notify_job_create (int sig_class);
int create_job_thread_ex (int thread_class, void *(*thread_work)(void *));
int create_new_job_class (int job_class, int min_threads, int max_threads);
int create_new_job_class_sub (int job_class, int min_threads, int max_threads, int subclass_cnt);
void *job_thread_ex (void *arg, void (*work_one)(void *, int));

/* creates a new async job as described */
job_t create_async_job (job_function_t run_job, unsigned long long job_signals, int job_subclass, int custom_bytes, unsigned long long job_type, JOB_REF_ARG (parent_job));
void job_change_signals (job_t job, unsigned long long job_signals);
/* puts job into execution queue according to its priority class (actually, unlocks it and sends signal 0) */
int schedule_job (JOB_REF_ARG (job));

job_t job_incref (job_t job);
static inline job_t job_incref_f (job_t job) {
  if (job) {
    job_incref (job);
  }
  return job;
}
void job_decref (JOB_REF_ARG (job));	// if job->j_refcnt becomes 0, invokes j_execute with op = JS_FREE
static inline void job_decref_f (job_t job) {
  job_decref (JOB_REF_PASS (job));
}

int unlock_job (JOB_REF_ARG (job));
int try_lock_job (job_t job, int set_flags, int clear_flags);

void complete_job (job_t job);	// if JF_COMPLETED is not set, sets it and acts according to JFS_PARENT_*

int change_locked_job_subclass (job_t job, int new_subclass);

static inline int check_job_completion (job_t job) {
  return job->j_flags & JF_COMPLETED;
}
static inline int check_job_validity (job_t job) {
  return job && !check_job_completion (job);
}
static inline int check_parent_job_validity (job_t job) {
  return check_job_validity (job->j_parent);
}
static inline int parent_job_aborted (job_t job) {
  return (job->j_status & JSP_PARENT_INCOMPLETE) && job->j_parent && check_job_completion (job->j_parent);
}
static inline int job_parent_ptr_valid (job_t job) {
  return (!(job->j_status & JSP_PARENT_RESPTR) || check_parent_job_validity (job));
}
static inline int job_fatal (job_t job, int error) {
  if (!job->j_error) {
    job->j_error = error;
  }
  return JOB_COMPLETED;
}

/* runs all pending jobs of class JF_CLASS_MAIN, then returns */
int run_pending_main_jobs (void);


/* ----------- JOB WAIT QUEUE ------ */

struct job_list_node;

typedef int (*job_list_node_type_t)(job_t list_job, int op, struct job_list_node *w);

struct job_list_node {
  struct job_list_node *jl_next;
  job_list_node_type_t jl_type;
  int jl_custom[0];
};

job_t create_job_list (void);
int insert_job_into_job_list (job_t list_job, JOB_REF_ARG(job), int mode);
void update_all_thread_stats (void);

/* adds job to the list of jobs awaited by connection */
// int conn_wait_job (job_t job, connection_job_t c, double timeout, struct conn_query_functions *cq);
/* increases connection's generation (effectively clearing list of awaited jobs), then adds given job */
// int conn_wait_only_job (job_t job, connection_job_t c, double timeout, struct conn_query_functions *cq);

extern int max_job_thread_id;

void check_main_thread (void);
int job_timer_wakeup_gateway (event_timer_t *et);
int job_timer_check (job_t job);
void job_signal (JOB_REF_ARG (job), int signo);
void complete_subjob (job_t job, JOB_REF_ARG (parent), int status);
void job_timer_insert (job_t job, double timeout);
void job_timer_remove (job_t job);
int job_timer_active (job_t job);
void job_timer_init (job_t job);
double job_timer_wakeup_time (job_t job);
void jobs_check_all_timers (void);

static inline void check_thread_class (int class) {
  assert (this_job_thread->job_class_mask & (1 << class));
}

void job_message_send (JOB_REF_ARG (job), JOB_REF_ARG (src), unsigned int type, struct raw_message *raw, int dup, int payload_ints, const unsigned int *payload, unsigned int flags, void (*destructor)(struct job_message *M));
void job_message_send_fake (JOB_REF_ARG (job), int (*receive_message)(job_t job, struct job_message *M, void *extra), void *extra, JOB_REF_ARG (src), unsigned int type, struct raw_message *raw, int dup, int payload_ints, const unsigned int *payload, unsigned int flags, void (*destructor)(struct job_message *M));
//void job_message_send_data (JOB_REF_ARG (job), JOB_REF_ARG (src), unsigned int type, void *ptr1, void *ptr2, int int1, long long long1, int payload_ints, const unsigned int *payload, unsigned int flags);
static inline void job_message_send_empty (JOB_REF_ARG (job), JOB_REF_ARG (src), unsigned int type, unsigned int flags) {
  job_message_send (JOB_REF_PASS (job), JOB_REF_PASS (src), type, &empty_rwm, 1, 0, NULL, flags, NULL);
}
    
#define TL_TRUE 0x3fedd339
static inline int job_message_answer_true (struct job_message *M) {    
  if (M->src) {
    job_message_send (JOB_REF_PASS (M->src), JOB_REF_NULL, TL_TRUE, &empty_rwm, 1, M->payload_ints, M->payload, JMC_EXTRACT_ANSWER (M->flags), NULL);
  }
  return 1;
}

static inline int job_message_continuation (job_t job, struct job_message *M, int payload_magic) {
  if (M->payload_ints >= 1) {
    assert (M->payload[0] == payload_magic);
    assert (M->payload_ints == 5);
    int (*func)(job_t, struct job_message *, void *) = *(void **)(M->payload + 1);
    void *extra = *(void **)(M->payload + 3);
    assert (func);
    return func (job, M, extra);
  }
  return 1;
}

void job_message_queue_free (job_t job);
void job_message_queue_init (job_t job);
void job_message_queue_work (job_t job, int (*receive_message)(job_t job, struct job_message *M, void *extra), void *extra, unsigned int mask);

int job_free (JOB_REF_ARG (job));
job_t job_timer_alloc (int thread_class, double (*alarm)(void *), void *extra);

struct thread_callback {
  struct thread_callback *next;
  void (*new_thread)(void);
};

void register_thread_callback (struct thread_callback *cb);
job_t alloc_timer_manager (int thread_class);

struct job_message_payload {
  job_t job;
  int message_class;
  int payload_ints;
  unsigned int payload[0];
};

static inline struct job_message_payload *job_message_payload_alloc (JOB_REF_ARG (job), int message_class, int payload_ints, unsigned int *payload) {
  struct job_message_payload *P = malloc (sizeof (*P) + 4 * payload_ints);
  P->message_class = message_class;
  P->payload_ints = payload_ints;
  P->job = PTR_MOVE (job);
  memcpy (P->payload, payload, 4 * payload_ints);
  return P;
}

long long jobs_get_allocated_memoty (void);

unsigned int *payload_continuation_create (unsigned int magic, int (*func)(job_t, struct job_message *, void *extra), void *extra);
#define PAYLOAD_CONTINUATION(_magic,_func,_extra) 5, payload_continuation_create (_magic, _func, _extra)

extern struct job_thread JobThreads[];
#define CNCT2(a,b) a ## b
#define CNCT(a,b) CNCT2(a,b)

#define MODULE_STAT_TYPE struct CNCT(jobs_module_stat_,MODULE)
#define MODULE_STR(a) MODULE_STR2(a)
#define MODULE_STR2(a) #a
#define MODULE_STAT_PREFIX_NAME CNCT(jobs_module_state_prefix_,MODULE)
#define MODULE_STAT_PREFIX char *MODULE_STAT_PREFIX_NAME

#define MODULE_STAT CNCT(jobs_module_stat_,MODULE)
#define MODULE_STAT_ARR CNCT(jobs_module_list_stat_,MODULE)

#define MODULE_STAT_FUNCTION int CNCT(MODULE,_prepare_stat) (stats_buffer_t *sb) { \
  sb_printf (sb, ">>>>>>%s>>>>>>\tstart\n", MODULE_STR(MODULE));


#define MODULE_STAT_FUNCTION_END \
  sb_printf (sb, "<<<<<<%s<<<<<<\tend\n", MODULE_STR(MODULE)); \
  return sb->pos; } 

#define MODULE_INIT \
  MODULE_STAT_TYPE *MODULE_STAT_ARR[MAX_JOB_THREADS]; \
  __thread MODULE_STAT_TYPE *MODULE_STAT; \
  MODULE_STAT_PREFIX; \
                                          \
  void CNCT(jobs_module_thread_init_,MODULE) (void) {\
    int id = get_this_thread_id ();\
    assert (id >= 0 && id < MAX_JOB_THREADS);\
    MODULE_STAT = MODULE_STAT_ARR[id] = calloc (sizeof (MODULE_STAT_TYPE), 1);\
  } \
  \
  struct thread_callback CNCT(MODULE,_thread_callback) = { \
    .new_thread = CNCT(jobs_module_thread_init_, MODULE), \
    .next = NULL \
  }; \
  void CNCT(jobs_module_register_,MODULE) (void) __attribute__ ((constructor));\
  void CNCT(jobs_module_register_,MODULE) (void) { \
    register_thread_callback (&CNCT(MODULE,_thread_callback)); \
  }

