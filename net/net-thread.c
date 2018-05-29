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

    Copyright 2015-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman     
    
*/
#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "net/net-thread.h"
#include "net/net-connections.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-server.h"

#include "common/mp-queue.h"
#include "common/kprintf.h"
#include "common/server-functions.h"

#define NEV_TCP_CONN_READY 1
#define NEV_TCP_CONN_CLOSE 2
#define NEV_TCP_CONN_ALARM 3
#define NEV_TCP_CONN_WAKEUP 4

struct notification_event {
  int type;
  void *who;
};

void run_notification_event (struct notification_event *ev) {
  connection_job_t C = ev->who;
  switch (ev->type) {
  case NEV_TCP_CONN_READY:
    if (TCP_RPCC_FUNC(C)->rpc_ready && TCP_RPCC_FUNC(C)->rpc_ready (C) < 0) {
      fail_connection (C, -8);
    }
    job_decref (JOB_REF_PASS (C));
    break;
  case NEV_TCP_CONN_CLOSE:
    TCP_RPCC_FUNC(C)->rpc_close (C, 0);
    job_decref (JOB_REF_PASS (C));
    break;
  case NEV_TCP_CONN_ALARM:
    TCP_RPCC_FUNC(C)->rpc_alarm (C);
    job_decref (JOB_REF_PASS (C));
    break;
  case NEV_TCP_CONN_WAKEUP:
    TCP_RPCC_FUNC(C)->rpc_wakeup (C);
    job_decref (JOB_REF_PASS (C));
    break;
  default:
    assert (0);
  }
  free (ev);
}

struct notification_event_job_extra {
  struct mp_queue *queue;
};
static job_t notification_job;

int notification_event_run (job_t job, int op, struct job_thread *JT) {   
  if (op != JS_RUN) {
    return JOB_ERROR;
  }
  struct notification_event_job_extra *E = (void *)job->j_custom;

  while (1) {
    struct notification_event *ev = mpq_pop_nw (E->queue, 4);
    if (!ev) { break; }

    run_notification_event (ev);
  }

  return 0;
}

void notification_event_job_create (void) {
  notification_job = create_async_job (notification_event_run, JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_FINISH), 0, sizeof (struct notification_event_job_extra), 0, JOB_REF_NULL);

  struct notification_event_job_extra *E = (void *)notification_job->j_custom;
  E->queue = alloc_mp_queue_w ();
  
  unlock_job (JOB_REF_CREATE_PASS (notification_job));
}

void notification_event_insert_conn (connection_job_t C, int type) {
  struct notification_event *ev = malloc (sizeof (*ev));
  ev->who = job_incref (C);
  ev->type = type;

  struct notification_event_job_extra *E = (void *)notification_job->j_custom;
  mpq_push_w (E->queue, ev, 0);
  job_signal (JOB_REF_CREATE_PASS (notification_job), JS_RUN);
}

void notification_event_insert_tcp_conn_close (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_CLOSE);
}

void notification_event_insert_tcp_conn_ready (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_READY);
}

void notification_event_insert_tcp_conn_alarm (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_ALARM);
}

void notification_event_insert_tcp_conn_wakeup (connection_job_t C) {
  notification_event_insert_conn (C, NEV_TCP_CONN_WAKEUP);
}
