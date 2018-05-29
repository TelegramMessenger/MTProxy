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
              2012-2013 Nikolai Durov
              2012-2013 Andrey Lopatin
    
    Copyright 2014-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman
*/

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kprintf.h"
#include "jobs/jobs.h"
#include "common/common-stats.h"
#include "common/server-functions.h"

#define MODULE raw_msg_buffer

int allocated_buffer_chunks, max_allocated_buffer_chunks, max_buffer_chunks;
long long max_allocated_buffer_bytes; 

MODULE_STAT_TYPE {
  long long total_used_buffers_size;
  int total_used_buffers;
  long long allocated_buffer_bytes;
  long long buffer_chunk_alloc_ops;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_LL (total_used_buffers_size);
  SB_SUM_ONE_I (total_used_buffers);
  SB_SUM_ONE_LL (allocated_buffer_bytes);
  SB_SUM_ONE_LL (buffer_chunk_alloc_ops);
  sb_printf (sb,
    "allocated_buffer_chunks\t%d\n"
    "max_allocated_buffer_chunks\t%d\n"
    "max_buffer_chunks\t%d\n"
    "max_allocated_buffer_bytes\t%lld\n",
    allocated_buffer_chunks,
    max_allocated_buffer_chunks,
    max_buffer_chunks,
    max_allocated_buffer_bytes
    );
MODULE_STAT_FUNCTION_END

void fetch_buffers_stat (struct buffers_stat *bs) {
  bs->total_used_buffers_size = SB_SUM_LL (total_used_buffers_size);
  bs->allocated_buffer_bytes = SB_SUM_LL (allocated_buffer_bytes);
  bs->buffer_chunk_alloc_ops = SB_SUM_LL (buffer_chunk_alloc_ops);
  bs->total_used_buffers = SB_SUM_I (total_used_buffers);
  bs->allocated_buffer_chunks = allocated_buffer_chunks;
  bs->max_allocated_buffer_chunks = max_allocated_buffer_chunks;
  bs->max_allocated_buffer_bytes = max_allocated_buffer_bytes;
  bs->max_buffer_chunks = max_buffer_chunks;
}

int buffer_size_values;
int rwm_peak_recovery;
struct msg_buffers_chunk ChunkHeaders[MAX_BUFFER_SIZE_VALUES];
__thread struct msg_buffers_chunk *ChunkSave[MAX_BUFFER_SIZE_VALUES];

int default_buffer_sizes[] = { 48, 512, 2048, 16384, 262144 };
int default_buffer_sizes_cnt = sizeof (default_buffer_sizes) / 4;

int free_std_msg_buffer (struct msg_buffers_chunk *C, struct msg_buffer *X);

void init_buffer_chunk_headers (void) {
  int i;
  struct msg_buffers_chunk *CH;
  assert (!buffer_size_values);
  for (i = 0, CH = ChunkHeaders; i < sizeof (default_buffer_sizes) / sizeof (int); i++, CH++) {
    CH->magic = MSG_CHUNK_HEAD_MAGIC;
    CH->buffer_size = default_buffer_sizes[i];
    CH->ch_next = CH->ch_prev = CH;
    CH->free_buffer = 0;
    assert (!i || default_buffer_sizes[i] > default_buffer_sizes[i-1]);
  }
  assert (i);
  buffer_size_values = i;
}

static inline void prepare_bs_inv (struct msg_buffers_chunk *C) {
  int x = C->buffer_size + 16;
  int i = __builtin_ctz (x);
  x >>= i;
  x = 1 - x;
  int y = 1;
  while (x) {
    y *= 1 + x;
    x *= x;
  }
  C->bs_inverse = y;
  C->bs_shift = i;
}

static void lock_chunk_head (struct msg_buffers_chunk *CH) {
  while (1) {
    if (__sync_bool_compare_and_swap (&CH->magic, MSG_CHUNK_HEAD_MAGIC, MSG_CHUNK_HEAD_LOCKED_MAGIC)) {
      break;
    }
    usleep (1000);
  }
}

static void unlock_chunk_head (struct msg_buffers_chunk *CH) {
  CH->magic = MSG_CHUNK_HEAD_MAGIC;
}

static int try_lock_chunk (struct msg_buffers_chunk *C) {
  if (C->magic != MSG_CHUNK_USED_MAGIC || !__sync_bool_compare_and_swap (&C->magic, MSG_CHUNK_USED_MAGIC, MSG_CHUNK_USED_LOCKED_MAGIC)) {
    return 0;
  }
  while (1) {
    struct msg_buffer *X = mpq_pop_nw (C->free_block_queue, 4);
    if (!X) { break; }
    assert (X->chunk == C);
    C->free_buffer (C, X);
  }
  return 1;
}

static void unlock_chunk (struct msg_buffers_chunk *C) {
  while (1) {
    while (1) {
      struct msg_buffer *X = mpq_pop_nw (C->free_block_queue, 4);
      if (!X) { break; }
      assert (X->chunk == C);
      C->free_buffer (C, X);
    }
    C->magic = MSG_CHUNK_USED_MAGIC;

    if (mpq_is_empty (C->free_block_queue) || !try_lock_chunk (C)) {
      break;
    }
  }
}

// returns locked chunk
struct msg_buffers_chunk *alloc_new_msg_buffers_chunk (struct msg_buffers_chunk *CH) {
  unsigned magic = CH->magic;
  assert (magic == MSG_CHUNK_HEAD_MAGIC || magic == MSG_CHUNK_HEAD_LOCKED_MAGIC);
  if (allocated_buffer_chunks >= max_buffer_chunks) {
    // ML
    return 0;
  }
  struct msg_buffers_chunk *C = malloc (MSG_BUFFERS_CHUNK_SIZE);
  if (!C) {
    return 0;
  }

  int buffer_size = CH->buffer_size, two_power, chunk_buffers;
  int buffer_hd_size = buffer_size + BUFF_HD_BYTES;
  int align = buffer_hd_size & -buffer_hd_size;
  if (align < 8) {
    align = 8;
  }
  if (align > 64) {
    align = 64;
  }

  int t = (MSG_BUFFERS_CHUNK_SIZE - offsetof (struct msg_buffers_chunk, free_cnt)) / (buffer_hd_size + 4);
  two_power = 1;
  while (two_power <= t) {
    two_power <<= 1;
  }

  chunk_buffers = (MSG_BUFFERS_CHUNK_SIZE - offsetof (struct msg_buffers_chunk, free_cnt) - two_power * 4 - align) / buffer_hd_size;
  assert (chunk_buffers > 0 && chunk_buffers < 65536 && chunk_buffers <= two_power);

  C->magic = MSG_CHUNK_USED_LOCKED_MAGIC;
  C->buffer_size = buffer_size;
  C->free_buffer = free_std_msg_buffer;
  C->ch_head = CH;
  

  C->first_buffer = (struct msg_buffer *) (((long) C + offsetof (struct msg_buffers_chunk, free_cnt) + two_power * 4 + align - 1) & -align);
  assert ((char *) (C->first_buffer) + chunk_buffers * buffer_hd_size <= (char *) C + MSG_BUFFERS_CHUNK_SIZE);

  C->two_power = two_power;
  C->tot_buffers = chunk_buffers;

  C->refcnt = 1;

  lock_chunk_head (CH);

  CH->tot_buffers += chunk_buffers;
  CH->free_buffers += chunk_buffers;
  CH->tot_chunks++;
  
  C->ch_next = CH->ch_next;
  C->ch_prev = CH;
  CH->ch_next = C;
  C->ch_next->ch_prev = C;

  unlock_chunk_head (CH);
  
  MODULE_STAT->allocated_buffer_bytes += MSG_BUFFERS_CHUNK_SIZE;  
  __sync_fetch_and_add (&allocated_buffer_chunks, 1);

  MODULE_STAT->buffer_chunk_alloc_ops ++;

  while (1) {
    barrier ();
    int keep_max_allocated_buffer_chunks = max_allocated_buffer_chunks;
    barrier ();
    int keep_allocated_buffer_chunks = allocated_buffer_chunks;
    barrier ();
    if (keep_max_allocated_buffer_chunks >= keep_allocated_buffer_chunks) {
      break;
    }
    __sync_bool_compare_and_swap (&max_allocated_buffer_chunks, keep_max_allocated_buffer_chunks, keep_allocated_buffer_chunks);
    if (allocated_buffer_chunks >= max_buffer_chunks - 8 && max_buffer_chunks >= 32 && verbosity < 3) { 
      // verbosity = 3; 
      // vkprintf (1, "Setting verbosity to 3 (NOTICE) because of high buffer chunk usage (used %d, max %d)\n", allocated_buffer_chunks, max_buffer_chunks);
    }
  }
  /*if (rwm_peak_recovery) {
    if (allocated_buffer_chunks > (max_buffer_chunks >> 2)) {    
      do_udp_wait (1, 1.0);
    }
    if (allocated_buffer_chunks > (max_buffer_chunks >> 1)) {    
      do_udp_wait (2, 1.0);
    }
  }*/

  prepare_bs_inv (C);
  
  int i;
  for (i = 0; i < chunk_buffers; i++) {
    C->free_cnt[two_power+i] = 1;
  }
  memset (&C->free_cnt[two_power + chunk_buffers], 0, (two_power - chunk_buffers) * 2);

  for (i = two_power - 1; i > 0; i--) {
    C->free_cnt[i] = C->free_cnt[2*i] + C->free_cnt[2*i+1];
  }

  C->free_block_queue = alloc_mp_queue_w ();

  //vkprintf (0, "allocated chunk %p\n", C);
  return C;
};

void free_msg_buffers_chunk_internal (struct msg_buffers_chunk *C, struct msg_buffers_chunk *CH) {
  assert (C->magic == MSG_CHUNK_USED_LOCKED_MAGIC);
  unsigned magic = CH->magic;
  assert (magic == MSG_CHUNK_HEAD_MAGIC || magic == MSG_CHUNK_HEAD_LOCKED_MAGIC);
  assert (C->buffer_size == CH->buffer_size);
  assert (C->tot_buffers == C->free_cnt[1]);
  assert (CH == C->ch_head);
  
  C->magic = 0;
  C->ch_head = 0;

  lock_chunk_head (CH);
  C->ch_next->ch_prev = C->ch_prev;
  C->ch_prev->ch_next = C->ch_next;

  CH->tot_buffers -= C->tot_buffers;
  CH->free_buffers -= C->tot_buffers;
  CH->tot_chunks--;
  unlock_chunk_head (CH);
  
  assert (CH->tot_chunks >= 0);  

  __sync_fetch_and_add (&allocated_buffer_chunks, -1);
  MODULE_STAT->allocated_buffer_bytes -= MSG_BUFFERS_CHUNK_SIZE;

  memset (C, 0, sizeof (struct msg_buffers_chunk));
  free (C);

  int si = buffer_size_values - 1;
  while (si > 0 && &ChunkHeaders[si-1] != CH) {
    si--;
  }
  assert (si >= 0);

  if (ChunkSave[si] == C) {
    ChunkSave[si] = NULL;
  }
  
  free_mp_queue (C->free_block_queue);
  C->free_block_queue = NULL;
}


void free_msg_buffers_chunk (struct msg_buffers_chunk *C) {
  assert (C->magic == MSG_CHUNK_USED_LOCKED_MAGIC);
  assert (C->free_cnt[1] == C->tot_buffers);

  free_msg_buffers_chunk_internal (C, C->ch_head);
}

int init_msg_buffers (long max_buffer_bytes) {
  if (!max_buffer_bytes) {
    max_buffer_bytes = max_allocated_buffer_bytes ?: MSG_DEFAULT_MAX_ALLOCATED_BYTES;
  }

  assert (max_buffer_bytes >= 0 && max_buffer_bytes <= MSG_MAX_ALLOCATED_BYTES);
  assert (max_buffer_bytes >= allocated_buffer_chunks * MSG_BUFFERS_CHUNK_SIZE);

  max_allocated_buffer_bytes = max_buffer_bytes;
  max_buffer_chunks = (unsigned long) max_buffer_bytes / MSG_BUFFERS_CHUNK_SIZE;

  if (!buffer_size_values) {
    init_buffer_chunk_headers ();
  }

  return 1;
}

static inline int get_buffer_no (struct msg_buffers_chunk *C, struct msg_buffer *X) {
  unsigned x = ((char *) X - (char *) C->first_buffer);
  x >>= C->bs_shift;
  x *= C->bs_inverse;
  assert (x <= (unsigned) C->tot_buffers && (char *) X == (char *) C->first_buffer + (C->buffer_size + 16) * x);
  return x;
}

struct msg_buffer *alloc_msg_buffer_internal (struct msg_buffer *neighbor, struct msg_buffers_chunk *CH, struct msg_buffers_chunk *C_hint, int si) {
  unsigned magic = CH->magic;
  assert (magic == MSG_CHUNK_HEAD_MAGIC || magic == MSG_CHUNK_HEAD_LOCKED_MAGIC);
  struct msg_buffers_chunk *C;
  if (!C_hint) {
    C = alloc_new_msg_buffers_chunk (CH);
    if (!C) {
      return 0;
    }
  } else {
    int found = 0;
    if (C_hint && C_hint->free_cnt[1] && try_lock_chunk (C_hint)) {
      assert (C_hint->ch_head == CH);
      C = C_hint;
      if (C_hint->free_cnt[1]) {
        found = 1;
      } else {
        unlock_chunk (C_hint);
      }
    }
    if (!found) {
      lock_chunk_head (CH);
      struct msg_buffers_chunk *CF = C_hint ? C_hint : CH->ch_next;
      C = CF;
      do {
        if (C == CH) {
          C = C->ch_next;
          continue;
        }
        if (!C->free_cnt[1]) {
          C = C->ch_next;
          continue;
        }
        if (!try_lock_chunk (C)) {
          C = C->ch_next;
          continue;
        }
        if (!C->free_cnt[1]) {
          unlock_chunk (C);
          C = C->ch_next;
          continue;
        }
        found = 1;
        break;
      } while (C != CF);
      unlock_chunk_head (CH);
      if (!found) {
        C = alloc_new_msg_buffers_chunk (CH);
        if (!C) {
          return 0;
        }
      }
      if (C_hint) {
        __sync_fetch_and_add (&C_hint->refcnt, -1);
      }
    }
  }
    
  assert (C != CH);
  assert (C->free_cnt[1]);
  assert (C->magic == MSG_CHUNK_USED_LOCKED_MAGIC);
  ChunkSave[si] = C;

  int two_power = C->two_power, i = 1;

  if (neighbor && neighbor->chunk == C) {
    int x = get_buffer_no (C, neighbor);
    vkprintf (3, "alloc_msg_buffer: allocating neighbor buffer for %d\n", x);
      
    int k = 0;
    if (x < two_power - 1 && C->free_cnt[two_power + x + 1]) {
      i = two_power + x + 1;
    } else {
      int j = 1, l = 0, r = two_power;
      while (i < two_power) {
        i <<= 1;
        int m = (l + r) >> 1;
        if (x < m) {
          if (C->free_cnt[i] > 0) {
            r = m;
            if (C->free_cnt[i+1] > 0) {
              j = i + 1;
            }
          } else {
            l = m;
            i++;
          }
        } else if (C->free_cnt[i+1] > 0) {
          l = m;
          i++;
        } else {
          k = i = j;
          while (i < two_power) {
            i <<= 1;
            if (!C->free_cnt[i]) {
              i++;
            }
            assert (-- C->free_cnt[i] >= 0);
          }
          break;
        }
      }
    }
    if (!k) {
      k = i;
    }
    while (k > 0) {
      assert (-- C->free_cnt[k] >= 0);
      k >>= 1;
    }
  } else {
    int j = C->free_cnt[1] < 16 ? C->free_cnt[1] : 16;
    j = ((long long) lrand48_j() * j) >> 31;
    assert (j >= 0 && j < C->free_cnt[1]);
    while (i < two_power) {
      assert (-- C->free_cnt[i] >= 0);
      i <<= 1;
      if (C->free_cnt[i] <= j) {
        j -= C->free_cnt[i];
        i++;
      }
    }
    assert (-- C->free_cnt[i] == 0);
  }

  assert (C != CH);
  unlock_chunk (C);
  //-- CH->free_buffers;

  i -= two_power;
  vkprintf (3, "alloc_msg_buffer(%d) [chunk %p, size %d]: tot_buffers = %d, free_buffers = %d\n", i, C, C->buffer_size, CH->tot_buffers, CH->free_buffers);
  assert (i >= 0 && i < C->tot_buffers);

  struct msg_buffer *X = (struct msg_buffer *) ((char *) C->first_buffer + i * (C->buffer_size + 16));

  X->chunk = C;
  X->refcnt = 1;
  X->magic = MSG_BUFFER_USED_MAGIC;

  //__sync_fetch_and_add (&total_used_buffers, 1);
  MODULE_STAT->total_used_buffers_size += C->buffer_size;
  MODULE_STAT->total_used_buffers ++;
  
  return X;
}

/* allocates buffer of at least given size, -1 = maximal */
struct msg_buffer *alloc_msg_buffer (struct msg_buffer *neighbor, int size_hint) {
  if (!buffer_size_values) {
    init_buffer_chunk_headers ();
  }
  int si = buffer_size_values - 1;
  if (size_hint >= 0) {
    while (si > 0 && ChunkHeaders[si-1].buffer_size >= size_hint) {
      si--;
    }
  }
  return alloc_msg_buffer_internal (neighbor, &ChunkHeaders[si], ChunkSave[si], si);
}

int free_std_msg_buffer (struct msg_buffers_chunk *C, struct msg_buffer *X) {
  assert (!X->refcnt && X->magic == MSG_BUFFER_USED_MAGIC && C->magic == MSG_CHUNK_USED_LOCKED_MAGIC && X->chunk == C);
  int x = get_buffer_no (C, X);
  int two_power = C->two_power;
  vkprintf (3, "free_msg_buffer(%d)\n", x);
  x += two_power;
  assert (!C->free_cnt[x]);
  do {
    assert (++C->free_cnt[x] > 0);
  } while (x >>= 1);

  X->magic = MSG_BUFFER_FREE_MAGIC;
  X->refcnt = -0x40000000;
  //++ C->ch_head->free_buffers;
  
  MODULE_STAT->total_used_buffers --;
  MODULE_STAT->total_used_buffers_size -= C->buffer_size;

  //if (C->free_cnt[1] == C->tot_buffers && C->ch_head->free_buffers * 4 >= C->tot_buffers * 5) {
  //  free_msg_buffers_chunk (C);
  //}

  return 1;
}

static int free_msg_buffer_job (job_t job, int op, struct job_thread *JT) {
  switch (op) {
  case JS_RUN: {
    struct msg_buffer *X = *(void **)job->j_custom;
    struct msg_buffers_chunk *C = X->chunk;
    unsigned magic = C->magic;
    assert (magic == MSG_CHUNK_USED_MAGIC || magic == MSG_CHUNK_USED_LOCKED_MAGIC);
    C->free_buffer (C, X);
    return JOB_COMPLETED;
  }
  case JS_FINISH:
    assert (job->j_refcnt == 1);
    return job_free (JOB_REF_PASS (job));
  default:
    assert (0);
  }
}

int free_msg_buffer (struct msg_buffer *X) {
  if (X->magic != MSG_BUFFER_USED_MAGIC) {
    vkprintf (0, "magic = 0x%08x\n", X->magic);
  }
  assert (X->magic == MSG_BUFFER_USED_MAGIC);
  assert (!X->refcnt);
  struct msg_buffers_chunk *C = X->chunk;
  unsigned magic = C->magic;
  assert (magic == MSG_CHUNK_USED_MAGIC || magic == MSG_CHUNK_USED_LOCKED_MAGIC);
  
  if (C->free_buffer == free_std_msg_buffer) {
    if (try_lock_chunk (C)) {
      C->free_buffer (C, X);
      unlock_chunk (C);
      return 1;
    } else {
      mpq_push_w (C->free_block_queue, X, 0);

      if (try_lock_chunk (C)) {
        unlock_chunk (C);
      }
      return 1;
    }
  } else {
    if (!this_job_thread || this_job_thread->thread_class == C->thread_class) {
      return C->free_buffer (C, X);
    } else {
      job_t job = create_async_job (free_msg_buffer_job, JSC_ALLOW (C->thread_class, JS_RUN) | JSIG_FAST (JS_FINISH), C->thread_subclass, sizeof (void *), 0, JOB_REF_NULL);
      *(void **)job->j_custom = X;
      schedule_job (JOB_REF_PASS (job));
      return 1;
    }
  }
}

int msg_buffer_reach_limit (double ratio) {
  return SB_SUM_LL(total_used_buffers_size) >= ratio * max_allocated_buffer_bytes;
}

double msg_buffer_usage (void) {
  return (double) SB_SUM_LL(total_used_buffers_size) / (double) max_allocated_buffer_bytes;
}
