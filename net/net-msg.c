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
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc             
              2014-2016 Vitaly Valtman
*/

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#include "sha1.h"
#include "kprintf.h"

#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "crc32c.h"
#include "crc32.h"
#include "crypto/aesni256.h"

#include "jobs/jobs.h"
#include "common/common-stats.h"
#include "common/server-functions.h"

struct raw_message empty_rwm = {
  .first = NULL,
  .last = NULL,
  .total_bytes = 0,
  .magic = RM_INIT_MAGIC,
  .first_offset = 0,
  .last_offset = 0
};

#define MODULE raw_msg

MODULE_STAT_TYPE {
  int rwm_total_msgs;
  int rwm_total_msg_parts;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_I (rwm_total_msgs);
  SB_SUM_ONE_I (rwm_total_msg_parts);
MODULE_STAT_FUNCTION_END


static inline struct msg_part *alloc_msg_part (void) { MODULE_STAT->rwm_total_msg_parts ++; struct msg_part *mp = (struct msg_part *) malloc (sizeof (struct msg_part)); mp->magic = MSG_PART_MAGIC; return mp; }
static inline void free_msg_part (struct msg_part *mp) { MODULE_STAT->rwm_total_msg_parts --; assert (mp->magic == MSG_PART_MAGIC); free (mp); }

struct msg_part *new_msg_part (struct msg_part *neighbor, struct msg_buffer *X) /* {{{ */{
  struct msg_part *mp = alloc_msg_part ();
  assert (mp);
  assert (mp->magic == MSG_PART_MAGIC);
  mp->refcnt = 1;
  mp->next = 0;
  mp->part = X;
  mp->offset = 0;
  mp->data_end = 0;
  return mp;
}
/* }}} */

#define check_msg_part_magic(x) \
  {\
    unsigned magic = (x)->magic;\
    assert (magic == MSG_PART_MAGIC || magic == MSG_PART_LOCKED_MAGIC);\
  }

static int msg_part_decref (struct msg_part *mp) /* {{{ */{
  struct msg_part *mpn;
  int cnt = 0;
  while (mp) {
    check_msg_part_magic (mp);
    if (mp->refcnt == 1) {
      mp->refcnt = 0;
    } else {
      if (__sync_fetch_and_add (&mp->refcnt, -1) > 1) {
        break;
      }
    }
  
    assert (mp->magic == MSG_PART_MAGIC);
    assert (!mp->refcnt);    
    msg_buffer_decref (mp->part);    

    mpn = mp->next;
    mp->part = 0;
    mp->next = 0;
    free_msg_part (mp); 
    mp = mpn;

    cnt ++;
  }
  return cnt;
}
/* }}} */


// after this function non-empty raw message raw should have following properties:
//   raw->last_offset = raw->last->data_end
//   raw->last->next = NULL
//   raw->last is locked, unless refcnt is 1 in full msg_part chain
struct msg_part *rwm_lock_last_part (struct raw_message *raw) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);

  if (!raw->first) { return NULL; }

  struct msg_part *locked = NULL;
  struct msg_part *mp = raw->last;
  if (mp->next || raw->last_offset != mp->data_end) {
    assert (raw->last_offset <= mp->data_end);
    // trying to append bytes to a sub-message of a longer chain, have to fork the chain
    fork_message_chain (raw);
  } else {
    if (mp->magic != MSG_PART_MAGIC || !__sync_bool_compare_and_swap (&mp->magic, MSG_PART_MAGIC, MSG_PART_LOCKED_MAGIC)) {
      fork_message_chain (raw);
    } else {
      locked = mp;
      barrier ();
      // rare case - somebody changed value mp between first check and lock
      if (mp->next || raw->last_offset != mp->data_end) {
        locked->magic = MSG_PART_MAGIC; 
        locked = NULL;
        fork_message_chain (raw);
      }
    }
  }
  return locked;
}
/* }}} */

// after this function non-empty raw message raw should have following properties:
//   raw->first_offset == raw->first->offset
struct msg_part *rwm_lock_first_part (struct raw_message *raw) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);

  if (!raw->first) { return NULL; }

  if (raw->first->refcnt == 1) {
    raw->first->offset = raw->first_offset;
    return NULL;
  }
  if (raw->first->offset == raw->first_offset) {
    return NULL;
  }

  __sync_fetch_and_add (&raw->first->part->refcnt, 1);
  struct msg_part *mp = new_msg_part (raw->first, raw->first->part);
  mp->offset = raw->first_offset;
  mp->data_end = raw->first->data_end;
  if (raw->last == raw->first) {
    raw->last = mp;
    mp->data_end = raw->last_offset;
  } else {
    mp->next = raw->first->next;
    assert (mp->next);
    __sync_fetch_and_add (&mp->next->refcnt, 1);
  }
  msg_part_decref (raw->first);
  raw->first = mp;

  return NULL;
}
/* }}} */

// struct raw_message itself is not freed since it is usually part of a larger structure
int rwm_free (struct raw_message *raw) /* {{{ */ {
  struct msg_part *mp = raw->first;
  int t = raw->magic;
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  MODULE_STAT->rwm_total_msgs --;
  memset (raw, 0, sizeof (*raw));
  return t == RM_TMP_MAGIC ? 0 : msg_part_decref (mp);
}
/* }}} */

int rwm_compare (struct raw_message *l, struct raw_message *r) /* {{{ */ {
  assert (l->magic == RM_INIT_MAGIC || l->magic == RM_TMP_MAGIC);
  assert (r->magic == RM_INIT_MAGIC || r->magic == RM_TMP_MAGIC);
  if (l && !l->total_bytes) { l = 0; }
  if (r && !r->total_bytes) { r = 0; }
  if (!l && !r) { return 0; }
  if (!l) { return -1; }
  if (!r) { return 1; }
  struct msg_part *lp = l->first;
  struct msg_part *rp = r->first;
  int lo = l->first_offset;
  int ro = r->first_offset;
  int ls = (lp == l->last) ? l->last_offset - lo : lp->data_end - lo;
  int rs = (rp == r->last) ? r->last_offset - ro : rp->data_end - ro;
  while (1) {
    if (ls && rs) {
      int z = ls > rs ? rs : ls;
      int x = memcmp (lp->part->data + lo, rp->part->data + ro, z);
      if (x != 0) { return x; }
      ls -= z;
      rs -= z;
      lo += z;
      ro += z;
    }
    if (!ls) {
      if (lp == l->last) {
        return l->total_bytes == r->total_bytes ? 0 : -1;
      }
      lp = lp->next;
      lo = lp->offset;
      ls = (lp == l->last) ? l->last_offset - lo: lp->data_end - lo;      
    }
    if (!rs) {
      if (rp == r->last) {
        return l->total_bytes == r->total_bytes ? 0 : 1;
      }
      rp = rp->next;
      ro = rp->offset;
      rs = (rp == r->last) ? r->last_offset - ro: rp->data_end - ro;
    }
  }
}
/* }}} */

// after this function non-empty raw message raw should have following properties:
//   refcnt of all msg_parts in raw is 1
//   raw->first_offset = raw->first->offset
//   raw->last_offset = raw->last->offset
//   raw->last->next = NULL
int fork_message_chain (struct raw_message *raw) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);
  struct msg_part *mp = raw->first, **mpp = &raw->first, *mpl = 0;
  int copy_last = 0, res = 0, total_bytes = raw->total_bytes;
  if (!mp) {
    return 0;
  }
  int ok = 1;
  if (raw->first_offset != mp->offset) {
    if (mp->refcnt == 1) {
      mp->offset = raw->first_offset;
    } else {
      ok = 0;
    }
  }
  while (ok && mp != raw->last && mp->refcnt == 1) {
    // can not be locked, since we have only possible link
    assert (mp->magic == MSG_PART_MAGIC); 

    total_bytes -= (mp->data_end - mp->offset);
    mpp = &mp->next;
    mpl = mp;
    mp = mp->next;
    assert (mp);
  }
  if (!ok || mp->refcnt != 1 || mp != raw->last) {
    struct msg_part *np = mp;
    while (!copy_last) {
      assert (mp);
      check_msg_part_magic (mp);
      struct msg_part *mpc = new_msg_part (mpl, mp->part);

      __sync_fetch_and_add (&mpc->part->refcnt, 1);
      mpc->offset = mp->offset;
      mpc->data_end = mp->data_end;

      if (mp == raw->first && raw->first_offset != mp->offset) {
        mpc->offset = raw->first_offset;
      }

      if (mp == raw->last) {
        mpc->data_end = raw->last_offset;
        copy_last = 1;
        raw->last = mpc;
      }
      *mpp = mpc;
      total_bytes -= (mpc->data_end - mpc->offset);
      ++res;
    
      mpp = &mpc->next;
      mpl = mpc;
      mp = mp->next;
    }
    msg_part_decref (np);
  } else {
    assert (mp == raw->last);
    assert (mp->magic == MSG_PART_MAGIC);
    if (raw->last_offset != mp->data_end) {
      mp->data_end = raw->last_offset;
    }
    total_bytes -= (mp->data_end - mp->offset);
    msg_part_decref (mp->next);
    mp->next = NULL;
  }
  if (total_bytes) {
    fprintf (stderr, "total_bytes = %d\n", total_bytes);
    rwm_dump_sizes (raw);
  }
  assert (!total_bytes);
  return res;
}
/* }}} */

void rwm_clean (struct raw_message *raw) /* {{{ */{
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  raw->first = raw->last = 0;
  raw->first_offset = raw->last_offset = 0;
  raw->total_bytes = 0;
}
/* }}} */

void rwm_clear (struct raw_message *raw) /* {{{ */{
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (raw->first && raw->magic == RM_INIT_MAGIC) {
    msg_part_decref (raw->first);
  }
  rwm_clean (raw);
}
/* }}} */

void rwm_clone (struct raw_message *dest_raw, struct raw_message *src_raw) /* {{{ */ {
  assert (src_raw->magic == RM_INIT_MAGIC || src_raw->magic == RM_TMP_MAGIC);
  memcpy (dest_raw, src_raw, sizeof (struct raw_message));
  if (src_raw->magic == RM_INIT_MAGIC && src_raw->first) {
    if (src_raw->first->refcnt == 1) {
      src_raw->first->refcnt ++;
    } else {
      __sync_fetch_and_add (&src_raw->first->refcnt, 1);
    }
  }
  MODULE_STAT->rwm_total_msgs ++;
}
/* }}} */

void rwm_move (struct raw_message *dest_raw, struct raw_message *src_raw) /* {{{ */ {
  assert (src_raw->magic == RM_INIT_MAGIC || src_raw->magic == RM_TMP_MAGIC);
  *dest_raw = *src_raw;
  memset (src_raw, 0, sizeof (*src_raw));
}
/* }}} */

int rwm_push_data_ext (struct raw_message *raw, const void *data, int alloc_bytes, int prepend, int small_buffer, int std_buffer) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);
  assert (alloc_bytes >= 0);
  if (!alloc_bytes) {
    return 0;
  }
  struct msg_part *mp, *mpl;
  int res = 0;
  struct msg_part *locked = NULL;

  if (!raw->first) {
    // create first part of empty message
    // no need to lock in this case, because refcnt in chain is 1 in newly-created message
    struct msg_buffer *X = alloc_msg_buffer (0, alloc_bytes >= small_buffer - prepend ? std_buffer : small_buffer);
    if (!X) {
      return 0;
    }
    mp = new_msg_part (0, X);
    if (alloc_bytes <= std_buffer) {
      if (prepend > std_buffer - alloc_bytes) {
        prepend = std_buffer - alloc_bytes;
      }
    }
    mp->offset = prepend;
    int sz = X->chunk->buffer_size - prepend;
    raw->first = raw->last = mp;
    raw->first_offset = prepend;
    if (sz >= alloc_bytes) {
      mp->data_end = prepend + alloc_bytes;
      raw->total_bytes = alloc_bytes;
      raw->last_offset = alloc_bytes + prepend;
      if (data) {
        memcpy (X->data + prepend, data, alloc_bytes);
      }
      return alloc_bytes;
    }
    mp->data_end = sz + prepend;
    alloc_bytes -= sz;
    raw->total_bytes = sz;
    raw->last_offset = sz + prepend;
    res = sz;
    if (data) {
      memcpy (X->data + prepend, data, sz);
      data += sz;
    }
  } else {
    // lock last part and try to add data inside last it
    locked = rwm_lock_last_part (raw);
    mp = raw->last;
    assert (mp);
    
    assert (mp && !mp->next && raw->last_offset == mp->data_end);
    struct msg_buffer *X = mp->part;

    // try to expand msg part
    // all other requirements are garanteed by rwm_lcok_last_part
    if (X->refcnt == 1) {
      int buffer_size = X->chunk->buffer_size;
      int sz = buffer_size - raw->last_offset;
      assert (sz >= 0 && sz <= buffer_size);
      if (sz > 0) {
        // can allocate sz bytes inside the last buffer in chain itself
        if (sz >= alloc_bytes) {
          if (data) {
            memcpy (X->data + raw->last_offset, data, alloc_bytes);
          }
          raw->total_bytes += alloc_bytes;
          raw->last_offset += alloc_bytes;
          mp->data_end += alloc_bytes;
          if (locked) { locked->magic = MSG_PART_MAGIC; }
          return alloc_bytes;
        }
        if (data) {
          memcpy (X->data + raw->last_offset, data, sz);
          data += sz;
        }
        raw->total_bytes += sz;
        raw->last_offset += sz;
        mp->data_end += sz;
        alloc_bytes -= sz;
      }
      res = sz;
    }
  }

  while (alloc_bytes > 0) {
    mpl = mp;
    struct msg_buffer *X = alloc_msg_buffer (mpl->part, raw->total_bytes + alloc_bytes >= std_buffer ? std_buffer : small_buffer);
    if (!X) {
      break;
    }
    mp = new_msg_part (mpl, X);
    mpl->next = raw->last = mp;
    int buffer_size = X->chunk->buffer_size;
    if (buffer_size >= alloc_bytes) {
      mp->data_end = alloc_bytes;
      raw->total_bytes += alloc_bytes;
      raw->last_offset = alloc_bytes;
      if (data) {
        memcpy (X->data, data, alloc_bytes);
      }
      res += alloc_bytes;
      break;
    }
    mp->data_end = buffer_size;
    alloc_bytes -= buffer_size;
    raw->total_bytes += buffer_size;
    raw->last_offset = buffer_size;
    res += buffer_size;
    if (data) {
      memcpy (X->data, data, buffer_size);
      data += buffer_size;
    }
  }
  if (locked) { locked->magic = MSG_PART_MAGIC; }
  return res;
}
/* }}} */

int rwm_push_data (struct raw_message *raw, const void *data, int alloc_bytes) /* {{{ */ {
  return rwm_push_data_ext (raw, data, alloc_bytes, RM_PREPEND_RESERVE, MSG_SMALL_BUFFER, MSG_STD_BUFFER);
}
/* }}} */

int rwm_push_data_front (struct raw_message *raw, const void *data, int alloc_bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);
  assert (alloc_bytes >= 0);
  if (!alloc_bytes) {
    return 0;
  }
  struct msg_part *mp = 0;
  int r = alloc_bytes;
  struct msg_part *locked = NULL;
  if (raw->first) {
    locked = rwm_lock_first_part (raw);
    mp = raw->first;
    struct msg_buffer *X = raw->first->part;
    if (X->refcnt == 1 && mp->refcnt == 1) {
      int size = raw->first_offset;
      if (alloc_bytes > size) {
        memcpy (X->data, data + (alloc_bytes - size), size);
        alloc_bytes -= size;
        raw->first_offset = raw->first->offset = 0;
        raw->total_bytes += size;
      } else {
        memcpy (X->data + size - alloc_bytes, data, alloc_bytes);
        raw->first->offset -= alloc_bytes;
        raw->first_offset = raw->first->offset;
        raw->total_bytes += alloc_bytes;
        if (locked) { locked->magic = MSG_PART_MAGIC; }
        return r;
      }
    }
  }
  while (alloc_bytes) {
    struct msg_buffer *X = alloc_msg_buffer (raw->first ? raw->first->part : 0, alloc_bytes >= MSG_SMALL_BUFFER ? MSG_STD_BUFFER : MSG_SMALL_BUFFER);
    assert (X);
    int size = X->chunk->buffer_size;
    mp = new_msg_part (raw->first, X);
    mp->next = raw->first;
    raw->first = mp;

    if (alloc_bytes > size) {
      memcpy (X->data, data + (alloc_bytes - size), size);
      alloc_bytes -= size;
      mp->data_end = size;
      mp->offset = 0;
      raw->total_bytes += size;
      if (!raw->last) {
        raw->last = mp;
        raw->last_offset = mp->data_end;
      }
    } else {
      memcpy (X->data + size - alloc_bytes, data, alloc_bytes);
      mp->data_end = size;
      mp->offset = (size - alloc_bytes);
      raw->first_offset = mp->offset;
      raw->total_bytes += alloc_bytes;
      if (!raw->last) {
        raw->last = mp;
        raw->last_offset = mp->data_end;
      }
      
      if (locked) { locked->magic = MSG_PART_MAGIC; }
      return r;
    }
  }
  assert (0);
  return r;
}
/* }}} */

int rwm_create (struct raw_message *raw, const void *data, int alloc_bytes) /* {{{ */ {
  MODULE_STAT->rwm_total_msgs ++;
  memset (raw, 0, sizeof (*raw));
  raw->magic = RM_INIT_MAGIC;
  return rwm_push_data (raw, data, alloc_bytes);
}
/* }}} */

int rwm_init (struct raw_message *raw, int alloc_bytes) /* {{{ */ {
  return rwm_create (raw, 0, alloc_bytes);
}
/* }}} */

void *rwm_prepend_alloc (struct raw_message *raw, int alloc_bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);
  assert (alloc_bytes >= 0);
  if (!alloc_bytes || alloc_bytes > MSG_STD_BUFFER) {
    return 0;
  }
  // struct msg_part *mp, *mpl;
  // int res = 0;
  if (!raw->first) {
    rwm_push_data (raw, 0, alloc_bytes);
    assert (raw->first == raw->last);
    assert (raw->total_bytes == alloc_bytes);
    return raw->first->part->data + raw->first_offset;
  }

  struct msg_part *locked = rwm_lock_first_part (raw);
  assert (raw->first_offset == raw->first->offset);
    
  if (raw->first->refcnt == 1 && raw->first->offset >= alloc_bytes && raw->first->part->refcnt == 1) {
    raw->first->offset -= alloc_bytes;
    raw->first_offset -= alloc_bytes;
    raw->total_bytes += alloc_bytes;
    if (locked) { locked->magic = MSG_PART_MAGIC; }
    return raw->first->part->data + raw->first_offset;
  }

  assert (raw->first_offset == raw->first->offset);
  struct msg_buffer *X = alloc_msg_buffer (raw->first ? raw->first->part : 0, alloc_bytes);
  assert (X);  
  int size = X->chunk->buffer_size;
  assert (size >= alloc_bytes);
  struct msg_part *mp = new_msg_part (raw->first, X);
  mp->next = raw->first;
  raw->first = mp;
  mp->data_end = size;
  mp->offset = size - alloc_bytes;
  raw->first_offset = mp->offset;
  raw->total_bytes += alloc_bytes;
  if (locked) { locked->magic = MSG_PART_MAGIC; }
  return raw->first->part->data + mp->offset;
}
/* }}} */

void *rwm_postpone_alloc (struct raw_message *raw, int alloc_bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC);
  assert (alloc_bytes >= 0);
  if (!alloc_bytes || alloc_bytes > MSG_STD_BUFFER) {
    return 0;
  }
  // struct msg_part *mp, *mpl;
  // int res = 0;
  if (!raw->first) {
    rwm_push_data (raw, 0, alloc_bytes);
    assert (raw->first == raw->last);
    assert (raw->total_bytes == alloc_bytes);
    return raw->first->part->data + raw->first_offset;
  }

  struct msg_part *locked = rwm_lock_last_part (raw);
  struct msg_part *mp = raw->last;
  
  int size = mp->part->chunk->buffer_size;
  if (size - mp->data_end >= alloc_bytes && mp->part->refcnt == 1) {
    raw->total_bytes += alloc_bytes;
    mp->data_end += alloc_bytes;
    raw->last_offset += alloc_bytes;
    if (locked) { locked->magic = MSG_PART_MAGIC; }
    return mp->part->data + mp->data_end - alloc_bytes;
  }
  struct msg_buffer *X = alloc_msg_buffer (mp->part, alloc_bytes);
  assert (X);
  size = X->chunk->buffer_size;
  assert (size >= alloc_bytes);
  
  mp = new_msg_part (raw->first, X);
  raw->last->next = mp;
  raw->last = mp;
 
  mp->data_end = alloc_bytes;
  mp->offset = 0;
  raw->last_offset = alloc_bytes;
  raw->total_bytes += alloc_bytes;
  
  if (locked) { locked->magic = MSG_PART_MAGIC; }
  return mp->part->data;
}
/* }}} */

int rwm_prepare_iovec (const struct raw_message *raw, struct iovec *iov, int iov_len, int bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (bytes > raw->total_bytes) {
    bytes = raw->total_bytes;
  }
  assert (bytes >= 0);
  int res = 0, total_bytes = raw->total_bytes, first_offset = raw->first_offset;
  struct msg_part *mp = raw->first;
  while (bytes > 0) {
    assert (mp);
    if (res == iov_len) {
      return -1;
    }
    int sz = (mp == raw->last ? raw->last_offset : mp->data_end) - first_offset;
    if (bytes < sz) {
      iov[res].iov_base = mp->part->data + first_offset;
      iov[res++].iov_len = bytes;
      return res;
    }
    iov[res].iov_base = mp->part->data + first_offset;
    iov[res++].iov_len = sz;
    bytes -= sz;
    total_bytes -= sz;
    if (!mp->next) {
      assert (mp == raw->last && !bytes && !total_bytes);
      return res;
    }
    mp = mp->next;
    first_offset = mp->offset;
  }
  return res;
}
/* }}} */

int rwm_process_memcpy (void *extra, const void *data, int len) /* {{{ */ {
  if (extra) {
    char **d = extra;
    memcpy (*d, data, len);
    *d += len;
  }
  return 0;
}
/* }}} */

int rwm_fetch_data_back (struct raw_message *raw, void *data, int bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (bytes > raw->total_bytes) {
    bytes = raw->total_bytes;
  }
  assert (bytes >= 0);
  if (!bytes) {
    return 0;
  }

  return rwm_process_ex (raw, bytes, raw->total_bytes - bytes, RMPF_TRUNCATE, rwm_process_memcpy, data ? &data : NULL);
}
/* }}} */

int rwm_fetch_lookup_back (struct raw_message *raw, void *data, int bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (bytes > raw->total_bytes) {
    bytes = raw->total_bytes;
  }
  assert (bytes >= 0);
  if (!bytes) {
    return 0;
  }

  return rwm_process_ex (raw, bytes, raw->total_bytes - bytes, 0, rwm_process_memcpy, data ? &data : NULL);
}
/* }}} */

int rwm_trunc (struct raw_message *raw, int len) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (len >= raw->total_bytes) { 
    return raw->total_bytes;
  }
  rwm_fetch_data_back (raw, 0, raw->total_bytes - len);
  return len;
}
/* }}} */

int rwm_split (struct raw_message *raw, struct raw_message *tail, int bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  assert (bytes >= 0);
  MODULE_STAT->rwm_total_msgs ++;
  tail->magic = raw->magic;
  if (bytes >= raw->total_bytes) { 
    tail->first = tail->last = 0;
    tail->first_offset = tail->last_offset = 0;
    tail->total_bytes = 0;
    return bytes == raw->total_bytes ? 0 : -1;
  }
  if (raw->total_bytes - bytes <= raw->last_offset - raw->last->offset) {
    int s = raw->total_bytes - bytes;
    raw->last_offset -= s;
    raw->total_bytes -= s;
    tail->first = tail->last = raw->last;
    if (raw->magic == RM_INIT_MAGIC) {
      __sync_fetch_and_add (&tail->first->refcnt, 1);
    }

    tail->first_offset = raw->last_offset;
    tail->last_offset = raw->last_offset + s;
    tail->total_bytes = s;
    return 0;
  }
  tail->total_bytes = raw->total_bytes - bytes;
  raw->total_bytes = bytes;
  struct msg_part *mp = raw->first;
  int ok = 1;
  while (bytes) {
    assert (mp);
    int sz = (mp == raw->last ? raw->last_offset : mp->data_end) - (mp == raw->first ? raw->first_offset : mp->offset);
    if (mp->refcnt != 1) { ok = 0; }
    if (sz < bytes) {
      bytes -= sz;
      mp = mp->next;
    } else {
      tail->last = raw->last;
      tail->last_offset = raw->last_offset;
      raw->last = mp;
      raw->last_offset = (mp == raw->first ? raw->first_offset : mp->offset) + bytes;
      tail->first = mp;
      tail->first_offset = raw->last_offset;
      
      if (raw->magic == RM_INIT_MAGIC) {
        if (ok) {
          mp->refcnt ++;
        } else {
          __sync_fetch_and_add (&mp->refcnt, 1);
        }
      }
      bytes = 0;
    }
  }
  return 0;
}
/* }}} */

int rwm_split_head (struct raw_message *head, struct raw_message *raw, int bytes) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  *head = *raw;
  return rwm_split (head, raw, bytes);
}
/* }}} */

int rwm_union (struct raw_message *raw, struct raw_message *tail) /* {{{ */ {
  //rwm_check (raw);
  //rwm_check (tail);
  assert (raw->magic == RM_INIT_MAGIC);
  struct msg_part *locked = NULL; 
//  assert (raw != tail);
  if (!raw->last) {
    *raw = *tail;
    MODULE_STAT->rwm_total_msgs --;
    tail->magic = 0;
    return 0;
  } else if (tail->first) {
    locked = rwm_lock_last_part (raw);
    
    // this code ensures that this function will not create message with loop
    // if there would be loop, that last msg_part in chains of raw and tail are same
    // then they can not be simultaneously locked, so this call will make copy of chain
    struct msg_part *l2 = rwm_lock_last_part (tail);     
    if (l2) { l2->magic = MSG_PART_MAGIC; }

    l2 = rwm_lock_first_part (tail);      
    raw->last->next = tail->first;
    __sync_fetch_and_add (&tail->first->refcnt, 1);

    raw->last_offset = tail->last_offset;
    raw->last = tail->last;
    raw->total_bytes += tail->total_bytes;

    if (l2) { l2->magic = MSG_PART_MAGIC; }
  }
  rwm_free (tail);
  //rwm_check (raw);
  if (locked) { locked->magic = MSG_PART_MAGIC; }
  return 0;
}
/* }}} */

int rwm_dump_sizes (struct raw_message *raw) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (!raw->first) { 
    fprintf (stderr, "( ) # %d\n", raw->total_bytes);
    assert (!raw->total_bytes);
  } else {
    int total_size  = 0;
    struct msg_part *mp = raw->first;
    fprintf (stderr, "(");
    while (mp != 0) {
      int size = (mp == raw->last ? raw->last_offset : mp->data_end) - (mp == raw->first ? raw->first_offset : mp->offset);
      fprintf (stderr, " %d", size);
      total_size += size;
      if (mp == raw->last) { break; }
      mp = mp->next;
    }
    assert (mp == raw->last);
    fprintf (stderr, " ) # %d\n", raw->total_bytes);
    assert (total_size == raw->total_bytes);
  }
  return 0;
}
/* }}} */

int rwm_check (struct raw_message *raw) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  if (!raw->first) { 
    assert (!raw->total_bytes);
  } else {
    int total_size  = 0;
    struct msg_part *mp = raw->first;
    assert (raw->first_offset >= raw->first->offset);
    assert (raw->last_offset <= raw->last->data_end);
    while (mp != 0) {
      int size = (mp == raw->last ? raw->last_offset : mp->data_end) - (mp == raw->first ? raw->first_offset : mp->offset);
      assert (mp->offset >= 0);
      assert (mp->data_end <= mp->part->chunk->buffer_size);
      total_size += size;
      if (mp == raw->last) { break; }
      mp = mp->next;
    }
    assert (mp == raw->last);
    if (total_size != raw->total_bytes) {
      fprintf (stderr, "total_size = %d, total_bytes = %d\n", total_size, raw->total_bytes);
      rwm_dump_sizes (raw);
    }
    assert (total_size == raw->total_bytes);
  }
  return 0;
}
/* }}} */

int rwm_dump (struct raw_message *raw) /* {{{ */ {
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  struct raw_message t;
  rwm_clone (&t, raw);
  static char R[10004];
  int r = rwm_fetch_data (&t, R, 10004);
  int x = (r > 10000) ? 10000 : r;
  hexdump (R, R + x);
  if (r > x) {
    fprintf (stderr, "%d bytes not printed\n", raw->total_bytes - x);
  }
  rwm_free (&t);
  return 0;
}
/* }}} */

int rwm_process_ex (struct raw_message *raw, int bytes, int offset, int flags, int (*process_block)(void *extra, const void *data, int len), void *extra) /* {{{ */ {
  //rwm_check (raw);
  assert (raw->magic == RM_INIT_MAGIC || raw->magic == RM_TMP_MAGIC);
  
  assert (bytes >= 0);
  assert (offset >= 0);
  if (bytes + offset > raw->total_bytes) {
    bytes = raw->total_bytes - offset;
  }
  if (bytes <= 0) { return 0; }

  // correct, because if raw->last == raw->first all bytes garanteed to be in this (only) msg part
  if (raw->total_bytes - offset <= raw->last_offset - raw->last->offset) {
    int x = raw->total_bytes - offset;
    int r = process_block (extra, raw->last->part->data + raw->last_offset - x, bytes);

    if (r >= 0) {
      if (flags & RMPF_ADVANCE) {
        if (raw->magic == RM_INIT_MAGIC) {
          __sync_fetch_and_add (&raw->last->refcnt, 1);
          msg_part_decref (raw->first);
        }
        raw->first = raw->last;
        raw->first_offset = raw->last_offset - x + bytes;
        raw->total_bytes -= offset + bytes;
      }
      if (flags & RMPF_TRUNCATE) {
        raw->total_bytes -= x;
        raw->last_offset -= x;
      }
    } else {
      return r;
    }

    //rwm_check (raw);
    return bytes;
  }

  int x = bytes, r;
  struct msg_part *mp = raw->first;
  int ok = 1;
  int save_offset = offset;
  while (mp) {
    check_msg_part_magic (mp);
    if (mp->refcnt != 1) { ok = 0; }
    int start = (mp == raw->first) ? raw->first_offset : mp->offset;
    int len = (mp == raw->last) ? raw->last_offset - start : mp->data_end - start;

    if (len >= offset) {
      start += offset;
      len -= offset;

      struct msg_part *np = mp;
      int save_start = start;

      int ok2 = ok;
      while (bytes) {
        if (len >= bytes) {
          r = bytes > 0 ? process_block (extra, mp->part->data + start, bytes) : 0;
          len = bytes; // to set last_offset
          bytes = 0;
        } else {
          r = len > 0 ? process_block (extra, mp->part->data + start, len) : 0;
          bytes -= len;
        }
        if (r < 0) {
          //rwm_check (raw);
          return r;
        }
        
        if (!bytes) { break; }
        mp = mp->next;
        assert (mp);
        start = (mp == raw->first) ? raw->first_offset : mp->offset;
        len = (mp == raw->last) ? raw->last_offset - start : mp->data_end - start;
        assert (mp);
        if (mp->refcnt != 1) { ok2 = 0; }
      }

      if (flags & RMPF_ADVANCE) {
        if (save_offset + x == raw->total_bytes) {
          rwm_clear (raw); 
        } else {
          if (raw->magic == RM_INIT_MAGIC && mp != raw->first) {
            if (ok2) {
              mp->refcnt ++;
            } else {
              __sync_fetch_and_add (&mp->refcnt, 1);
            }
            msg_part_decref (raw->first);
          }

          raw->first = mp;
          raw->first_offset = start + len; 

          if (ok2 && raw->magic == RM_INIT_MAGIC) {
            mp->offset = start + len;
          }
          raw->total_bytes -= save_offset + x; 
        }
      }

      if (flags & RMPF_TRUNCATE) {
        if (!save_offset) {
          rwm_clear (raw);
        } else {
          raw->total_bytes = save_offset;

          raw->last = np;
          raw->last_offset = save_start;

          if (ok) {
            raw->last->data_end = raw->last_offset;
            msg_part_decref (raw->last->next);
            raw->last->next = NULL;
          }
        }
      }

      if (!raw->total_bytes) {
        rwm_clear (raw);
      }
      //rwm_check (raw);
      return x;
    }
    offset -= len;
    mp = mp->next;
  }
  assert (0);
  return 0;
}
/* }}} */

int rwm_process_and_advance (struct raw_message *raw, int bytes, int (*process_block)(void *extra, const void *data, int len), void *extra) /* {{{ */ {
  return rwm_process_ex (raw, bytes, 0, RMPF_ADVANCE, process_block, extra); 
}
/* }}} */

int rwm_process (struct raw_message *raw, int bytes, int (*process_block)(void *extra, const void *data, int len), void *extra) /* {{{ */ {
  return rwm_process_ex (raw, bytes, 0, 0, process_block, extra); 
}
/* }}} */

int rwm_process_from_offset (struct raw_message *raw, int bytes, int offset, int (*process_block)(void *extra, const void *data, int len), void *extra) /* {{{ */{
  return rwm_process_ex (raw, bytes, offset, 0, process_block, extra); 
}
/* }}} */

int rwm_transform_from_offset (struct raw_message *raw, int bytes, int offset, int (*transform_block)(void *extra, void *data, int len), void *extra) /* {{{ */ {
  return rwm_process_ex (raw, bytes, offset, 0, (void *)transform_block, extra); 
}
/* }}} */

/* rwm_sha1 {{{ */
int sha1_wrap (void *extra, const void *data, int len) {
  sha1_update (extra, (void *)data, len);
  return 0;
}

int rwm_sha1 (struct raw_message *raw, int bytes, unsigned char output[20]) {
  sha1_context *ctx = EVP_MD_CTX_new();

  sha1_starts (ctx);
  int res = rwm_process (raw, bytes, sha1_wrap, ctx);
  sha1_finish (ctx, output);
  EVP_MD_CTX_free(ctx);

  return res;
}
/* }}} */

/* {{{ crc32c */
static int crc32c_process (void *extra, const void *data, int len) {
  unsigned crc32c = *(unsigned *)extra;
  *(unsigned *)extra = crc32c_partial (data, len, crc32c);
  return 0;
}

unsigned rwm_crc32c (struct raw_message *raw, int bytes) {
  unsigned crc32c = ~0;

  assert (rwm_process (raw, bytes, crc32c_process, &crc32c) == bytes);

  return ~crc32c;
}
/* }}} */

/* {{{ crc32 */
static int crc32_process (void *extra, const void *data, int len) {
  unsigned crc32 = *(unsigned *)extra;
  *(unsigned *)extra = crc32_partial (data, len, crc32);
  return 0;
}

unsigned rwm_crc32 (struct raw_message *raw, int bytes) {
  unsigned crc32 = ~0;

  assert (rwm_process (raw, bytes, crc32_process, &crc32) == bytes);

  return ~crc32;
}
/* }}} */

/* custom crc32 {{{ */
struct custom_crc32_data {
  crc32_partial_func_t partial;
  unsigned crc32;
};

static int custom_crc32_process (void *extra, const void *data, int len) {
  struct custom_crc32_data *DP = extra;
  DP->crc32 = DP->partial (data, len, DP->crc32);
  return 0;
}

unsigned rwm_custom_crc32 (struct raw_message *raw, int bytes, crc32_partial_func_t custom_crc32_partial) {
  struct custom_crc32_data D;
  D.partial = custom_crc32_partial;
  D.crc32 = -1;

  assert (raw->total_bytes >= bytes);
  assert (rwm_process (raw, bytes, (void *)custom_crc32_process, &D) == bytes);

  return ~D.crc32;
}
/* }}} */

int rwm_process_nop (void *extra, const void *data, int len) /* {{{ */ {
  return 0;
}
/* }}} */

int rwm_fetch_data (struct raw_message *raw, void *buf, int bytes) /* {{{ */ {
  if (buf) {
    return rwm_process_and_advance (raw, bytes, rwm_process_memcpy, &buf);
  } else {
    return rwm_process_and_advance (raw, bytes, rwm_process_nop, 0);
  }
}
/* }}} */

int rwm_skip_data (struct raw_message *raw, int bytes) /* {{{ */ {
  return rwm_process_and_advance (raw, bytes, rwm_process_nop, 0);
}
/* }}} */

int rwm_fetch_lookup (struct raw_message *raw, void *buf, int bytes) /* {{{ */ {
  if (buf) {
    return rwm_process (raw, bytes, rwm_process_memcpy, &buf);
  } else {
    return rwm_process (raw, bytes, rwm_process_nop, 0);
  }
}
/* }}} */

int rwm_get_block_ptr_bytes (struct raw_message *raw) {
  if (!raw->total_bytes) {
    return 0;
  }
  struct msg_part *mp = raw->first;
  while (1) {
    assert (mp);
    int bytes = ((mp == raw->last) ? raw->last_offset : mp->data_end) - raw->first_offset;
    if (bytes) { 
      return bytes;
    }    
    
    assert (mp != raw->last);
    if (mp->refcnt == 1) {
      raw->first = mp->next;
      mp->next = NULL;
    } else {
      raw->first = mp->next;
      __sync_fetch_and_add (&mp->next->refcnt, 1);
    }
    msg_part_decref (mp);
    raw->first_offset = raw->first->offset;
    mp = mp->next;
  }
}

void *rwm_get_block_ptr (struct raw_message *raw) {
  if (!raw->first) { return NULL; }
  return raw->first->part->data + raw->first_offset;
}

void rwm_to_tl_string (struct raw_message *raw) {
  assert (raw->magic == RM_INIT_MAGIC);
  if (raw->total_bytes < 0xfe) {
    assert (rwm_push_data_front (raw, &raw->total_bytes, 1) == 1);
  } else {
    assert (rwm_push_data_front (raw, &raw->total_bytes, 3) == 3);
    int b = 0xfe;
    assert (rwm_push_data_front (raw, &b, 1) == 1);
  }

  int pad = (-raw->total_bytes) & 3;
  if (pad) {
    int zero = 0;
    assert (rwm_push_data (raw, &zero, pad) == pad);
  }
}

void rwm_from_tl_string (struct raw_message *raw) {
  assert (raw->magic == RM_INIT_MAGIC);
  int x = 0;
  assert (raw->total_bytes > 0);
  assert (rwm_fetch_data (raw, &x, 1) == 1);
  assert (x != 0xff);
  if (x == 0xfe) {
    assert (raw->total_bytes >= 3);
    assert (rwm_fetch_data (raw, &x, 3) == 3);
  }
  assert (raw->total_bytes >= x);
  rwm_trunc (raw, x);
}

/*{{{ encrypt_decrypt */
struct rwm_encrypt_decrypt_tmp  {
  int bp;
  int buf_left;
  int left;
  int block_size;
  struct raw_message *raw;
  EVP_CIPHER_CTX *evp_ctx;
  char buf[16] __attribute__((aligned(16)));
};

int rwm_process_encrypt_decrypt (struct rwm_encrypt_decrypt_tmp *x, const void *data, int len) {
  int bsize = x->block_size;
  struct raw_message *res = x->raw;
  if (!x->buf_left) {
    struct msg_buffer *X = alloc_msg_buffer (res->last->part, x->left >= MSG_STD_BUFFER ? MSG_STD_BUFFER : x->left);
    assert (X);
    struct msg_part *mp = new_msg_part (res->last, X);
    res->last->next = mp;
    res->last = mp;
    res->last_offset = 0;
    x->buf_left = X->chunk->buffer_size;
  }
  x->left -= len;
  assert (res->last_offset >= 0);
  assert (x->buf_left >= 0);
  assert (x->buf_left + res->last_offset <= res->last->part->chunk->buffer_size);
  if (x->bp) {
    int to_fill = bsize - x->bp;
    if (len >= to_fill) {
      memcpy (x->buf + x->bp, data, to_fill);
      len -= to_fill;
      data += to_fill;
      x->bp = 0;     
      if (x->buf_left >= bsize) {
        evp_crypt (x->evp_ctx, x->buf, res->last->part->data + res->last_offset, bsize);
        res->last->data_end += bsize;
        res->last_offset += bsize;
        x->buf_left -= bsize;
      } else {
        evp_crypt (x->evp_ctx, x->buf, x->buf, bsize);
        memcpy (res->last->part->data + res->last_offset, x->buf, x->buf_left);
        int t = x->buf_left;
        res->last->data_end += t;
      
        struct msg_buffer *X = alloc_msg_buffer (res->last->part, x->left + len + bsize >= MSG_STD_BUFFER ? MSG_STD_BUFFER : x->left + len + bsize);
        assert (X);
        struct msg_part *mp = new_msg_part (res->last, X);
        res->last->next = mp;
        res->last = mp;
        res->last_offset = 0;
        x->buf_left = X->chunk->buffer_size;
        assert (x->buf_left >= bsize - t);

        memcpy (res->last->part->data, x->buf + t, bsize - t);
        res->last_offset = bsize - t;
        res->last->data_end = bsize - t;
        x->buf_left -= (bsize - t);
      }
      res->total_bytes += bsize;
    } else {
      memcpy (x->buf + x->bp, data, len);
      x->bp += len;
      return 0;
    }
  }
  if (len & (bsize - 1)) {
    int l = len & -bsize;
    memcpy (x->buf, data + l, len - l);
    x->bp = len - l;
    len = l;
  }
  assert (res->last_offset >= 0);
  assert (x->buf_left >= 0);
  assert (x->buf_left + res->last_offset <= res->last->part->chunk->buffer_size);
  while (1) {
    if (x->buf_left < bsize) {
      struct msg_buffer *X = alloc_msg_buffer (res->last->part, x->left + len >= MSG_STD_BUFFER ? MSG_STD_BUFFER : x->left + len);
      assert (X);
      struct msg_part *mp = new_msg_part (res->last, X);
      res->last->next = mp;
      res->last = mp;
      res->last_offset = 0;
      x->buf_left = X->chunk->buffer_size;
    }
    assert (res->last_offset >= 0);
    assert (x->buf_left >= 0);
    assert (x->buf_left + res->last_offset <= res->last->part->chunk->buffer_size);
    if (len <= x->buf_left) {
      assert (!(len & (bsize - 1)));
      evp_crypt (x->evp_ctx, data, (res->last->part->data + res->last_offset), len);
      res->last->data_end += len;
      res->last_offset += len;
      res->total_bytes += len;
      x->buf_left -= len;
      return 0;
    } else {
      int t = x->buf_left & -bsize;
      evp_crypt (x->evp_ctx, data, res->last->part->data + res->last_offset, t);
      res->last->data_end += t;
      res->last_offset += t;
      res->total_bytes += t;
      data += t;
      len -= t;
      x->buf_left -= t;
    }
  }
}


int rwm_encrypt_decrypt_to (struct raw_message *raw, struct raw_message *res, int bytes, EVP_CIPHER_CTX *evp_ctx, int block_size) {
  assert (bytes >= 0);
  assert (block_size && !(block_size & (block_size - 1)));
  if (bytes > raw->total_bytes) {
    bytes = raw->total_bytes;
  }
  bytes &= -block_size;
  if (!bytes) {
    return 0;
  }

  struct msg_part *locked = rwm_lock_last_part (res);
  
  if (!res->last || res->last->part->refcnt != 1) {
    int l = res->last ? bytes : bytes + RM_PREPEND_RESERVE;
    struct msg_buffer *X = alloc_msg_buffer (res->last ? res->last->part : 0, l >= MSG_STD_BUFFER ? MSG_STD_BUFFER : l);
    assert (X);
    struct msg_part *mp = new_msg_part (res->last, X);
    if (res->last) {
      res->last->next = mp;
      res->last = mp;
      res->last_offset = 0;
    } else {
      res->last = res->first = mp;
      res->last_offset = res->first_offset = mp->offset = mp->data_end = RM_PREPEND_RESERVE;
    }
  }
  struct rwm_encrypt_decrypt_tmp t;
  t.bp = 0;
  if (res->last->part->refcnt == 1) {
    t.buf_left = res->last->part->chunk->buffer_size - res->last_offset;
  } else {
    t.buf_left = 0;
  }
  t.raw = res;
  t.evp_ctx = evp_ctx;
  t.left = bytes;
  t.block_size = block_size;
  int r = rwm_process_and_advance (raw, bytes, (void *)rwm_process_encrypt_decrypt, &t);
  if (locked) {
    locked->magic = MSG_PART_MAGIC;
  }
  return r;
}
/* }}} */
