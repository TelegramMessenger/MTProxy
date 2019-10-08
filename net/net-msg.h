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

#pragma once

#include <stdlib.h>
#include <sys/uio.h>
#include <assert.h>

#include "crypto/aesni256.h"
#include "net/net-msg-buffers.h"
#include "crc32.h"


/* INVARIANTS FOR MULTITHREAD USE:
  - any raw message is valid until you have the link
  - any tmp raw message is valid until it's parent is not modified
  - pointer to raw message implies lock on it.
  - msg part can be modified only if you have lock or you have only valid link
  - msg buffer can be modified if it's reference counter is 1 and overlying msg part can be modified
  - msg parts can not have loops
*/

/*
  msg_part mp can be expanded to left, if mp->refcnt=1, mp->part->refcnt=1, mp=raw->first, where raw is raw_message we have in this thread
  msg_part mp can be expanded to right, if mp->part->refcnt=1, mp->next=NULL and ((mp is locked) or (refcnt on chain from raw->first to mp is 1))

  it is invalid to change any msg_parts after raw->last
*/
/*
 *        MESSAGE PARTS (struct msg_part)
 */

struct msg_part {
  // fields inherited from msg_buffer
  //struct msg_buffers_chunk *chunk;
#ifndef _LP64
  int resvd;
#endif
  int refcnt;
  int magic;
  // fields specific to msg_part
  struct msg_part *next;
  struct msg_buffer *part;
  int offset;   // data offset inside part->data
  int data_end; // end of data offset inside part->data
};

extern int rwm_total_msg_parts;
extern int rwm_total_msgs;

#define MSG_PART_MAGIC 0x8341aa7
#define MSG_PART_LOCKED_MAGIC (~MSG_PART_MAGIC)
struct msg_part *new_msg_part (struct msg_part *neighbor, struct msg_buffer *X);

/*
 *        RAW MESSAGES (struct raw_message) = chains of MESSAGE PARTs
 */

// ordinary raw message (changing refcnt of pointed msg_parts)
#define        RM_INIT_MAGIC        0x23513473
// temp raw message (doesn't change refcnts of pointed msg_parts), used for fast read iterators
#define        RM_TMP_MAGIC        0x52a717f3

#define        RM_PREPEND_RESERVE        128

struct raw_message {
  struct msg_part *first, *last;        // 'last' doesn't increase refcnt of pointed msg_part
  int total_bytes;        // bytes in the chain (extra bytes ignored even if present)
  int magic;                // one of RM_INIT_MAGIC, RM_TMP_MAGIC
  int first_offset;        // offset of first used byte inside first buffer data
  int last_offset;        // offset after last used byte inside last buffer data
};

/* NB: struct raw_message itself is never allocated or freed by the following functions since 
        it is usually part (field) of a larger structure
*/

int rwm_free (struct raw_message *raw);
int rwm_init (struct raw_message *raw, int alloc_bytes);
int rwm_create (struct raw_message *raw, const void *data, int alloc_bytes);
void rwm_clone (struct raw_message *dest_raw, struct raw_message *src_raw);
void rwm_move (struct raw_message *dest_raw, struct raw_message *src_raw);
int rwm_push_data (struct raw_message *raw, const void *data, int alloc_bytes);
int rwm_push_data_ext (struct raw_message *raw, const void *data, int alloc_bytes, int prepend, int small_buffer, int std_buffer);
int rwm_push_data_front (struct raw_message *raw, const void *data, int alloc_bytes);
int rwm_fetch_data (struct raw_message *raw, void *data, int bytes);
int rwm_skip_data (struct raw_message *raw, int bytes);
int rwm_fetch_lookup (struct raw_message *raw, void *buf, int bytes);
int rwm_fetch_data_back (struct raw_message *raw, void *data, int bytes);
int rwm_fetch_lookup_back (struct raw_message *raw, void *data, int bytes);
int rwm_trunc (struct raw_message *raw, int len);
int rwm_union (struct raw_message *raw, struct raw_message *tail);
int rwm_split (struct raw_message *raw, struct raw_message *tail, int bytes);
int rwm_split_head (struct raw_message *head, struct raw_message *raw, int bytes);
void *rwm_prepend_alloc (struct raw_message *raw, int alloc_bytes);
void *rwm_postpone_alloc (struct raw_message *raw, int alloc_bytes);

void rwm_clean (struct raw_message *raw);
void rwm_clear (struct raw_message *raw);
int rwm_check (struct raw_message *raw);
int fork_message_chain (struct raw_message *raw);

int rwm_compare (struct raw_message *l, struct raw_message *r);

int rwm_prepare_iovec (const struct raw_message *raw, struct iovec *iov, int iov_len, int bytes);
int rwm_dump_sizes (struct raw_message *raw);
int rwm_dump (struct raw_message *raw);
unsigned rwm_crc32c (struct raw_message *raw, int bytes);
unsigned rwm_crc32 (struct raw_message *raw, int bytes);
unsigned rwm_custom_crc32 (struct raw_message *raw, int bytes, crc32_partial_func_t custom_crc32_partial);

int rwm_process (struct raw_message *raw, int bytes, int (*process_block)(void *extra, const void *data, int len), void *extra);

#define RMPF_ADVANCE 1
#define RMPF_TRUNCATE 2
int rwm_process_ex (struct raw_message *raw, int bytes, int offset, int flags, int (*process_block)(void *extra, const void *data, int len), void *extra);


/* negative exit code of process stops processing */
int rwm_process_from_offset (struct raw_message *raw, int bytes, int offset, int (*process_block)(void *extra, const void *data, int len), void *extra);
/* warning: in current realization refcnt of message chain should be 1 */
int rwm_transform_from_offset (struct raw_message *raw, int bytes, int offset, int (*transform_block)(void *extra, void *data, int len), void *extra);
int rwm_process_and_advance (struct raw_message *raw, int bytes, int (*process_block)(void *extra, const void *data, int len), void *extra);
int rwm_sha1 (struct raw_message *raw, int bytes, unsigned char output[20]);
int rwm_encrypt_decrypt_to (struct raw_message *raw, struct raw_message *res, int bytes, EVP_CIPHER_CTX *evp_ctx, int block_size);

void *rwm_get_block_ptr (struct raw_message *raw);
int rwm_get_block_ptr_bytes (struct raw_message *raw);

void rwm_to_tl_string (struct raw_message *raw);

extern struct raw_message empty_rwm;
void rwm_from_tl_string (struct raw_message *raw);
