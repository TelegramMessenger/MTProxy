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
              2012-2013 Vitaliy Valtman              
    
    Copyright 2014-2016 Telegram Messenger Inc             
              2014-2016 Vitaly Valtman     
*/

struct tree_any_ptr {
  struct tree_any_ptr *left, *right;
  void *x;
  int y;
};

static inline void tree_act_any (struct tree_any_ptr *T, void (*f)(void *)) {
  if (!T) { return; }
  tree_act_any (T->left, f);
  f (T->x);
  tree_act_any (T->right, f);
}

static inline void tree_act_any_ex (struct tree_any_ptr *T, void (*f)(void *, void *), void *extra) {
  if (!T) { return; }
  tree_act_any_ex (T->left, f, extra);
  f (T->x, extra);
  tree_act_any_ex (T->right, f, extra);
}

static inline void tree_act_any_ex2 (struct tree_any_ptr *T, void (*f)(void *, void *, void *), void *extra, void *extra2) {
  if (!T) { return; }
  tree_act_any_ex2 (T->left, f, extra, extra2);
  f (T->x, extra, extra2);
  tree_act_any_ex2 (T->right, f, extra, extra2);
}

static inline void tree_act_any_ex3 (struct tree_any_ptr *T, void (*f)(void *, void *, void *, void *), void *extra, void *extra2, void *extra3) {
  if (!T) { return; }
  tree_act_any_ex3 (T->left, f, extra, extra2, extra3);
  f (T->x, extra, extra2, extra3);
  tree_act_any_ex3 (T->right, f, extra, extra2, extra3);
}


#define DEFINE_HASH(prefix,name,value_t,value_compare,value_hash) \
  prefix hash_elem_ ## name ## _t *hash_lookup_ ## name (hash_table_ ## name ## _t *T, value_t x) __attribute__ ((unused)); \
  prefix void hash_insert_ ## name (hash_table_ ## name ## _t *T, value_t x) __attribute__ ((unused)); \
  prefix int hash_delete_ ## name (hash_table_ ## name ## _t *T, value_t x) __attribute__ ((unused)); \
  prefix void hash_clear_ ## name (hash_table_ ## name ## _t *T) __attribute__ ((unused)); \
  prefix void hash_clear_act_ ## name (hash_table_ ## name ## _t *T, void (*act)(value_t)) __attribute__ ((unused)); \
  prefix hash_elem_ ## name ## _t *hash_lookup_ ## name (hash_table_ ## name ## _t *T, value_t x) { \
    long long hash = value_hash (x); if (hash < 0) { hash = -hash; } if (hash < 0) { hash = 0;} \
    if (T->mask) { hash = hash & T->mask;} \
    else { hash %= (T->size);}  \
    if (!T->E[hash]) { return 0; } \
    hash_elem_ ## name ## _t *E = T->E[hash]; \
    do { \
      if (!value_compare (E->x, x)) { return E; } \
      E = E->next; \
    } while (E != T->E[hash]); \
    return 0; \
  } \
  \
  prefix void hash_insert_ ## name (hash_table_ ## name ## _t *T, value_t x) { \
    long long hash = value_hash (x); if (hash < 0) { hash = -hash; } if (hash < 0) { hash = 0;} \
    if (T->mask) { hash = hash & T->mask;} \
    else { hash %= (T->size);}  \
    hash_elem_ ## name ## _t *E = hash_alloc_ ## name (x); \
    if (T->E[hash]) { \
      E->next = T->E[hash]; \
      E->prev = T->E[hash]->prev; \
      E->next->prev = E; \
      barrier (); \
      E->prev->next = E; \
    } else { \
      E->next = E; \
      E->prev = E; \
      barrier (); \
      T->E[hash] = E; \
    } \
  } \
  \
  prefix int hash_delete_ ## name (hash_table_ ## name ## _t *T, value_t x) { \
    long long hash = value_hash (x); if (hash < 0) { hash = -hash; } if (hash < 0) { hash = 0;} \
    if (T->mask) { hash = hash & T->mask;} \
    else { hash %= (T->size);}  \
    if (!T->E[hash]) { return 0; } \
    hash_elem_ ## name ## _t *E = T->E[hash]; \
    int ok = 0; \
    do { \
      if (!value_compare (E->x, x)) { ok = 1; break; } \
      E = E->next; \
    } while (E != T->E[hash]); \
    if (!ok) { return 0; } \
    E->next->prev = E->prev; \
    E->prev->next = E->next; \
    if (T->E[hash] != E) { \
      hash_free_ ## name (E); \
    } else if (E->next == E) { \
      T->E[hash] = 0; \
      hash_free_ ## name (E); \
    } else { \
      T->E[hash] = E->next; \
      hash_free_ ## name (E); \
    } \
    return 1; \
  } \
  \
  prefix void hash_clear_ ## name (hash_table_ ## name ## _t *T) { \
    int i; \
    for (i = 0; i < T->size; i++) { \
      if (T->E[i]) { \
        hash_elem_ ## name ## _t *cur = T->E[i]; \
        hash_elem_ ## name ## _t *first = cur; \
        do { \
          void *next = cur->next; \
          hash_free_ ## name (cur); \
          cur = next; \
        } while (cur != first); \
        T->E[i] = 0; \
      } \
    } \
  } \
  \
  prefix void hash_clear_act_ ## name (hash_table_ ## name ## _t *T, void (*act)(value_t)) { \
    int i; \
    for (i = 0; i < T->size; i++) { \
      if (T->E[i]) { \
        hash_elem_ ## name ## _t *cur = T->E[i]; \
        hash_elem_ ## name ## _t *first = cur; \
        do { \
          void *next = cur->next; \
          act (cur->x); \
          hash_free_ ## name (cur); \
          cur = next; \
        } while (cur != first); \
        T->E[i] = 0; \
      } \
    } \
  } \


#define DEFINE_HASH_STD_ALLOC_PREFIX(prefix,name,value_t,value_compare,value_hash)\
  DECLARE_HASH_TYPE(name,value_t) \
  prefix hash_elem_ ## name ## _t *hash_alloc_ ## name (value_t x);                                          \
  prefix void hash_free_ ## name (hash_elem_ ## name ## _t *T);                                                  \
  DEFINE_HASH(prefix,name,value_t,value_compare,value_hash); \
  hash_elem_ ## name ## _t *hash_alloc_ ## name (value_t x) { \
    hash_elem_ ## name ## _t *E = zmalloc (sizeof (*E)); \
    E->x = x; \
    return E; \
  } \
  void hash_free_ ## name (hash_elem_ ## name ## _t *E) { \
    zfree (E, sizeof (*E)); \
  } \

#define DEFINE_HASH_STDNOZ_ALLOC_PREFIX(prefix,name,value_t,value_compare,value_hash)\
  DECLARE_HASH_TYPE(name,value_t) \
  prefix hash_elem_ ## name ## _t *hash_alloc_ ## name (value_t x);                                          \
  prefix void hash_free_ ## name (hash_elem_ ## name ## _t *T);                                                  \
  DEFINE_HASH(prefix,name,value_t,value_compare,value_hash); \
  hash_elem_ ## name ## _t *hash_alloc_ ## name (value_t x) { \
    hash_elem_ ## name ## _t *E = malloc (sizeof (*E)); \
    E->x = x; \
    return E; \
  } \
  void hash_free_ ## name (hash_elem_ ## name ## _t *E) { \
    free (E); \
  } \

#define DEFINE_HASH_STD_ALLOC(name,value_t,value_compare,value_hash) \
  DEFINE_HASH_STD_ALLOC_PREFIX(static,name,value_t,value_compare,value_hash)

#define DEFINE_HASH_STDNOZ_ALLOC(name,value_t,value_compare,value_hash) \
  DEFINE_HASH_STDNOZ_ALLOC_PREFIX(static,name,value_t,value_compare,value_hash)

#define DECLARE_HASH_TYPE(name,value_t) \
  struct hash_elem_ ## name { \
    struct hash_elem_ ## name *next, *prev;\
    value_t x;\
  }; \
  struct hash_table_ ## name {\
    struct hash_elem_ ## name **E; \
    int size; \
    int mask; \
  }; \
  typedef struct hash_elem_ ## name hash_elem_ ## name ## _t; \
  typedef struct hash_table_ ## name hash_table_ ## name ## _t; \

#define HASH_DEG2(name,deg) \
  static struct hash_elem_ ## name *_hash_arr_ ## name[(1 << (deg))]; \
  static struct hash_table_ ## name hash_table_ ## name ## _ptr = { \
    .E = _hash_arr_ ## name, \
    .size = (1 << (deg)), \
    .mask = (1 << (deg)) - 1 \
  }; \
  static struct hash_table_ ## name *hash_table_ ## name = & hash_table_ ## name ## _ptr;


#define std_int_compare(a,b) ((a) - (b))
#define std_ll_ptr_compare(a,b) ((*(long long *)(a)) - (*(long long *)(b)))
#define std_int_hash(x) ((x) >= 0 ? (x) : -(x) >= 0 ? -(x) : 0)
