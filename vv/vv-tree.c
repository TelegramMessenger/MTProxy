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


#include <assert.h>
      
extern long long total_vv_tree_nodes;

#define SUFFIX2(a,b) a ## b
#define SUFFIX(a,b) SUFFIX2(a,b)

#ifndef TREE_NAME
#  define TREE_NAME any
#endif

#ifndef Y_TYPE
#  define Y_TYPE int
#endif

#ifndef Y_CMP
#  define Y_CMP(a,b) ((a) - (b))
#endif

#ifdef TREE_GLOBAL
#  define TREE_PREFIX
#else
#  define TREE_PREFIX static
#endif

#ifndef TREE_NODE_TYPE
#  define TREE_NODE_TYPE struct SUFFIX(tree_, TREE_NAME)
#endif

#ifndef X_TYPE
#  define X_TYPE int
#endif

#ifndef X_CMP
#  define X_CMP(a,b) ((a) - (b))
#endif

#ifndef TREE_BODY_ONLY
TREE_NODE_TYPE {
  TREE_NODE_TYPE *left, *right;
  X_TYPE x;
  Y_TYPE y;
#ifdef TREE_WEIGHT
  int weight;
#endif
#if defined(TREE_COUNT) || defined (TREE_WEIGHT)
  int count;
#endif
#ifdef TREE_PTHREAD
  int refcnt;
#endif
};

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_alloc_,TREE_NAME) (X_TYPE x, Y_TYPE y) __attribute__ ((unused, warn_unused_result));
TREE_PREFIX void SUFFIX(tree_free_,TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
#if defined(TREE_COUNT) || defined(TREE_WEIGHT)
  TREE_PREFIX void SUFFIX(tree_relax_,TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
#endif

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_lookup_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) __attribute__ ((unused));
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_lookup_next_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) __attribute__ ((unused));
#ifdef TREE_NOPTR
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_lookup_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x) __attribute__ ((unused));
TREE_PREFIX X_TYPE *SUFFIX(tree_lookup_value_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) __attribute__ ((unused));
TREE_PREFIX X_TYPE *SUFFIX(tree_lookup_value_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x) __attribute__ ((unused));
#else
TREE_PREFIX X_TYPE SUFFIX(tree_lookup_ptr_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) __attribute__ ((unused));
#ifdef TREE_PTHREAD
TREE_PREFIX X_TYPE SUFFIX(tree_lookup_sub_ptr_,TREE_NAME) (TREE_NODE_TYPE **T, X_TYPE x) __attribute__ ((unused));
#endif
#endif
TREE_PREFIX void SUFFIX(tree_split_,TREE_NAME) (TREE_NODE_TYPE **L, TREE_NODE_TYPE **R,
    TREE_NODE_TYPE *T, X_TYPE x) __attribute__ ((unused));

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_insert_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x, Y_TYPE y
#ifdef TREE_WEIGHT
  , int weight
#endif
) __attribute__ ((unused, warn_unused_result));

TREE_PREFIX void SUFFIX(tree_insert_sub_,TREE_NAME) (TREE_NODE_TYPE **T, X_TYPE x, Y_TYPE y
#ifdef TREE_WEIGHT
  , int weight
#endif
) __attribute__ ((unused));

#ifdef TREE_NOPTR
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_insert_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x, Y_TYPE y
#ifdef TREE_WEIGHT
  , int weight
#endif
) __attribute__ ((unused, warn_unused_result));
#endif
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_merge_,TREE_NAME) (TREE_NODE_TYPE *L, TREE_NODE_TYPE *R) __attribute__ ((unused, warn_unused_result));
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_delete_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) __attribute__ ((unused, warn_unused_result));
TREE_PREFIX void SUFFIX(tree_delete_sub_,TREE_NAME) (TREE_NODE_TYPE **T, X_TYPE x) __attribute__ ((unused));
#ifdef TREE_NOPTR
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_delete_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x) __attribute__ ((unused, warn_unused_result));
#endif
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_get_min_, TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_get_max_, TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
TREE_PREFIX void SUFFIX(tree_act_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE)) __attribute__ ((unused));
TREE_PREFIX void SUFFIX(tree_act_ex_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE, void *), void *ex) __attribute__ ((unused));
TREE_PREFIX void SUFFIX(tree_act_ex2_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE, void *, void *), void *ex, void *ex2) __attribute__ ((unused));
TREE_PREFIX void SUFFIX(tree_act_ex3_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE, void *, void *, void *), void *ex, void *ex2, void *ex3) __attribute__ ((unused));

TREE_PREFIX void SUFFIX(tree_check_,TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_clear_, TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
TREE_PREFIX int SUFFIX(tree_count_,TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));

#ifdef TREE_PTHREAD
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_clone_, TREE_NAME) (TREE_NODE_TYPE *T) __attribute__ ((unused));
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(get_tree_ptr_, TREE_NAME) (TREE_NODE_TYPE **T) __attribute__ ((unused));
TREE_PREFIX void SUFFIX(free_tree_ptr_, TREE_NAME)(TREE_NODE_TYPE *T) __attribute__ ((unused));
#endif

#endif

#ifndef TREE_HEADER_ONLY
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_lookup_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) {
  long long c;
  while (T && (c = X_CMP (x, T->x))) {
    T = (c < 0) ? T->left : T->right;
  }
  return T;
}

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_lookup_next_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) {
  long long c;
  TREE_NODE_TYPE *B = 0;
  while (T && (c = X_CMP (x, T->x))) {
    if (c < 0) { B = T; T = T->left; }
    else { T = T->right; }
  }
  return T ? T : B;
}

#ifdef TREE_NOPTR
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_lookup_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x) {
  long long c;
  while (T && (c = X_CMP ((*x), T->x))) {
    T = (c < 0) ? T->left : T->right;
  }
  return T;
}

TREE_PREFIX X_TYPE *SUFFIX(tree_lookup_value_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) {
  long long c;
  while (T && (c = X_CMP (x, T->x))) {
    T = (c < 0) ? T->left : T->right;
  }
  return T ? &T->x : NULL;
}

TREE_PREFIX X_TYPE *SUFFIX(tree_lookup_value_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x) {
  long long c;
  while (T && (c = X_CMP ((*x), T->x))) {
    T = (c < 0) ? T->left : T->right;
  }
  return T ? &T->x : NULL;
}
#else
TREE_PREFIX X_TYPE SUFFIX(tree_lookup_ptr_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) {
  long long c;
  while (T && (c = X_CMP (x, T->x))) {
    T = (c < 0) ? T->left : T->right;
  }
  return T ? T->x : 0;
}

#ifdef TREE_PTHREAD
TREE_PREFIX X_TYPE SUFFIX(tree_lookup_sub_ptr_,TREE_NAME) (TREE_NODE_TYPE **T, X_TYPE x) {
  TREE_NODE_TYPE *copy = SUFFIX(get_tree_ptr_,TREE_NAME)(T);

  X_TYPE R = SUFFIX(tree_lookup_ptr_,TREE_NAME) (copy, x);
  #ifdef TREE_INCREF
    if (R) {
      TREE_INCREF (R);
    }
  #endif

  SUFFIX(tree_free_,TREE_NAME) (copy);

  return R;
}
#endif
#endif

TREE_PREFIX void SUFFIX(tree_split_,TREE_NAME) (TREE_NODE_TYPE **L, TREE_NODE_TYPE **R,
    TREE_NODE_TYPE *T, X_TYPE x) {
  if (!T) { *L = *R = NULL; return; }

  #ifdef TREE_PTHREAD
  T = SUFFIX(tree_clone_,TREE_NAME) (T);
  #endif

  long long c = X_CMP (x, T->x);
  if (c < 0) {
    *R = T;
    SUFFIX(tree_split_,TREE_NAME) (L, &T->left, T->left, x);
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (*R);
    #endif
  } else {
    *L = T;
    SUFFIX(tree_split_,TREE_NAME) (&T->right, R, T->right, x);
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (*L);
    #endif
  }
}

#ifdef TREE_NOPTR
TREE_PREFIX void SUFFIX(tree_split_p_,TREE_NAME) (TREE_NODE_TYPE **L, TREE_NODE_TYPE **R,
    TREE_NODE_TYPE *T, X_TYPE *x) {
  if (!T) { *L = *R = NULL; return; }
  
  #ifdef TREE_PTHREAD
  T = SUFFIX(tree_clone_,TREE_NAME) (T);
  #endif

  long long c = X_CMP ((*x), T->x);
  if (c < 0) {
    *R = T;
    SUFFIX(tree_split_p_,TREE_NAME) (L, &T->left, T->left, x);
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (*R);
    #endif
  } else {
    *L = T;
    SUFFIX(tree_split_p_,TREE_NAME) (&T->right, R, T->right, x);
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (*L);
    #endif
  }
}
#endif


TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_insert_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x, Y_TYPE y
#ifdef TREE_WEIGHT
  , int weight
#endif
) {
  TREE_NODE_TYPE *P;
  if (!T) {
    P = SUFFIX (tree_alloc_, TREE_NAME) (x, y);
    #ifdef TREE_WEIGHT
      P->weight = weight;
    #endif
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (P);
    #endif
    return P;
  }
  
  #ifdef TREE_PTHREAD
  T = SUFFIX(tree_clone_,TREE_NAME) (T);
  #endif
  long long c = Y_CMP (y, T->y);
  if (c < 0) {
    c = X_CMP (x, T->x);
    assert (c);
    if (c < 0) {
      T->left = SUFFIX(tree_insert_,TREE_NAME) (T->left, x, y
      #ifdef TREE_WEIGHT
      ,weight
      #endif
      );
    } else {
      T->right = SUFFIX(tree_insert_,TREE_NAME) (T->right, x, y
      #ifdef TREE_WEIGHT
      ,weight
      #endif
      );
    }
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (T);
    #endif
    return T;
  }
  P = SUFFIX (tree_alloc_, TREE_NAME) (x, y);
  #ifdef TREE_WEIGHT
    P->weight = weight;
  #endif
  SUFFIX(tree_split_,TREE_NAME) (&P->left, &P->right, T, x);
  #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
    SUFFIX(tree_relax_,TREE_NAME) (P);
  #endif
  return P;
}

TREE_PREFIX void SUFFIX(tree_insert_sub_,TREE_NAME) (TREE_NODE_TYPE **T, X_TYPE x, Y_TYPE y
#ifdef TREE_WEIGHT
  , int weight
#endif
) {
  #ifdef TREE_PTHREAD
    TREE_NODE_TYPE *TT = *T;

    if (TT) {
      __sync_fetch_and_add (&TT->refcnt, 1);
    }
  #endif

  *T = SUFFIX(tree_insert_,TREE_NAME)(*T, x, y 
    #ifdef TREE_WEIGHT
    , weight
    #endif
    );
  
  #ifdef TREE_PTHREAD
    if (TT) {
      mfence ();
      SUFFIX(free_tree_ptr_,TREE_NAME)(TT);
    }
  #endif
}

#ifdef TREE_NOPTR
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_insert_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x, Y_TYPE y
#ifdef TREE_WEIGHT
  , int weight
#endif
) {
  TREE_NODE_TYPE *P;
  if (!T) {
    P = SUFFIX (tree_alloc_, TREE_NAME) (*x, y);
    #ifdef TREE_WEIGHT
      P->weight = weight;
    #endif
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (P);
    #endif
    return P;
  }
  
  #ifdef TREE_PTHREAD
  T = SUFFIX(tree_clone_,TREE_NAME) (T);
  #endif
  long long c = Y_CMP (y, T->y);
  if (c < 0) {
    c = X_CMP ((*x), T->x);
    assert (c);
    if (c < 0) {
      T->left = SUFFIX(tree_insert_p_,TREE_NAME) (T->left, x, y
      #ifdef TREE_WEIGHT
      ,weight
      #endif
      );
    } else {
      T->right = SUFFIX(tree_insert_p_,TREE_NAME) (T->right, x, y
      #ifdef TREE_WEIGHT
      ,weight
      #endif
      );
    }
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (T);
    #endif
    return T;
  }
  P = SUFFIX (tree_alloc_, TREE_NAME) (*x, y);
  #ifdef TREE_WEIGHT
    P->weight = weight;
  #endif
  SUFFIX(tree_split_p_,TREE_NAME) (&P->left, &P->right, T, x);
  #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
    SUFFIX(tree_relax_,TREE_NAME) (P);
  #endif
  return P;
}
#endif

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_merge_,TREE_NAME) (TREE_NODE_TYPE *L, TREE_NODE_TYPE *R) {
  if (!L) { return R; }
  if (!R) { return L; }
  if (Y_CMP (L->y, R->y) > 0) {
    #ifdef TREE_PTHREAD
      L = SUFFIX(tree_clone_,TREE_NAME) (L);
    #endif
    L->right = SUFFIX (tree_merge_,TREE_NAME) (L->right, R);
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (L);
    #endif
    return L;
  } else {
    #ifdef TREE_PTHREAD
      R = SUFFIX(tree_clone_,TREE_NAME) (R);
    #endif
    R->left = SUFFIX (tree_merge_,TREE_NAME) (L, R->left);
    #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
      SUFFIX(tree_relax_,TREE_NAME) (R);
    #endif
    return R;
  }
}

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_delete_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE x) {
  assert (T);
  #ifdef TREE_PTHREAD
    T = SUFFIX(tree_clone_,TREE_NAME) (T);
  #endif
  long long c = X_CMP (x, T->x);
  if (!c) {
    TREE_NODE_TYPE *N = SUFFIX(tree_merge_,TREE_NAME) (T->left, T->right);

    T->left = T->right = NULL;
    SUFFIX(tree_free_,TREE_NAME)(T);
    return N;
  } else  if (c < 0) {
    T->left = SUFFIX(tree_delete_,TREE_NAME) (T->left, x);
  } else {
    T->right = SUFFIX(tree_delete_,TREE_NAME) (T->right, x);
  }
  #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
    SUFFIX(tree_relax_,TREE_NAME) (T);
  #endif
  return T;
}

TREE_PREFIX void SUFFIX(tree_delete_sub_,TREE_NAME) (TREE_NODE_TYPE **T, X_TYPE x) {
  #ifdef TREE_PTHREAD
    TREE_NODE_TYPE *TT = *T;

    if (TT) {
      __sync_fetch_and_add (&TT->refcnt, 1);
    }
  #endif

  *T = SUFFIX(tree_delete_,TREE_NAME)(*T, x);
  
  #ifdef TREE_PTHREAD
    if (TT) {
      mfence ();
      SUFFIX(free_tree_ptr_,TREE_NAME)(TT);
    }
  #endif
}

#ifdef TREE_NOPTR
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_delete_p_,TREE_NAME) (TREE_NODE_TYPE *T, X_TYPE *x) {
  assert (T);
  #ifdef TREE_PTHREAD
    T = SUFFIX(tree_clone_,TREE_NAME) (T);
  #endif
  long long c = X_CMP ((*x), T->x);
  if (!c) {
    TREE_NODE_TYPE *N = SUFFIX(tree_merge_,TREE_NAME) (T->left, T->right);

    T->left = T->right = NULL;
    SUFFIX(tree_free_,TREE_NAME)(T);
    return N;
  } else  if (c < 0) {
    T->left = SUFFIX(tree_delete_p_,TREE_NAME) (T->left, x);
  } else {
    T->right = SUFFIX(tree_delete_p_,TREE_NAME) (T->right, x);
  }
  #if defined(TREE_COUNT) || defined(TREE_WEIGHT)
    SUFFIX(tree_relax_,TREE_NAME) (T);
  #endif
  return T;
}
#endif

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_get_min_, TREE_NAME) (TREE_NODE_TYPE *T) {
  while (T && T->left) {
    T = T->left;
  }
  return T;
}

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_get_max_, TREE_NAME) (TREE_NODE_TYPE *T) {
  while (T && T->right) {
    T = T->right;
  }
  return T;
}

TREE_PREFIX void SUFFIX(tree_act_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE x)) {
  if (!T) { return; }
  SUFFIX(tree_act_, TREE_NAME)(T->left, act);
  act (T->x);
  SUFFIX(tree_act_, TREE_NAME)(T->right, act);
}

TREE_PREFIX void SUFFIX(tree_act_ex_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE, void *), void *ex) {
  if (!T) { return; }
  SUFFIX(tree_act_ex_, TREE_NAME)(T->left, act, ex);
  act (T->x, ex);
  SUFFIX(tree_act_ex_, TREE_NAME)(T->right, act, ex);
}

TREE_PREFIX void SUFFIX(tree_act_ex2_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE, void *, void *), void *ex, void *ex2) {
  if (!T) { return; }
  SUFFIX(tree_act_ex2_, TREE_NAME)(T->left, act, ex, ex2);
  act (T->x, ex, ex2);
  SUFFIX(tree_act_ex2_, TREE_NAME)(T->right, act, ex, ex2);
}

TREE_PREFIX void SUFFIX(tree_act_ex3_, TREE_NAME) (TREE_NODE_TYPE *T, void (*act)(X_TYPE, void *, void *, void *), void *ex, void *ex2, void *ex3) {
  if (!T) { return; }
  SUFFIX(tree_act_ex3_, TREE_NAME)(T->left, act, ex, ex2, ex3);
  act (T->x, ex, ex2, ex3);
  SUFFIX(tree_act_ex3_, TREE_NAME)(T->right, act, ex, ex2, ex3);
}


#ifndef TREE_PTHREAD
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_clear_, TREE_NAME) (TREE_NODE_TYPE *T) {
  if (!T) {
    return 0;
  }
  SUFFIX(tree_clear_, TREE_NAME) (T->left);
  SUFFIX(tree_clear_, TREE_NAME) (T->right);
  SUFFIX(tree_free_, TREE_NAME) (T);
  return 0;
}
#else
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_clear_, TREE_NAME) (TREE_NODE_TYPE *T) {
  if (!T) {
    return 0;
  }
  SUFFIX(tree_free_, TREE_NAME) (T);
  return 0;
}
#endif

TREE_PREFIX void SUFFIX(tree_check_,TREE_NAME) (TREE_NODE_TYPE *T) {
  if (!T) {
    return;
  }
  if (T->left) { assert (Y_CMP (T->left->y, T->y) <= 0); assert (X_CMP (T->left->x, T->x) < 0); }
  if (T->right) { assert (Y_CMP (T->right->y, T->y) <= 0); assert (X_CMP (T->right->x, T->x) > 0); }
  SUFFIX (tree_check_, TREE_NAME) (T->left);
  SUFFIX (tree_check_, TREE_NAME) (T->right);
}

TREE_PREFIX int SUFFIX(tree_count_,TREE_NAME) (TREE_NODE_TYPE *T) {
  if (!T) {
    return 0;
  }
  return 1 + SUFFIX (tree_count_, TREE_NAME) (T->left) + SUFFIX (tree_count_, TREE_NAME) (T->right);
}


TREE_PREFIX TREE_NODE_TYPE *SUFFIX (tree_alloc_, TREE_NAME) (X_TYPE x, Y_TYPE y) {
  TREE_NODE_TYPE *T = 
  #ifndef TREE_MALLOC
    zmalloc0 (sizeof (*T));
  #else
    calloc (sizeof (*T), 1);
  #endif
  T->x = x;
  T->y = y;
  #ifdef TREE_PTHREAD
  T->refcnt = 1;
  #endif
  T->left = T->right = NULL;
  __sync_fetch_and_add (&total_vv_tree_nodes, 1);
  return T;
}


TREE_PREFIX void SUFFIX (tree_free_, TREE_NAME) (TREE_NODE_TYPE *T) {
  #ifdef TREE_PTHREAD
    if (!T) { return; }
    if (__sync_fetch_and_add (&T->refcnt, -1) > 1) {
      return;
    }
    assert (!T->refcnt);
    if (T->left) { SUFFIX (tree_free_, TREE_NAME) ( T->left ); }
    if (T->right) { SUFFIX (tree_free_, TREE_NAME) ( T->right ); }
  #else
    assert (T);
  #endif
  #ifdef TREE_DECREF
    TREE_DECREF (T->x);
  #endif
  #ifndef TREE_MALLOC
    zfree (T, sizeof (*T));
  #else
    free (T);
  #endif
  __sync_fetch_and_add (&total_vv_tree_nodes, -1);
}

#ifdef TREE_PTHREAD
TREE_PREFIX TREE_NODE_TYPE *SUFFIX(tree_clone_, TREE_NAME) (TREE_NODE_TYPE *T) {
  assert (T);
  #ifdef TREE_INCREF
    TREE_INCREF (T->x);
  #endif
  TREE_NODE_TYPE *R = SUFFIX (tree_alloc_, TREE_NAME) (T->x, T->y);
  assert (R);

  if (T->left) {
    __sync_fetch_and_add (&T->left->refcnt, 1);
    R->left = T->left;
  }
  
  if (T->right) {
    __sync_fetch_and_add (&T->right->refcnt, 1);
    R->right = T->right;
  }

  SUFFIX (tree_free_, TREE_NAME) (T);
  return R;
}
#endif


#ifdef TREE_COUNT
TREE_PREFIX void SUFFIX(tree_relax_,TREE_NAME)  (TREE_NODE_TYPE *T) {
  T->count = 1 + (T->left ? T->left->count : 0) + (T->right ? T->right->count : 0);
}
#endif
#ifdef TREE_WEIGHT
TREE_PREFIX void SUFFIX(tree_relax_,TREE_NAME)  (TREE_NODE_TYPE *T) {
  T->count = T->weight + (T->left ? T->left->count : 0) + (T->right ? T->right->count : 0);
}
#endif

#ifdef TREE_PTHREAD

TREE_PREFIX void SUFFIX(incref_tree_ptr_,TREE_NAME) (TREE_NODE_TYPE *T) {
  if (T) {
    assert (__sync_fetch_and_add (&T->refcnt, 1) > 0);
  }
}

TREE_PREFIX TREE_NODE_TYPE *SUFFIX(get_tree_ptr_, TREE_NAME) (TREE_NODE_TYPE **T)  {
  return get_ptr_multithread_copy ((void **)T, (void *)SUFFIX(incref_tree_ptr_,TREE_NAME));
}

TREE_PREFIX void SUFFIX(free_tree_ptr_, TREE_NAME)(TREE_NODE_TYPE *T) {
  if (T && is_hazard_ptr (T, COMMON_HAZARD_PTR_NUM, COMMON_HAZARD_PTR_NUM)) {
    struct free_later *F = malloc (sizeof (*F));
    F->ptr = T;
    F->free = (void *)SUFFIX(free_tree_ptr_, TREE_NAME);
    insert_free_later_struct (F);
  } else {
    SUFFIX(tree_free_, TREE_NAME) (T);
  }
}

#endif



#endif
#undef TREE_NAME
#undef Y_TYPE
#undef Y_CMP
#undef TREE_GLOBAL
#undef TREE_NODE_TYPE
#undef X_TYPE
#undef X_CMP
#undef SUFFIX2
#undef SUFFIX
#undef TREE_NOPTR
#undef TREE_GLOBAL
#undef TREE_MALLOC
#undef TREE_COUNT
#undef TREE_WEIGHT
#undef TREE_PREFIX
#undef TREE_INCREF
#undef TREE_DECREF
#undef TREE_HEADER_ONLY
#undef TREE_BODY_ONLY
#undef TREE_PTHREAD
