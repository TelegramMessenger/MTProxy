#include "drand48-compat.h"
#include <string.h>   /* memset */
#include <math.h>     /* ldexp */

#ifndef __GLIBC__

/* glibc-compatible constants */
#define DR48_A   0x5deece66dULL
#define DR48_C   0x00000000bULL
#define DR48_MASK ((1ULL << 48) - 1ULL)

static inline uint64_t pack48(const unsigned short x[3]) {
  return ((uint64_t)x[0])
       | ((uint64_t)x[1] << 16)
       | ((uint64_t)x[2] << 32);
}

static inline void unpack48(uint64_t v, unsigned short x[3]) {
  x[0] = (unsigned short)(v & 0xFFFFu);
  x[1] = (unsigned short)((v >> 16) & 0xFFFFu);
  x[2] = (unsigned short)((v >> 32) & 0xFFFFu);
}

static inline void ensure_init(struct drand48_data *b) {
  if (b-> __init)
    return;

  /* Allow "zero-filled struct" init, as man page suggests. */
  b->__x[0] = 0x330e;
  b->__x[1] = 0;
  b->__x[2] = 0;
  b->__a = DR48_A;
  b->__c = (unsigned short)DR48_C;
  b->__init = 1;
}

static inline void iterate(unsigned short xsubi[3], struct drand48_data *b) {
  uint64_t x = pack48(xsubi);
  /* (a*x + c) mod 2^48 */
  x = (b->__a * x + (uint64_t)b->__c) & DR48_MASK;
  unpack48(x, xsubi);
}

int srand48_r(long int seedval, struct drand48_data *buffer) {
  /* Standards say seedval is effectively 32-bit. */
  if (sizeof(long int) > 4)
    seedval &= 0xffffffffL;

  buffer->__x[2] = (unsigned short)((uint32_t)seedval >> 16);
  buffer->__x[1] = (unsigned short)((uint32_t)seedval & 0xFFFFu);
  buffer->__x[0] = 0x330e;

  buffer->__a = DR48_A;
  buffer->__c = (unsigned short)DR48_C;
  buffer->__init = 1;
  return 0;
}

int seed48_r(unsigned short int seed16v[3], struct drand48_data *buffer) {
  ensure_init(buffer);

  buffer->__old_x[0] = buffer->__x[0];
  buffer->__old_x[1] = buffer->__x[1];
  buffer->__old_x[2] = buffer->__x[2];

  buffer->__x[0] = seed16v[0];
  buffer->__x[1] = seed16v[1];
  buffer->__x[2] = seed16v[2];

  buffer->__a = DR48_A;
  buffer->__c = (unsigned short)DR48_C;
  buffer->__init = 1;
  return 0;
}

/* param[0..2] = X, param[3..5] = A, param[6] = C */
int lcong48_r(unsigned short int param[7], struct drand48_data *buffer) {
  buffer->__x[0] = param[0];
  buffer->__x[1] = param[1];
  buffer->__x[2] = param[2];

  buffer->__a = ((unsigned long long)param[3])
              | ((unsigned long long)param[4] << 16)
              | ((unsigned long long)param[5] << 32);

  buffer->__c = param[6];
  buffer->__init = 1;
  return 0;
}

int drand48_r(struct drand48_data *buffer, double *result) {
  ensure_init(buffer);
  iterate(buffer->__x, buffer);

  uint64_t x = pack48(buffer->__x);
  /* x in [0, 2^48); convert to [0.0, 1.0) */
  *result = ldexp((double)x, -48);
  return 0;
}

int erand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, double *result) {
  ensure_init(buffer);
  iterate(xsubi, buffer);

  uint64_t x = pack48(xsubi);
  *result = ldexp((double)x, -48);
  return 0;
}

int lrand48_r(struct drand48_data *buffer, long int *result) {
  ensure_init(buffer);
  iterate(buffer->__x, buffer);

  uint64_t x = pack48(buffer->__x);
  /* non-negative in [0, 2^31) */
  *result = (long int)(x >> 17);
  return 0;
}

int nrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, long int *result) {
  ensure_init(buffer);
  iterate(xsubi, buffer);

  uint64_t x = pack48(xsubi);
  *result = (long int)(x >> 17);
  return 0;
}

int mrand48_r(struct drand48_data *buffer, long int *result) {
  ensure_init(buffer);
  iterate(buffer->__x, buffer);

  uint64_t x = pack48(buffer->__x);
  /* signed in [-2^31, 2^31) */
  int32_t v = (int32_t)(x >> 16);
  *result = (long int)v;
  return 0;
}

int jrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, long int *result) {
  ensure_init(buffer);
  iterate(xsubi, buffer);

  uint64_t x = pack48(xsubi);
  int32_t v = (int32_t)(x >> 16);
  *result = (long int)v;
  return 0;
}

#endif
