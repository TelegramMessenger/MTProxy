#pragma once

/*
  Drop-in drand48_r compat for non-glibc libcs (e.g., musl).
  Provides:
    struct drand48_data
    srand48_r, seed48_r, lcong48_r
    drand48_r, erand48_r
    lrand48_r, nrand48_r
    mrand48_r, jrand48_r

  Compile this ONLY when your libc doesn't provide these symbols,
  otherwise you'll get duplicate symbol errors.
*/

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct drand48_data {
  unsigned short int __x[3];      /* Current state. */
  unsigned short int __old_x[3];  /* Old state. */
  unsigned short int __c;         /* Additive const. */
  unsigned short int __init;      /* Init flag. */
  unsigned long long int __a;     /* Factor. */
};

int srand48_r(long int seedval, struct drand48_data *buffer);
int seed48_r(unsigned short int seed16v[3], struct drand48_data *buffer);
int lcong48_r(unsigned short int param[7], struct drand48_data *buffer);

int drand48_r(struct drand48_data *buffer, double *result);
int erand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, double *result);

int lrand48_r(struct drand48_data *buffer, long int *result);
int nrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, long int *result);

int mrand48_r(struct drand48_data *buffer, long int *result);
int jrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer, long int *result);

#ifdef __cplusplus
}
#endif
