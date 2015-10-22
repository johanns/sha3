/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#ifndef _SHA3_H_
#define _SHA3_H_

#include <ruby.h>

#include "KeccakHash.h"
#include "digest.h"

#ifdef  __cplusplus
extern "C" {
#endif

extern VALUE mSHA3;
extern VALUE eSHA3Error;

int get_hlen(VALUE);
void Init_sha3_n(void);

#ifdef  __cplusplus
}
#endif

#endif
