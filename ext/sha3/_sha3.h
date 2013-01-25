#ifndef __SHA3_H_
#define __SHA3_H_

#include <ruby.h>

#include "KeccakNISTInterface.h"

#include "_digest.h"

extern VALUE mSHA3;
extern VALUE mSHA3Error;

int get_hlen(VALUE);
void Init_sha3_n(void);

#endif