#ifndef __SHA3_H_
#define __SHA3_H_

#include <ruby.h>
#include "KeccakNISTInterface.h"

// From ruby/ext/openssl/ossl_digest.c
#define GETMDX(obj, mdx) do {                                    \
  Data_Get_Struct((obj), MDX, (mdx));                            \
  if (!(mdx)) {                                                  \
    rb_raise(rb_eRuntimeError, "Digest data not initialized!");  \
  }                                                              \
} while (0)

#define SAFEGETMDX(obj, mdx) do {                                \
  if (!rb_obj_is_kind_of(obj, cDigest)) {                        \
    rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)",\
             rb_obj_classname(obj), rb_class2name(cDigest));     \
  }                                                              \
  GETMDX(obj, mdx);                                              \
} while(0)

VALUE mSHA3;
VALUE cDigest;
VALUE eDigestError;

typedef struct {
  hashState *state;
  int hashbitlen;
} MDX;

#endif