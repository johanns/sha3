/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#ifndef _DIGEST_H_
#define _DIGEST_H_

#ifdef  __cplusplus
extern "C" {
#endif

// From ruby/ext/openssl/ossl_digest.c
#define GETMDX(obj, mdx) do {                                    \
  Data_Get_Struct((obj), MDX, (mdx));                            \
  if (!(mdx)) {                                                  \
    rb_raise(rb_eRuntimeError, "Digest data not initialized!");  \
  }                                                              \
} while (0)

#define SAFEGETMDX(obj, mdx) do {                                \
  if (!rb_obj_is_kind_of(obj, cSHA3Digest)) {                        \
    rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)",\
             rb_obj_classname(obj), rb_class2name(cSHA3Digest));     \
  }                                                              \
  GETMDX(obj, mdx);                                              \
} while(0)

extern VALUE cSHA3Digest;
extern VALUE eSHA3DigestError;

typedef struct {
  Keccak_HashInstance *state;
  int hashbitlen;
} MDX;

void Init_sha3_n_digest(void);

#ifdef  __cplusplus
}
#endif

#endif
