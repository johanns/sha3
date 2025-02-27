/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#ifndef _DIGEST_H_
#define _DIGEST_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  Keccak_HashInstance *state;
  int hashbitlen;
} MDX;

// TypedData functions
extern const rb_data_type_t mdx_type;

extern VALUE cSHA3Digest;
extern VALUE eSHA3DigestError;

// Static inline functions replacing macros
static inline void get_mdx(VALUE obj, MDX **mdx) {
  TypedData_Get_Struct((obj), MDX, &mdx_type, (*mdx));
  if (!(*mdx)) {
    rb_raise(rb_eRuntimeError, "Digest data not initialized!");
  }
}

static inline void safe_get_mdx(VALUE obj, MDX **mdx) {
  if (!rb_obj_is_kind_of(obj, cSHA3Digest)) {
    rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)",
             rb_obj_classname(obj), rb_class2name(cSHA3Digest));
  }
  get_mdx(obj, mdx);
}

void Init_sha3_n_digest(void);

#ifdef __cplusplus
}
#endif

#endif
