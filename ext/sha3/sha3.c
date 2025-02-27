/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#include "sha3.h"

/* -------------------------------------------------------------------------
   Added static ID values so we initialize once and avoid repeated calls
   to rb_intern in get_hlen()
   ------------------------------------------------------------------------- */
static ID sha3_224_id;
static ID sha3_256_id;
static ID sha3_384_id;
static ID sha3_512_id;

VALUE mSHA3;
VALUE eSHA3Error;

int get_hlen(VALUE obj) {
  if (TYPE(obj) == T_SYMBOL) {
    ID symid = SYM2ID(obj);

    if (symid == sha3_224_id) {
      return 224;
    } else if (symid == sha3_256_id) {
      return 256;
    } else if (symid == sha3_384_id) {
      return 384;
    } else if (symid == sha3_512_id) {
      return 512;
    }

    rb_raise(eSHA3Error,
             "invalid hash bit symbol (should be: :sha3_224, "
             ":sha3_256, :sha3_384, or :sha3_512)");
  } else if (TYPE(obj) == T_FIXNUM) {
    int hlen = NUM2INT(obj);

    switch (hlen) {
      case 224:
      case 256:
      case 384:
      case 512:
        return hlen;
      default:
        rb_raise(rb_eArgError, "invalid hash bit length (should be: 224, 256, 384, or 512)");
    }
  }

  rb_raise(eSHA3Error, "unknown type value");
  return 0;  // Never reached, but silences compiler warnings
}

void Init_sha3_n() {
  mSHA3 = rb_define_module("SHA3");
  eSHA3Error = rb_define_class_under(mSHA3, "SHA3Error", rb_eStandardError);

  /* Initialize static symbol IDs for faster lookup in get_hlen() */
  sha3_224_id = rb_intern("sha3_224");
  sha3_256_id = rb_intern("sha3_256");
  sha3_384_id = rb_intern("sha3_384");
  sha3_512_id = rb_intern("sha3_512");

  Init_sha3_n_digest();
}
