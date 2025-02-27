/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#include "sha3.h"

/* -------------------------------------------------------------------------
   Added static ID values so we initialize once and avoid repeated calls
   to rb_intern in get_hlen()
   ------------------------------------------------------------------------- */
static ID sha224_id;
static ID sha256_id;
static ID sha384_id;
static ID sha512_id;

VALUE mSHA3;
VALUE eSHA3Error;

int get_hlen(VALUE obj) {
  if (TYPE(obj) == T_SYMBOL) {
    ID symid = SYM2ID(obj);

    if (symid == sha224_id) {
      return 224;
    } else if (symid == sha256_id) {
      return 256;
    } else if (symid == sha384_id) {
      return 384;
    } else if (symid == sha512_id) {
      return 512;
    }

    rb_raise(eSHA3Error,
             "invalid hash bit symbol (should be: :sha224, "
             ":sha256, :sha384, or :sha512)");
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
  sha224_id = rb_intern("sha224");
  sha256_id = rb_intern("sha256");
  sha384_id = rb_intern("sha384");
  sha512_id = rb_intern("sha512");

  Init_sha3_n_digest();
}
