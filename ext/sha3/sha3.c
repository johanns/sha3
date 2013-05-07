/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#include "sha3.h"

VALUE mSHA3;
VALUE eSHA3Error;

int get_hlen(VALUE obj)
{
  int hlen;

  if (TYPE(obj) == T_SYMBOL) {
    ID symid;

    symid = SYM2ID(obj);

    if (rb_intern("sha224") == symid)
      hlen = 224;
    else if (rb_intern("sha256") == symid)
      hlen = 256;
    else if (rb_intern("sha384") == symid)
      hlen = 384;
    else if (rb_intern("sha512") == symid)
      hlen = 512;
    else
      rb_raise(eSHA3Error, "invalid hash bit symbol (should be: :sha224, :sha256, :sha384, or :sha512");
  }
  else if (TYPE(obj) == T_FIXNUM) {
    hlen = NUM2INT(obj);

    if ((hlen != 224) && (hlen != 256) && (hlen != 384) && (hlen != 512))
      rb_raise(rb_eArgError, "invalid hash bit length (should be: 224, 256, 384, or 512)");
  }
  else
    rb_raise(eSHA3Error, "unknown type value");

  return hlen;
}

void Init_sha3_n()
{
  mSHA3 = rb_define_module("SHA3");
  eSHA3Error = rb_define_class_under(mSHA3, "SHA3Error", rb_eStandardError);

  Init_sha3_n_digest();
}