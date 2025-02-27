/* Copyright (c) 2012 - 2025 Johanns Gregorian <io+sha3@jsg.io> */

#include "sha3.h"

/* -------------------------------------------------------------------------
   Added static ID values so we initialize once and avoid repeated calls
   to rb_intern in get_hlen()
   ------------------------------------------------------------------------- */
static ID sha3_224_id;
static ID sha3_256_id;
static ID sha3_384_id;
static ID sha3_512_id;
static ID shake_128_id;
static ID shake_256_id;

VALUE mSHA3;
VALUE eSHA3Error;

int get_hlen(VALUE obj, algorithm_type* algorithm) {
    if (TYPE(obj) == T_SYMBOL) {
        ID symid = SYM2ID(obj);

        if (symid == sha3_224_id) {
            *algorithm = SHA3_224;
            return 224;
        } else if (symid == sha3_256_id) {
            *algorithm = SHA3_256;
            return 256;
        } else if (symid == sha3_384_id) {
            *algorithm = SHA3_384;
            return 384;
        } else if (symid == sha3_512_id) {
            *algorithm = SHA3_512;
            return 512;
        } else if (symid == shake_128_id) {
            *algorithm = SHAKE_128;
            return 128;
        } else if (symid == shake_256_id) {
            *algorithm = SHAKE_256;
            return 256;
        }

        rb_raise(eSHA3Error,
                 "invalid hash algorithm symbol (should be: :sha3_224, "
                 ":sha3_256, :sha3_384, :sha3_512, :shake_128, or :shake_256)");
    } else if (TYPE(obj) == T_FIXNUM) {
        int hlen = NUM2INT(obj);

        switch (hlen) {
            case 224:
                *algorithm = SHA3_224;
                return hlen;
            case 256:
                *algorithm = SHA3_256;
                return hlen;
            case 384:
                *algorithm = SHA3_384;
                return hlen;
            case 512:
                *algorithm = SHA3_512;
                return hlen;
            default:
                rb_raise(rb_eArgError,
                         "invalid hash bit length (should be: 224, 256, 384, or 512)");
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
    shake_128_id = rb_intern("shake_128");
    shake_256_id = rb_intern("shake_256");

    Init_sha3_n_digest();
}
