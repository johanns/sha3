/* Copyright (c) 2012 - 2025 Johanns Gregorian <io+sha3@jsg.io> */

#ifndef _DIGEST_H_
#define _DIGEST_H_

#include <ruby.h>
#include <ruby/encoding.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { SHA3_224 = 0, SHA3_256, SHA3_384, SHA3_512, SHAKE_128, SHAKE_256 } algorithm_type;

typedef struct {
    Keccak_HashInstance* state;
    int hashbitlen;
    algorithm_type algorithm;
} MDX;

// TypedData functions
extern const rb_data_type_t mdx_type;

extern VALUE cSHA3Digest;
extern VALUE eSHA3DigestError;

// Static inline functions replacing macros
static inline void get_mdx(VALUE obj, MDX** mdx) {
    TypedData_Get_Struct((obj), MDX, &mdx_type, (*mdx));
    if (!(*mdx)) {
        rb_raise(rb_eRuntimeError, "Digest data not initialized!");
    }
}

static inline void safe_get_mdx(VALUE obj, MDX** mdx) {
    if (!rb_obj_is_kind_of(obj, cSHA3Digest)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(obj),
                 rb_class2name(cSHA3Digest));
    }
    get_mdx(obj, mdx);
}

void Init_sha3_n_digest(void);

#ifdef __cplusplus
}
#endif

#endif
