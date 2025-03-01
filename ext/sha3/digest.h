// Copyright (c) 2012 - 2025 Johanns Gregorian <io+sha3@jsg.io>

#ifndef _DIGEST_H_
#define _DIGEST_H_

#include <ruby.h>
#include <ruby/encoding.h>
#include <string.h>

#include "KeccakHash.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { SHA3_224 = 0, SHA3_256, SHA3_384, SHA3_512, SHAKE_128, SHAKE_256 } sha3_digest_algorithms;

typedef HashReturn (*keccak_init_func)(Keccak_HashInstance*);

typedef struct {
    Keccak_HashInstance* state;
    int hashbitlen;
    sha3_digest_algorithms algorithm;
} sha3_digest_context_t;

VALUE _sha3_digest_class;
VALUE _sha3_digest_error_class;

/* Static IDs for faster symbol lookup */
static ID _sha3_224_id;
static ID _sha3_256_id;
static ID _sha3_384_id;
static ID _sha3_512_id;
static ID _shake_128_id;
static ID _shake_256_id;

// TypedData functions
extern const rb_data_type_t sha3_digest_data_type_t;

// Static inline functions replacing macros
static inline void get_sha3_digest_context(VALUE obj, sha3_digest_context_t** context) {
    TypedData_Get_Struct((obj), sha3_digest_context_t, &sha3_digest_data_type_t, (*context));
    if (!(*context)) {
        rb_raise(rb_eRuntimeError, "Digest data not initialized!");
    }
}

static inline void safe_get_sha3_digest_context(VALUE obj, sha3_digest_context_t** context) {
    if (!rb_obj_is_kind_of(obj, _sha3_digest_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(obj),
                 rb_class2name(_sha3_digest_class));
    }
    get_sha3_digest_context(obj, context);
}

/* Allocation and initialization */
static VALUE rb_sha3_digest_alloc(VALUE);
static VALUE rb_sha3_digest_init(int, VALUE*, VALUE);

/* Core digest operations */
static VALUE rb_sha3_digest_copy(VALUE, VALUE);
static VALUE rb_sha3_digest_finish(int, VALUE*, VALUE);
static VALUE rb_sha3_digest_reset(VALUE);
static VALUE rb_sha3_digest_update(VALUE, VALUE);

/* Digest properties */
static VALUE rb_sha3_digest_block_length(VALUE);
static VALUE rb_sha3_digest_length(VALUE);
static VALUE rb_sha3_digest_name(VALUE);

/* Output methods */
static VALUE rb_sha3_digest_digest(int, VALUE*, VALUE);
static VALUE rb_sha3_digest_hexdigest(int, VALUE*, VALUE);
static VALUE rb_sha3_digest_hex_squeeze(VALUE, VALUE);
static VALUE rb_sha3_digest_squeeze(VALUE, VALUE);
static VALUE rb_sha3_digest_self_digest(VALUE, VALUE, VALUE);
static VALUE rb_sha3_digest_self_hexdigest(VALUE, VALUE, VALUE);

#ifdef __cplusplus
}
#endif

#endif
