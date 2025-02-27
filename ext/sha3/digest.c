/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#include <string.h>

#include "sha3.h"

VALUE cSHA3Digest;
VALUE eSHA3DigestError;

/*
 * == Notes
 *
 *    ::Digest::Class call sequence ->
 *    | .alloc() ->
 *    | .new() ->
 *    | .update() ->
 *    | .digest or .hexdigest or .inspect -> (Instance.digest or .hexdigest())
 * ->
 *    --| .alloc() ->
 *      | .copy() ->
 *      | .finish() ->
 *
 */

static void free_mdx(MDX* mdx) {
    if (mdx) {
        if (mdx->state) {
            free(mdx->state);
        }
        free(mdx);
    }
}

static VALUE c_digest_alloc(VALUE klass) {
    MDX* mdx = (MDX*)malloc(sizeof(MDX));
    if (!mdx) {
        rb_raise(eSHA3DigestError, "failed to allocate object memory");
    }

    mdx->state = (Keccak_HashInstance*)calloc(1, sizeof(Keccak_HashInstance));
    if (!mdx->state) {
        free_mdx(mdx);
        rb_raise(eSHA3DigestError, "failed to allocate state memory");
    }

    VALUE obj = Data_Wrap_Struct(klass, 0, free_mdx, mdx);
    mdx->hashbitlen = 0;

    return obj;
}

static VALUE c_digest_update(VALUE, VALUE);

typedef HashReturn (*keccak_init_func)(Keccak_HashInstance*);

HashReturn c_keccak_hash_initialize(MDX* mdx) {
    switch (mdx->hashbitlen) {
        case 224:
            return Keccak_HashInitialize_SHA3_224(mdx->state);
        case 256:
            return Keccak_HashInitialize_SHA3_256(mdx->state);
        case 384:
            return Keccak_HashInitialize_SHA3_384(mdx->state);
        case 512:
            return Keccak_HashInitialize_SHA3_512(mdx->state);
    }

    return KECCAK_FAIL;
}

// SHA3::Digest.new(type, [data]) -> self
static VALUE c_digest_init(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    VALUE hlen, data;

    rb_scan_args(argc, argv, "02", &hlen, &data);
    GETMDX(self, mdx);

    mdx->hashbitlen = NIL_P(hlen) ? 256 : get_hlen(hlen);

    if (c_keccak_hash_initialize(mdx) != KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to initialize algorithm state");
    }

    if (!NIL_P(data)) {
        return c_digest_update(self, data);
    }

    return self;
}

// SHA3::Digest.update(data) -> self
static VALUE c_digest_update(VALUE self, VALUE data) {
    MDX* mdx;
    BitLength dlen;

    StringValue(data);
    GETMDX(self, mdx);

    // Check for empty data
    if (RSTRING_LEN(data) == 0) {
        return self;
    }

    // Check for NULL data pointer
    if (RSTRING_PTR(data) == NULL) {
        rb_raise(eSHA3DigestError, "cannot update with NULL data");
    }

    dlen = (RSTRING_LEN(data) * 8);

    if (Keccak_HashUpdate(mdx->state, (BitSequence*)RSTRING_PTR(data), dlen) != KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to update hash data");
    }

    return self;
}

// SHA3::Digest.reset() -> self
static VALUE c_digest_reset(VALUE self) {
    MDX* mdx;
    GETMDX(self, mdx);

    memset(mdx->state, 0, sizeof(Keccak_HashInstance));

    if (c_keccak_hash_initialize(mdx) != KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to reset internal state");
    }

    return self;
}

static int cmp_states(const MDX* mdx1, const MDX* mdx2) {
    // First check the hashbitlen
    if (mdx1->hashbitlen != mdx2->hashbitlen) {
        return 0;
    }

    // Then check all the state fields
    return ((memcmp(&(mdx1->state->sponge.state), &(mdx2->state->sponge.state),
                    sizeof(mdx1->state->sponge.state)) == 0) &&
            (mdx1->state->sponge.rate == mdx2->state->sponge.rate) &&
            (mdx1->state->sponge.byteIOIndex == mdx2->state->sponge.byteIOIndex) &&
            (mdx1->state->sponge.squeezing == mdx2->state->sponge.squeezing) &&
            (mdx1->state->fixedOutputLength == mdx2->state->fixedOutputLength) &&
            (mdx1->state->delimitedSuffix == mdx2->state->delimitedSuffix));
}

// SHA3::Digest.copy(obj) -> self
static VALUE c_digest_copy(VALUE self, VALUE obj) {
    MDX *mdx1, *mdx2;

    rb_check_frozen(self);
    if (self == obj) {
        return self;
    }

    GETMDX(self, mdx1);
    SAFEGETMDX(obj, mdx2);

    memcpy(mdx1->state, mdx2->state, sizeof(Keccak_HashInstance));
    mdx1->hashbitlen = mdx2->hashbitlen;

    if (!cmp_states(mdx1, mdx2)) {
        rb_raise(eSHA3DigestError, "failed to copy state");
    }

    return self;
}

// SHA3::Digest.digest_length -> Integer
static VALUE c_digest_length(VALUE self) {
    MDX* mdx;
    GETMDX(self, mdx);

    return ULL2NUM(mdx->hashbitlen / 8);
}

// SHA3::Digest.block_length -> Integer
static VALUE c_digest_block_length(VALUE self) {
    MDX* mdx;
    GETMDX(self, mdx);

    return ULL2NUM(200 - (2 * (mdx->hashbitlen / 8)));
}

// SHA3::Digest.name -> String
static VALUE c_digest_name(VALUE self) {
    return rb_str_new2("SHA3");
}

// SHA3::Digest.finish() -> String
static VALUE c_digest_finish(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    VALUE str;
    int digest_bytes;

    rb_scan_args(argc, argv, "01", &str);
    GETMDX(self, mdx);

    digest_bytes = mdx->hashbitlen / 8;

    if (NIL_P(str)) {
        str = rb_str_new(0, digest_bytes);
    } else {
        StringValue(str);
        rb_str_resize(str, digest_bytes);
    }

    if (Keccak_HashFinal(mdx->state, (BitSequence*)RSTRING_PTR(str)) != KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to finalize digest");
    }

    return str;
}

void Init_sha3_n_digest() {
    rb_require("digest");

    /* SHA3::Digest (class) */
    cSHA3Digest = rb_define_class_under(mSHA3, "Digest", rb_path2class("Digest::Class"));
    /* SHA3::Digest::DigestError (class) */
    eSHA3DigestError = rb_define_class_under(cSHA3Digest, "DigestError", rb_eStandardError);

    // SHA3::Digest (class) methods
    rb_define_alloc_func(cSHA3Digest, c_digest_alloc);
    rb_define_method(cSHA3Digest, "initialize", c_digest_init, -1);
    rb_define_method(cSHA3Digest, "update", c_digest_update, 1);
    rb_define_method(cSHA3Digest, "reset", c_digest_reset, 0);
    rb_define_method(cSHA3Digest, "initialize_copy", c_digest_copy, 1);
    rb_define_method(cSHA3Digest, "digest_length", c_digest_length, 0);
    rb_define_method(cSHA3Digest, "block_length", c_digest_block_length, 0);
    rb_define_method(cSHA3Digest, "name", c_digest_name, 0);
    rb_define_private_method(cSHA3Digest, "finish", c_digest_finish, -1);

    rb_define_alias(cSHA3Digest, "<<", "update");
}
