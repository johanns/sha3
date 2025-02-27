/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */


#include "sha3.h"
#include "digest.h"

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

// TypedData functions for MDX struct
static void mdx_free(void* ptr) {
    MDX* mdx = (MDX*)ptr;
    if (mdx) {
        if (mdx->state) {
            free(mdx->state);
        }
        free(mdx);
    }
}

static size_t mdx_memsize(const void* ptr) {
    const MDX* mdx = (const MDX*)ptr;
    size_t size = sizeof(MDX);
    if (mdx && mdx->state) {
        size += sizeof(Keccak_HashInstance);
    }
    return size;
}

const rb_data_type_t mdx_type = {"SHA3::Digest",
                                 {
                                     NULL,
                                     mdx_free,
                                     mdx_memsize,
                                 },
                                 NULL,
                                 NULL,
                                 RUBY_TYPED_FREE_IMMEDIATELY};

static VALUE c_digest_alloc(VALUE klass) {
    MDX* mdx = (MDX*)malloc(sizeof(MDX));
    if (!mdx) {
        rb_raise(eSHA3DigestError, "failed to allocate object memory");
    }

    mdx->state = (Keccak_HashInstance*)calloc(1, sizeof(Keccak_HashInstance));
    if (!mdx->state) {
        mdx_free(mdx);
        rb_raise(eSHA3DigestError, "failed to allocate state memory");
    }

    VALUE obj = TypedData_Wrap_Struct(klass, &mdx_type, mdx);
    mdx->hashbitlen = 0;
    mdx->algorithm = SHA3_256;  // Default algorithm

    return obj;
}

static VALUE c_digest_update(VALUE, VALUE);

typedef HashReturn (*keccak_init_func)(Keccak_HashInstance*);

HashReturn c_keccak_hash_initialize(MDX* mdx) {
    switch (mdx->algorithm) {
        case SHA3_224:
            return Keccak_HashInitialize_SHA3_224(mdx->state);
        case SHA3_256:
            return Keccak_HashInitialize_SHA3_256(mdx->state);
        case SHA3_384:
            return Keccak_HashInitialize_SHA3_384(mdx->state);
        case SHA3_512:
            return Keccak_HashInitialize_SHA3_512(mdx->state);
        case SHAKE_128:
            return Keccak_HashInitialize_SHAKE128(mdx->state);
        case SHAKE_256:
            return Keccak_HashInitialize_SHAKE256(mdx->state);
    }

    return KECCAK_FAIL;
}

// SHA3::Digest.new(type, [data]) -> self
static VALUE c_digest_init(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    VALUE hlen, data;

    rb_scan_args(argc, argv, "02", &hlen, &data);
    get_mdx(self, &mdx);

    if (NIL_P(hlen)) {
        mdx->algorithm = SHA3_256;
        mdx->hashbitlen = 256;
    } else {
        mdx->hashbitlen = get_hlen(hlen, &mdx->algorithm);
    }

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
    get_mdx(self, &mdx);

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
    get_mdx(self, &mdx);

    memset(mdx->state, 0, sizeof(Keccak_HashInstance));

    if (c_keccak_hash_initialize(mdx) != KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to reset internal state");
    }

    return self;
}

static int cmp_states(const MDX* mdx1, const MDX* mdx2) {
    // First check the hashbitlen and algorithm
    if (mdx1->hashbitlen != mdx2->hashbitlen || mdx1->algorithm != mdx2->algorithm) {
        return 0;
    }

    // Compare the internal state structure
    if (memcmp(&(mdx1->state->sponge.state), &(mdx2->state->sponge.state),
               sizeof(mdx1->state->sponge.state)) != 0) {
        return 0;
    }

    // Compare sponge parameters
    if ((mdx1->state->sponge.rate != mdx2->state->sponge.rate) ||
        (mdx1->state->sponge.byteIOIndex != mdx2->state->sponge.byteIOIndex) ||
        (mdx1->state->sponge.squeezing != mdx2->state->sponge.squeezing)) {
        return 0;
    }

    // Compare hash-specific parameters
    if ((mdx1->state->fixedOutputLength != mdx2->state->fixedOutputLength) ||
        (mdx1->state->delimitedSuffix != mdx2->state->delimitedSuffix)) {
        return 0;
    }

    // All comparisons passed
    return 1;
}

// SHA3::Digest.copy(obj) -> self
static VALUE c_digest_copy(VALUE self, VALUE obj) {
    MDX *mdx1, *mdx2;

    rb_check_frozen(self);
    if (self == obj) {
        return self;
    }

    get_mdx(self, &mdx1);
    safe_get_mdx(obj, &mdx2);

    memcpy(mdx1->state, mdx2->state, sizeof(Keccak_HashInstance));
    mdx1->hashbitlen = mdx2->hashbitlen;
    mdx1->algorithm = mdx2->algorithm;

    if (!cmp_states(mdx1, mdx2)) {
        rb_raise(eSHA3DigestError, "failed to copy state");
    }

    return self;
}

// SHA3::Digest.digest_length -> Integer
static VALUE c_digest_length(VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    return ULL2NUM(mdx->hashbitlen / 8);
}

// SHA3::Digest.block_length -> Integer
static VALUE c_digest_block_length(VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    return ULL2NUM(200 - (2 * (mdx->hashbitlen / 8)));
}

// SHA3::Digest.name -> String
static VALUE c_digest_name(VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    switch (mdx->algorithm) {
        case SHA3_224:
            return rb_str_new2("SHA3-224");
        case SHA3_256:
            return rb_str_new2("SHA3-256");
        case SHA3_384:
            return rb_str_new2("SHA3-384");
        case SHA3_512:
            return rb_str_new2("SHA3-512");
        case SHAKE_128:
            return rb_str_new2("SHAKE128");
        case SHAKE_256:
            return rb_str_new2("SHAKE256");
        default:
            return rb_str_new2("SHA3");
    }
}

// SHA3::Digest.finish() -> String
static VALUE c_digest_finish(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    VALUE str;
    int digest_bytes;

    rb_scan_args(argc, argv, "01", &str);
    get_mdx(self, &mdx);

    // For both SHA3 and SHAKE algorithms, use the security strength (hashbitlen)
    // as the default output length
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

// SHA3::Digest.squeeze(length) -> String
static VALUE c_digest_squeeze(VALUE self, VALUE length) {
    MDX* mdx;
    VALUE str, copy;
    int output_bytes;

    Check_Type(length, T_FIXNUM);
    output_bytes = NUM2INT(length);

    if (output_bytes <= 0) {
        rb_raise(eSHA3DigestError, "output length must be positive");
    }

    get_mdx(self, &mdx);

    // Only SHAKE algorithms support arbitrary-length output
    if (mdx->algorithm != SHAKE_128 && mdx->algorithm != SHAKE_256) {
        rb_raise(eSHA3DigestError, "squeeze is only supported for SHAKE algorithms");
    }

    // Create a copy of the digest object to avoid modifying the original
    copy = rb_obj_clone(self);

    // Get the MDX struct from the copy
    MDX* mdx_copy;
    get_mdx(copy, &mdx_copy);

    str = rb_str_new(0, output_bytes);

    // Finalize the hash on the copy
    if (Keccak_HashFinal(mdx_copy->state, NULL) != KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to finalize digest");
    }

    // Then squeeze out the desired number of bytes
    if (Keccak_HashSqueeze(mdx_copy->state, (BitSequence*)RSTRING_PTR(str), output_bytes * 8) !=
        KECCAK_SUCCESS) {
        rb_raise(eSHA3DigestError, "failed to squeeze output");
    }

    // NOTE: We don't need the copy anymore...Ruby's GC will handle freeing it

    return str;
}

// SHA3::Digest.hex_squeeze(length) -> String
static VALUE c_digest_hex_squeeze(VALUE self, VALUE length) {
    VALUE bin_str, result_array;

    // Get the binary output using the existing squeeze function
    bin_str = c_digest_squeeze(self, length);

    // Use Ruby's built-in unpack method to convert to hex
    result_array = rb_funcall(bin_str, rb_intern("unpack"), 1, rb_str_new2("H*"));

    // Extract the first element from the array
    return rb_ary_entry(result_array, 0);
}

// SHA3::Digest.digest([length]) -> String
static VALUE c_digest_digest(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    VALUE length;

    rb_scan_args(argc, argv, "01", &length);
    get_mdx(self, &mdx);

    // For SHAKE algorithms
    if (mdx->algorithm == SHAKE_128 || mdx->algorithm == SHAKE_256) {
        if (NIL_P(length)) {
            rb_raise(eSHA3DigestError, "output length must be specified for SHAKE algorithms");
        }
        return c_digest_squeeze(self, length);
    }

    // For SHA3 algorithms, call the parent implementation
    return rb_call_super(argc, argv);
}

// SHA3::Digest.hexdigest([length]) -> String
static VALUE c_digest_hexdigest(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    VALUE length;

    rb_scan_args(argc, argv, "01", &length);
    get_mdx(self, &mdx);

    // For SHAKE algorithms
    if (mdx->algorithm == SHAKE_128 || mdx->algorithm == SHAKE_256) {
        if (NIL_P(length)) {
            rb_raise(eSHA3DigestError, "output length must be specified for SHAKE algorithms");
        }
        return c_digest_hex_squeeze(self, length);
    }

    // For SHA3 algorithms, call the parent implementation
    return rb_call_super(argc, argv);
}

void Init_sha3_n_digest(void) {
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
    rb_define_method(cSHA3Digest, "squeeze", c_digest_squeeze, 1);
    rb_define_method(cSHA3Digest, "hex_squeeze", c_digest_hex_squeeze, 1);
    rb_define_method(cSHA3Digest, "digest", c_digest_digest, -1);
    rb_define_method(cSHA3Digest, "hexdigest", c_digest_hexdigest, -1);
    rb_define_private_method(cSHA3Digest, "finish", c_digest_finish, -1);

    rb_define_alias(cSHA3Digest, "<<", "update");
}
