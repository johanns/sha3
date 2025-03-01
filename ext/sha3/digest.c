#include "digest.h"

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

/*
 * SHA3 module
 */
void Init_sha3_digest(void) {
    rb_require("digest");

    /* Initialize static symbol IDs for faster lookup in get_hlen() */
    sha3_224_id = rb_intern("sha3_224");
    sha3_256_id = rb_intern("sha3_256");
    sha3_384_id = rb_intern("sha3_384");
    sha3_512_id = rb_intern("sha3_512");
    shake_128_id = rb_intern("shake_128");
    shake_256_id = rb_intern("shake_256");

    /*
     * Document-module: SHA3
     *
     * This hosts the SHA3::Digest classes.
     */
    sha3_module = rb_define_module("SHA3");

    /*
     * Document-class: SHA3::Digest
     *
     * It is a subclass of the Digest::Class class, which provides a framework for
     * creating and manipulating hash digests.
     */
    digest_class = rb_define_class_under(sha3_module, "Digest", rb_path2class("Digest::Class"));

    /*
     * Default-const: SHA3::VERSION
     *
     * It is the version of the SHA3 module.
     */
    rb_define_const(sha3_module, "VERSION", rb_str_new2("2.0.0"));

    /*
     * Document-class: SHA3::Digest::DigestError
     *
     * It is a subclass of the StandardError class -- see the Ruby documentation
     * for more information.
     */
    digest_error_class = rb_define_class_under(digest_class, "DigestError", rb_eStandardError);

    rb_define_alloc_func(digest_class, rb_digest_alloc);
    rb_define_method(digest_class, "initialize", rb_digest_init, -1);
    rb_define_method(digest_class, "update", rb_digest_update, 1);
    rb_define_method(digest_class, "reset", rb_digest_reset, 0);
    rb_define_method(digest_class, "initialize_copy", rb_digest_copy, 1);
    rb_define_method(digest_class, "digest_length", rb_digest_length, 0);
    rb_define_method(digest_class, "block_length", rb_digest_block_length, 0);
    rb_define_method(digest_class, "name", rb_digest_name, 0);
    rb_define_method(digest_class, "squeeze", rb_digest_squeeze, 1);
    rb_define_method(digest_class, "hex_squeeze", rb_digest_hex_squeeze, 1);
    rb_define_method(digest_class, "digest", rb_digest_digest, -1);
    rb_define_method(digest_class, "hexdigest", rb_digest_hexdigest, -1);
    rb_define_private_method(digest_class, "finish", rb_digest_finish, -1);

    /* Define the class method self.digest */
    rb_define_singleton_method(digest_class, "digest", rb_digest_self_digest, 2);
    rb_define_singleton_method(digest_class, "hexdigest", rb_digest_self_hexdigest, 2);
    rb_define_alias(digest_class, "<<", "update");
}

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

        rb_raise(digest_error_class,
                 "invalid hash algorithm symbol (should be: :sha3_224, "
                 ":sha3_256, :sha3_384, :sha3_512, :shake_128, or :shake_256)");
    }

    rb_raise(digest_error_class, "unknown type value");
    return 0;  // Never reached, but silences compiler warnings
}

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

/* TypedData structure for MDX */
const rb_data_type_t mdx_type = {"SHA3::Digest",
                                 {
                                     NULL,
                                     mdx_free,
                                     mdx_memsize,
                                 },
                                 NULL,
                                 NULL,
                                 RUBY_TYPED_FREE_IMMEDIATELY};

static VALUE rb_digest_alloc(VALUE klass) {
    MDX* mdx = (MDX*)malloc(sizeof(MDX));
    if (!mdx) {
        rb_raise(digest_error_class, "failed to allocate object memory");
    }

    mdx->state = (Keccak_HashInstance*)calloc(1, sizeof(Keccak_HashInstance));
    if (!mdx->state) {
        mdx_free(mdx);
        rb_raise(digest_error_class, "failed to allocate state memory");
    }

    VALUE obj = TypedData_Wrap_Struct(klass, &mdx_type, mdx);
    mdx->hashbitlen = 0;
    mdx->algorithm = SHA3_256;  // Default algorithm

    return obj;
}

HashReturn keccak_hash_initialize(MDX* mdx) {
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

/*
 * :call-seq:
 *   ::new() -> instance
 *   ::new([algorithm], [message]) -> instance
 *
 * Creates a new digest object.
 *
 * +algorithm+::
 *   _optional_ The algorithm to use.
 *   Valid algorithms are:
 *   - :sha3_224
 *   - :sha3_256
 *   - :sha3_384
 *   - :sha3_512
 *   - :shake_128
 *   - :shake_256
 *
 * +message+::
 *   _optional_ The message to hash.
 *
 * = example
 *   SHA3::Digest.new(:sha3_256)
 *   SHA3::Digest.new(:shake_128, "initial data")
 */
static VALUE rb_digest_init(int argc, VALUE* argv, VALUE self) {
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

    if (keccak_hash_initialize(mdx) != KECCAK_SUCCESS) {
        rb_raise(digest_error_class, "failed to initialize algorithm state");
    }

    if (!NIL_P(data)) {
        return rb_digest_update(self, data);
    }

    return self;
}

/*
 * :call-seq:
 *   update(string) -> digest
 *
 * Updates the digest with the given string.
 *
 * +string+::
 *   The string to update the digest with.
 *
 * = example
 *   digest.update("more data")
 *   digest << "more data"  # alias for update
 */
static VALUE rb_digest_update(VALUE self, VALUE data) {
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
        rb_raise(digest_error_class, "cannot update with NULL data");
    }

    dlen = (RSTRING_LEN(data) * 8);

    if (Keccak_HashUpdate(mdx->state, (BitSequence*)RSTRING_PTR(data), dlen) != KECCAK_SUCCESS) {
        rb_raise(digest_error_class, "failed to update hash data");
    }

    return self;
}

/*
 * :call-seq:
 *   reset -> digest
 *
 * Resets the digest to its initial state.
 *
 * = example
 *   digest.reset
 */
static VALUE rb_digest_reset(VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    memset(mdx->state, 0, sizeof(Keccak_HashInstance));

    if (keccak_hash_initialize(mdx) != KECCAK_SUCCESS) {
        rb_raise(digest_error_class, "failed to reset internal state");
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

/*
 * :call-seq:
 *   initialize_copy(other) -> digest
 *
 * Initializes the digest with the state of another digest.
 *
 * +other+::
 *   The digest to copy the state from.
 *
 * = example
 *   new_digest = digest.dup
 */
static VALUE rb_digest_copy(VALUE self, VALUE obj) {
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
        rb_raise(digest_error_class, "failed to copy state");
    }

    return self;
}

/*
 * :call-seq:
 *   length -> Integer
 *
 * Returns the length of the digest in bytes.
 *
 * = example
 *   digest.length  #=> 32 for SHA3-256
 */
static VALUE rb_digest_length(VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    return ULL2NUM(mdx->hashbitlen / 8);
}

/*
 * :call-seq:
 *   block_length -> Integer
 *
 * Returns the block length of the algorithm in bytes.
 *
 * = example
 *   digest.block_length
 */
static VALUE rb_digest_block_length(VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    return ULL2NUM(200 - (2 * (mdx->hashbitlen / 8)));
}

/*
 * :call-seq:
 *   name -> String
 *
 * Returns the name of the algorithm.
 *
 * = example
 *   digest.name  #=> "SHA3-256"
 */
static VALUE rb_digest_name(VALUE self) {
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
            rb_raise(digest_error_class, "unknown algorithm");
    }
}

/*
 * :call-seq:
 *   finish([message]) -> String
 *
 * Returns the final digest as a binary string.
 *
 * +message+::
 *   _optional_ Update state with additional data before finalizing.
 *
 * = example
 *   digest.finish
 *   digest.finish("final chunk")
 */
static VALUE rb_digest_finish(int argc, VALUE* argv, VALUE self) {
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
        rb_raise(digest_error_class, "failed to finalize digest");
    }

    return str;
}

/*
 * :call-seq:
 *   squeeze(length) -> String
 *
 * Returns the squeezed output as a binary string. Only available for SHAKE algorithms.
 *
 * +length+::
 *   The length in bytes of the output to squeeze.
 *
 * = example
 *   digest.squeeze(32)  # Get 32 bytes of output
 */
static VALUE rb_digest_squeeze(VALUE self, VALUE length) {
    MDX* mdx;
    VALUE str, copy;
    int output_bytes;

    Check_Type(length, T_FIXNUM);
    output_bytes = NUM2INT(length);

    if (output_bytes <= 0) {
        rb_raise(digest_error_class, "output length must be positive");
    }

    get_mdx(self, &mdx);

    // Only SHAKE algorithms support arbitrary-length output
    if (mdx->algorithm != SHAKE_128 && mdx->algorithm != SHAKE_256) {
        rb_raise(digest_error_class, "squeeze is only supported for SHAKE algorithms");
    }

    // Create a copy of the digest object to avoid modifying the original
    copy = rb_obj_clone(self);

    // Get the MDX struct from the copy
    MDX* mdx_copy;
    get_mdx(copy, &mdx_copy);

    str = rb_str_new(0, output_bytes);

    // Finalize the hash on the copy
    if (Keccak_HashFinal(mdx_copy->state, NULL) != KECCAK_SUCCESS) {
        rb_raise(digest_error_class, "failed to finalize digest");
    }

    // Then squeeze out the desired number of bytes
    if (Keccak_HashSqueeze(mdx_copy->state, (BitSequence*)RSTRING_PTR(str), output_bytes * 8) !=
        KECCAK_SUCCESS) {
        rb_raise(digest_error_class, "failed to squeeze output");
    }

    // NOTE: We don't need the copy anymore...Ruby's GC will handle freeing it

    return str;
}

/*
 * :call-seq:
 *   hex_squeeze(length) -> String
 *
 * Returns the hexadecimal representation of the squeezed output. Only available for SHAKE
 * algorithms.
 *
 * +length+::
 *   The length in bytes of the output to squeeze.
 *
 * = example
 *   digest.hex_squeeze(32)  # Get 64 hex characters (32 bytes)
 */
static VALUE rb_digest_hex_squeeze(VALUE self, VALUE length) {
    VALUE bin_str, result_array;

    // Get the binary output using the existing squeeze function
    bin_str = rb_digest_squeeze(self, length);

    // Use Ruby's built-in unpack method to convert to hex
    result_array = rb_funcall(bin_str, rb_intern("unpack"), 1, rb_str_new2("H*"));

    // Extract the first element from the array
    return rb_ary_entry(result_array, 0);
}

/*
 * :call-seq:
 *   digest() -> string
 *   digest([data]) -> string
 *   digest(length) -> string
 *   digest(length, data) -> string
 *
 * Returns the binary representation of the digest.
 *
 * +length+::
 *   The length of the output to squeeze when using SHAKE algorithms.
 *   This parameter is required for SHAKE algorithms.
 *
 * +data+::
 *   _optional_ Update state with additional data before returning digest.
 *
 * = example
 *   digest.digest()
 *   digest.digest('compute me')
 *   digest.digest(12)  # For SHAKE algorithms
 *   digest.digest(12, 'compute me')  # For SHAKE algorithms
 */
static VALUE rb_digest_digest(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    if (mdx->algorithm != SHAKE_128 && mdx->algorithm != SHAKE_256) {
        return rb_call_super(argc, argv);
    }

    VALUE length, data;
    rb_scan_args(argc, argv, "02", &length, &data);

    // For SHAKE algorithms
    if (NIL_P(length)) {
        rb_raise(digest_error_class, "output length must be specified for SHAKE algorithms");
    }

    // If data is provided, update the state before squeezing
    if (!NIL_P(data)) {
        rb_digest_update(self, data);
    }

    return rb_digest_squeeze(self, length);
}

/*
 * :call-seq:
 *   hexdigest() -> string
 *   hexdigest([data]) -> string
 *   hexdigest(length) -> string
 *   hexdigest(length, data) -> string
 *
 * Returns the hexadecimal representation of the digest.
 *
 * +length+::
 *   The length of the output to squeeze when using SHAKE algorithms.
 *   This parameter is required for SHAKE algorithms.
 *
 * +data+::
 *   _optional_ Update state with additional data before returning digest.
 *
 * = example
 *   digest.hexdigest()
 *   digest.hexdigest('compute me')
 *   digest.hexdigest(12)  # For SHAKE algorithms
 *   digest.hexdigest(12, 'compute me')  # For SHAKE algorithms
 */
static VALUE rb_digest_hexdigest(int argc, VALUE* argv, VALUE self) {
    MDX* mdx;
    get_mdx(self, &mdx);

    if (mdx->algorithm != SHAKE_128 && mdx->algorithm != SHAKE_256) {
        return rb_call_super(argc, argv);
    }

    VALUE length, data;
    rb_scan_args(argc, argv, "02", &length, &data);

    if (NIL_P(length)) {
        rb_raise(digest_error_class, "output length must be specified for SHAKE algorithms");
    }

    // If data is provided, update the state before squeezing
    if (!NIL_P(data)) {
        rb_digest_update(self, data);
    }

    return rb_digest_hex_squeeze(self, length);
}

/*
 * :call-seq:
 *   SHA3::Digest.digest(name, data) -> string
 *
 * Returns the binary digest of the given +data+ using the algorithm specified by +name+.
 *
 * +name+::
 *   The hash algorithm to use (as a Symbol).
 *   Valid algorithms are:
 *   - :sha3_224
 *   - :sha3_256
 *   - :sha3_384
 *   - :sha3_512
 *   - :shake_128
 *   - :shake_256
 *
 * +data+::
 *   The data to hash.
 *
 * = example
 *   SHA3::Digest.digest(:sha3_256, "data to hash")
 *
 * = note
 * This method defaults to squeezing 16 bytes for SHAKE128 and 32 bytes for SHAKE256.
 * To squeeze a different length, use #squeeze instance method.
 */
static VALUE rb_digest_self_digest(VALUE klass, VALUE name, VALUE data) {
    VALUE args[2];
    algorithm_type algorithm;

    /* For SHAKE algorithms, we need to handle them differently */
    if (TYPE(name) == T_SYMBOL) {
        ID symid = SYM2ID(name);
        if (symid == shake_128_id || symid == shake_256_id) {
            /* Create a new digest instance with the specified algorithm */
            VALUE digest = rb_class_new_instance(1, &name, klass);

            /* Update it with the data */
            rb_digest_update(digest, data);

            /* For SHAKE algorithms, use a default output length based on the security strength */
            int output_length = (symid == shake_128_id) ? 16 : 32; /* 128/8 or 256/8 */

            /* Return the squeezed output */
            return rb_digest_squeeze(digest, INT2NUM(output_length));
        }
    }

    /* Call the superclass method with arguments in reverse order */
    args[0] = data;
    args[1] = name;

    return rb_call_super(2, args);
}

/*
 * :call-seq:
 *   SHA3::Digest.hexdigest(name, data) -> string
 *
 * Returns the hexadecimal representation of the given +data+ using the algorithm specified by
 * +name+.
 *
 * +name+::
 *   The hash algorithm to use (as a Symbol).
 *   Valid algorithms are:
 *   - :sha3_224
 *   - :sha3_256
 *   - :sha3_384
 *   - :sha3_512
 *   - :shake_128
 *   - :shake_256
 *
 * +data+::
 *   The data to hash.
 *
 * = example
 *   SHA3::Digest.hexdigest(:sha3_256, "data to hash")
 *
 * = note
 * This method defaults to squeezing 16 bytes for SHAKE128 and 32 bytes for SHAKE256.
 * To squeeze a different length, use #hex_squeeze instance method.
 */
static VALUE rb_digest_self_hexdigest(VALUE klass, VALUE name, VALUE data) {
    VALUE args[2];
    algorithm_type algorithm;

    /* For SHAKE algorithms, we need to handle them differently */
    if (TYPE(name) == T_SYMBOL) {
        ID symid = SYM2ID(name);
        if (symid == shake_128_id || symid == shake_256_id) {
            /* Create a new digest instance with the specified algorithm */
            VALUE digest = rb_class_new_instance(1, &name, klass);

            /* Update it with the data */
            rb_digest_update(digest, data);

            /* For SHAKE algorithms, use a default output length based on the security strength */
            int output_length = (symid == shake_128_id) ? 16 : 32; /* 128/8 or 256/8 */

            /* Return the hexadecimal representation of the squeezed output */
            return rb_digest_hex_squeeze(digest, INT2NUM(output_length));
        }
    }

    /* Call the superclass method with arguments in reverse order */
    args[0] = data;
    args[1] = name;

    return rb_call_super(2, args);
}
