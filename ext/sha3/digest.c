#include "digest.h"

#include "KeccakHash.h"
#include "sha3.h"

/*
 * == Notes
 *
 *    ::Digest::Class call sequence ->
 *    | .alloc() ->
 *    | .new() ->
 *    | .update() ->
 *    | .digest or .hexdigest or .inspect -> (Instance.digest or .hexdigest()) ->
 *    --| .alloc() ->
 *      | .copy() ->
 *      | .finish() ->
 *
 */

/*** Types and structs  ***/

typedef enum { SHA3_224 = 0, SHA3_256, SHA3_384, SHA3_512, SHAKE_128, SHAKE_256 } sha3_digest_algorithms;

typedef struct {
    Keccak_HashInstance *state;
    int hashbitlen;
    sha3_digest_algorithms algorithm;
} sha3_digest_context_t;

typedef HashReturn (*keccak_init_func)(Keccak_HashInstance *);

/*** Function prototypes ***/

static int compare_contexts(const sha3_digest_context_t *, const sha3_digest_context_t *);
static inline void get_sha3_digest_context(VALUE, sha3_digest_context_t **);
static inline void safe_get_sha3_digest_context(VALUE, sha3_digest_context_t **);
static inline int is_shake_algorithm(sha3_digest_algorithms);

static int get_hashbit_length(VALUE, sha3_digest_algorithms *);
static HashReturn keccak_hash_initialize(sha3_digest_context_t *);

static void sha3_digest_free_context(void *);
static size_t sha3_digest_context_size(const void *);

/* Allocation and initialization */
static VALUE rb_sha3_digest_alloc(VALUE);
static VALUE rb_sha3_digest_init(int, VALUE *, VALUE);
static VALUE rb_sha3_digest_copy(VALUE, VALUE);

/* Core digest operations */
static VALUE rb_sha3_digest_finish(int, VALUE *, VALUE);
static VALUE rb_sha3_digest_reset(VALUE);
static VALUE rb_sha3_digest_update(VALUE, VALUE);

/* Digest properties */
static VALUE rb_sha3_digest_block_length(VALUE);
static VALUE rb_sha3_digest_length(VALUE);
static VALUE rb_sha3_digest_name(VALUE);

/* Output methods */
static VALUE rb_sha3_digest_digest(int, VALUE *, VALUE);
static VALUE rb_sha3_digest_hexdigest(int, VALUE *, VALUE);
static VALUE rb_sha3_digest_hex_squeeze(VALUE, VALUE);
static VALUE rb_sha3_digest_squeeze(VALUE, VALUE);
static VALUE rb_sha3_digest_self_digest(VALUE, VALUE, VALUE);
static VALUE rb_sha3_digest_self_hexdigest(VALUE, VALUE, VALUE);

/*** Globals variables  ***/

VALUE _sha3_digest_class;
VALUE _sha3_digest_error_class;

/* Define the ID variables */
static ID _sha3_224_id;
static ID _sha3_256_id;
static ID _sha3_384_id;
static ID _sha3_512_id;
static ID _shake_128_id;
static ID _shake_256_id;

/* TypedData structure for sha3_digest_context_t */
const rb_data_type_t sha3_digest_data_type = {"SHA3::Digest",
                                              {
                                                  NULL,
                                                  sha3_digest_free_context,
                                                  sha3_digest_context_size,
                                                  NULL,
                                              },
                                              NULL,
                                              NULL,
                                              RUBY_TYPED_FREE_IMMEDIATELY};

void Init_sha3_digest(void) {
    rb_require("digest");

    /* Initialize static symbol IDs for faster lookup in get_hlen() */
    _sha3_224_id = rb_intern("sha3_224");
    _sha3_256_id = rb_intern("sha3_256");
    _sha3_384_id = rb_intern("sha3_384");
    _sha3_512_id = rb_intern("sha3_512");
    _shake_128_id = rb_intern("shake_128");
    _shake_256_id = rb_intern("shake_256");

    if (NIL_P(_sha3_module)) {
        // This is both a safeguard and a workaround for RDoc
        _sha3_module = rb_define_module("SHA3");
    }

    /*
     * Document-class: SHA3::Digest
     *
     * It is a subclass of the Digest::Class class, which provides a framework for
     * creating and manipulating hash digest. Supported Algorithms are:
     * - SHA3-224 (:sha3_224)
     * - SHA3-256 (:sha3_256)
     * - SHA3-384 (:sha3_384)
     * - SHA3-512 (:sha3_512)
     * - SHAKE128 (:shake_128)
     * - SHAKE256 (:shake_256)
     */
    _sha3_digest_class = rb_define_class_under(_sha3_module, "Digest", rb_path2class("Digest::Class"));

    /*
     * Document-class: SHA3::Digest::DigestError
     *
     * All SHA3::Digest methods raise this exception on error.
     *
     * It is a subclass of the StandardError class -- see the Ruby documentation
     * for more information.
     */
    _sha3_digest_error_class = rb_define_class_under(_sha3_digest_class, "Error", rb_eStandardError);

    rb_define_alloc_func(_sha3_digest_class, rb_sha3_digest_alloc);
    rb_define_method(_sha3_digest_class, "initialize", rb_sha3_digest_init, -1);
    rb_define_method(_sha3_digest_class, "update", rb_sha3_digest_update, 1);
    rb_define_method(_sha3_digest_class, "reset", rb_sha3_digest_reset, 0);
    rb_define_method(_sha3_digest_class, "initialize_copy", rb_sha3_digest_copy, 1);
    rb_define_method(_sha3_digest_class, "digest_length", rb_sha3_digest_length, 0);
    rb_define_method(_sha3_digest_class, "block_length", rb_sha3_digest_block_length, 0);
    rb_define_method(_sha3_digest_class, "name", rb_sha3_digest_name, 0);

    rb_define_method(_sha3_digest_class, "squeeze", rb_sha3_digest_squeeze, 1);
    rb_define_method(_sha3_digest_class, "hex_squeeze", rb_sha3_digest_hex_squeeze, 1);
    rb_define_method(_sha3_digest_class, "digest", rb_sha3_digest_digest, -1);
    rb_define_method(_sha3_digest_class, "hexdigest", rb_sha3_digest_hexdigest, -1);

    rb_define_private_method(_sha3_digest_class, "finish", rb_sha3_digest_finish, -1);

    /* Define the class method self.digest */
    rb_define_singleton_method(_sha3_digest_class, "digest", rb_sha3_digest_self_digest, 2);
    rb_define_singleton_method(_sha3_digest_class, "hexdigest", rb_sha3_digest_self_hexdigest, 2);

    rb_define_alias(_sha3_digest_class, "<<", "update");
}

// Static inline functions replacing macros
static inline void get_sha3_digest_context(VALUE obj, sha3_digest_context_t **context) {
    TypedData_Get_Struct((obj), sha3_digest_context_t, &sha3_digest_data_type, (*context));
    if (!(*context)) {
        rb_raise(rb_eRuntimeError, "Digest data not initialized!");
    }

    if (!(*context)->state) {
        rb_raise(rb_eRuntimeError, "Digest state not initialized!");
    }
}

static inline void safe_get_sha3_digest_context(VALUE obj, sha3_digest_context_t **context) {
    if (!rb_obj_is_kind_of(obj, _sha3_digest_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(obj),
                 rb_class2name(_sha3_digest_class));
    }
    get_sha3_digest_context(obj, context);
}

static inline int is_shake_algorithm(sha3_digest_algorithms alg) { return alg == SHAKE_128 || alg == SHAKE_256; }

static int get_hashbit_length(VALUE obj, sha3_digest_algorithms *algorithm) {
    if (TYPE(obj) != T_SYMBOL) {
        rb_raise(_sha3_digest_error_class, "hash algorithm must be a symbol");
    }

    ID symid = SYM2ID(obj);

    if (symid == _sha3_224_id) {
        *algorithm = SHA3_224;
        return 224;
    } else if (symid == _sha3_256_id) {
        *algorithm = SHA3_256;
        return 256;
    } else if (symid == _sha3_384_id) {
        *algorithm = SHA3_384;
        return 384;
    } else if (symid == _sha3_512_id) {
        *algorithm = SHA3_512;
        return 512;
    } else if (symid == _shake_128_id) {
        *algorithm = SHAKE_128;
        return 128;
    } else if (symid == _shake_256_id) {
        *algorithm = SHAKE_256;
        return 256;
    }

    rb_raise(rb_eArgError,
             "invalid hash algorithm symbol (should be: :sha3_224, "
             ":sha3_256, :sha3_384, :sha3_512, :shake_128, or :shake_256)");

    return 0;  // Never reached, but silences compiler warnings
}

static void sha3_digest_free_context(void *ptr) {
    sha3_digest_context_t *context = (sha3_digest_context_t *)ptr;
    if (context) {
        if (context->state) {
            ruby_xfree(context->state);
            context->state = NULL;
        }
        ruby_xfree(context);
    }
}

static size_t sha3_digest_context_size(const void *ptr) {
    const sha3_digest_context_t *context = (const sha3_digest_context_t *)ptr;
    size_t size = sizeof(sha3_digest_context_t);

    if (context && context->state) {
        size += sizeof(Keccak_HashInstance);
    }

    return size;
}

static HashReturn keccak_hash_initialize(sha3_digest_context_t *context) {
    switch (context->algorithm) {
        case SHA3_224:
            return Keccak_HashInitialize_SHA3_224(context->state);
        case SHA3_256:
            return Keccak_HashInitialize_SHA3_256(context->state);
        case SHA3_384:
            return Keccak_HashInitialize_SHA3_384(context->state);
        case SHA3_512:
            return Keccak_HashInitialize_SHA3_512(context->state);
        case SHAKE_128:
            return Keccak_HashInitialize_SHAKE128(context->state);
        case SHAKE_256:
            return Keccak_HashInitialize_SHAKE256(context->state);
    }

    return KECCAK_FAIL;
}

static VALUE rb_sha3_digest_alloc(VALUE klass) {
    sha3_digest_context_t *context = RB_ALLOC(sha3_digest_context_t);
    if (!context) {
        rb_raise(_sha3_digest_error_class, "failed to allocate object memory");
    }

    context->state = RB_ALLOC(Keccak_HashInstance);
    if (!context->state) {
        rb_raise(_sha3_digest_error_class, "failed to allocate state memory");
    }
    memset(context->state, 0, sizeof(*context->state));

    context->hashbitlen = 0;
    context->algorithm = SHA3_256;

    VALUE obj = TypedData_Wrap_Struct(klass, &sha3_digest_data_type, context);
    return obj;
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
static VALUE rb_sha3_digest_init(int argc, VALUE *argv, VALUE self) {
    sha3_digest_context_t *context;
    VALUE hlen, data;

    rb_scan_args(argc, argv, "02", &hlen, &data);
    get_sha3_digest_context(self, &context);

    if (NIL_P(hlen)) {
        context->algorithm = SHA3_256;
        context->hashbitlen = 256;
    } else {
        context->hashbitlen = get_hashbit_length(hlen, &context->algorithm);
    }

    if (keccak_hash_initialize(context) != KECCAK_SUCCESS) {
        rb_raise(_sha3_digest_error_class, "failed to initialize algorithm state");
    }

    if (!NIL_P(data)) {
        return rb_sha3_digest_update(self, data);
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
static VALUE rb_sha3_digest_update(VALUE self, VALUE data) {
    sha3_digest_context_t *context;
    BitLength dlen;

    StringValue(data);
    get_sha3_digest_context(self, &context);

    // Check for empty data
    if (RSTRING_LEN(data) == 0) {
        return self;
    }

    // Check for NULL data pointer
    if (RSTRING_PTR(data) == NULL) {
        rb_raise(_sha3_digest_error_class, "cannot update with NULL data");
    }

    // Prevent integer overflow and validate size
    size_t data_len = RSTRING_LEN(data);
    if (data_len > SIZE_MAX / 8) {
        rb_raise(_sha3_digest_error_class, "data too large (exceeds maximum size)");
    }

    dlen = (data_len * 8);

    if (Keccak_HashUpdate(context->state, (BitSequence *)RSTRING_PTR(data), dlen) != KECCAK_SUCCESS) {
        rb_raise(_sha3_digest_error_class, "failed to update hash data");
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
static VALUE rb_sha3_digest_reset(VALUE self) {
    sha3_digest_context_t *context;
    get_sha3_digest_context(self, &context);

    memset(context->state, 0, sizeof(Keccak_HashInstance));

    if (keccak_hash_initialize(context) != KECCAK_SUCCESS) {
        rb_raise(_sha3_digest_error_class, "failed to reset internal state");
    }

    return self;
}

static int compare_contexts(const sha3_digest_context_t *context1, const sha3_digest_context_t *context2) {
    if (!context1 || !context2 || !context1->state || !context2->state) {
        return 0;
    }

    // First check the hashbitlen and algorithm
    if (context1->hashbitlen != context2->hashbitlen || context1->algorithm != context2->algorithm) {
        return 0;
    }

    // Compare the internal state structure
    if (memcmp(&(context1->state->sponge.state), &(context2->state->sponge.state),
               sizeof(context1->state->sponge.state)) != 0) {
        return 0;
    }

    // Compare sponge parameters
    if ((context1->state->sponge.rate != context2->state->sponge.rate) ||
        (context1->state->sponge.byteIOIndex != context2->state->sponge.byteIOIndex) ||
        (context1->state->sponge.squeezing != context2->state->sponge.squeezing)) {
        return 0;
    }

    // Compare hash-specific parameters
    if ((context1->state->fixedOutputLength != context2->state->fixedOutputLength) ||
        (context1->state->delimitedSuffix != context2->state->delimitedSuffix)) {
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
static VALUE rb_sha3_digest_copy(VALUE self, VALUE other) {
    sha3_digest_context_t *context;
    sha3_digest_context_t *other_context;

    rb_check_frozen(self);
    if (self == other) {
        return self;
    }

    if (!rb_obj_is_kind_of(other, _sha3_digest_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(other),
                 rb_class2name(_sha3_digest_class));
    }

    safe_get_sha3_digest_context(other, &other_context);
    safe_get_sha3_digest_context(self, &context);

    if (!context || !other_context) {
        rb_raise(_sha3_digest_error_class, "invalid context for copy");
    }

    context->hashbitlen = other_context->hashbitlen;
    context->algorithm = other_context->algorithm;
    memcpy(context->state, other_context->state, sizeof(Keccak_HashInstance));

    if (!compare_contexts(context, other_context)) {
        rb_raise(_sha3_digest_error_class, "failed to copy state");
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
static VALUE rb_sha3_digest_length(VALUE self) {
    sha3_digest_context_t *context;
    get_sha3_digest_context(self, &context);

    return ULL2NUM(context->hashbitlen / 8);
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
static VALUE rb_sha3_digest_block_length(VALUE self) {
    sha3_digest_context_t *context;
    get_sha3_digest_context(self, &context);

    return ULL2NUM(200 - (2 * (context->hashbitlen / 8)));
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
static VALUE rb_sha3_digest_name(VALUE self) {
    sha3_digest_context_t *context;
    get_sha3_digest_context(self, &context);

    switch (context->algorithm) {
        case SHA3_224:
            return rb_str_new_cstr("SHA3-224");
        case SHA3_256:
            return rb_str_new_cstr("SHA3-256");
        case SHA3_384:
            return rb_str_new_cstr("SHA3-384");
        case SHA3_512:
            return rb_str_new_cstr("SHA3-512");
        case SHAKE_128:
            return rb_str_new_cstr("SHAKE128");
        case SHAKE_256:
            return rb_str_new_cstr("SHAKE256");
        default:
            rb_raise(_sha3_digest_error_class, "unknown algorithm");
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
static VALUE rb_sha3_digest_finish(int argc, VALUE *argv, VALUE self) {
    sha3_digest_context_t *context;
    VALUE str;
    int digest_bytes;

    rb_scan_args(argc, argv, "01", &str);
    get_sha3_digest_context(self, &context);

    // For both SHA3 and SHAKE algorithms, use the security strength (hashbitlen)
    // as the default output length
    digest_bytes = context->hashbitlen / 8;

    if (NIL_P(str)) {
        str = rb_str_new(0, digest_bytes);
    } else {
        StringValue(str);
        rb_str_resize(str, digest_bytes);
    }

    if (Keccak_HashFinal(context->state, (BitSequence *)RSTRING_PTR(str)) != KECCAK_SUCCESS) {
        rb_raise(_sha3_digest_error_class, "failed to finalize digest");
    }

    return str;
}

/*
 * :call-seq:
 *   squeeze(length) -> String
 *
 * Returns the squeezed output as a binary string. Only available for SHAKE algorithms.
 * This method creates a copy of the current instance to preserve the original state.
 *
 * +length+::
 *   The length in bytes of the output to squeeze.
 *
 * = example
 *   digest.squeeze(32)  # Get 32 bytes of output
 */
static VALUE rb_sha3_digest_squeeze(VALUE self, VALUE length) {
    sha3_digest_context_t *context;
    VALUE str, copy;
    long output_bytes;

    Check_Type(length, T_FIXNUM);
    output_bytes = NUM2LONG(length);

    if (output_bytes <= 0) {
        rb_raise(_sha3_digest_error_class, "output length must be positive");
    }

    if (output_bytes > (1L << 20)) {  // Limit to 1MB output
        rb_raise(_sha3_digest_error_class, "output length too large (max 1MB)");
    }

    get_sha3_digest_context(self, &context);

    // Only SHAKE algorithms support arbitrary-length output
    if (!is_shake_algorithm(context->algorithm)) {
        rb_raise(_sha3_digest_error_class, "squeeze is only supported for SHAKE algorithms");
    }

    // Create a copy of the digest object to avoid modifying the original
    copy = rb_obj_clone(self);
    if (NIL_P(copy)) {
        rb_raise(_sha3_digest_error_class, "failed to clone digest object");
    }

    // Get the sha3_digest_context_t struct from the copy
    sha3_digest_context_t *context_copy;
    get_sha3_digest_context(copy, &context_copy);

    str = rb_str_new(0, output_bytes);

    // Finalize the hash on the copy
    if (Keccak_HashFinal(context_copy->state, NULL) != KECCAK_SUCCESS) {
        rb_raise(_sha3_digest_error_class, "failed to finalize digest");
    }

    // Then squeeze out the desired number of bytes
    if (Keccak_HashSqueeze(context_copy->state, (BitSequence *)RSTRING_PTR(str), output_bytes * 8) != KECCAK_SUCCESS) {
        rb_raise(_sha3_digest_error_class, "failed to squeeze output");
    }

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
static VALUE rb_sha3_digest_hex_squeeze(VALUE self, VALUE length) {
    // Get the binary output using the existing squeeze function
    VALUE bin_str = rb_sha3_digest_squeeze(self, length);
    // Use Ruby's built-in unpack method to convert to hex
    return rb_funcall(bin_str, rb_intern("unpack1"), 1, rb_str_new_cstr("H*"));
}

static VALUE prepare_shake_output(VALUE self, int argc, VALUE *argv, int hex_output) {
    sha3_digest_context_t *context;
    VALUE length, data;

    get_sha3_digest_context(self, &context);
    rb_scan_args(argc, argv, "02", &length, &data);

    if (NIL_P(length)) {
        rb_raise(_sha3_digest_error_class, "output length must be specified for SHAKE algorithms");
    }

    Check_Type(length, T_FIXNUM);

    if (!NIL_P(data)) {
        rb_sha3_digest_update(self, data);
    }

    return hex_output ? rb_sha3_digest_hex_squeeze(self, length) : rb_sha3_digest_squeeze(self, length);
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
static VALUE rb_sha3_digest_digest(int argc, VALUE *argv, VALUE self) {
    sha3_digest_context_t *context;
    get_sha3_digest_context(self, &context);

    if (context->algorithm != SHAKE_128 && context->algorithm != SHAKE_256) {
        return rb_call_super(argc, argv);
    }

    return prepare_shake_output(self, argc, argv, 0);
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
static VALUE rb_sha3_digest_hexdigest(int argc, VALUE *argv, VALUE self) {
    sha3_digest_context_t *context;
    get_sha3_digest_context(self, &context);

    if (context->algorithm != SHAKE_128 && context->algorithm != SHAKE_256) {
        return rb_call_super(argc, argv);
    }

    return prepare_shake_output(self, argc, argv, 1);
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
static VALUE rb_sha3_digest_self_digest(VALUE klass, VALUE name, VALUE data) {
    // Add null checks
    if (NIL_P(name) || NIL_P(data)) {
        rb_raise(_sha3_digest_error_class, "algorithm name and data cannot be nil");
    }

    // Add type validation for name
    if (TYPE(name) != T_SYMBOL) {
        rb_raise(_sha3_digest_error_class, "algorithm name must be a symbol");
    }

    // Existing code...
    VALUE args[2];

    // Need to add type checking for the data parameter
    StringValue(data);

    /* For SHAKE algorithms, we need to handle them differently */
    if (TYPE(name) == T_SYMBOL) {
        ID symid = SYM2ID(name);
        if (symid == _shake_128_id || symid == _shake_256_id) {
            /* Create a new digest instance with the specified algorithm */
            VALUE digest = rb_class_new_instance(1, &name, klass);

            /* Update it with the data */
            rb_sha3_digest_update(digest, data);

            /* For SHAKE algorithms, use a default output length based on the security strength */
            int output_length = (symid == _shake_128_id) ? 16 : 32; /* 128/8 or 256/8 */

            /* Return the squeezed output */
            return rb_sha3_digest_squeeze(digest, INT2NUM(output_length));
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
static VALUE rb_sha3_digest_self_hexdigest(VALUE klass, VALUE name, VALUE data) {
    VALUE digest;

    if (NIL_P(name) || NIL_P(data)) {
        rb_raise(_sha3_digest_error_class, "algorithm name and data cannot be nil");
    }

    if (TYPE(name) != T_SYMBOL) {
        rb_raise(_sha3_digest_error_class, "algorithm name must be a symbol");
    }

    StringValue(data);

    ID symid = SYM2ID(name);
    digest = rb_class_new_instance(1, &name, klass);
    rb_sha3_digest_update(digest, data);

    if (symid == _shake_128_id || symid == _shake_256_id) {
        int output_length = (symid == _shake_128_id) ? 16 : 32;
        return rb_sha3_digest_hex_squeeze(digest, INT2NUM(output_length));
    }

    return rb_funcall(digest, rb_intern("hexdigest"), 0);
}
