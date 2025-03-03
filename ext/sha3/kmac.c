#include "kmac.h"

#include "KeccakHash.h"
#include "SP800-185.h"
#include "sha3.h"

// SHA3::KMAC.new(algorithm, output_length, key, customization)
// SHA3::KMAC128.new(output_length, key, customization)
// SHA3::KMAC256.new(output_length, key, customization)
// kmac.update
// kmac.digest | kmac.hexdigest

/*** Types and structs  ***/

typedef enum { KMAC_128 = 0, KMAC_256 } sha3_kmac_algorithms;

typedef struct {
    KMAC_Instance* state;
    sha3_kmac_algorithms algorithm;

    size_t output_length;
} sha3_kmac_context_t;

/*** Function prototypes ***/

static int compare_contexts(const sha3_kmac_context_t*, const sha3_kmac_context_t*);
static void sha3_kmac_free_context(void*);
static size_t sha3_kmac_context_size(const void*);

/* Allocation and initialization */
static VALUE rb_sha3_kmac_alloc(VALUE);
static VALUE rb_sha3_kmac_init(int, VALUE*, VALUE);
static VALUE rb_sha3_kmac_copy(VALUE, VALUE);

/* Core digest operations */
static VALUE rb_sha3_kmac_finish(int, VALUE*, VALUE);
static VALUE rb_sha3_kmac_update(VALUE, VALUE);

/* Digest properties */
static VALUE rb_sha3_kmac_name(VALUE);

/* Output methods */
static VALUE rb_sha3_kmac_digest(int, VALUE*, VALUE);
static VALUE rb_sha3_kmac_hexdigest(int, VALUE*, VALUE);
static VALUE rb_sha3_kmac_self_digest(int, VALUE*, VALUE);
static VALUE rb_sha3_kmac_self_hexdigest(int, VALUE*, VALUE);

/*** Global variables ***/

VALUE _sha3_kmac_class;
VALUE _sha3_kmac_error_class;

/* Define the ID variables */
static ID _kmac_128_id;
static ID _kmac_256_id;

/* TypedData structure for sha3_kmac_context_t */
const rb_data_type_t sha3_kmac_data_type_t = {"SHA3::KMAC",
                                              {
                                                  NULL,
                                                  sha3_kmac_free_context,
                                                  sha3_kmac_context_size,
                                              },
                                              NULL,
                                              NULL,
                                              RUBY_TYPED_FREE_IMMEDIATELY};

void Init_sha3_kmac(void) {
    _kmac_128_id = rb_intern("kmac_128");
    _kmac_256_id = rb_intern("kmac_256");

    if (NIL_P(_sha3_module)) {
        _sha3_module = rb_define_module("SHA3");
    }

    /*
     * Document-class: SHA3::KMAC
     *
     * It is a subclass of the Digest::Class class, which provides a framework for
     * creating and manipulating hash digests.
     */
    _sha3_kmac_class = rb_define_class_under(_sha3_module, "KMAC", rb_cObject);

    /*
     * Document-class: SHA3::KMAC::KMACError
     *
     * All KMAC methods raise this exception on error.
     *
     * It is a subclass of the StandardError class -- see the Ruby documentation
     * for more information.
     */
    _sha3_kmac_error_class = rb_define_class_under(_sha3_kmac_class, "KMACError", rb_eStandardError);

    rb_define_alloc_func(_sha3_kmac_class, rb_sha3_kmac_alloc);
    rb_define_method(_sha3_kmac_class, "initialize", rb_sha3_kmac_init, -1);
    rb_define_method(_sha3_kmac_class, "initialize_copy", rb_sha3_kmac_copy, 1);
    rb_define_method(_sha3_kmac_class, "update", rb_sha3_kmac_update, 1);
    rb_define_method(_sha3_kmac_class, "name", rb_sha3_kmac_name, 0);

    rb_define_method(_sha3_kmac_class, "digest", rb_sha3_kmac_digest, -1);
    rb_define_method(_sha3_kmac_class, "hexdigest", rb_sha3_kmac_hexdigest, -1);

    rb_define_private_method(_sha3_kmac_class, "finish", rb_sha3_kmac_finish, -1);

    rb_define_alias(_sha3_kmac_class, "<<", "update");

    rb_define_singleton_method(_sha3_kmac_class, "digest", rb_sha3_kmac_self_digest, -1);
    rb_define_singleton_method(_sha3_kmac_class, "hexdigest", rb_sha3_kmac_self_hexdigest, -1);

    return;
}

static int compare_contexts(const sha3_kmac_context_t* context1, const sha3_kmac_context_t* context2) {
    // First check the algorithm
    if (context1->algorithm != context2->algorithm) {
        return 0;
    }

    // Compare the internal state structure
    if (memcmp(context1->state, context2->state, sizeof(KMAC_Instance)) != 0) {
        return 0;
    }

    // All comparisons passed
    return 1;
}

static inline void get_sha3_kmac_context(VALUE obj, sha3_kmac_context_t** context) {
    TypedData_Get_Struct((obj), sha3_kmac_context_t, &sha3_kmac_data_type_t, (*context));
    if (!(*context)) {
        rb_raise(rb_eRuntimeError, "KMAC data not initialized!");
    }
}

static inline void safe_get_sha3_kmac_context(VALUE obj, sha3_kmac_context_t** context) {
    if (!rb_obj_is_kind_of(obj, _sha3_kmac_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(obj),
                 rb_class2name(_sha3_kmac_class));
    }
    get_sha3_kmac_context(obj, context);
}

static void sha3_kmac_free_context(void* ptr) {
    sha3_kmac_context_t* context = (sha3_kmac_context_t*)ptr;
    if (context) {
        if (context->state) {
            free(context->state);
        }
        free(context);
    }
}

static size_t sha3_kmac_context_size(const void* ptr) {
    const sha3_kmac_context_t* context = (const sha3_kmac_context_t*)ptr;
    size_t size = sizeof(sha3_kmac_context_t);

    if (context && context->state) {
        size += sizeof(KMAC_Instance);
    }

    return size;
}

static VALUE rb_sha3_kmac_alloc(VALUE klass) {
    sha3_kmac_context_t* context = (sha3_kmac_context_t*)malloc(sizeof(sha3_kmac_context_t));
    if (!context) {
        rb_raise(_sha3_kmac_error_class, "failed to allocate object memory");
    }

    context->state = (KMAC_Instance*)calloc(1, sizeof(KMAC_Instance));
    if (!context->state) {
        sha3_kmac_free_context(context);
        rb_raise(_sha3_kmac_error_class, "failed to allocate state memory");
    }

    VALUE obj = TypedData_Wrap_Struct(klass, &sha3_kmac_data_type_t, context);
    context->output_length = 0;     // Default output length in bits
    context->algorithm = KMAC_128;  // Default algorithm

    return obj;
}

/*
 * :call-seq:
 *   ::new(algorithm, output_length, key, [customization]) -> instance
 *
 * Creates a new KMAC object.
 *
 * +algorithm+::
 *   The KMAC algorithm to use (as a Symbol).
 *   Valid algorithms are:
 *   - :kmac_128
 *   - :kmac_256
 *
 * +output_length+::
 *   The length of the output in bytes.
 *
 * +key+::
 *   The key to use for the KMAC.
 *
 * +customization+::
 *   _optional_ The customization string to use.
 *
 * = example
 *   SHA3::KMAC.new(:kmac_128, 32, "key")
 *   SHA3::KMAC.new(:kmac_256, 64, "key", "customization")
 */
static VALUE rb_sha3_kmac_init(int argc, VALUE* argv, VALUE self) {
    sha3_kmac_context_t* context;
    VALUE algorithm, output_length, key, customization;

    rb_scan_args(argc, argv, "31", &algorithm, &output_length, &key, &customization);

    get_sha3_kmac_context(self, &context);

    ID sym = SYM2ID(algorithm);
    if (rb_equal(sym, _kmac_128_id)) {
        context->algorithm = KMAC_128;
    } else if (rb_equal(sym, _kmac_256_id)) {
        context->algorithm = KMAC_256;
    } else {
        rb_raise(_sha3_kmac_error_class, "invalid algorithm");
    }

    if (!NIL_P(output_length)) {
        Check_Type(output_length, T_FIXNUM);
        context->output_length = NUM2ULONG(output_length) * 8;
    }

    if (!NIL_P(key)) {
        Check_Type(key, T_STRING);
        size_t key_len = RSTRING_LEN(key) * 8;
        const unsigned char* key_ptr = (const unsigned char*)RSTRING_PTR(key);

        if (context->algorithm == KMAC_128) {
            if (KMAC128_Initialize(context->state, key_ptr, key_len, context->output_length,
                                   NIL_P(customization) ? NULL : (const unsigned char*)RSTRING_PTR(customization),
                                   NIL_P(customization) ? 0 : RSTRING_LEN(customization) * 8) != 0) {
                rb_raise(_sha3_kmac_error_class, "failed to initialize KMAC128");
            }
        } else {
            if (KMAC256_Initialize(context->state, key_ptr, key_len, context->output_length,
                                   NIL_P(customization) ? NULL : (const unsigned char*)RSTRING_PTR(customization),
                                   NIL_P(customization) ? 0 : RSTRING_LEN(customization) * 8) != 0) {
                rb_raise(_sha3_kmac_error_class, "failed to initialize KMAC256");
            }
        }
    }

    return self;
}

/*
 * :call-seq:
 *   initialize_copy(other) -> kmac
 *
 * Initializes the KMAC with the state of another KMAC.
 *
 * +other+::
 *   The KMAC to copy the state from.
 *
 * = example
 *   new_kmac = kmac.dup
 */
static VALUE rb_sha3_kmac_copy(VALUE self, VALUE other) {
    sha3_kmac_context_t* context;
    sha3_kmac_context_t* other_context;

    rb_check_frozen(self);
    if (self == other) {
        return self;
    }

    if (!rb_obj_is_kind_of(other, _sha3_kmac_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(other),
                 rb_class2name(_sha3_kmac_class));
    }

    safe_get_sha3_kmac_context(other, &other_context);
    get_sha3_kmac_context(self, &context);

    context->algorithm = other_context->algorithm;
    context->output_length = other_context->output_length;
    memcpy(context->state, other_context->state, sizeof(KMAC_Instance));

    if (!compare_contexts(context, other_context)) {
        rb_raise(_sha3_kmac_error_class, "failed to copy state");
    }

    return self;
}

/*
 * :call-seq:
 *   update(string) -> kmac
 *
 * Updates the KMAC with the given string.
 *
 * +string+::
 *   The string to update the KMAC with.
 *
 * = example
 *   kmac.update("more data")
 *   kmac << "more data"  # alias for update
 */
static VALUE rb_sha3_kmac_update(VALUE self, VALUE data) {
    sha3_kmac_context_t* context;
    size_t data_len;

    Check_Type(data, T_STRING);
    data_len = RSTRING_LEN(data) * 8;

    get_sha3_kmac_context(self, &context);

    if (context->algorithm == KMAC_128) {
        if (KMAC128_Update(context->state, (const BitSequence*)RSTRING_PTR(data), data_len) != 0) {
            rb_raise(_sha3_kmac_error_class, "failed to update KMAC128");
        }
    } else {
        if (KMAC256_Update(context->state, (const BitSequence*)RSTRING_PTR(data), data_len) != 0) {
            rb_raise(_sha3_kmac_error_class, "failed to update KMAC256");
        }
    }

    return self;
}

/*
 * :call-seq:
 *   finish([message]) -> String
 *
 * Returns the final KMAC as a binary string.
 *
 * +message+::
 *   _optional_ Output buffer to receive the final KMAC value.
 *
 * = example
 *   kmac.finish
 */
static VALUE rb_sha3_kmac_finish(int argc, VALUE* argv, VALUE self) {
    sha3_kmac_context_t* context;
    VALUE output;

    rb_scan_args(argc, argv, "01", &output);

    get_sha3_kmac_context(self, &context);

    if (NIL_P(output)) {
        output = rb_str_new(0, context->output_length / 8);
    } else {
        StringValue(output);
        rb_str_resize(output, context->output_length / 8);
    }

    if (context->algorithm == KMAC_128) {
        if (KMAC128_Final(context->state, (BitSequence*)RSTRING_PTR(output)) != 0) {
            rb_raise(_sha3_kmac_error_class, "failed to finalize KMAC128");
        }
    } else {
        if (KMAC256_Final(context->state, (BitSequence*)RSTRING_PTR(output)) != 0) {
            rb_raise(_sha3_kmac_error_class, "failed to finalize KMAC256");
        }
    }

    return output;
}

/*
 * :call-seq:
 *   name -> String
 *
 * Returns the name of the algorithm.
 *
 * = example
 *   kmac.name  #=> "KMAC128" or "KMAC256"
 */
static VALUE rb_sha3_kmac_name(VALUE self) {
    sha3_kmac_context_t* context;

    get_sha3_kmac_context(self, &context);

    switch (context->algorithm) {
        case KMAC_128:
            return rb_str_new2("KMAC128");
        case KMAC_256:
            return rb_str_new2("KMAC256");
        default:
            rb_raise(_sha3_kmac_error_class, "unknown algorithm");
    }
}

/*
 * :call-seq:
 *   digest() -> string
 *   digest([data]) -> string
 *
 * Returns the binary representation of the KMAC.
 * This method creates a copy of the current instance so that
 * the original state is preserved for future updates.
 *
 * +data+::
 *   _optional_ Update state with additional data before returning KMAC.
 *
 * = example
 *   kmac.digest
 *   kmac.digest('final chunk')
 */
static VALUE rb_sha3_kmac_digest(int argc, VALUE* argv, VALUE self) {
    VALUE copy, data;

    rb_scan_args(argc, argv, "01", &data);

    // Create a copy of the instance to avoid modifying the original
    copy = rb_obj_clone(self);

    // If data is provided, update the copy's state
    if (!NIL_P(data)) {
        rb_sha3_kmac_update(copy, data);
    }

    // Call finish on the copy
    return rb_sha3_kmac_finish(0, NULL, copy);
}

/*
 * :call-seq:
 *   hexdigest() -> string
 *   hexdigest([data]) -> string
 *
 * Returns the hexadecimal representation of the KMAC.
 * This method creates a copy of the current instance so that
 * the original state is preserved for future updates.
 *
 * +data+::
 *   _optional_ Update state with additional data before returning KMAC.
 *
 * = example
 *   kmac.hexdigest
 *   kmac.hexdigest('final chunk')
 */
static VALUE rb_sha3_kmac_hexdigest(int argc, VALUE* argv, VALUE self) {
    VALUE bin_str = rb_sha3_kmac_digest(argc, argv, self);
    return rb_funcall(bin_str, rb_intern("unpack1"), 1, rb_str_new2("H*"));
}

/*
 * :call-seq:
 *   ::digest(algorithm, data, output_length, key, [customization]) -> string
 *
 * One-shot operation to return the binary KMAC digest without explicitly creating an instance.
 *
 * +algorithm+::
 *   The KMAC algorithm to use (as a Symbol) - :kmac_128 or :kmac_256
 * +data+::
 *   The data to digest
 * +output_length+::
 *   The length of the output in bytes
 * +key+::
 *   The key to use for the KMAC
 * +customization+::
 *   _optional_ The customization string to use
 *
 * = example
 *   SHA3::KMAC.digest(:kmac_128, "data", 32, "key")
 *   SHA3::KMAC.digest(:kmac_128, "data", 32, "key", "customization")
 */
static VALUE rb_sha3_kmac_self_digest(int argc, VALUE* argv, VALUE klass) {
    VALUE algorithm, data, output_length, key, customization;

    rb_scan_args(argc, argv, "41", &algorithm, &data, &output_length, &key, &customization);

    VALUE kmac = rb_funcall(klass, rb_intern("new"), 4, algorithm, output_length, key, customization);
    return rb_funcall(kmac, rb_intern("digest"), 1, data);
}

/*
 * :call-seq:
 *   ::hexdigest(algorithm, data, output_length, key, [customization]) -> string
 *
 * One-shot operation to return the hexadecimal KMAC digest without explicitly creating an instance.
 *
 * +algorithm+::
 *   The KMAC algorithm to use (as a Symbol) - :kmac_128 or :kmac_256
 * +data+::
 *   The data to digest
 * +output_length+::
 *   The length of the output in bytes
 * +key+::
 *   The key to use for the KMAC
 * +customization+::
 *   _optional_ The customization string to use
 *
 * = example
 *   SHA3::KMAC.hexdigest(:kmac_128, "data", 32, "key")
 *   SHA3::KMAC.hexdigest(:kmac_128, "data", 32, "key", "customization")
 */
static VALUE rb_sha3_kmac_self_hexdigest(int argc, VALUE* argv, VALUE klass) {
    VALUE algorithm, data, output_length, key, customization;

    rb_scan_args(argc, argv, "41", &algorithm, &data, &output_length, &key, &customization);

    VALUE kmac = rb_funcall(klass, rb_intern("new"), 4, algorithm, output_length, key, customization);
    return rb_funcall(kmac, rb_intern("hexdigest"), 1, data);
}
