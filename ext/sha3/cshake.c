#include "cshake.h"

#include "common.h"
#include "sha3.h"
#include "sp800_185.h"

/*** Types and structs  ***/
typedef struct {
    sp800_185_context_t base;
} sha3_cshake_context_t;

/*** Function prototypes ***/
static void sha3_cshake_free_context(void *);
static size_t sha3_cshake_context_size(const void *);

/* Allocation and initialization */
static VALUE rb_sha3_cshake_alloc(VALUE);
static VALUE rb_sha3_cshake_init(int, VALUE *, VALUE);
static VALUE rb_sha3_cshake_copy(VALUE, VALUE);

/* Core digest operations */
static VALUE rb_sha3_cshake_finish(int argc, VALUE *argv, VALUE self);
static VALUE rb_sha3_cshake_update(VALUE, VALUE);

/* Digest properties */
static VALUE rb_sha3_cshake_name(VALUE self);

/* Output methods */
static VALUE rb_sha3_cshake_digest(int argc, VALUE *argv, VALUE self);
static VALUE rb_sha3_cshake_hexdigest(int argc, VALUE *argv, VALUE self);
static VALUE rb_sha3_cshake_squeeze(VALUE self, VALUE length);
static VALUE rb_sha3_cshake_hex_squeeze(VALUE self, VALUE length);

/*** Global variables ***/
VALUE _sha3_cshake_class;
VALUE _sha3_cshake_error_class;

/* Define the ID variables */
static ID _cshake_128_id;
static ID _cshake_256_id;

/* TypedData structure for sha3_cshake_context_t */
static const rb_data_type_t sha3_cshake_data_type = {
    "SHA3::CSHAKE",
    {
        NULL, sha3_cshake_free_context,  // Use our free function directly
        sha3_cshake_context_size,        /* We'll do our own size calculation */
        NULL,                            /* dcompact field */
    },
    NULL,
    NULL,
    RUBY_TYPED_FREE_IMMEDIATELY,
};

// Helper function to extract context from a Ruby object
void get_cshake_context(VALUE obj, sp800_185_context_t **context) {
    sha3_cshake_context_t *cshake_ctx;
    TypedData_Get_Struct(obj, sha3_cshake_context_t, &sha3_cshake_data_type, cshake_ctx);
    *context = &cshake_ctx->base;
}

void Init_sha3_cshake(void) {
    _cshake_128_id = rb_intern("cshake_128");
    _cshake_256_id = rb_intern("cshake_256");

    if (!_sha3_module) {
        _sha3_module = rb_define_module("SHA3");
    }

    /*
     * Document-class: SHA3::CSHAKE
     *
     * CSHAKE (Customizable SHAKE) is a family of functions that allow for domain separation and customization of the
     * output. It is based on the cSHAKE algorithm defined in NIST SP800-185.
     */
    _sha3_cshake_class = rb_define_class_under(_sha3_module, "CSHAKE", rb_cObject);

    /*
     * Document-class: SHA3::CSHAKE::Error
     *
     * All CSHAKE methods raise this exception on error.
     *
     * It is a subclass of the StandardError class -- see the Ruby documentation
     * for more information.
     */
    _sha3_cshake_error_class = rb_define_class_under(_sha3_cshake_class, "Error", rb_eStandardError);

    rb_define_alloc_func(_sha3_cshake_class, rb_sha3_cshake_alloc);
    rb_define_method(_sha3_cshake_class, "initialize", rb_sha3_cshake_init, -1);
    rb_define_method(_sha3_cshake_class, "initialize_copy", rb_sha3_cshake_copy, 1);

    // Define instance methods
    rb_define_method(_sha3_cshake_class, "update", rb_sha3_cshake_update, 1);
    rb_define_method(_sha3_cshake_class, "name", rb_sha3_cshake_name, 0);

    rb_define_method(_sha3_cshake_class, "digest", rb_sha3_cshake_digest, -1);
    rb_define_method(_sha3_cshake_class, "hexdigest", rb_sha3_cshake_hexdigest, -1);

    rb_define_method(_sha3_cshake_class, "squeeze", rb_sha3_cshake_squeeze, 1);
    rb_define_method(_sha3_cshake_class, "hex_squeeze", rb_sha3_cshake_hex_squeeze, 1);

    rb_define_private_method(_sha3_cshake_class, "finish", rb_sha3_cshake_finish, -1);

    rb_define_alias(_sha3_cshake_class, "<<", "update");

    return;
}

/* Use common memory management functions */
DEFINE_SP800_185_MEMORY_FUNCS(sha3_cshake, sha3_cshake_context_t)

/* Use common allocation function */
DEFINE_SP800_185_ALLOC(sha3_cshake, sha3_cshake_context_t, cSHAKE_Instance, _sha3_cshake_error_class)

/*
 * :call-seq:
 *   ::new(algorithm, output_length) -> cshake
 *   ::new(algorithm, output_length, name: "", customization: "") -> cshake
 *
 * Initializes a new CSHAKE instance with the specified algorithm and output length.
 *
 * +algorithm+::
 *   The CSHAKE algorithm to use (as a Symbol) - :cshake_128 or :cshake_256
 *
 * +output_length+::
 *   The length of the output in bytes. Set to 0 for an arbitrarily-long output using "squeeze" (XOF) methods.
 *
 * +name+::
 *   _optional_ The name string to use for domain separation
 *
 * +customization+::
 *   _optional_ The customization string to use
 *
 * = example
 *   # Initialize instance for fixed-length operation
 *   cshake = SHA3::CSHAKE.new(:cshake_128, 32, name: 'my-app')
 *   cshake << 'data...'
 *   cshake.hexdigest
 *
 *   # Initialize instance for XOF operation (arbitrary-long output)
 *   cshake = SHA3::CSHAKE.new(:cshake_256, 0, customization: 'Email Signature')
 *   cshake.update('data...')
 *   cshake.squeeze(64)
 */
static VALUE rb_sha3_cshake_init(int argc, VALUE *argv, VALUE self) {
    VALUE algorithm, length, keywords;

    rb_scan_args_kw(RB_SCAN_ARGS_LAST_HASH_KEYWORDS, argc, argv, "2:", &algorithm, &length, &keywords);

    if (NIL_P(algorithm)) {
        rb_raise(rb_eArgError, "missing keyword: algorithm");
    }
    Check_Type(algorithm, T_SYMBOL);

    if (NIL_P(length)) {
        rb_raise(rb_eArgError, "missing keyword: length");
    }
    Check_Type(length, T_FIXNUM);

    if (NUM2INT(length) < 0) {
        rb_raise(rb_eArgError, "output length must be non-negative");
    }

    ID table[] = {
        rb_intern("name"),
        rb_intern("customization"),
    };

    VALUE values[2];
    rb_get_kwargs(keywords, table, 0, 2, values);

    VALUE name_str = values[0] == Qundef ? rb_str_new2("") : values[0];
    StringValue(name_str);

    VALUE customization = values[1] == Qundef ? rb_str_new2("") : values[1];
    StringValue(customization);

    sha3_cshake_context_t *context;
    TypedData_Get_Struct(self, sha3_cshake_context_t, &sha3_cshake_data_type, context);

    // Store the output length in bits
    context->base.output_length = NUM2INT(length) * 8;
    context->base.error_class = _sha3_cshake_error_class;

    // Find the appropriate function table based on the algorithm
    sp800_185_algorithm_t alg_type;
    if (algorithm == ID2SYM(_cshake_128_id)) {
        alg_type = SP800_185_CSHAKE_128;
    } else if (algorithm == ID2SYM(_cshake_256_id)) {
        alg_type = SP800_185_CSHAKE_256;
    } else {
        rb_raise(rb_eArgError, "invalid algorithm: %s", rb_id2name(SYM2ID(algorithm)));
    }

    context->base.functions = sp800_185_get_algorithm(alg_type);
    if (!context->base.functions) {
        rb_raise(_sha3_cshake_error_class, "algorithm not available");
    }

    // Initialize using the safe accessor function
    int result = sp800_185_init_cshake(context->base.functions, context->base.state, context->base.output_length,
                                       (BitSequence *)RSTRING_PTR(name_str), RSTRING_LEN(name_str) * 8,
                                       (BitSequence *)RSTRING_PTR(customization), RSTRING_LEN(customization) * 8);

    if (result != 0) {
        rb_raise(_sha3_cshake_error_class, "failed to initialize %s algorithm", context->base.functions->name);
    }

    return self;
}

/*
 * :call-seq:
 *   ::copy(other) -> cshake
 *
 * Creates a copy of the CSHAKE instance.
 *
 * +other+::
 *  The CSHAKE instance to copy.
 *
 * = example
 *  cshake2 = cshake.dup
 */
DEFINE_SP800_185_COPY_METHOD(rb_sha3_cshake_copy, sha3_cshake_context_t, sha3_cshake_data_type, _sha3_cshake_class)

/*
 * :call-seq:
 *   update(string) -> cshake
 *
 * Updates the CSHAKE instance with the provided string.
 *
 * +string+::
 *   The string to update the CSHAKE with.
 *
 * = example
 *   cshake.update("more data")
 *   cshake << "more data"  # alias for update
 */
DEFINE_SP800_185_SIMPLE_METHOD(rb_sha3_cshake_update, sp800_185_rb_update, get_cshake_context)

/*
 * :call-seq:
 *   name -> string
 *
 * Returns the name of the CSHAKE instance.
 */
DEFINE_SP800_185_RETURN_METHOD(rb_sha3_cshake_name, sp800_185_rb_name, get_cshake_context)

/*
 * :call-seq:
 *   finish([message]) -> string
 *
 * Returns the final CSHAKE digest as a binary string.
 *
 * +message+::
 *   _optional_ Output buffer to receive the final CSHAKE value.
 *
 * = example
 *   cshake.finish
 */
DEFINE_SP800_185_VARARGS_METHOD(rb_sha3_cshake_finish, sp800_185_rb_finish, get_cshake_context)

/*
 * :call-seq:
 *   digest([data]) -> string
 *
 * Returns the digest of the CSHAKE instance.
 *
 * +data+::
 *   _optional_ Additional data to include in the digest.
 *
 * = example
 *   cshake.digest
 *   cshake.digest("final chunk")
 */
DEFINE_SP800_185_VARARGS_METHOD(rb_sha3_cshake_digest, sp800_185_rb_digest, get_cshake_context)

/*
 * :call-seq:
 *   hexdigest([data]) -> string
 *
 * Returns the hexadecimal digest of the CSHAKE instance.
 *
 * +data+::
 *   _optional_ Additional data to include in the digest.
 *
 * = example
 *   cshake.hexdigest
 *   cshake.hexdigest("final chunk")
 */
DEFINE_SP800_185_VARARGS_METHOD(rb_sha3_cshake_hexdigest, sp800_185_rb_hexdigest, get_cshake_context)

/*
 * :call-seq:
 *   squeeze(length) -> string
 *
 * Returns the CSHAKE digest with the specified length.
 *
 * +length+::
 *   The length of the output in bytes.
 *
 * = example
 *   cshake.squeeze(32)
 */
DEFINE_SP800_185_VALUE_METHOD(rb_sha3_cshake_squeeze, sp800_185_rb_squeeze, get_cshake_context)

/*
 * :call-seq:
 *   hex_squeeze(length) -> string
 *
 * Returns the hexadecimal CSHAKE digest with the specified length.
 *
 * +length+::
 *   The length of the output in bytes.
 *
 * = example
 *   cshake.hex_squeeze(32)
 */
DEFINE_SP800_185_VALUE_METHOD(rb_sha3_cshake_hex_squeeze, sp800_185_rb_hex_squeeze, get_cshake_context)
