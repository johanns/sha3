#include "cshake.h"

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
    RUBY_TYPED_FREE_IMMEDIATELY};

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
     * All KMAC methods raise this exception on error.
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

static void sha3_cshake_free_context(void *ptr) { sp800_185_free_context((sp800_185_context_t *)ptr); }

static size_t sha3_cshake_context_size(const void *ptr) {
    return sp800_185_context_size((const sp800_185_context_t *)ptr, sizeof(sha3_cshake_context_t));
}

static VALUE rb_sha3_cshake_alloc(VALUE klass) {
    sha3_cshake_context_t *context =
        (sha3_cshake_context_t *)sp800_185_alloc_context(sizeof(sha3_cshake_context_t), sizeof(cSHAKE_Instance));

    if (!context) {
        rb_raise(_sha3_cshake_error_class, "failed to allocate memory");
    }

    // Create the Ruby object with TypedData - this will automatically handle freeing
    VALUE obj = TypedData_Wrap_Struct(klass, &sha3_cshake_data_type, context);

    return obj;
}

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
 *   # Initialize instance for fix-ed-length operation
 *   cshake = SHA3::CSHAKE.new(:cshake_128, 32, name: 'my-app')
 *   cshake << 'data...'
 *   cshake.hexdigest
 *
 *   # Initialize instance for XOF operation (arbitrary-long output)
 *   cshake = SHA3::CSHAKE.new(:cshake_256, 0, customization: 'Email Signature')
 *   cshask.update('data...')
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
    long len_check = NUM2LONG(length);

    if (len_check < 0) {
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
    context->base.output_length = (size_t)len_check * 8;
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
static VALUE rb_sha3_cshake_copy(VALUE self, VALUE other) {
    sha3_cshake_context_t *context, *other_context;

    rb_check_frozen(self);
    if (self == other) {
        return self;
    }

    if (!rb_obj_is_kind_of(other, _sha3_cshake_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(other),
                 rb_class2name(_sha3_cshake_class));
    }

    TypedData_Get_Struct(other, sha3_cshake_context_t, &sha3_cshake_data_type, other_context);
    TypedData_Get_Struct(self, sha3_cshake_context_t, &sha3_cshake_data_type, context);

    // Copy the base context attributes
    context->base.functions = other_context->base.functions;
    context->base.output_length = other_context->base.output_length;

    // Copy the algorithm-specific state
    memcpy(context->base.state, other_context->base.state, context->base.functions->state_size);

    return self;
}

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
static VALUE rb_sha3_cshake_update(VALUE self, VALUE data) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);
    sp800_185_update(context, data);

    return self;
}

/*
 * :call-seq:
 *   name -> string
 *
 * Returns the name of the CSHAKE instance.
 */
static VALUE rb_sha3_cshake_name(VALUE self) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);

    return rb_str_new2(sp800_185_name(context));
}

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
static VALUE rb_sha3_cshake_finish(int argc, VALUE *argv, VALUE self) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);

    VALUE output = argc > 0 ? argv[0] : Qnil;
    return sp800_185_finish(context, output);
}

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
static VALUE rb_sha3_cshake_digest(int argc, VALUE *argv, VALUE self) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);

    VALUE data = argc > 0 ? argv[0] : Qnil;

    return sp800_185_digest(context, data);
}

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
static VALUE rb_sha3_cshake_hexdigest(int argc, VALUE *argv, VALUE self) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);

    VALUE data = argc > 0 ? argv[0] : Qnil;

    return sp800_185_hexdigest(context, data);
}

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
static VALUE rb_sha3_cshake_squeeze(VALUE self, VALUE length) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);

    return sp800_185_squeeze(context, length);
}

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
static VALUE rb_sha3_cshake_hex_squeeze(VALUE self, VALUE length) {
    sp800_185_context_t *context;
    get_cshake_context(self, &context);

    return sp800_185_hex_squeeze(context, length);
}
