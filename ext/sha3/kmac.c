#include "kmac.h"

#include "sha3.h"
#include "sp800_185.h"

/*** Types and structs  ***/
typedef struct {
    sp800_185_context_t base;
} sha3_kmac_context_t;

/*** Function prototypes ***/
static void sha3_kmac_free_context(void *);
static size_t sha3_kmac_context_size(const void *);

/* Allocation and initialization */
static VALUE rb_sha3_kmac_alloc(VALUE);
static VALUE rb_sha3_kmac_init(int, VALUE *, VALUE);
static VALUE rb_sha3_kmac_copy(VALUE, VALUE);

/* Core digest operations */
static VALUE rb_sha3_kmac_finish(int, VALUE *, VALUE);
static VALUE rb_sha3_kmac_update(VALUE, VALUE);

/* Digest properties */
static VALUE rb_sha3_kmac_name(VALUE);

/* Output methods */
static VALUE rb_sha3_kmac_digest(int, VALUE *, VALUE);
static VALUE rb_sha3_kmac_hexdigest(int, VALUE *, VALUE);
static VALUE rb_sha3_kmac_self_digest(int, VALUE *, VALUE);
static VALUE rb_sha3_kmac_self_hexdigest(int, VALUE *, VALUE);

static VALUE rb_sha3_kmac_squeeze(VALUE, VALUE);
static VALUE rb_sha3_kmac_hex_squeeze(VALUE, VALUE);

/*** Global variables ***/
VALUE _sha3_kmac_class;
VALUE _sha3_kmac_error_class;

/* Define the ID variables */
static ID _kmac_128_id;
static ID _kmac_256_id;

/* TypedData structure for sha3_kmac_context_t */
const rb_data_type_t sha3_kmac_data_type_t = {
    "SHA3::KMAC",
    {
        NULL, sha3_kmac_free_context, sha3_kmac_context_size, NULL, /* dcompact field */
    },
    NULL,
    NULL,
    RUBY_TYPED_FREE_IMMEDIATELY,
};

// Helper function to extract context from a Ruby object
void get_kmac_context(VALUE obj, sp800_185_context_t **context) {
    sha3_kmac_context_t *kmac_ctx;
    TypedData_Get_Struct(obj, sha3_kmac_context_t, &sha3_kmac_data_type_t, kmac_ctx);
    *context = &kmac_ctx->base;
}

void Init_sha3_kmac(void) {
    _kmac_128_id = rb_intern("kmac_128");
    _kmac_256_id = rb_intern("kmac_256");

    if (!_sha3_module) {
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
    _sha3_kmac_error_class = rb_define_class_under(_sha3_kmac_class, "Error", rb_eStandardError);

    rb_define_alloc_func(_sha3_kmac_class, rb_sha3_kmac_alloc);
    rb_define_method(_sha3_kmac_class, "initialize", rb_sha3_kmac_init, -1);
    rb_define_method(_sha3_kmac_class, "initialize_copy", rb_sha3_kmac_copy, 1);
    rb_define_method(_sha3_kmac_class, "update", rb_sha3_kmac_update, 1);
    rb_define_method(_sha3_kmac_class, "name", rb_sha3_kmac_name, 0);

    rb_define_method(_sha3_kmac_class, "digest", rb_sha3_kmac_digest, -1);
    rb_define_method(_sha3_kmac_class, "hexdigest", rb_sha3_kmac_hexdigest, -1);

    rb_define_method(_sha3_kmac_class, "squeeze", rb_sha3_kmac_squeeze, 1);
    rb_define_method(_sha3_kmac_class, "hex_squeeze", rb_sha3_kmac_hex_squeeze, 1);

    rb_define_private_method(_sha3_kmac_class, "finish", rb_sha3_kmac_finish, -1);

    rb_define_alias(_sha3_kmac_class, "<<", "update");

    rb_define_singleton_method(_sha3_kmac_class, "digest", rb_sha3_kmac_self_digest, -1);
    rb_define_singleton_method(_sha3_kmac_class, "hexdigest", rb_sha3_kmac_self_hexdigest, -1);

    return;
}

static void sha3_kmac_free_context(void *ptr) { sp800_185_free_context((sp800_185_context_t *)ptr); }

static size_t sha3_kmac_context_size(const void *ptr) {
    return sp800_185_context_size((const sp800_185_context_t *)ptr, sizeof(sha3_kmac_context_t));
}

static VALUE rb_sha3_kmac_alloc(VALUE klass) {
    sha3_kmac_context_t *context =
        (sha3_kmac_context_t *)sp800_185_alloc_context(sizeof(sha3_kmac_context_t), sizeof(KMAC_Instance));

    if (!context) {
        rb_raise(_sha3_kmac_error_class, "failed to allocate memory");
    }

    // Create the Ruby object with TypedData - this will automatically handle freeing
    VALUE obj = TypedData_Wrap_Struct(klass, &sha3_kmac_data_type_t, context);

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
 *   The length of the output in bytes. Set to 0 for an arbitrarily-long output using "squeeze" (XOF) methods.
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
 *   SHA3::KMAC.new(:kmac_128, 0, "key", "customization")
 *
 */
static VALUE rb_sha3_kmac_init(int argc, VALUE *argv, VALUE self) {
    VALUE algorithm, output_length, key, customization;

    rb_scan_args(argc, argv, "31", &algorithm, &output_length, &key, &customization);

    // Check and convert arguments
    if (NIL_P(algorithm)) {
        rb_raise(rb_eArgError, "missing keyword: algorithm");
    }
    Check_Type(algorithm, T_SYMBOL);

    if (NIL_P(output_length)) {
        rb_raise(rb_eArgError, "missing keyword: output_length");
    }
    Check_Type(output_length, T_FIXNUM);

    if (NIL_P(key)) {
        rb_raise(rb_eArgError, "missing keyword: key");
    }
    StringValue(key);

    if (!NIL_P(customization)) {
        StringValue(customization);
    } else {
        customization = rb_str_new2("");
    }

    sha3_kmac_context_t *context;
    TypedData_Get_Struct(self, sha3_kmac_context_t, &sha3_kmac_data_type_t, context);

    // Store the output length in bits
    context->base.output_length = NUM2ULONG(output_length) * 8;
    context->base.error_class = _sha3_kmac_error_class;

    // Find the appropriate function table based on the algorithm
    ID sym_id = SYM2ID(algorithm);
    if (sym_id == _kmac_128_id) {
        context->base.functions = &sp800_185_functions[SP800_185_KMAC_128];
    } else if (sym_id == _kmac_256_id) {
        context->base.functions = &sp800_185_functions[SP800_185_KMAC_256];
    } else {
        rb_raise(rb_eArgError, "invalid algorithm: %s", rb_id2name(sym_id));
    }

    // Initialize the KMAC instance
    size_t key_len = RSTRING_LEN(key) * 8;
    size_t customization_len = RSTRING_LEN(customization) * 8;

    int result = context->base.functions->kmac.init(context->base.state, (const BitSequence *)RSTRING_PTR(key), key_len,
                                                    context->base.output_length,
                                                    (const BitSequence *)RSTRING_PTR(customization), customization_len);

    if (result != 0) {
        rb_raise(_sha3_kmac_error_class, "failed to initialize %s", context->base.functions->name);
    }

    return self;
}

/*
 * :call-seq:
 *   ::copy(other) -> kmac
 *
 * Creates a copy of the KMAC instance.
 *
 * +other+::
 *   The KMAC to copy the state from.
 *
 * = example
 *   new_kmac = kmac.dup
 */
static VALUE rb_sha3_kmac_copy(VALUE self, VALUE other) {
    sha3_kmac_context_t *context, *other_context;

    rb_check_frozen(self);
    if (self == other) {
        return self;
    }

    if (!rb_obj_is_kind_of(other, _sha3_kmac_class)) {
        rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(other),
                 rb_class2name(_sha3_kmac_class));
    }

    TypedData_Get_Struct(other, sha3_kmac_context_t, &sha3_kmac_data_type_t, other_context);
    TypedData_Get_Struct(self, sha3_kmac_context_t, &sha3_kmac_data_type_t, context);

    // Copy the base context attributes
    context->base.functions = other_context->base.functions;
    context->base.output_length = other_context->base.output_length;

    // Copy the algorithm-specific state
    memcpy(context->base.state, other_context->base.state, context->base.functions->state_size);

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
    sp800_185_context_t *context;
    get_kmac_context(self, &context);
    sp800_185_update(context, data);

    return self;
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
    sp800_185_context_t *context;
    get_kmac_context(self, &context);

    return rb_str_new2(sp800_185_name(context));
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
static VALUE rb_sha3_kmac_finish(int argc, VALUE *argv, VALUE self) {
    sp800_185_context_t *context;
    get_kmac_context(self, &context);

    VALUE output = argc > 0 ? argv[0] : Qnil;

    return sp800_185_finish(context, output);
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
static VALUE rb_sha3_kmac_digest(int argc, VALUE *argv, VALUE self) {
    sp800_185_context_t *context;
    get_kmac_context(self, &context);

    VALUE data = argc > 0 ? argv[0] : Qnil;

    return sp800_185_digest(context, data);
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
static VALUE rb_sha3_kmac_hexdigest(int argc, VALUE *argv, VALUE self) {
    sp800_185_context_t *context;
    get_kmac_context(self, &context);

    VALUE data = argc > 0 ? argv[0] : Qnil;

    return sp800_185_hexdigest(context, data);
}

/*
 * :call-seq:
 *   squeeze(length) -> string
 *
 * Returns the squeezed output as a binary string.
 * This method creates a copy of the current instance so that
 * the original state is preserved for future updates.
 *
 * = note
 * The KMAC instance must be initialized with 0 output length before calling this method.
 *
 * = example
 *   kmac.squeeze(128)
 */
static VALUE rb_sha3_kmac_squeeze(VALUE self, VALUE length) {
    sp800_185_context_t *context;
    get_kmac_context(self, &context);

    return sp800_185_squeeze(context, length);
}

/*
 * :call-seq:
 *   hex_squeeze(length) -> string
 *
 * Returns the squeezed output as a hexadecimal string.
 * This method creates a copy of the current instance so that
 * the original state is preserved for future updates.
 *
 * = note
 * The KMAC instance must be initialized with 0 output length before calling this method.
 *
 * = example
 *   kmac.hex_squeeze(128)
 */
static VALUE rb_sha3_kmac_hex_squeeze(VALUE self, VALUE length) {
    sp800_185_context_t *context;
    get_kmac_context(self, &context);

    return sp800_185_hex_squeeze(context, length);
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
static VALUE rb_sha3_kmac_self_digest(int argc, VALUE *argv, VALUE klass) {
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
static VALUE rb_sha3_kmac_self_hexdigest(int argc, VALUE *argv, VALUE klass) {
    VALUE algorithm, data, output_length, key, customization;

    rb_scan_args(argc, argv, "41", &algorithm, &data, &output_length, &key, &customization);

    VALUE kmac = rb_funcall(klass, rb_intern("new"), 4, algorithm, output_length, key, customization);

    return rb_funcall(kmac, rb_intern("hexdigest"), 1, data);
}
