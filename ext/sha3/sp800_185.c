#include "sp800_185.h"

#include "sha3.h"



/*** Function table for SP800-185 algorithms ***/
sp800_185_function_table_t sp800_185_functions[] = {{.algorithm = SP800_185_CSHAKE_128,
                                                     .name = "CSHAKE128",
                                                     .state_size = sizeof(cSHAKE_Instance),
                                                     .cshake = {.init = (sp800_185_init_fn)cSHAKE128_Initialize,
                                                                .update = (sp800_185_update_fn)cSHAKE128_Update,
                                                                .final = (sp800_185_final_fn)cSHAKE128_Final,
                                                                .squeeze = (sp800_185_squeeze_fn)cSHAKE128_Squeeze}},
                                                    {.algorithm = SP800_185_CSHAKE_256,
                                                     .name = "CSHAKE256",
                                                     .state_size = sizeof(cSHAKE_Instance),
                                                     .cshake = {.init = (sp800_185_init_fn)cSHAKE256_Initialize,
                                                                .update = (sp800_185_update_fn)cSHAKE256_Update,
                                                                .final = (sp800_185_final_fn)cSHAKE256_Final,
                                                                .squeeze = (sp800_185_squeeze_fn)cSHAKE256_Squeeze}},
                                                    {.algorithm = SP800_185_KMAC_128,
                                                     .name = "KMAC128",
                                                     .state_size = sizeof(KMAC_Instance),
                                                     .kmac = {.init = (sp800_185_init_key_fn)KMAC128_Initialize,
                                                              .update = (sp800_185_update_fn)KMAC128_Update,
                                                              .final = (sp800_185_final_fn)KMAC128_Final,
                                                              .squeeze = (sp800_185_squeeze_fn)KMAC128_Squeeze}},
                                                    {.algorithm = SP800_185_KMAC_256,
                                                     .name = "KMAC256",
                                                     .state_size = sizeof(KMAC_Instance),
                                                     .kmac = {.init = (sp800_185_init_key_fn)KMAC256_Initialize,
                                                              .update = (sp800_185_update_fn)KMAC256_Update,
                                                              .final = (sp800_185_final_fn)KMAC256_Final,
                                                              .squeeze = (sp800_185_squeeze_fn)KMAC256_Squeeze}}};

// Generic context allocation function
sp800_185_context_t *sp800_185_alloc_context(size_t context_size, size_t state_size) {
    sp800_185_context_t *context = (sp800_185_context_t *)malloc(context_size);
    if (!context) return NULL;

    context->state = calloc(1, state_size);
    if (!context->state) {
        free(context);
        return NULL;
    }

    context->error_class = Qnil; // Initialize error class to nil

    return context;
}

// Generic context freeing function
void sp800_185_free_context(sp800_185_context_t *context) {
    if (context) {
        if (context->state) {
            free(context->state);
        }
        free(context);
    }
}

// Generic context size function
size_t sp800_185_context_size(const sp800_185_context_t *context, size_t struct_size) {
    size_t size = struct_size;
    if (context && context->functions) {
        size += context->functions->state_size;
    }
    return size;
}

// Generic state copy function
void *sp800_185_copy_state(sp800_185_context_t *context) {
    if (context->functions->state_size <= 0) {
        rb_raise(context->error_class, "invalid state size");
    }
    void *state_copy = malloc(context->functions->state_size);

    if (!state_copy) {
        rb_raise(rb_eNoMemError, "failed to allocate memory for state copy");
    }

    memcpy(state_copy, context->state, context->functions->state_size);

    return state_copy;
}

VALUE sp800_185_update(sp800_185_context_t *context, VALUE data) {
    StringValue(data);
    size_t data_len = (RSTRING_LEN(data) * 8);

    if (data_len == 0) {
        return Qnil;
    }

    // Use the function table to call the appropriate update function
    int result;

    // KMAC, cSHAKE, and ParallelHash share the same update function signature
    switch (context->functions->algorithm) {
        case SP800_185_CSHAKE_128:
        case SP800_185_CSHAKE_256:
            result =
                context->functions->cshake.update(context->state, (const BitSequence *)RSTRING_PTR(data), data_len);
            break;
        case SP800_185_KMAC_128:
        case SP800_185_KMAC_256:
            result = context->functions->kmac.update(context->state, (const BitSequence *)RSTRING_PTR(data), data_len);
            break;
        default:
            rb_raise(context->error_class, "unknown algorithm");
            return Qnil;
    }

    if (result != 0) {
        rb_raise(context->error_class, "failed to update %s state", context->functions->name);
    }

    return Qnil;
}

VALUE sp800_185_finish(sp800_185_context_t *context, VALUE output) {
    // Create a new string if output isn't provided
    if (NIL_P(output)) {
        output = rb_str_new(0, context->output_length / 8);
    } else {
        StringValue(output);
        rb_str_resize(output, context->output_length / 8);
    }

    // Use the function table to call the appropriate final function
    int result;

    switch (context->functions->algorithm) {
        case SP800_185_CSHAKE_128:
        case SP800_185_CSHAKE_256:
            result = context->functions->cshake.final(context->state, (BitSequence *)RSTRING_PTR(output));
            break;
        case SP800_185_KMAC_128:
        case SP800_185_KMAC_256:
            result = context->functions->kmac.final(context->state, (BitSequence *)RSTRING_PTR(output));
            break;
        default:
            rb_raise(context->error_class, "unknown algorithm");
            return Qnil;
    }

    if (result != 0) {
        rb_raise(context->error_class, "failed to finalize %s state", context->functions->name);
    }

    return output;
}

const char *sp800_185_name(sp800_185_context_t *context) { return context->functions->name; }

VALUE sp800_185_digest(sp800_185_context_t *context, VALUE data) {
    if (context->output_length == 0) {
        rb_raise(context->error_class, "use squeeze methods for arbitrary length output");
    }

    // Create a copy of the state for processing
    void *state_copy = malloc(context->functions->state_size);
    if (!state_copy) {
        rb_raise(rb_eNoMemError, "failed to allocate memory for state copy");
    }

    memcpy(state_copy, context->state, context->functions->state_size);

    int result;

    // If data is provided, update the copy
    if (!NIL_P(data)) {
        StringValue(data);
        size_t data_len = (RSTRING_LEN(data) * 8);

        if (data_len > 0) {
            switch (context->functions->algorithm) {
                case SP800_185_CSHAKE_128:
                case SP800_185_CSHAKE_256:
                    result =
                        context->functions->cshake.update(state_copy, (const BitSequence *)RSTRING_PTR(data), data_len);
                    break;
                case SP800_185_KMAC_128:
                case SP800_185_KMAC_256:
                    result =
                        context->functions->kmac.update(state_copy, (const BitSequence *)RSTRING_PTR(data), data_len);
                    break;
                default:
                    free(state_copy);
                    rb_raise(context->error_class, "unknown algorithm");
                    return Qnil;
            }

            if (result != 0) {
                free(state_copy);
                rb_raise(context->error_class, "failed to update %s state", context->functions->name);
            }
        }
    }

    // Prepare output and finalize
    VALUE output = rb_str_new(0, context->output_length / 8);

    switch (context->functions->algorithm) {
        case SP800_185_CSHAKE_128:
        case SP800_185_CSHAKE_256:
            result = context->functions->cshake.final(state_copy, (BitSequence *)RSTRING_PTR(output));
            break;
        case SP800_185_KMAC_128:
        case SP800_185_KMAC_256:
            result = context->functions->kmac.final(state_copy, (BitSequence *)RSTRING_PTR(output));
            break;
        default:
            free(state_copy);
            rb_raise(context->error_class, "unknown algorithm");
            return Qnil;
    }

    free(state_copy);

    if (result != 0) {
        rb_raise(context->error_class, "failed to finalize %s state", context->functions->name);
    }

    return output;
}

VALUE sp800_185_hexdigest(sp800_185_context_t *context, VALUE data) {
    VALUE bin_str = sp800_185_digest(context, data);
    return rb_funcall(bin_str, rb_intern("unpack1"), 1, rb_str_new2("H*"));
}

VALUE sp800_185_squeeze(sp800_185_context_t *context, VALUE length) {
    if (context->output_length != 0) {
        rb_raise(context->error_class, "use digest methods for fixed-length output");
    }

    size_t output_byte_len;
    VALUE str;

    Check_Type(length, T_FIXNUM);
    output_byte_len = NUM2ULONG(length);

    if (output_byte_len <= 0) {
        rb_raise(context->error_class, "output length must be specified");
    }

    // Create a copy of the state for processing
    void *state_copy = malloc(context->functions->state_size);
    if (!state_copy) {
        rb_raise(rb_eNoMemError, "failed to allocate memory for state copy");
    }

    memcpy(state_copy, context->state, context->functions->state_size);

    // First transition the state to FINAL
    VALUE dummy_output = rb_str_new(0, 0);
    int result;

    switch (context->functions->algorithm) {
        case SP800_185_CSHAKE_128:
        case SP800_185_CSHAKE_256:
            result = context->functions->cshake.final(state_copy, (BitSequence *)RSTRING_PTR(dummy_output));
            break;
        case SP800_185_KMAC_128:
        case SP800_185_KMAC_256:
            result = context->functions->kmac.final(state_copy, (BitSequence *)RSTRING_PTR(dummy_output));
            break;
        default:
            free(state_copy);
            rb_raise(context->error_class, "unknown algorithm");
            return Qnil;
    }

    if (result != 0) {
        free(state_copy);
        rb_raise(context->error_class, "failed to finalize %s state", context->functions->name);
    }

    // Allocate the output buffer for the specified number of bytes
    str = rb_str_new(0, output_byte_len);

    // Use the function table to call the appropriate squeeze function
    switch (context->functions->algorithm) {
        case SP800_185_CSHAKE_128:
        case SP800_185_CSHAKE_256:
            result =
                context->functions->cshake.squeeze(state_copy, (BitSequence *)RSTRING_PTR(str), output_byte_len * 8);
            break;
        case SP800_185_KMAC_128:
        case SP800_185_KMAC_256:
            result = context->functions->kmac.squeeze(state_copy, (BitSequence *)RSTRING_PTR(str), output_byte_len * 8);
            break;
        default:
            free(state_copy);
            rb_raise(context->error_class, "unknown algorithm");
            return Qnil;
    }

    free(state_copy);

    if (result != 0) {
        rb_raise(context->error_class, "failed to squeeze %s", context->functions->name);
    }

    return str;
}

VALUE sp800_185_hex_squeeze(sp800_185_context_t *context, VALUE length) {
    VALUE binary_result = sp800_185_squeeze(context, length);
    return rb_funcall(binary_result, rb_intern("unpack1"), 1, rb_str_new2("H*"));
}
