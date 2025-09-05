// Copyright (c) 2025 Johanns Gregorian <io+sha3@jsg.io>

#ifndef _SHA3_COMMON_H_
#define _SHA3_COMMON_H_

#include <ruby.h>

#include "sp800_185.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Common macros for SP800-185 based implementations (CSHAKE, KMAC) */

/* Define a simple method that just calls an sp800_185 function */
#define DEFINE_SP800_185_SIMPLE_METHOD(method_name, sp_func, get_ctx_func) \
    static VALUE method_name(VALUE self, VALUE data) {                     \
        sp800_185_context_t *context;                                      \
        get_ctx_func(self, &context);                                      \
        sp_func(context, data);                                            \
        return self;                                                       \
    }

/* Define a method that returns a value from sp800_185 function */
#define DEFINE_SP800_185_RETURN_METHOD(method_name, sp_func, get_ctx_func) \
    static VALUE method_name(VALUE self) {                                 \
        sp800_185_context_t *context;                                      \
        get_ctx_func(self, &context);                                      \
        return sp_func(context);                                           \
    }

/* Define a method with single VALUE parameter that returns VALUE */
#define DEFINE_SP800_185_VALUE_METHOD(method_name, sp_func, get_ctx_func) \
    static VALUE method_name(VALUE self, VALUE param) {                   \
        sp800_185_context_t *context;                                     \
        get_ctx_func(self, &context);                                     \
        return sp_func(context, param);                                   \
    }

/* Define a method with variable arguments */
#define DEFINE_SP800_185_VARARGS_METHOD(method_name, sp_func, get_ctx_func) \
    static VALUE method_name(int argc, VALUE *argv, VALUE self) {           \
        sp800_185_context_t *context;                                       \
        get_ctx_func(self, &context);                                       \
        VALUE param = argc > 0 ? argv[0] : Qnil;                            \
        return sp_func(context, param);                                     \
    }

/* Define common memory management functions */
#define DEFINE_SP800_185_MEMORY_FUNCS(prefix, context_type)                                              \
    static void prefix##_free_context(void *ptr) { sp800_185_free_context((sp800_185_context_t *)ptr); } \
                                                                                                         \
    static size_t prefix##_context_size(const void *ptr) {                                               \
        return sp800_185_context_size((const sp800_185_context_t *)ptr, sizeof(context_type));           \
    }

/* Define common allocation function */
#define DEFINE_SP800_185_ALLOC(prefix, context_type, instance_type, error_class)                                      \
    static VALUE rb_##prefix##_alloc(VALUE klass) {                                                                   \
        context_type *context = (context_type *)sp800_185_alloc_context(sizeof(context_type), sizeof(instance_type)); \
                                                                                                                      \
        if (!context) {                                                                                               \
            rb_raise(error_class, "failed to allocate memory");                                                       \
        }                                                                                                             \
                                                                                                                      \
        VALUE obj = TypedData_Wrap_Struct(klass, &prefix##_data_type, context);                                       \
        return obj;                                                                                                   \
    }

/* Define common copy method */
#define DEFINE_SP800_185_COPY_METHOD(method_name, context_type, data_type, class_var)                    \
    static VALUE method_name(VALUE self, VALUE other) {                                                  \
        context_type *context, *other_context;                                                           \
                                                                                                         \
        rb_check_frozen(self);                                                                           \
        if (self == other) {                                                                             \
            return self;                                                                                 \
        }                                                                                                \
                                                                                                         \
        if (!rb_obj_is_kind_of(other, class_var)) {                                                      \
            rb_raise(rb_eTypeError, "wrong argument (%s)! (expected %s)", rb_obj_classname(other),       \
                     rb_class2name(class_var));                                                          \
        }                                                                                                \
                                                                                                         \
        TypedData_Get_Struct(other, context_type, &data_type, other_context);                            \
        TypedData_Get_Struct(self, context_type, &data_type, context);                                   \
                                                                                                         \
        /* Copy the base context attributes */                                                           \
        context->base.functions = other_context->base.functions;                                         \
        context->base.output_length = other_context->base.output_length;                                 \
        context->base.error_class = other_context->base.error_class;                                     \
                                                                                                         \
        /* Copy the algorithm-specific state */                                                          \
        if (context->base.functions && other_context->base.state) {                                      \
            memcpy(context->base.state, other_context->base.state, context->base.functions->state_size); \
        }                                                                                                \
                                                                                                         \
        return self;                                                                                     \
    }

/* Ruby wrapper functions for SP800-185 operations */
VALUE sp800_185_rb_update(sp800_185_context_t *context, VALUE data);
VALUE sp800_185_rb_name(sp800_185_context_t *context);
VALUE sp800_185_rb_finish(sp800_185_context_t *context, VALUE output);
VALUE sp800_185_rb_digest(sp800_185_context_t *context, VALUE data);
VALUE sp800_185_rb_hexdigest(sp800_185_context_t *context, VALUE data);
VALUE sp800_185_rb_squeeze(sp800_185_context_t *context, VALUE length);
VALUE sp800_185_rb_hex_squeeze(sp800_185_context_t *context, VALUE length);

/* Helper function to register common methods */
void register_sp800_185_common_methods(VALUE klass);

#ifdef __cplusplus
}
#endif

#endif /* _SHA3_COMMON_H_ */
