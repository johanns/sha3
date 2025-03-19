#ifndef _SHA3_SP800_185_H_
#define _SHA3_SP800_185_H_

#include <ruby.h>
#include <ruby/thread.h>

#include "KeccakHash.h"
#include "SP800-185.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SP800-185 algorithm family */
typedef enum {
    SP800_185_CSHAKE_128 = 0,
    SP800_185_CSHAKE_256,
    SP800_185_KMAC_128,
    SP800_185_KMAC_256,
} sp800_185_algorithm_t;

/* Common function pointer typedefs for SP800-185 algorithms */
typedef int (*sp800_185_init_fn)(void *state, size_t capacity, const BitSequence *N, size_t NLen, const BitSequence *S,
                                 size_t SLen);

typedef int (*sp800_185_init_key_fn)(void *state, const BitSequence *key, BitLength keyBitLen, BitLength outputBitLen,
                                     const BitSequence *customization, BitLength customBitLen);

typedef int (*sp800_185_update_fn)(void *state, const BitSequence *data, size_t dataLen);
typedef int (*sp800_185_final_fn)(void *state, BitSequence *output);
typedef int (*sp800_185_squeeze_fn)(void *state, BitSequence *output, size_t outputLen);

/* Function table for SP800-185 algorithm operations */
typedef struct {
    sp800_185_algorithm_t algorithm;
    const char *name;
    size_t state_size;

    union {
        struct {
            sp800_185_init_fn init;
            sp800_185_update_fn update;
            sp800_185_final_fn final;
            sp800_185_squeeze_fn squeeze;
        } cshake;

        struct {
            sp800_185_init_key_fn init;
            sp800_185_update_fn update;
            sp800_185_final_fn final;
            sp800_185_squeeze_fn squeeze;
        } kmac;
    };
} sp800_185_function_table_t;

/* Base context structure for SP800-185 algorithms */
typedef struct {
    void *state;
    const sp800_185_function_table_t *functions;
    size_t output_length;
    VALUE error_class;
} sp800_185_context_t;

/* Global variables */
extern sp800_185_function_table_t sp800_185_functions[];

extern sp800_185_context_t *sp800_185_alloc_context(size_t, size_t);
extern size_t sp800_185_context_size(const sp800_185_context_t *, size_t);
extern void sp800_185_free_context(sp800_185_context_t *);

/* Helper functions - these are now internal C functions with an additional context parameter */
VALUE sp800_185_update(sp800_185_context_t *context, VALUE data);
VALUE sp800_185_digest(sp800_185_context_t *context, VALUE data);
VALUE sp800_185_hexdigest(sp800_185_context_t *context, VALUE data);
VALUE sp800_185_finish(sp800_185_context_t *context, VALUE output);
VALUE sp800_185_squeeze(sp800_185_context_t *context, VALUE length);
VALUE sp800_185_hex_squeeze(sp800_185_context_t *context, VALUE length);
const char *sp800_185_name(sp800_185_context_t *context);

// Macro to define common Ruby methods
#define DEFINE_SP800_185_METHOD(name) static VALUE rb_sp800_185_##name(int argc, VALUE *argv, VALUE self);

DEFINE_SP800_185_METHOD(update)
DEFINE_SP800_185_METHOD(finish)
DEFINE_SP800_185_METHOD(digest)
DEFINE_SP800_185_METHOD(hexdigest)
DEFINE_SP800_185_METHOD(squeeze)
DEFINE_SP800_185_METHOD(hex_squeeze)

#ifdef __cplusplus
}
#endif

#endif /* _SHA3_SP800_185_H_ */
