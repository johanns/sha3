#ifndef _SHA3_SP800_185_H_
#define _SHA3_SP800_185_H_

#include <ruby.h>
#include <ruby/thread.h>
#include <stdbool.h>

#include "KeccakHash.h"
#include "SP800-185.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations for types from Keccak if not already defined */
#ifndef KECCAK_TYPES_DEFINED
typedef unsigned char BitSequence;
typedef size_t BitLength;
#endif

/* SP800-185 algorithm family */
typedef enum {
    SP800_185_CSHAKE_128 = 0,
    SP800_185_CSHAKE_256,
    SP800_185_KMAC_128,
    SP800_185_KMAC_256,
} sp800_185_algorithm_t;

/* Common function pointer typedefs for SP800-185 algorithms */
typedef int (*sp800_185_update_fn)(void *state, const BitSequence *data, size_t dataLen);
typedef int (*sp800_185_final_fn)(void *state, BitSequence *output);
typedef int (*sp800_185_squeeze_fn)(void *state, BitSequence *output, size_t outputLen);

/* Error codes for SP800-185 operations */
typedef enum {
    SP800_185_SUCCESS = 0,
    SP800_185_ERROR_INVALID_ALGORITHM = -1,
    SP800_185_ERROR_INVALID_PARAMS = -2,
    SP800_185_ERROR_INIT_FAILED = -3,
    SP800_185_ERROR_INVALID_STATE = -4
} sp800_185_error_t;

/* Parameter structures for different algorithms */
typedef struct {
    size_t capacity;
    const BitSequence *N;
    size_t NLen;
    const BitSequence *S;
    size_t SLen;
} cshake_init_params_t;

typedef struct {
    const BitSequence *key;
    BitLength keyBitLen;
    BitLength outputBitLen;
    const BitSequence *customization;
    BitLength customBitLen;
} kmac_init_params_t;

typedef struct {
    sp800_185_algorithm_t algorithm;
    const char *name;
    size_t state_size;
    bool is_keyed; /* true for KMAC, false for CSHAKE */

    /* All algorithms use these same signatures */
    sp800_185_update_fn update;
    sp800_185_final_fn final;
    sp800_185_squeeze_fn squeeze;

    /* Generic initialization - let the caller handle parameter differences */
    int (*init)(void *state, void *params);
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

/* Algorithm lookup functions */
const sp800_185_function_table_t *sp800_185_get_algorithm(sp800_185_algorithm_t algorithm);
const sp800_185_function_table_t *sp800_185_get_algorithm_by_name(const char *name);

/* Safe accessor functions for algorithm-specific operations */
static inline int sp800_185_init_cshake(const sp800_185_function_table_t *table, void *state, size_t capacity,
                                        const BitSequence *N, size_t NLen, const BitSequence *S, size_t SLen) {
    if (!table || table->is_keyed) {
        return SP800_185_ERROR_INVALID_ALGORITHM;
    }
    cshake_init_params_t params = {capacity, N, NLen, S, SLen};
    return table->init(state, &params);
}

static inline int sp800_185_init_kmac(const sp800_185_function_table_t *table, void *state, const BitSequence *key,
                                      BitLength keyBitLen, BitLength outputBitLen, const BitSequence *customization,
                                      BitLength customBitLen) {
    if (!table || !table->is_keyed) {
        return SP800_185_ERROR_INVALID_ALGORITHM;
    }
    kmac_init_params_t params = {key, keyBitLen, outputBitLen, customization, customBitLen};
    return table->init(state, &params);
}

/* Validation and utility functions */
bool sp800_185_validate_table(const sp800_185_function_table_t *table);
const char *sp800_185_algorithm_name(sp800_185_algorithm_t algorithm);

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

#ifdef __cplusplus
}
#endif

#endif /* _SHA3_SP800_185_H_ */
