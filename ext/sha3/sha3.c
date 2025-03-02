#include "sha3.h"

VALUE _sha3_module;

void Init_sha3_ext(void) {
    /*
     * Document-module: SHA3
     *
     * This module provides implementations of the SHA-3 family of cryptographic hash functions
     * and the SHAKE extendable-output functions.
     *
     * It includes the SHA3::Digest and SHA3::KMAC classes, which offer methods for computing digests and keyed message
     * authentication codes (KMAC).
     *
     * == Classes
     * SHA3::Digest
     * SHA3::Digest::DigestError
     * SHA3::KMAC
     * SHA3::KMAC::KMACError
     *
     */
    _sha3_module = rb_define_module("SHA3");

    Init_sha3_digest();

    return;
}
