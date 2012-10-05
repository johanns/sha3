#include <ruby.h>
#include "KeccakNISTInterface.h"

#define MAX_DIGEST_SIZE 64

VALUE mSHA3;

/* @overload digest(data, data_len, hashbit_len)
 * 
 * @param data        [String] The DATA!
 * @param data_len    [String] The number of input bits provided in the input data.
 * @param hashbit_len [Fixnum] The desired number of output bits (i.e., 224, 256, 384, 512).
 *
 * @return [String] Computed hash
*/
VALUE m_sha3_digest(VALUE self, VALUE data, VALUE datalen, VALUE hashbitlen)
{
  int hlen = NUM2INT(hashbitlen);

  if ((hlen != 224) && (hlen != 256) && (hlen != 384) && (hlen != 512))
    rb_raise(rb_eArgError, "invalid hashbit_len given (valid options: 224, 256, 384, or 512)");

  StringValue(data);

  VALUE s = rb_str_new(0, hlen / 8);

  if (Hash(hlen, RSTRING_PTR(data), NUM2ULL(datalen), RSTRING_PTR(s)) != SUCCESS)
    rb_raise(rb_eException, "unable to generate hash");

  return s;
}

void Init_sha3_n()
{
  mSHA3 = rb_define_module("SHA3");

  rb_define_module_function(mSHA3, "digest", m_sha3_digest, 3);
}