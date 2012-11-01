#include "_sha3.h"

static VALUE c_digest_update(VALUE, VALUE);

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
    rb_raise(rb_eArgError, "invalid hashbit_len given (valid options are: 224, 256, 384, and 512)");

  StringValue(data);

  VALUE s = rb_str_new(0, hlen / 8);

  if (Hash(hlen, RSTRING_PTR(data), NUM2ULL(datalen), RSTRING_PTR(s)) != SUCCESS)
    rb_raise(eDigestError, "failed to generate hash");

  return s;
}

static VALUE c_digest_alloc(VALUE klass) {}
static VALUE c_digest_init(int argc, VALUE *argv, VALUE self) {}
static VALUE c_digest_update(VALUE self, VALUE data) {}
static VALUE c_digest_reset(VALUE self) {}
static VALUE c_digest_copy(VALUE self, VALUE obj) {}
static VALUE c_digest_length(VALUE self) {}
static VALUE c_digest_block_length(VALUE self) {}
static VALUE c_digest_name(VALUE self) {}
static VALUE c_digest_finish(int argc, VALUE *argv, VALUE self) {}

void Init_sha3_n()
{
  rb_require("digest");

  // SHA3 (module)
  mSHA3 = rb_define_module("SHA3");
  // SHA3::Digest (class)
  cDigest = rb_define_class_under(mSHA3, "Digest", rb_path2class("Digest::Class"));
  // SHA3::Digest::DigestError (class)
  eDigestError = rb_define_class_under(cDigest, "DigestError", rb_eStandardError);

  // SHA3 (module) functions
  rb_define_module_function(mSHA3, "digest", m_sha3_digest, 3);

  // SHA3::Digest (class) methods
  rb_define_alloc_func(cDigest, c_digest_alloc);
  rb_define_method(cDigest, "initialize", c_digest_init, -1);
  rb_define_method(cDigest, "update", c_digest_update, 1);
  rb_define_method(cDigest, "reset", c_digest_reset, 0);
  rb_define_method(cDigest, "initialize_copy", c_digest_copy, 1);
  rb_define_method(cDigest, "digest_length", c_digest_length, 0);
  rb_define_method(cDigest, "block_legnth", c_digest_block_length, 0);
  rb_define_method(cDigest, "name", c_digest_name, 0);
  rb_define_private_method(cDigest, "finish", c_digest_finish, -1);

  return;
}