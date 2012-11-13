#include "_sha3.h"

/* Document-module: SHA3 
 * SHA3
 */

/* Document-class: SHA3::Digest < Digest::Class
 * SHA3::Digest allows you to compute message digests
 * (interchangeably called "hashes") of arbitrary data that are
 * cryptographically secure using SHA3 (Keccak) algorithm.
 *  
 * == Usage
 *
 *  require 'sha3'
 * 
 * === Basics
 *     
 *  # Instantiate a new SHA3::Digest class with 256 bit length
 *  s = SHA3::Digest.new(:sha256)
 *  # => #<SHA3::Digest: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470>
 *
 *  # Update hash state, and compute new value
 *  s.update "Compute Me"
 *  # => #<SHA3::Digest: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470>
 *     
 *  # << is an .update() alias
 *  s << "Me too"
 *  # => #<SHA3::Digest: e26f539eee3a05c52eb1f9439652d23343adea9764f011da232d24cd6d19924a>
 *     
 *  # Print digest bytes string
 *  puts s.digest
 *     
 *  # Print digest hex string
 *  puts s.hexdigest
 *
 * === Hashing a file
 *
 *  # Compute the hash value for given file, and return the result as hex
 *  s = SHA3::Digest.new(224).file("my_awesome_file.bin").hexdigest
 *
 * === Bit operation
 *     
 *  # Compute hash of "011"
 *  SHA3::Digest.compute(:sha224, "\xC0", 3).unpack("H*")
 *  # => ["2b695a6fd92a2b3f3ce9cfca617d22c9bb52815dd59a9719b01bad25"]
 *
 * == Notes
 *  
 *    ::Digest::Class call sequence ->
 *    | .alloc() ->
 *    | .new() ->
 *    | .update() ->
 *    | .digest or .hexdigest or .inspect -> (Instance.digest or .hexdigest()) ->
 *    --| .alloc() ->
 *      | .copy() ->
 *      | .finish() ->
 *  
 */

static int get_hlen(VALUE obj)
{
  int hlen;

  if (TYPE(obj) == T_SYMBOL) {
    ID symid;

    symid = SYM2ID(obj);

    if (rb_intern("sha224") == symid)
      hlen = 224;
    else if (rb_intern("sha256") == symid)
      hlen = 256;
    else if (rb_intern("sha384") == symid)
      hlen = 384;
    else if (rb_intern("sha512") == symid)
      hlen = 512;
    else
      rb_raise(eDigestError, "invalid hash bit symbol (should be: :sha224, :sha256, :sha384, or :sha512");
  }
  else if (TYPE(obj) == T_FIXNUM) {
    hlen = NUM2INT(obj);

    if ((hlen != 224) && (hlen != 256) && (hlen != 384) && (hlen != 512))
      rb_raise(rb_eArgError, "invalid hash bit length (should be: 224, 256, 384, or 512)");
  }
  else
    rb_raise(eDigestError, "unknown type value");

  return hlen;
}

static void free_allox(MDX *mdx) 
{
  if (mdx) {
    if (mdx->state)
      free(mdx->state);

    free(mdx);
  } 

  return;
}

static VALUE c_digest_alloc(VALUE klass) 
{
  MDX *mdx;
  VALUE obj;

  mdx = (MDX *) malloc(sizeof(*mdx));
  if (!mdx)
    rb_raise(eDigestError, "failed to allocate object memory");

  mdx->state = (hashState *) malloc(sizeof(*mdx->state));
  memset(mdx->state, 0, sizeof(*mdx->state));
  
  if (!mdx->state)
    rb_raise(eDigestError, "failed to allocate state memory");

  obj = Data_Wrap_Struct(klass, 0, free_allox, mdx);

  return obj;
}

static VALUE c_digest_update(VALUE, VALUE);

// SHA3::Digest.new(type, [data]) -> self
static VALUE c_digest_init(int argc, VALUE *argv, VALUE self)
{ 
  MDX *mdx;
  VALUE hlen, data;

  rb_scan_args(argc, argv, "02", &hlen, &data);
  GETMDX(self, mdx);

  if (!NIL_P(hlen))
    mdx->hashbitlen = get_hlen(hlen);
  else
    mdx->hashbitlen = 256;

  if (Init(mdx->state, mdx->hashbitlen) != SUCCESS)
    rb_raise(eDigestError, "failed to initialize algorithm state");

  if (!NIL_P(data))
    return c_digest_update(self, data);

  return self;
}

// SHA3::Digest.update(data) -> self
static VALUE c_digest_update(VALUE self, VALUE data) 
{
  MDX *mdx;
  DataLength dlen;

  StringValue(data);
  GETMDX(self, mdx);

  dlen = (RSTRING_LEN(data) * 8);

  if (Update(mdx->state, RSTRING_PTR(data), dlen) != SUCCESS)
    rb_raise(eDigestError, "failed to update hash data");

  return self;
}

// SHA3::Digest.reset() -> self
static VALUE c_digest_reset(VALUE self) 
{
  MDX *mdx;

  GETMDX(self, mdx);

  memset(mdx->state, 0, sizeof(*mdx->state));

  if (Init(mdx->state, mdx->hashbitlen) != SUCCESS)
    rb_raise(eDigestError, "failed to reset internal state");

  return self;
}

// SHA3::Digest.copy(obj) -> self
static VALUE c_digest_copy(VALUE self, VALUE obj) 
{
  MDX *mdx1, *mdx2;

  rb_check_frozen(self);
  if (self == obj)
    return self;

  GETMDX(self, mdx1);
  SAFEGETMDX(obj, mdx2);

  memcpy(mdx1->state, mdx2->state, sizeof(hashState));
  mdx1->hashbitlen = mdx2->hashbitlen;
 
  // Fetch the data again to make sure it was copied
  GETMDX(self, mdx1);
  SAFEGETMDX(obj, mdx2);
  if ((mdx1->state != mdx2->state) && (mdx1->hashbitlen != mdx2->hashbitlen))
    rb_raise(eDigestError, "failed to copy state");

  return self;
}

// SHA3::Digest.digest_length -> Integer
static VALUE c_digest_length(VALUE self) 
{
  MDX *mdx;
  GETMDX(self, mdx);

  return ULL2NUM(mdx->hashbitlen / 8);
}

// SHA3::Digest.block_length -> Integer
static VALUE c_digest_block_length(VALUE self) 
{
  MDX *mdx;
  GETMDX(self, mdx);

  return ULL2NUM(200 - (2 * (mdx->hashbitlen / 8)));
}

// SHA3::Digest.name -> String
static VALUE c_digest_name(VALUE self) 
{
  return rb_str_new2("SHA3");
}

// SHA3::Digest.finish() -> String
static VALUE c_digest_finish(int argc, VALUE *argv, VALUE self) 
{
  MDX *mdx;
  VALUE str;

  rb_scan_args(argc, argv, "01", &str);
  GETMDX(self, mdx);

  if (NIL_P(str)) {
    str = rb_str_new(0, mdx->hashbitlen / 8);
  } 
  else {
    StringValue(str);
    rb_str_resize(str, mdx->hashbitlen / 8);
  }

  if (Final(mdx->state, RSTRING_PTR(str)) != SUCCESS)
    rb_raise(eDigestError, "failed to finalize digest");

  return str;
}

// SHA3::Digest.compute(type, data, [datalen]) -> String (bytes)
// TO-DO: styled output (hex)
VALUE c_digest_compute(int argc, VALUE *argv, VALUE self)
{
  VALUE hlen, data, dlen, str;
  int hashbitlen;
  DataLength datalen;

  rb_scan_args(argc, argv, "21", &hlen, &data, &dlen);

  hashbitlen = get_hlen(hlen);

  StringValue(data);
  
  if (!NIL_P(dlen))
    datalen = NUM2ULL(dlen);
  else
    datalen = (RSTRING_LEN(data) * 8);

  str = rb_str_new(0, hashbitlen / 8);

  if (Hash(hashbitlen, RSTRING_PTR(data), datalen, RSTRING_PTR(str)) != SUCCESS)
    rb_raise(eDigestError, "failed to generate hash");

  return str;
}

void Init_sha3_n()
{
  rb_require("digest");

  mSHA3 = rb_define_module("SHA3");
  /* SHA3::Digest (class) */
  cDigest = rb_define_class_under(mSHA3, "Digest", rb_path2class("Digest::Class"));
  /* SHA3::Digest::DigestError (class) */ 
  eDigestError = rb_define_class_under(cDigest, "DigestError", rb_eStandardError);

  // SHA3::Digest (class) methods
  rb_define_alloc_func(cDigest, c_digest_alloc);
  rb_define_method(cDigest, "initialize", c_digest_init, -1);
  rb_define_method(cDigest, "update", c_digest_update, 1);
  rb_define_method(cDigest, "reset", c_digest_reset, 0);
  rb_define_method(cDigest, "initialize_copy", c_digest_copy, 1);
  rb_define_method(cDigest, "digest_length", c_digest_length, 0);
  rb_define_method(cDigest, "block_length", c_digest_block_length, 0);
  rb_define_method(cDigest, "name", c_digest_name, 0);
  rb_define_private_method(cDigest, "finish", c_digest_finish, -1);

  rb_define_alias(cDigest, "<<", "update");
  
  // SHA3 (module) functions (support bit operations)
  rb_define_singleton_method(cDigest, "compute", c_digest_compute, -1);

  return;
}