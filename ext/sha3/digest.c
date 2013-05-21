/* Copyright (c) 2012 - 2013 Johanns Gregorian <io+sha3@jsani.com> */

#include "sha3.h"

VALUE cDigest;
VALUE eDigestError;

/*
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

  mdx = (MDX *) malloc(sizeof(MDX));
  if (!mdx)
    rb_raise(eDigestError, "failed to allocate object memory");

  mdx->state = (hashState *) malloc(sizeof(hashState));  
  if (!mdx->state) {
    free_allox(mdx);
    rb_raise(eDigestError, "failed to allocate state memory");
  }

  obj = Data_Wrap_Struct(klass, 0, free_allox, mdx);

  memset(mdx->state, 0, sizeof(hashState));
  mdx->hashbitlen = 0;

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

  memset(mdx->state, 0, sizeof(hashState));

  if (Init(mdx->state, mdx->hashbitlen) != SUCCESS)
    rb_raise(eDigestError, "failed to reset internal state");

  return self;
}

// Fix: And, permanent reminder of a rookie mistake in c_digest_copy, comparing structs with ==/!= op
// Fix: Woke-up after 2-hours of sleep, and for good reason. Fixed string comparison. Need to re-read K&R!
static int cmp_states(MDX *mdx1, MDX *mdx2)
{
    return (
      (mdx1->hashbitlen == mdx2->hashbitlen) &&
      (strcmp(mdx1->state->state, mdx2->state->state) == 0) &&
      (strcmp(mdx1->state->dataQueue, mdx2->state->dataQueue) == 0) &&
      (mdx1->state->rate == mdx2->state->rate) &&
      (mdx1->state->capacity == mdx2->state->capacity) &&
      (mdx1->state->bitsInQueue == mdx2->state->bitsInQueue) &&
      (mdx1->state->fixedOutputLength == mdx2->state->fixedOutputLength) &&
      (mdx1->state->squeezing == mdx2->state->squeezing) &&
      (mdx1->state->bitsAvailableForSqueezing == mdx2->state->bitsAvailableForSqueezing)
    );
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
  if (!cmp_states(mdx1, mdx2))
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
static VALUE c_digest_compute(int argc, VALUE *argv, VALUE self)
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

void Init_sha3_n_digest()
{
  rb_require("digest");

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