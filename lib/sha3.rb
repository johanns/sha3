require 'sha3/version'
require 'sha3_n'

module SHA3
  extend self

  def digest_224(data, data_len)
    SHA3::digest(data, data_len, 224)
  end

  def digest_256(data, data_len)
    SHA3::digest(data, data_len, 256)
  end

  def digest_384(data, data_len)
    SHA3::digest(data, data_len, 384)
  end

  def digest_512(data, data_len)
    SHA3::digest(data, data_len, 512)
  end
end