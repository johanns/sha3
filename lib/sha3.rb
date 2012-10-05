require 'sha3/version'
require 'sha3_n'

module SHA3
  extend self

  def digest_224(data)
    SHA3::digest(data, data.length * 8, 224)
  end

  def digest_256(data)
    SHA3::digest(data, data.length * 8, 256)
  end

  def digest_384(data)
    SHA3::digest(data, data.length * 8, 384)
  end

  def digest_512(data)
    SHA3::digest(data, data.length * 8, 512)
  end
end