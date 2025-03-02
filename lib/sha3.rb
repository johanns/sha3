# frozen_string_literal: true

module SHA3
  require 'sha3_ext'

  VERSION = "2.0.0"

  alg = {
    sha3_224: 'SHA3_224',
    sha3_256: 'SHA3_256',
    sha3_384: 'SHA3_384',
    sha3_512: 'SHA3_512',
    shake_128: 'SHAKE_128',
    shake_256: 'SHAKE_256'
  }

  alg.each do |key, name|
    klass = Class.new(Digest) do
      define_method(:initialize) do |*data|
        if data.length > 1
          raise ArgumentError,
                "wrong number of arguments (#{data.length} for 1)"
        end

        super(key, data.first)
      end
    end

    singleton = (class << klass; self; end)
    singleton.class_eval do
      define_method(:digest) { |data| Digest.digest(key, data) }
      define_method(:hexdigest) { |data| Digest.hexdigest(key, data) }
    end

    # Define the class under SHA3::Digest
    SHA3::Digest.const_set(name, klass)
  end
end
