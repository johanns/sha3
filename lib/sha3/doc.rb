require 'digest'

module SHA3
  # A sub-class of (MRI Ruby based) Digest::Class, it implements SHA3 (Keccak) digest algorithm.
  #
  # @note SHA3::Digest class provides a four sub-classes for the available hash bit lengths (types).
  #   You can instantiate a new instance of Digest sub-class for a given type using the following sub-classes:
  #
  #     SHA3::Digest::SHA224([data])
  #     SHA3::Digest::SHA256([data])
  #     SHA3::Digest::SHA384([data])
  #     SHA3::Digest::SHA512([data])
  #
  #   The [data] parameter is optional.
  class Digest < Digest::Class
    # Creates a Digest instance based on given hash bit length (type).
    #
    # @param type [Number, Symbol] optional parameter used to set hash bit length (type).
    #   Valid options are:
    #
    #       Number: 224, 256, 384, or 512
    #     Symobols: :sha224, :sha256, :sha384, or :sha512
    #
    #   Default value: 256 (bits)
    # @param data [String] optional parameter used to update initial instance state.
    #     #
    # @return [Digest] self
    #
    # @example
    #   digest = SHA3::Digest.new      # => Defaults to 256 bits
    #   digest = SHA3::Digest.new(224) # => Initialize a new 224 bit digest instance
    #   digest = SHA3::Digest::SHA224  # => An alternate method for creating a digest class with 224 bit hash bit length
    def initialize(type, data)
      # See function: c_digest_init(...) in ext/sha3/_digest.c
    end

    # Updates, and recalculates Message Digest (state) with given data. If a message digest
    # is to be computed from several subsequent sources, then each may be passed individually
    # to the Digest instance.
    #
    # @param data [String] data to compute
    #
    # @return [Digest] self
    #
    # @example
    #   digest = SHA3::Digest::SHA256.new
    #   digest.update('hash me')
    #   digest.update('me too')
    def update(data)
      # See function: c_digest_update(...) in ext/sha3/_digest.c
    end

    # Alias for update method
    alias << :update

    # Resets the Digest object to initial state, abandoning computed data.
    #
    # @return [Digest] self
    def reset
      # See function: c_digest_reset(...) in ext/sha3/_digest.c
    end

    # Returns message digest length in bytes.
    #
    # @return [Number] message length in bytes.
    #
    # @example
    #   digest = SHA3::Digest::SHA256.new
    #   digest.length # Result => 32 (or 256 bits)
    def length
      # See function: c_digest_length(...) in ext/sha3/_digest.c
    end

    # Returns digest block length in bytes.
    #
    # @return [Number] digest block length in bytes.
    #
    # @example
    #   digest = SHA3::Digest::SHA384.new
    #   digest.block_length # Result => 104
    def block_length
      # See function: c_digest_block_length(...) in ext/sha3/_digest.c
    end

    # Returns name of initialized digest
    #
    # @return [String] name
    def name
      # See function: c_digest_name(...) in ext/sha3/_digest.c
    end

    # Returns computed hash value for given hash type, and data in hex (string).
    #
    # @param type [Number, Symbol] See {#initialize} for valid type values.
    # @param data [String] data to compute hash value
    #
    # @return (String) computed hash as hex-encoded string
    #
    # @example
    #   SHA3::Digest.hexdigest(256, 'compute me, please')
    #   SHA3::Digest::SHA256.hexdigest('compute me, please') # => Alternate syntax
    def self.hexdigest(type, data)
    end

    # Returns computed hash value for given hash type, and data in bytes.
    #
    # @param type [Number, Symbol] See {#initialize} for valid type values.
    # @param data [String] data to compute hash value
    #
    # @return [String] computed hash in bytes
    #
    # @example
    #   SHA3::Digest.digest(256, 'compute me, please')
    #   SHA3::Digest::SHA256.digest('compute me, please') # => Alternate syntax
    def self.digest(type, data)
    end
  end

  class DigestError < StandardError
  end
end
