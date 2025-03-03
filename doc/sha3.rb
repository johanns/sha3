# frozen_string_literal: true

module SHA3
  module Digest
    # SHA3_224 is a cryptographic hash function that produces a 224-bit (28-byte) hash value.
    #
    # Usage:
    #   digest = SHA3::Digest::SHA3_224.new
    #   digest.update("message")
    #   hash = digest.hexdigest
    #
    #   # Or more simply:
    #   hash = SHA3::Digest::SHA3_224.hexdigest("message")
    #
    # See SHA3::Digest for complete API list and additional documentation.
    class SHA3_224 < ::Digest::Class; end

    # SHA3_256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value.
    #
    # Usage:
    #   digest = SHA3::Digest::SHA3_256.new
    #   digest.update("message")
    #   hash = digest.hexdigest
    #
    #   # Or more simply:
    #   hash = SHA3::Digest::SHA3_256.hexdigest("message")
    #
    # See SHA3::Digest for complete API list and additional documentation.
    class SHA3_256 < ::Digest::Class; end

    # SHA3_384 is a cryptographic hash function that produces a 384-bit (48-byte) hash value.
    #
    # Usage:
    #   digest = SHA3::Digest::SHA3_384.new
    #   digest.update("message")
    #   hash = digest.hexdigest
    #
    #   # Or more simply:
    #   hash = SHA3::Digest::SHA3_384.hexdigest("message")
    #
    # See SHA3::Digest for complete API list and additional documentation.
    class SHA3_384 < ::Digest::Class; end

    # SHA3_512 is a cryptographic hash function that produces a 512-bit (64-byte) hash value.
    #
    # Usage:
    #   digest = SHA3::Digest::SHA3_512.new
    #   digest.update("message")
    #   hash = digest.hexdigest
    #
    #   # Or more simply:
    #   hash = SHA3::Digest::SHA3_512.hexdigest("message")
    #
    # See SHA3::Digest for complete API list and additional documentation.
    class SHA3_512 < ::Digest::Class; end

    # SHAKE_128 is an extendable-output function (XOF) that can produce hash values of any desired length.
    #
    # Usage:
    #   digest = SHA3::Digest::SHAKE_128.new
    #   digest.update("message")
    #   hash = digest.hexdigest(32)  # Get 32 bytes (64 hex chars) of output
    #
    #   # Or more simply:
    #   hash = SHA3::Digest::SHAKE_128.hexdigest("message", 32)
    #
    # See SHA3::Digest for complete API list and additional documentation.
    class SHAKE_128 < ::Digest::Class; end

    # SHAKE_256 is an extendable-output function (XOF) that can produce hash values of any desired length.
    #
    # Usage:
    #   digest = SHA3::Digest::SHAKE_256.new
    #   digest.update("message")
    #   hash = digest.hexdigest(32)  # Get 32 bytes (64 hex chars) of output
    #
    #   # Or more simply:
    #   hash = SHA3::Digest::SHAKE_256.hexdigest("message", 32)
    #
    # See SHA3::Digest for complete API list and additional documentation.
    class SHAKE_256 < ::Digest::Class; end
  end
end
