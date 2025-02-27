# frozen_string_literal: true

require 'sha3_n'
require 'sha3/version'

module SHA3
  class Digest
    # Based on 'OpenSSL for Ruby 2' project
    # Copyright (C) 2002 Michal Rokos <m.rokos@sh.cvut.cz>
    alg = { sha3_224: 'SHA3_224', sha3_256: 'SHA3_256', sha3_384: 'SHA3_384', sha3_512: 'SHA3_512' }

    def self.digest(name, data)
      super(data, name)
    end

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

      const_set(name, klass)
    end
  end
end
