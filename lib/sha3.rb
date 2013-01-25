require 'sha3_n'
require 'sha3/version'

module SHA3
  class Digest

    # Based on 'OpenSSL for Ruby 2' project
    # Copyright (C) 2002 Michal Rokos <m.rokos@sh.cvut.cz>
    alg = { :sha224 => "SHA224", :sha256 => "SHA256", :sha384 => "SHA384", :sha512 => "SHA512"}

    def self.digest(name, data)
      super(data, name)
    end

    alg.each { |key, name|
      klass = Class.new(Digest) {
        define_method(:initialize) { |*data|
          if data.length > 1
            raise ArgumentError,
              "wrong number of arguments (#{data.length} for 1)"
          end

          super(key, data.first)
        }
      }
      singleton = (class << klass; self; end)
      singleton.class_eval{
        define_method(:digest){ |data| Digest.digest(key, data) }
        define_method(:hexdigest){ |data| Digest.hexdigest(key, data) }
      }

      const_set(name, klass)
    }
  end
end
