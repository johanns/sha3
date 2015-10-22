# -*- encoding: utf-8 -*-

require File.expand_path('../lib/sha3/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = "sha3"
  gem.version       = SHA3::VERSION
  gem.summary       = %q{SHA3 for Ruby}
  gem.description   = %q{SHA3 for Ruby is a native (C) FIPS 202 compliant implementation of SHA3 (Keccak) cryptographic hashing algorithm.}
  gem.license       = "MIT"
  gem.authors       = ["Johanns Gregorian"]
  gem.email         = "io+sha3@jsg.io"
  gem.homepage      = "https://github.com/johanns/sha3#readme"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']
  gem.extensions    = ['ext/sha3/extconf.rb']

  gem.add_development_dependency "rake-compiler"
  gem.add_development_dependency 'rspec', '~> 3.3'
  gem.add_development_dependency 'rubygems-tasks'
  gem.add_development_dependency 'yard'
end
