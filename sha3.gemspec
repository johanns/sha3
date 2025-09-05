# frozen_string_literal: true

require_relative 'lib/constants'

Gem::Specification.new do |spec|
  spec.name = 'sha3'
  spec.version = SHA3::VERSION

  spec.authors = ['Johanns Gregorian']
  spec.email = ['io+sha3@jsg.io']

  spec.description = <<~DESC
    A high-performance native binding to the SHA3 (FIPS 202) cryptographic hashing algorithms, based on the XKCP - eXtended Keccak Code Package.
    This gem provides support for the standard SHA-3 fixed-length functions (224, 256, 384, and 512 bits),
    as well as the SHAKE128/SHAKE256 extendable-output functions (XOFs), cSHAKE128/256, and KMAC as specified in NIST SP 800-185.'
  DESC
  spec.summary = 'SHA-3 (FIPS 202), SHAKE128/SHAKE256, cSHAKE128/cSHAKE256, and KMAC (NIST SP 800-185), powered by XKCP.'

  spec.homepage = 'https://github.com/johanns/sha3'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 2.7.0'

  spec.metadata['changelog_uri'] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['documentation_uri'] = 'https://docs.jsg.io/sha3/index.html'

  spec.post_install_message = <<-NOTICE
    [NOTICE] SHA3 version 2.0 introduces breaking changes to the API.
    Please review the changelog and ensure compatibility with your application.
    If you need the previous behavior, lock your Gemfile to version '~> 1.0'."
  NOTICE

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git))})
    end
  end

  spec.extensions = ['ext/sha3/extconf.rb']
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.cert_chain = ['certs/io+sha3@jsg.io.pem']
  spec.signing_key = File.expand_path('~/.ssh/gem-private_key.pem') if $PROGRAM_NAME =~ /gem\z/
end
