# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = 'sha3'
  spec.version = '2.0.0'

  spec.authors = ['Johanns Gregorian']
  spec.email = ['io+sha3@jsg.io']

  spec.description = 'A XKCP based native (C) binding to SHA3 (FIPS 202) cryptographic hashing algorithm.'
  spec.summary = 'SHA3 (FIPS 202) cryptographic hashing algorithm'

  spec.homepage = 'https://github.com/johanns/sha3'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 2.7.0'

  spec.metadata['changelog_uri'] = "#{spec.homepage}/CHANGELOG.md"
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['documentation_uri'] = 'https://docs.jsg.io/sha3/html/index.html'

  spec.post_install_message = <<-MSG
    [NOTICE] SHA3 version 2.0 introduces breaking changes to the API.
    Please review the changelog and ensure compatibility with your application.
    If you need the previous behavior, lock your Gemfile to version '~> 1.0'."
  MSG

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git))})
    end
  end

  spec.extensions = ['ext/sha3/extconf.rb']
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.cert_chain = ['certs/johanns.pem']
  spec.signing_key = File.expand_path('~/.ssh/gem-private_key.pem') if $PROGRAM_NAME =~ /gem\z/

  spec.add_dependency('rdoc', '~> 6.12')
end
