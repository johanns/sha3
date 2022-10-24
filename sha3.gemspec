# frozen_string_literal: true

require_relative 'lib/sha3/version'

# rubocop:disable Metrics/BlockLength(Rubocop)
Gem::Specification.new do |spec|
  spec.name = 'sha3'
  spec.version = SHA3::VERSION

  spec.authors = ['Johanns Gregorian']
  spec.email = ['io+sha3@jsg.io']

  spec.description = 'A XKCP based native (C) binding to SHA3 (FIPS 202) cryptographic hashing algorithm.'
  spec.summary = 'SHA3 (FIPS 202) cryptographic hashing algorithm'

  spec.homepage = 'https://github.com/johanns/sha3'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 2.6.0'

  spec.metadata['changelog_uri'] = "#{spec.homepage}/CHANGELOG.md"
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end

  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.extensions = ['ext/sha3/extconf.rb']
  spec.require_paths = ['lib']

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.add_development_dependency('rake', '~> 13.0')
  spec.add_development_dependency('rake-compiler', '~> 1.2')
  spec.add_development_dependency('rspec', '~> 3.11')
  spec.add_development_dependency('rubocop', '~> 1.37')
  spec.add_development_dependency('rubocop-rake', '~> 0.6')
  spec.add_development_dependency('rubocop-rspec', '~> 2.14')

  spec.cert_chain = ['certs/johanns.pem']
  spec.signing_key = File.expand_path('~/.ssh/gem-private_key.pem') if $PROGRAM_NAME =~ /gem\z/
end
# rubocop:enable Metrics/BlockLength(Rubocop)
