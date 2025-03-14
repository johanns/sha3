# SHA3 for Ruby

[![Gem Version](https://badge.fury.io/rb/sha3.svg)](https://badge.fury.io/rb/sha3) [![Ruby](https://github.com/johanns/sha3/actions/workflows/main.yml/badge.svg)](https://github.com/johanns/sha3/actions/workflows/main.yml)

A high-performance native binding to the SHA3 (FIPS 202) cryptographic hashing algorithms, based on the [XKCP - eXtended Keccak Code Package](https://github.com/XKCP/XKCP).

This gem provides support for the standard SHA-3 fixed-length functions (224, 256, 384, and 512 bits), as well as the SHAKE128/SHAKE256 extendable-output functions (XOFs), cSHAKE128/cSHAKE256, and KMAC (Keccak Message Authentication Code) as specified in NIST SP 800-185.

> [!CAUTION]
> **Security Notice**: Do not use SHA-3 for hashing passwords. Instead, use a slow hashing function such as PBKDF2, Argon2, bcrypt, or scrypt.

> [!IMPORTANT]
> **Breaking Changes**: SHA3 version 2.0 introduces breaking changes in the API to support new features and functionality. Please review the changelog and ensure compatibility with your application. If you need the previous behavior, lock your Gemfile to version '~> 1.0'.

## Table of Contents

- [Documentation](#documentation)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [SHA-3 Fixed Hash Functions](#sha-3-fixed-hash-functions)
  - [Alternate Class Syntax](#alternate-class-syntax)
  - [Hashing a File](#hashing-a-file)
  - [SHAKE128/256 Functions](#shake128256-functions)
  - [cSHAKE128/256 Functions](#cshake128256-functions)
  - [KMAC Functions](#kmac-functions)
- [Development](#development)
  - [Dependencies](#dependencies)
  - [Testing](#testing)
  - [Supported Ruby Versions](#supported-ruby-versions)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Credits](#credits)

## Documentation

- [API Documentation](https://docs.jsg.io/sha3/html/index.html)
- [GitHub Repository](https://github.com/johanns/sha3#readme)
- [Issue Tracker](https://github.com/johanns/sha3/issues)

## Features

- Full support for all SHA-3 variants (224, 256, 384, and 512 bits)
- Support for SHAKE128 and SHAKE256 extendable-output functions (XOFs)
- Support for cSHAKE128 and cSHAKE256 extendable-output functions (XOFs) with domain separation and personalization
- Support for KMAC (Keccak Message Authentication Code)
- Native C implementation for high performance
- Simple, Ruby-friendly API that follows Ruby's standard Digest interface
- Comprehensive test suite with official NIST test vectors
- Thread-safe implementation

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'sha3', '~> 2.2'
```

And then execute:

```sh
bundle install
```

Or install it yourself as:

```sh
gem install sha3
```

## Usage

### SHA-3 Fixed Hash Functions

```ruby
require 'sha3'

# Create a new digest instance
digest = SHA3::Digest.new(:sha3_224, 'Start here')

# Add more data to be hashed
digest << "Compute Me"
digest.update("Me too")

# Get the final hash value as a hex string
digest.hexdigest
# => "d6d38021d60857..."

# Or as a binary string
digest.digest
```

Valid algorithm symbols are:

- `:sha3_224` - SHA-3 224 bits
- `:sha3_256` - SHA-3 256 bits
- `:sha3_384` - SHA-3 384 bits
- `:sha3_512` - SHA-3 512 bits
- `:shake_128` - SHAKE128 extendable-output function
- `:shake_256` - SHAKE256 extendable-output function

### Alternate Class Syntax

For convenience, you can also use dedicated classes for each algorithm:

```ruby
# Available classes
SHA3::Digest::SHA3_224.new([data])
SHA3::Digest::SHA3_256.new([data])
SHA3::Digest::SHA3_384.new([data])
SHA3::Digest::SHA3_512.new([data])
SHA3::Digest::SHAKE_128.new([data])
SHA3::Digest::SHAKE_256.new([data])
```

```ruby
# Example usage
digest = SHA3::Digest::SHA3_256.new('Start here')

digest << "Compute Me"
digest.update("Me too")

digest.hexdigest
# => "bedf0dd9a15b647..."
```

### Hashing a File

```ruby
# Compute the hash value for a given file, and return the result as hex
hash = SHA3::Digest::SHA3_256.file("my_file.bin").hexdigest

# Using SHAKE function to generate an arbitrary-length hash output
shake = SHA3::Digest::SHAKE_128.file("my_file.bin").hexdigest(320)

# Calling SHA3::Digest.file(...) defaults to SHA3_256
hash = SHA3::Digest.file("my_file.bin").hexdigest
# => "a9801db49389339..."
```

### SHAKE128/256 Functions

SHAKE128 and SHAKE256 are extendable-output functions (XOFs) that allow you to "squeeze" an arbitrary number of bytes from the hash state:

```ruby
# Create a new SHAKE128 instance
shake = SHA3::Digest::SHAKE_128.new

# Add data to hash
shake << 'Squeeze this data...'

# Squeeze 120 bytes (240 hex characters) from the hash state
result = shake.hex_squeeze(120)

# Or get binary output
binary_result = shake.squeeze(1024)

# You can call squeeze functions multiple times with arbitrary output lengths
first_part = shake.squeeze(32)       # Get 32 bytes
second_part = shake.squeeze(64)      # Get 64 bytes
third_part = shake.hex_squeeze(128)  # Get 128 bytes as hex
```

### cSHAKE128/256 Functions

cSHAKE128 and cSHAKE256 are customizable versions of SHAKE128 and SHAKE256, allowing for domain separation and personalization through a customization string.

```ruby
# Create a new cSHAKE instance with a fixed output length
cshake = SHA3::CSHAKE.new(:cshake_128, 32, name: 'my-app', customization: 'Email Signature')

# Add data to hash
cshake << 'Compute me...'

# Get final output
cshake.digest

# Create a new cSHAKE instance for an arbitrarily-long (XOF) operation
cshake = SHA3::CSHAKE.new(:cshake_256, 0, customization: 'Signature')

# Add data to hash
cshake.update('Beep Beep')

# Squeeze 64-bytes of data from state
cshake.squeeze(64)
```

### KMAC Functions

KMAC (Keccak Message Authentication Code) is a message authentication code algorithm based on the SHAKE extendable-output functions:

```ruby
require 'sha3'

# Create a new KMAC instance
# Parameters: algorithm, output_length (in bytes), key, [customization] optional
kmac = SHA3::KMAC.new(:kmac_128, 32, "my secret key", "app-specific customization")

# Add data to be authenticated (update can be called multiple times)
kmac.update("Authenticate this message")
# or use the << operator
kmac << "And this too"

# Get the result as a hex string
result = kmac.hexdigest
# => "a8982c..."

# Or as binary
binary_result = kmac.digest

# One-shot operation (customization is optional)
# Parameters: algorithm, data, data, output_length (in bytes),key, [customization] optional
result = SHA3::KMAC.hexdigest(:kmac_256, "message", 64, "key", "customization")
```

## Development

### Dependencies

- **C/C++** compiler and native build tools (e.g., Clang/LLVM, GCC, MinGW, etc.)
- **Gems**: rake, rake-compiler, rspec, yard

### Testing

Run `rake` to build and run the (RSpec) tests.

To run the tests manually:

```bash
bundle exec rspec
```

The test suite includes a special `sha3_vectors_spec.rb` file that automatically:
1. Downloads the official SHA3 test vectors from the XKCP repository
2. Parses the test vectors
3. Runs tests against all SHA3 variants (224, 256, 384, and 512 bit)

The test vectors are downloaded only once and cached in the `spec/data` directory for future test runs.

### Supported Ruby Versions

- MRI Ruby 2.7 - 3.4

## Roadmap

As of version 2.2.0 (2025), this gem is feature complete with a stable API—future updates will focus exclusively on performance improvements, security enhancements, and bug fixes.

- [X] 0.1.0: Add support for SHA-3 variants (224, 256, 384, and 512 bit)
- [X] 2.0.0: Add support for SHAKE128 and SHAKE256 extendable-output functions (XOFs)
- [X] 2.1.0: Add support for KMAC
- [X] 2.2.0: Add support for cSHAKE

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

Copyright (c) 2012 - 2025 Johanns Gregorian (https://github.com/johanns)

Released under the MIT License. See [LICENSE.txt](LICENSE.txt) for details.

## Credits

- [XKCP - eXtended Keccak Code Package](https://github.com/XKCP/XKCP) by the Keccak team: [https://keccak.team/index.html](https://keccak.team/index.html)
- All contributors to the SHA3 for Ruby project

