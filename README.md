# sha3  

[![Gem Version](https://badge.fury.io/rb/sha3.svg)](https://badge.fury.io/rb/sha3) [![Ruby](https://github.com/johanns/sha3/actions/workflows/main.yml/badge.svg)](https://github.com/johanns/sha3/actions/workflows/main.yml)

**SHA3 for Ruby** is a XKCP based native (C) binding to SHA3 (FIPS 202) cryptographic hashing algorithm.

- [Home](https://github.com/johanns/sha3#readme)
- [Issues](https://github.com/johanns/sha3/issues)
- [Documentation](http://rubydoc.info/gems/sha3/frames)
- [XKCP - eXtended Keccak Code Package](https://github.com/XKCP/XKCP)

## Warning

- Please do NOT use SHA3 to hash passwords -- use a slow hashing function instead (e.g.: `pbkdf2`, `argon2`, `bcrypt` or `scrypt`)
- Version 1.0 introduces new API and is incompatible with previous versions (0.x).

## Module details

**SHA3::Digest**: A standard *Digest* _subclass_. The interface, and operation of this class are parallel to digest classes bundled with MRI-based Rubies (e.g.: **Digest::SHA2**, and **OpenSSL::Digest**).

See [documentation for Ruby's **Digest** class for additional details](http://www.ruby-doc.org/stdlib-2.2.3/libdoc/digest/rdoc/Digest.html).

## Installation

```shell
gem install sha3
```

## Usage

```ruby
require 'sha3'
```

Valid hash bit-lengths are: *224*, *256*, *384*, *512*.

```ruby
:sha224  :sha256  :sha384  :sha512

# SHA3::Digest.new(224) is SHA3::Digest.new(:sha224)
```

Alternatively, you can instantiate using one of four sub-classes:

```ruby
SHA3::Digest::SHA224.new() # 224 bits
SHA3::Digest::SHA256.new() # 256 bits
SHA3::Digest::SHA384.new() # 384 bits
SHA3::Digest::SHA512.new() # 512 bits
```

### Basics

```ruby
# Instantiate a new SHA3::Digest class with 256 bit length
s = SHA3::Digest.new(:sha256)

# OR #

s = SHA3::Digest::SHA256.new()

# Update hash state, and compute new value
s.update "Compute Me"

# << is an .update() alias
s << "Me too"

# Returns digest value in bytes
s.digest
# => "\xBE\xDF\r\xD9\xA1..."

# Returns digest value as hex string
s.hexdigest
# => "bedf0dd9a15b647..."

### Digest class-methods: ###

SHA3::Digest.hexdigest(:sha224, "Hash me, please")
# => "200e7bc18cd613..."

SHA3::Digest::SHA384.digest("Hash me, please")
# => "\xF5\xCEpC\xB0eV..."
```

### Hashing a file

```ruby
# Compute the hash value for given file, and return the result as hex
s = SHA3::Digest::SHA224.file("my_fantastical_file.bin").hexdigest

# Calling SHA3::Digest.file(...) defaults to SHA256
s = SHA3::Digest.file("tests.sh")
# => #<SHA3::Digest: a9801db49389339...>
```

### Development Dependencies

* Native build tools (e.g., Clang/LLVM, GCC, Minigw, etc.)
* Gems: rubygems-tasks, rake, rspec, yard

### Testing

Call ```rake``` to run the included RSpec tests.

Only a small subset of test vectors are included in the source repository; however, the complete test vectors suite is available for download. Simply run the ```tests.sh``` shell script (available in the root of source directory) to generate full byte-length RSpec test files.

  ```sh tests.sh```

### Rubies

Supported Ruby versions:

  - MRI Ruby 2.6 - 3.1

## Credits

XKCP by Keccak team: [https://keccak.team/index.html]()

## Copyright

Copyright (c) 2012 - 2022 Johanns Gregorian (https://github.com/johanns)

**See LICENSE.txt for details.**
