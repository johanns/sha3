# sha3  

[![Gem Version](https://badge.fury.io/rb/sha3.svg)](https://badge.fury.io/rb/sha3) [![CI](https://secure.travis-ci.org/johanns/sha3.png)](https://secure.travis-ci.org/johanns/sha3) [![Dependencies](https://gemnasium.com/johanns/sha3.png)](https://gemnasium.com/johanns/sha3) [![CodeClimate](https://codeclimate.com/github/johanns/sha3.png)](https://codeclimate.com/github/johanns/sha3)

**SHA3 for Ruby** is a native (C) binding to SHA3 (Keccak FIPS 202) cryptographic hashing algorithm.

- Home :: [https://github.com/johanns/sha3#readme]()
- Issues :: [https://github.com/johanns/sha3/issues]()
- Documentation :: [http://rubydoc.info/gems/sha3/frames]()

## Warnings

- Version 1.0+ breaks compatibility with previous versions of this gem.
- Do NOT use SHA3 to hash passwords; use either ```bcrypt``` or ```scrypt``` instead!

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

## Development

* Native build tools (e.g., GCC, Minigw, etc.)
* Gems: rubygems-tasks, rake, rspec, yard

### Testing + RSpec

Call ```rake``` to run the included RSpec tests.

Only a small subset of test vectors are included in the source repository; however, the complete test vectors suite is available for download. Simply run the ```tests.sh``` shell script (available in the root of source directory) to generate full byte-length RSpec test files.

  ```sh tests.sh```

### Rubies

Tested with Rubies:

  - MRI Ruby-Head
  - MRI 2.1.0
  - MRI 2.0.0
  - MRI 1.9.3
  - MRI 1.9.2
  - MRI 1.8.7
  - Rubinius 2

On:

  - Ubuntu 12.04, 12.10, 13.04, 14.04, 15.04
  - Windows 7, 8, 8.1, 10
  - Mac OS X 10.6 - 10.11

## Releases

- *1.0.1* :: FIPS 202 compliance (breaks compatibility with earlier releases)
- *0.2.6* :: Fixed bug #4
- *0.2.5* :: Bug fixes. (See ChangeLog.rdoc)
- *0.2.4* :: Bug fixes. (YANKED)
- *0.2.3* :: Added documentation file (decoupled form C source); refactored C source.
- *0.2.2* :: Added sub-class for each SHA3 supported bit-lengths (example: SHA3::Digest::SHA256). Minor bug fix.
- *0.2.0* :: Production worthy, but breaks API compatibility with 0.1.x. Backward-compatibility will be maintained henceforth.
- *0.1.x* :: Alpha code, and not suitable for production.

## TO DO

- Add SHAKE128/256 support

## Copyright

Copyright (c) 2012 - 2015 Johanns Gregorian (https://github.com/johanns)

**See LICENSE.txt for details.**
