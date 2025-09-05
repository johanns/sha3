# SHA3 Ruby Gem Changelog

## v2.2.3 (2025-09-05)

### Bug Fixes
- Fixed memory leak by freeing context memory on allocation failure in rb_sha3_digest_alloc
- Fixed heredoc delimiters for description and post-install message in gemspec
- Fixed example comment typo in cshake

### Improvements
- Introduced common abstraction layer for SP800-185 algorithms (cSHAKE, KMAC)
- Improved memory management and error handling in digest.c
- Significantly reduced code duplication in cshake.c and kmac.c

### Testing
- Improved test organization and coverage for SHA3 algorithms
- Added comprehensive tests for edge cases and error conditions

### Maintenance
- Added RuboCop configuration for code style consistency

## v2.2.2 (2025-09-05)

### Improvements
- Streamlined SP800-185 algorithm initialization
- Enhanced error handling in cSHAKE and KMAC implementations
- Refactored internal API for better maintainability

## v2.2.1 (2025-09-05)

### Bug Fixes
- Fixed out-of-bounds array access when parsing optional key arguments in cSHAKE

### Maintenance
- Removed obsolete macro definitions for Ruby methods in SP800-185 header

## v2.2.0 (2025-03-15)

### Features
- Added support for cSHAKE

## v2.1.0 (2025-03-15)

### Features
- Added support for KMAC

## v2.0.0 (2025-03-15)

### Features
- Added support for SHAKE128 and SHAKE256 extendable-output functions (XOFs)

## v1.0.5 (2022-10-23)

### Security
- Fixed buffer overflow vulnerability in Keccak implementation by updating to latest XKCP library
- Added test to verify fix for buffer overflow vulnerability

### Improvements
- Updated XKCP library with improved directory structure
- Refactored byte-length test vector generator

### Documentation
- Updated README with current supported Ruby versions
- Added credits section to README
- Fixed typo in README
- Updated gem description

### Maintenance
- Updated development dependencies
- Removed bundler from development dependencies list
- Updated signing certificate
- Added macOS file types to .gitignore
