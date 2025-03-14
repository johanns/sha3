# SHA3 Ruby Gem Changelog

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
