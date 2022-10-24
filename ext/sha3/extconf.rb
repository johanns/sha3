# frozen_string_literal: true

require 'mkmf'
require 'rbconfig'

# Maintaining XKCP lib directory structure to hopefully simplify 
# future upgrades.

keccak_base_files = [
  'lib/high/Keccak/KeccakSponge.c',
  'lib/high/Keccak/FIPS202/KeccakHash.c'
]

if 1.size == 8
  Logging.message "=== Using 64-bit reference ===\n"

  keccak_base_files << 'lib/low/KeccakP-1600/ref-64bits/KeccakP-1600-reference.c'
else
  Logging.message "=== Using 32-bit reference ===\n"

  keccak_base_files << 'lib/low/KeccakP-1600/ref-32bits/KeccakP-1600-reference32BI.c'
end

FileUtils.cp keccak_base_files.map { |f| "#{$srcdir}/#{f}" }, $srcdir

extension_name = 'sha3_n'
dir_config(extension_name)

$INCFLAGS << [
  ' -I$(src) ',
  ' -I$(srcdir)lib/ ',
  ' -I$(srcdir)/lib/common ',
  ' -I$(srcdir)/lib/high/Keccak ',
  ' -I$(srcdir)/lib/high/Keccak/FIPS202 ',
  ' -I$(srcdir)/lib/low/KeccakP-1600/common ',
  ' -I$(srcdir)/lib/low/KeccakP-1600/ref-32bits ',
  ' -I$(srcdir)/lib/low/KeccakP-1600/ref-64bits '
].join

$CFLAGS << ' -fomit-frame-pointer -O3 -g0 -fms-extensions '
$CFLAGS << ' -march=native ' if enable_config('march-tune-native', false)

find_header('sha3.h')
find_header('digest.h')
find_header('align.h')
find_header('brg_endian.h')
find_header('KeccakSponge.h')
find_header('KeccakHash.h')

create_makefile extension_name
