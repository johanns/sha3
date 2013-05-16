require 'mkmf'
require 'rbconfig'

FileUtils.rm "#{$srcdir}/KeccakF-1600-opt.c", :force => true

build_cpu = RbConfig::CONFIG['build_cpu']

if 1.size == 4 and build_cpu =~ /i386|x86_32/   # x86 32bit optimized code
  Logging::message "=== Using i386 optimized Keccak code ===\n"
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt32.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
elsif 1.size == 8 and build_cpu =~ /i686|x86_64/
  Logging::message "=== Using i686 optimized Keccak code ===\n"
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt64.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
else # Ha? Use reference code -- slow
  Logging::message "=== Using reference Keccak code ===\n"
  FileUtils.cp "#{$srcdir}/KeccakF-1600-reference.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
end

find_header("KeccakF-1600-interface.h")
find_header("KeccakSponge.h")
find_header("KeccakNISTInterface.h")
find_header("sha3.h")
find_header("digest.h")

$CFLAGS = ' -fomit-frame-pointer -O3 -g0 -march=nocona '
create_makefile 'sha3_n'
