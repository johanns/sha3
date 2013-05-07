require 'mkmf'

FileUtils.rm "#{$srcdir}/KeccakF-1600-opt.c", :force => true

case 1.size
when 4 # x86 32bit optimized code
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt32.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
when 8 # x86 64bit optimized code
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt64.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
else # Ha? Use reference code -- slow
  FileUtils.cp "#{$srcdir}/KeccakF-1600-reference.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
end

find_header("KeccakF-1600-interface.h")
find_header("KeccakSponge.h")
find_header("KeccakNISTInterface.h")
find_header("sha3.h")
find_header("digest.h")

$CFLAGS = ' -fomit-frame-pointer -O3 -g0 -march=nocona '
create_makefile 'sha3_n'

