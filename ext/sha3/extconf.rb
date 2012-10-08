require 'mkmf'

if 1.size == 4
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt32.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
elsif
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt64.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
end

$CFLAGS = ' -fomit-frame-pointer -O3 -g0 -march=nocona '
create_makefile 'sha3_n'

