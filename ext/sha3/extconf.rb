require 'mkmf'

case 1.size
when 4 # 32bit optimized code
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt32.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
when 8 # 64bit optimized code
  FileUtils.cp "#{$srcdir}/KeccakF-1600-opt64.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
else # Ha? Use reference code
  FileUtils.cp "#{$srcdir}/KeccakF-1600-reference.c-arch", "#{$srcdir}/KeccakF-1600-opt.c"
end

$CFLAGS = ' -fomit-frame-pointer -O3 -g0 -march=nocona '
create_makefile 'sha3_n'

