require 'mkmf'

$CFLAGS = ' -msse -msse2 -Wall '
create_makefile 'sha3_n'

