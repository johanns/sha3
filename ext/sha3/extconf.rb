require 'mkmf'
require 'rbconfig'

target_cpu = RbConfig::CONFIG['target_cpu']

if 1.size == 4 and target_cpu =~ /i386|x86_32/   # x86 32bit optimized code
  Logging::message "=== Using reference  ===\n"
  FileUtils.cp Dir["#{$srcdir}/Reference/*"].collect { |f| File.expand_path(f) }, "#{$srcdir}/"
elsif 1.size == 8 and target_cpu =~ /i686|x86_64/
  Logging::message "=== Using optimized (64-bit) ===\n"
  FileUtils.cp Dir["#{$srcdir}/Optimized64/*"].collect { |f| File.expand_path(f) }, "#{$srcdir}/"
else
  Logging::message "=== Using reference ===\n"
  FileUtils.cp Dir["#{$srcdir}/Reference/*"].collect { |f| File.expand_path(f) }, "#{$srcdir}/"
end

find_header("sha3.h")
find_header("digest.h")

$CFLAGS = ' -fomit-frame-pointer -O3 -g0'

if enable_config('march-tune-native', false)
  $CFLAGS += ' -march=native'
end

create_makefile 'sha3_n'
