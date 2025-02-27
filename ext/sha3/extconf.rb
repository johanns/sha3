# frozen_string_literal: true

require 'mkmf'
require 'rbconfig'

b64 = 8.size == 8
extension_name = 'sha3_n'
ref_dir = b64 ? 'ref-64bits' : 'ref-32bits'

dir_config(extension_name)

# Set compiler flags
$CFLAGS << ' -fomit-frame-pointer -O3 -g0 -fms-extensions'

# Add architecture-specific optimizations if enabled
$CFLAGS << ' -march=native' if enable_config('march-tune-native', false)

# Add security hardening flags
$CFLAGS << ' -D_FORTIFY_SOURCE=2 -fstack-protector-strong'

# Add warning flags to catch potential issues
$CFLAGS << ' -Wall -Wextra -Wformat -Wformat-security'

# Add vectorization flags for better performance on supported platforms
$CFLAGS << ' -ftree-vectorize' if RUBY_PLATFORM =~ /x86_64|amd64|arm64/

# Find all relevant subdirectories and filter appropriately
vpath_dirs = Dir.glob("#{$srcdir}/lib/**/*")
                .select { |path| File.directory?(path) }
                .select { |dir| !dir.include?('KeccakP-1600/ref-') || dir.include?(ref_dir) }

# Process directory paths for both VPATH and INCFLAGS
vpath_dirs_processed = vpath_dirs.map { |dir| dir.sub($srcdir, '') }

# Add source directories to VPATH
$VPATH << vpath_dirs_processed
          .map { |dir| "$(srcdir)#{dir}" }
          .join(File::PATH_SEPARATOR)

# Add include flags
$INCFLAGS << vpath_dirs_processed
             .map { |dir| " -I$(srcdir)#{dir}" }
             .join('')

# Base source files
$srcs = ['sha3.c', 'digest.c']

# Find and add all .c files from the filtered directories
$srcs += vpath_dirs.flat_map { |dir| Dir.glob("#{dir}/*.c") }
                   .map { |file| File.basename(file) }
                   .uniq

create_makefile(extension_name)
