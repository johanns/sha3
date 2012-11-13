# Based on python-sha3's / digest-sha3 test generator.

FILES = [
  ['data/ShortMsgKAT_224.txt', 224],
  ['data/ShortMsgKAT_256.txt', 256],
  ['data/ShortMsgKAT_384.txt', 384],
  ['data/ShortMsgKAT_512.txt', 512],
  ['data/LongMsgKAT_224.txt', 224],
]

def gen_digest_byte_tests
  FILES.each do |path, hashlen|
    name = File.basename(path).split('.')[0]

    f = File.new("sha3_digest_#{name}_spec.rb", "w")
    f.puts(
%Q{require 'spec_helper'
require 'sha3'

describe "SHA3::Digest.new(#{hashlen})" do
  it "should match byte-length test vectors (#{name})." do
})
    contents = File.read(path).split('Len = ')
    contents.each do |test|
      lines = test.split("\n")
      if !lines.empty? && lines[0] !~ /^#/
        length = lines[0].to_i
        if length % 8 == 0 && length != 0
          msg_raw = [lines[1].split(' = ').last].pack("H*")
          md = lines[2].split(' = ').last.downcase
          f.puts(
%Q{   SHA3::Digest.new(#{hashlen}, #{msg_raw.inspect}).hexdigest.should(eq("#{md}"))
})
        end
      end
    end
    f.puts(
%Q{ end
end
})
    f.close
  end
end

def gen_compute_bit_tests
  FILES.each do |path, hashlen|
    name = File.basename(path).split('.')[0]

    f = File.new("sha3_compute_#{name}_spec.rb", "w")
    f.puts(
%Q{require 'spec_helper'
require 'sha3'

describe "SHA3::Digest.compute(#{hashlen})" do
  it "should match bit-length test vectors (#{name})." do
})
    contents = File.read(path).split('Len = ')
    contents.each do |test|
      lines = test.split("\n")
      if !lines.empty? && lines[0] !~ /^#/
        length = lines[0].to_i
        if length != 0
          msg_raw = [lines[1].split(' = ').last].pack("H*")
          md = lines[2].split(' = ').last.downcase
          f.puts(
%Q{   SHA3::Digest.compute(#{hashlen}, #{msg_raw.inspect}, #{length}).unpack("H*").first.should(eq("#{md}"))
})
        end
      end
    end
    f.puts(
%Q{ end
end
})
    f.close
  end
end

def setup
  
end

gen_digest_byte_tests
gen_compute_bit_tests
