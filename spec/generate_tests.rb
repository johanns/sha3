# Based on python-sha3's / digest-sha3 test generator.

FILES = [
  ['data/ShortMsgKAT_SHA3-224.txt', 224],
  ['data/ShortMsgKAT_SHA3-256.txt', 256],
  ['data/ShortMsgKAT_SHA3-384.txt', 384],
  ['data/ShortMsgKAT_SHA3-512.txt', 512],
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
%Q{   expect(SHA3::Digest.new(#{hashlen}, #{msg_raw.inspect}).hexdigest).to eq("#{md}")
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
