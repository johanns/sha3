# frozen_string_literal: true

# Based on python-sha3's / digest-sha3 test generator.

FILES = [
  ['data/ShortMsgKAT_SHA3-224.txt', 224],
  ['data/ShortMsgKAT_SHA3-256.txt', 256],
  ['data/ShortMsgKAT_SHA3-384.txt', 384],
  ['data/ShortMsgKAT_SHA3-512.txt', 512]
].freeze

TEMPLATES = {
  required: <<~REQUIRED,
    # frozen_string_literal: true

    require 'spec_helper'
    require 'sha3'
  REQUIRED

  spec: <<~SPEC,

    RSpec.describe 'SHA3::Digest.new(HASH_LEN)' do
      it 'should pass byte-length test vectors of SHA3-HASH_LEN (NAME)' do
  SPEC

  expect: <<~EXPECT,
    expect(SHA3::Digest.new(HASHLEN, ['MSG'].pack('H*')).hexdigest).to eq('DIGEST')
  EXPECT

  ending: <<~ENDING
      end
    end

  ENDING
}.freeze

def parse_test_file(path)
  File.read(path)
      .split('Len = ')
      .filter_map do |test|
        lines = test.split("\n")
        next if lines.empty? || lines[0] =~ /^#/

        length = lines[0].to_i
        next unless (length % 8).zero? && length.positive?

        msg_raw = lines[1].split(' = ').last
        digest = lines[2].split(' = ').last.downcase

        [msg_raw, digest]
      end
end

def generate_test_file(path, hashlen)
  name = File.basename(path).split('.')[0]
  filename = "sha3_digest_#{hashlen}_spec.rb"

  File.open(filename, 'w') do |f|
    f.puts(TEMPLATES[:required])
    f.puts(
      TEMPLATES[:spec]
        .gsub('HASH_LEN', hashlen.to_s)
        .gsub('NAME', name)
    )

    parse_test_file(path).each do |msg_raw, digest|
      f.puts(
        TEMPLATES[:expect]
          .gsub('HASHLEN', hashlen.to_s)
          .gsub('MSG', msg_raw)
          .gsub('DIGEST', digest)
      )
    end

    f.puts(TEMPLATES[:ending])
  end
end

def gen_digest_byte_tests
  FILES.each do |path, hashlen|
    generate_test_file(path, hashlen)
  end
end

gen_digest_byte_tests
