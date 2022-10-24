# frozen_string_literal: true

# Based on python-sha3's / digest-sha3 test generator.

FILES = [
  ['data/ShortMsgKAT_SHA3-224.txt', 224],
  ['data/ShortMsgKAT_SHA3-256.txt', 256],
  ['data/ShortMsgKAT_SHA3-384.txt', 384],
  ['data/ShortMsgKAT_SHA3-512.txt', 512]
].freeze

# rubocop:disable Layout/HeredocIndentation(RuboCop)
REQUIRED = <<-REQUIRED
# frozen_string_literal: true

require 'spec_helper'
require 'sha3'
REQUIRED

SPEC = <<-SPEC

RSpec.describe 'SHA3::Digest.new(HASH_LEN)' do
  it 'should pass byte-length test vectors of SHA3-HASH_LEN (NAME)' do
SPEC

EXPECT = <<-EXPECT
    expect(SHA3::Digest.new(HASHLEN, ['MSG'].pack('H*')).hexdigest).to eq('DIGEST')
EXPECT

ENDING = <<~ENDING
  end
end

ENDING
# rubocop:enable Layout/HeredocIndentation(RuboCop)

# rubocop:disable Metrics/AbcSize(RuboCop) # (RuboCop)
# rubocop:disable Metrics/MethodLength(RuboCop)
def gen_digest_byte_tests
  FILES.each do |path, hashlen|
    name = File.basename(path).split('.')[0]

    f = File.new("sha3_digest_#{hashlen}_spec.rb", 'w')
    f.puts(REQUIRED)
    f.puts(
      SPEC
      .gsub(/HASH_LEN/, hashlen.to_s)
      .gsub(/NAME/, name)
    )

    contents = File.read(path).split('Len = ')
    contents.each do |test|
      lines = test.split("\n")
      next unless !lines.empty? && lines[0] !~ /^#/

      length = lines[0].to_i
      next unless (length % 8).zero? && length != 0

      msg_raw = lines[1].split(' = ').last
      digest = lines[2].split(' = ').last.downcase

      f.puts(
        EXPECT
          .gsub(/HASHLEN/, hashlen.to_s)
          .gsub(/MSG/, msg_raw)
          .gsub(/DIGEST/, digest)
      )
    end

    f.puts(ENDING)
    f.close
  end
end
# rubocop:enable Metrics/AbcSize(RuboCop)
# rubocop:enable Metrics/MethodLength(RuboCop)

def setup; end

gen_digest_byte_tests
