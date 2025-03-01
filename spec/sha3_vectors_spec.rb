# frozen_string_literal: true

require 'spec_helper'
require 'sha3'
require 'fileutils'
require 'open-uri'

RSpec.describe SHA3::Digest do
  # Test vector URLs
  VECTOR_URLS = {
    sha3_224: 'https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-224.txt',
    sha3_256: 'https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-256.txt',
    sha3_384: 'https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-384.txt',
    sha3_512: 'https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-512.txt',
    shake_128: 'https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHAKE128.txt',
    shake_256: 'https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHAKE256.txt'
  }.freeze

  # Output length for SHAKE algorithms in bits (as specified in the test vectors)
  SHAKE_OUTPUT_LENGTH = 512

  # Algorithm families
  SHA3_ALGORITHMS = %i[sha3_224 sha3_256 sha3_384 sha3_512].freeze
  SHAKE_ALGORITHMS = %i[shake_128 shake_256].freeze

  # Path to test vectors data directory
  let(:data_dir) { File.join(File.dirname(__FILE__), 'data') }

  # Create data directory before running tests
  before(:all) do
    data_dir = File.join(File.dirname(__FILE__), 'data')
    FileUtils.mkdir_p(data_dir) unless Dir.exist?(data_dir)
  end

  # Helper method to process test vectors line by line
  def process_test_vectors(path)
    return to_enum(:process_test_vectors, path) unless block_given?

    current_length = nil
    current_msg = nil

    File.foreach(path) do |line|
      line = line.strip

      if line.start_with?('Len = ')
        # Start of a new test vector
        current_length = line.split(' = ').last.to_i
      elsif line.start_with?('Msg = ') && current_length && (current_length % 8).zero? && current_length.positive?
        # Message line
        current_msg = line.split(' = ').last
      elsif (line.start_with?('MD = ') || line.start_with?('Squeezed = ')) && current_msg
        # Digest line - we have a complete test vector (SHA3 uses "MD", SHAKE uses "Squeezed")
        digest = line.split(' = ').last.downcase
        yield [current_msg, digest]

        # Reset for next vector
        current_length = nil
        current_msg = nil
      end
    end
  end

  # Helper method to download test vectors
  def ensure_test_vectors(hash_type, url)
    # Simply use the hash_type as the filename
    vector_file = File.join(data_dir, "#{hash_type}.txt")

    unless File.exist?(vector_file)
      puts "Downloading #{hash_type} test vectors..."
      begin
        File.binwrite(vector_file, URI.open(url, open_timeout: 10, read_timeout: 20).read)
      rescue OpenURI::HTTPError, SocketError => e
        warn "Failed to download #{hash_type} test vectors: #{e.message}"
        raise "Test vector download failed. Please check your internet connection or manually download the file to #{vector_file}"
      end
    end

    vector_file
  end

  # Helper to get the appropriate digest for a hash type
  def calculate_digest(hash_type, binary_input)
    # For SHA3 algorithms, we use the bit length from the algorithm name
    # For SHAKE algorithms, we need to specify the output length explicitly
    if SHAKE_ALGORITHMS.include?(hash_type)
      # SHAKE algorithms require an output length parameter
      SHA3::Digest.new(hash_type, binary_input).hexdigest(SHAKE_OUTPUT_LENGTH)
    else
      # SHA3 algorithms use their built-in output length
      SHA3::Digest.new(hash_type, binary_input).hexdigest
    end
  end

  # Test each hash type
  VECTOR_URLS.each do |hash_type, url|
    describe ".new(#{hash_type})" do
      it "passes byte-length test vectors of #{hash_type}" do
        # Ensure test vectors are available
        vector_file = ensure_test_vectors(hash_type, url)

        # Process test vectors one at a time
        vector_count = 0

        process_test_vectors(vector_file) do |msg_raw, expected_digest|
          binary_input = [msg_raw].pack('H*')
          actual_digest = calculate_digest(hash_type, binary_input)

          expect(actual_digest).to eq(expected_digest),
                                   "Failed for input: #{msg_raw[0..20]}... (#{binary_input.bytesize} bytes)"

          vector_count += 1
        end

        # Ensure we processed at least some vectors
        expect(vector_count).to be > 0, "No valid test vectors found in #{vector_file}"
      end
    end
  end
end
