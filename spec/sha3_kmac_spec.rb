# frozen_string_literal: true

require 'spec_helper'

# Test vectors from NIST SP 800-185
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
KMAC_TEST_VECTORS = [
  {
    algorithm: :kmac_128,
    custom: '',
    data: '00010203',
    description: 'KMAC128 Empty Customization',
    hex_output: 'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e',
    key: '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F',
    length: 32
  },
  {
    algorithm: :kmac_128,
    custom: 'My Tagged Application',
    data: '00010203',
    description: 'KMAC128 Non-Empty Customization',
    hex_output: '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5',
    length: 32,
    key: '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F'
  },
  {
    algorithm: :kmac_256,
    custom: '',
    data: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
          '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' \
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' \
          '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' \
          '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' \
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' \
          'c0c1c2c3c4c5c6c7',
    description: 'KMAC256 Empty Customization',
    hex_output: '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691' \
                '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69',
    length: 64,
    key: '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F'
  },
  {
    algorithm: :kmac_256,
    custom: 'My Tagged Application',
    data: '00010203',
    description: 'KMAC256 Non-Empty Customization',
    hex_output: '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7' \
                'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd',
    length: 64,
    key: '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F'
  }
].freeze

RSpec.describe SHA3::KMAC do
  describe '.new' do
    it 'initializes with required parameters' do
      expect { described_class.new(:kmac_128, 32, 'my key') }.not_to raise_error
    end

    it 'accepts algorithm specification' do
      expect { described_class.new(:kmac_128, 32, 'my key') }.not_to raise_error
      expect { described_class.new(:kmac_256, 32, 'my key') }.not_to raise_error
    end

    it 'accepts a customization string' do
      expect { described_class.new(:kmac_128, 32, 'my key', 'custom string') }.not_to raise_error
    end

    it 'raises an error for invalid algorithm' do
      expect { described_class.new(:invalid_algo, 32, 'my key') }.to raise_error(ArgumentError)
    end

    it 'requires the algorithm, output length, and key parameters' do
      expect { described_class.new }.to raise_error(ArgumentError)
      expect { described_class.new(:kmac_128) }.to raise_error(ArgumentError)
      expect { described_class.new(:kmac_128, 32) }.to raise_error(ArgumentError)
    end
  end

  describe '#update' do
    it 'updates the internal state' do
      kmac = described_class.new(:kmac_128, 32, 'my key')

      expect(kmac.update('test data')).to eq(kmac)
    end

    it 'can be called multiple times' do
      kmac = described_class.new(:kmac_128, 32, 'my key')
      kmac.update('test ')

      expect { kmac.update('data') }.not_to raise_error
    end

    it 'supports the << operator alias' do
      kmac = described_class.new(:kmac_128, 32, 'my key')
      expect(kmac << 'test data').to eq(kmac)
    end
  end

  describe '#digest' do
    it 'returns binary digest with specified output length' do
      kmac = described_class.new(:kmac_128, 32, 'my key')
      kmac.update('test data')
      digest = kmac.digest

      expect(digest).to be_a(String)
      expect(digest.length).to eq(32)
      expect(digest.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'accepts data parameter for convenience' do
      kmac = described_class.new(:kmac_128, 32, 'my key')
      digest1 = kmac.digest('test data')

      kmac.update('test data')
      digest2 = kmac.digest

      expect(digest1).to eq(digest2)
    end
  end

  describe '#hexdigest' do
    it 'returns hexadecimal digest with specified output length' do
      kmac = described_class.new(:kmac_128, 32, 'my key')
      kmac.update('test data')
      hexdigest = kmac.hexdigest

      expect(hexdigest).to be_a(String)
      expect(hexdigest.length).to eq(64) # 32 bytes = 64 hex characters
      expect(hexdigest).to match(/\A[0-9a-f]+\z/)
    end

    it 'accepts data parameter for convenience' do
      kmac = described_class.new(:kmac_128, 32, 'my key')
      hexdigest1 = kmac.hexdigest('test data')

      kmac.update('test data')
      hexdigest2 = kmac.hexdigest

      expect(hexdigest1).to eq(hexdigest2)
    end
  end

  describe '.digest' do
    it 'returns binary digest for given algorithm, data and output length' do
      digest = described_class.digest(:kmac_128, 'test data', 32, 'key')

      expect(digest).to be_a(String)
      expect(digest.length).to eq(32)
    end

    it 'accepts key parameter' do
      digest1 = described_class.digest(:kmac_128, 'test data', 32, '')
      digest2 = described_class.digest(:kmac_128, 'test data', 32, 'key')

      expect(digest1).not_to eq(digest2)
    end

    it 'accepts customization string' do
      digest1 = described_class.digest(:kmac_128, 'test data', 32, 'key')
      digest2 = described_class.digest(:kmac_128, 'test data', 32, 'key', 'custom')

      expect(digest1).not_to eq(digest2)
    end
  end

  describe '.hexdigest' do
    it 'returns hexadecimal digest for given algorithm, data and output length' do
      hexdigest = described_class.hexdigest(:kmac_128, 'test data', 32, 'key')

      expect(hexdigest).to be_a(String)
      expect(hexdigest.length).to eq(64) # 32 bytes = 64 hex characters
      expect(hexdigest).to match(/\A[0-9a-f]+\z/)
    end

    it 'accepts key and customization string parameters' do
      hexdigest1 = described_class.hexdigest(:kmac_128, 'test data', 32, 'key')
      hexdigest2 = described_class.hexdigest(:kmac_128, 'test data', 32, 'key', 'custom')

      expect(hexdigest1).not_to eq(hexdigest2)
    end
  end

  describe 'edge cases' do
    it 'handles empty strings correctly' do
      kmac = described_class.new(:kmac_128, 32, 'key')

      expect { kmac.update('') }.not_to raise_error
      expect(kmac.digest).to be_a(String)
      expect(kmac.digest.length).to eq(32)
    end

    it 'raises error on nil update' do
      kmac = described_class.new(:kmac_128, 32, 'key')
      expect { kmac.update(nil) }.to raise_error(TypeError)
    end

    it 'handles very long input data' do
      long_data = 'a' * 10_000

      expect { described_class.new(:kmac_128, 32, 'test').update(long_data) }.not_to raise_error
    end

    it 'handles different output lengths' do
      expect(described_class.new(:kmac_128, 16, 'key').digest.length).to eq(16)
      expect(described_class.new(:kmac_128, 64, 'key').digest.length).to eq(64)
      expect(described_class.new(:kmac_128, 128, 'key').digest.length).to eq(128)
    end
  end

  describe 'cryptographic properties' do
    it 'produces different outputs for different keys with same data' do
      data = 'test data'
      digest1 = described_class.digest(:kmac_128, data, 32, 'key1')
      digest2 = described_class.digest(:kmac_128, data, 32, 'key2')
      expect(digest1).not_to eq(digest2)
    end

    it 'produces different outputs for different customization strings' do
      data = 'test data'
      key = 'secret key'
      digest1 = described_class.digest(:kmac_128, data, 32, key, 'custom1')
      digest2 = described_class.digest(:kmac_128, data, 32, key, 'custom2')
      expect(digest1).not_to eq(digest2)
    end

    it 'produces different outputs for same key but different algorithms' do
      data = 'test data'
      key = 'secret key'
      digest1 = described_class.digest(:kmac_128, data, 32, key)
      digest2 = described_class.digest(:kmac_256, data, 32, key)
      expect(digest1).not_to eq(digest2)
    end
  end

  describe 'clone and dup' do
    it 'preserves the state when cloning' do
      kmac = described_class.new(:kmac_128, 32, 'key')
      kmac.update('test data')

      clone = kmac.clone

      expect(kmac.digest).to eq(clone.digest)
    end

    it 'preserves the state when duping' do
      kmac = described_class.new(:kmac_128, 32, 'key')
      kmac.update('test data')

      dup = kmac.dup

      expect(kmac.digest).to eq(dup.digest)
    end
  end

  KMAC_TEST_VECTORS.each do |vector|
    describe "test vector for #{vector[:description]}" do
      it 'produces the expected digest' do
        kmac = described_class.new(
          vector[:algorithm],
          vector[:length],
          [vector[:key]].pack('H*'),
          vector[:custom]
        )

        kmac.update([vector[:data]].pack('H*'))

        expect(kmac.hexdigest).to eq(vector[:hex_output])
      end
    end
  end
end
