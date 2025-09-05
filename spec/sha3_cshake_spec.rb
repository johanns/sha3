# frozen_string_literal: true

require 'spec_helper'

require 'sha3'

# Test vectors from NIST SP 800-185
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
CSHAKE_TEST_VECTORS = [
  {
    algorithm: :cshake_128,
    name: '',
    customization: 'Email Signature',
    data: '00010203',
    description: 'cSHAKE128 Non-Empty Customization',
    hex_output: 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5',
    length: 32
  },
  {
    algorithm: :cshake_128,
    name: '',
    customization: 'Email Signature',
    data: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
          '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' \
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' \
          '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' \
          '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' \
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' \
          'c0c1c2c3c4c5c6c7',
    description: 'cSHAKE128 Non-Empty Customization Long Data',
    hex_output: 'c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b',
    length: 32
  },
  {
    algorithm: :cshake_256,
    name: '',
    customization: 'Email Signature',
    data: '00010203',
    description: 'cSHAKE256 Non-Empty Customization',
    hex_output: 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1' \
                '64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c',
    length: 64
  },
  {
    algorithm: :cshake_256,
    name: '',
    customization: 'Email Signature',
    data: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
          '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' \
          '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' \
          '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' \
          '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' \
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' \
          'c0c1c2c3c4c5c6c7',
    description: 'cSHAKE256 Non-Empty Customization Long Data',
    hex_output: '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917' \
                '27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb',
    length: 64
  }
].freeze

RSpec.describe SHA3::CSHAKE do
  describe '.new' do
    it 'initializes with required parameters' do
      expect { described_class.new(:cshake_128, 32) }.not_to raise_error
    end

    it 'accepts algorithm specification' do
      expect { described_class.new(:cshake_128, 32) }.not_to raise_error
      expect { described_class.new(:cshake_256, 32) }.not_to raise_error
    end

    it 'accepts name and customization strings' do
      expect { described_class.new(:cshake_128, 32, name: 'test name') }.not_to raise_error
      expect { described_class.new(:cshake_128, 32, customization: 'test custom') }.not_to raise_error
      expect do
        described_class.new(:cshake_128, 32, name: 'test name', customization: 'test custom')
      end.not_to raise_error
    end

    it 'raises an error for invalid algorithm' do
      expect { described_class.new(:invalid_algo, 32) }.to raise_error(ArgumentError)
    end

    it 'requires the algorithm and output length parameters' do
      expect { described_class.new }.to raise_error(ArgumentError)
      expect { described_class.new(:cshake_128) }.to raise_error(ArgumentError)
    end
  end

  describe '#update' do
    it 'updates the internal state' do
      cshake = described_class.new(:cshake_128, 32)

      expect(cshake.update('test data')).to eq(cshake)
    end

    it 'can be called multiple times' do
      cshake = described_class.new(:cshake_128, 32)
      cshake.update('test ')

      expect { cshake.update('data') }.not_to raise_error
    end

    it 'supports the << operator alias' do
      cshake = described_class.new(:cshake_128, 32)
      expect(cshake << 'test data').to eq(cshake)
    end
  end

  describe '#digest' do
    it 'returns binary digest with specified output length' do
      cshake = described_class.new(:cshake_128, 32)
      cshake.update('test data')
      digest = cshake.digest

      expect(digest).to be_a(String)
      expect(digest.length).to eq(32)
      expect(digest.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'accepts data parameter for convenience' do
      cshake = described_class.new(:cshake_128, 32)
      digest1 = cshake.digest('test data')

      cshake.update('test data')
      digest2 = cshake.digest

      expect(digest1).to eq(digest2)
    end
  end

  describe '#hexdigest' do
    it 'returns hexadecimal digest with specified output length' do
      cshake = described_class.new(:cshake_128, 32)
      cshake.update('test data')
      hexdigest = cshake.hexdigest

      expect(hexdigest).to be_a(String)
      expect(hexdigest.length).to eq(64) # 32 bytes = 64 hex characters
      expect(hexdigest).to match(/\A[0-9a-f]+\z/)
    end

    it 'accepts data parameter for convenience' do
      cshake = described_class.new(:cshake_128, 32)
      hexdigest1 = cshake.hexdigest('test data')

      cshake.update('test data')
      hexdigest2 = cshake.hexdigest

      expect(hexdigest1).to eq(hexdigest2)
    end
  end

  describe '#squeeze' do
    it 'returns binary output with specified length' do
      cshake = described_class.new(:cshake_128, 0) # 0 for XOF mode
      cshake.update('test data')
      output = cshake.squeeze(32)

      expect(output).to be_a(String)
      expect(output.length).to eq(32)
      expect(output.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'can be called multiple times for different lengths' do
      cshake = described_class.new(:cshake_128, 0) # 0 for XOF mode
      cshake.update('test data')

      output1 = cshake.squeeze(16)
      output2 = cshake.squeeze(32)

      expect(output1.length).to eq(16)
      expect(output2.length).to eq(32)
    end
  end

  describe '#hex_squeeze' do
    it 'returns hexadecimal output with specified length' do
      cshake = described_class.new(:cshake_128, 0) # 0 for XOF mode
      cshake.update('test data')
      hex_output = cshake.hex_squeeze(32)

      expect(hex_output).to be_a(String)
      expect(hex_output.length).to eq(64) # 32 bytes = 64 hex characters
      expect(hex_output).to match(/\A[0-9a-f]+\z/)
    end
  end

  describe '#name' do
    it 'returns the name of the instance.' do
      cshake = described_class.new(:cshake_128, 32)

      expect(cshake.name).to eq('CSHAKE128')
    end
  end

  describe 'edge cases' do
    it 'handles empty strings correctly' do
      cshake = described_class.new(:cshake_128, 32)

      expect { cshake.update('') }.not_to raise_error
      expect(cshake.digest).to be_a(String)
      expect(cshake.digest.length).to eq(32)
    end

    it 'raises error on nil update' do
      cshake = described_class.new(:cshake_128, 32)
      expect { cshake.update(nil) }.to raise_error(TypeError)
    end

    it 'handles very long input data' do
      long_data = 'a' * 10_000

      expect { described_class.new(:cshake_128, 32).update(long_data) }.not_to raise_error
    end

    it 'handles different output lengths' do
      expect(described_class.new(:cshake_128, 16).digest.length).to eq(16)
      expect(described_class.new(:cshake_128, 64).digest.length).to eq(64)
      expect(described_class.new(:cshake_128, 128).digest.length).to eq(128)
    end
  end

  describe 'cryptographic properties' do
    it 'produces different outputs for different name strings with same data' do
      data = 'test data'
      digest1 = described_class.new(:cshake_128, 32, name: 'name1').update(data).digest
      digest2 = described_class.new(:cshake_128, 32, name: 'name2').update(data).digest
      expect(digest1).not_to eq(digest2)
    end

    it 'produces different outputs for different customization strings' do
      data = 'test data'
      digest1 = described_class.new(:cshake_128, 32, customization: 'custom1').update(data).digest
      digest2 = described_class.new(:cshake_128, 32, customization: 'custom2').update(data).digest
      expect(digest1).not_to eq(digest2)
    end

    it 'produces different outputs for same data but different algorithms' do
      data = 'test data'
      digest1 = described_class.new(:cshake_128, 32).update(data).digest
      digest2 = described_class.new(:cshake_256, 32).update(data).digest
      expect(digest1).not_to eq(digest2)
    end
  end

  describe 'clone and dup' do
    it 'preserves the state when cloning' do
      cshake = described_class.new(:cshake_128, 32)
      cshake.update('test data')

      clone = cshake.clone

      expect(cshake.digest).to eq(clone.digest)
    end

    it 'preserves the state when duping' do
      cshake = described_class.new(:cshake_128, 32)
      cshake.update('test data')

      dup = cshake.dup

      expect(cshake.digest).to eq(dup.digest)
    end
  end

  CSHAKE_TEST_VECTORS.each do |vector|
    describe "test vector for #{vector[:description]}" do
      it 'produces the expected digest' do
        cshake = described_class.new(
          vector[:algorithm],
          vector[:length],
          name: vector[:name],
          customization: vector[:customization]
        )

        cshake.update([vector[:data]].pack('H*'))

        expect(cshake.hexdigest).to eq(vector[:hex_output])
      end
    end
  end
end
