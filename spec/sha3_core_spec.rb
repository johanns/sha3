require 'spec_helper'
require 'sha3'

RSpec.describe SHA3 do
  it 'should have a VERSION constant' do
    expect(subject.const_get('VERSION')).not_to be_empty
  end

  it 'should have a KECCAK_VERSION constant' do
    expect(subject.const_get('KECCAK_VERSION')).not_to be_empty
  end

  it 'should have Digest class' do
    expect(subject.const_get('Digest').is_a?(Class)).to be_truthy
  end
end

RSpec.describe SHA3::Digest do
  it 'should pass Digest.new() (default: :sha256) usage test' do
    sha = SHA3::Digest.new()

    expect(sha.hexdigest).to eq('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')
    expect(sha.update(['cc'].pack('H*'))).to eq('677035391cd3701293d385f037ba32796252bb7ce180b00b582dd9b20aaad7f0')
    expect(sha.reset).to eq('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')

    sha << (['6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa'].pack('H*'))

    expect(sha.hexdigest).to eq('f60c53ba2132293b881f0513e7ab47fe9746ed4a6ac9cade61e6d802d5872372')
    expect(sha.digest_length).to eq(32)
    expect(sha.block_length).to eq(136)
  end

  it 'should pass Digest.new(:sha224) usage test' do
    sha = SHA3::Digest.new(:sha224)

    expect(sha.hexdigest).to eq('6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7')
    expect(sha.update(['cc'].pack('H*'))).to eq('df70adc49b2e76eee3a6931b93fa41841c3af2cdf5b32a18b5478c39')
    expect(sha.reset).to eq('6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7')

    sha << (['5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d'].pack('H*'))

    expect(sha.hexdigest).to eq('2ebe13f12ec43e3f6b0506d7ab216e1c311394f7c89d69a920cd00c0')
    expect(sha.digest_length).to eq(28)
    expect(sha.block_length).to eq(144)
  end

  it 'should pass Digest.new(:sha256) usage test' do
    sha = SHA3::Digest.new(:sha256)

    expect(sha.hexdigest).to eq('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')
    expect(sha.update(['cc'].pack('H*'))).to eq('677035391cd3701293d385f037ba32796252bb7ce180b00b582dd9b20aaad7f0')
    expect(sha.reset).to eq('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')

    sha << (['6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa'].pack('H*'))

    expect(sha.hexdigest).to eq('f60c53ba2132293b881f0513e7ab47fe9746ed4a6ac9cade61e6d802d5872372')
    expect(sha.digest_length).to eq(32)
    expect(sha.block_length).to eq(136)
  end

  it 'should pass Digest.new(:sha384) usage test' do
    sha = SHA3::Digest.new(:sha384)

    expect(sha.hexdigest).to eq('0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004')

    expect(sha.update(['cc'].pack('H*'))).to eq('5ee7f374973cd4bb3dc41e3081346798497ff6e36cb9352281dfe07d07fc530ca9ad8ef7aad56ef5d41be83d5e543807')
    expect(sha.reset).to eq('0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004')

    sha << (['3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3'].pack('H*'))

    expect(sha.hexdigest).to eq('9b809198dcce24175e33098331d3a402a821ae9326e72775aae34d1a9bb53d2b57863905cfd60543bbc42b454007c315')
    expect(sha.digest_length).to eq(48)
    expect(sha.block_length).to eq(104)
  end

  it 'should pass Digest.new(:sha512) usage test' do
    sha = SHA3::Digest.new(:sha512)

    expect(sha.hexdigest).to eq('a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26')
    expect(sha.update(['cc'].pack('H*'))).to eq('3939fcc8b57b63612542da31a834e5dcc36e2ee0f652ac72e02624fa2e5adeecc7dd6bb3580224b4d6138706fc6e80597b528051230b00621cc2b22999eaa205')
    expect(sha.reset).to eq('a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26')

    sha << (['03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661'].pack('H*'))

    expect(sha.hexdigest).to eq('1fcd1e38ab03c750366cf86dd72ec3bf22f5bbf7fea0149d31b6a67b68b537b59ba37917fd88ced9aa8d2941a65f552b7928b3785c66d640f3b74af039ed18ce')
    expect(sha.digest_length).to eq(64)
    expect(sha.block_length).to eq(72)
  end
end

RSpec.describe 'SHA3::Digest::SHAxyz' do
  it 'should pass Digest.SHA224() usage test' do
    sha = SHA3::Digest::SHA224.new()

    expect(sha.hexdigest).to eq('6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7')
    expect(sha.update(['cc'].pack('H*'))).to eq('df70adc49b2e76eee3a6931b93fa41841c3af2cdf5b32a18b5478c39')
    expect(sha.reset).to eq('6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7')

    sha << (['5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d'].pack("H*"))

    expect(sha.hexdigest).to eq('2ebe13f12ec43e3f6b0506d7ab216e1c311394f7c89d69a920cd00c0')
    expect(sha.digest_length).to eq(28)
    expect(sha.block_length).to eq(144)
  end

  it 'should pass Digest.SHA256() usage test' do
    sha = SHA3::Digest::SHA256.new()

    expect(sha.hexdigest).to eq('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')
    expect(sha.update(['cc'].pack('H*'))).to eq('677035391cd3701293d385f037ba32796252bb7ce180b00b582dd9b20aaad7f0')
    expect(sha.reset).to eq('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')

    sha << (['6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa'].pack("H*"))

    expect(sha.hexdigest).to eq('f60c53ba2132293b881f0513e7ab47fe9746ed4a6ac9cade61e6d802d5872372')
    expect(sha.digest_length).to eq(32)
    expect(sha.block_length).to eq(136)
  end

  it 'should pass Digest.SHA384() usage test' do
    sha = SHA3::Digest::SHA384.new()

    expect(sha.hexdigest).to eq('0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004')

    expect(sha.update(['cc'].pack('H*'))).to eq('5ee7f374973cd4bb3dc41e3081346798497ff6e36cb9352281dfe07d07fc530ca9ad8ef7aad56ef5d41be83d5e543807')
    expect(sha.reset).to eq('0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004')

    sha << (['3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3'].pack("H*"))

    expect(sha.hexdigest).to eq('9b809198dcce24175e33098331d3a402a821ae9326e72775aae34d1a9bb53d2b57863905cfd60543bbc42b454007c315')
    expect(sha.digest_length).to eq(48)
    expect(sha.block_length).to eq(104)
  end

  it 'should pass Digest.SHA512() usage test' do
    sha = SHA3::Digest::SHA512.new()

    expect(sha.hexdigest).to eq('a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26')
    expect(sha.update(['cc'].pack('H*'))).to eq('3939fcc8b57b63612542da31a834e5dcc36e2ee0f652ac72e02624fa2e5adeecc7dd6bb3580224b4d6138706fc6e80597b528051230b00621cc2b22999eaa205')
    expect(sha.reset).to eq('a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26')

    sha << (['03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661'].pack("H*"))

    expect(sha.hexdigest).to eq('1fcd1e38ab03c750366cf86dd72ec3bf22f5bbf7fea0149d31b6a67b68b537b59ba37917fd88ced9aa8d2941a65f552b7928b3785c66d640f3b74af039ed18ce')
    expect(sha.digest_length).to eq(64)
    expect(sha.block_length).to eq(72)
  end
end
