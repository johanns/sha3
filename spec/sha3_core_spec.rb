require 'spec_helper'
require 'sha3'

describe SHA3 do
  it "should have a VERSION constant" do
    subject.const_get('VERSION').should_not be_empty
  end

  it "should have a KECCAK_VERSION constant" do
    subject.const_get('KECCAK_VERSION').should_not be_empty
  end

  it "should have Digest class" do
    subject.const_get('Digest').is_a?(Class).should be_true
  end 
end

describe SHA3::Digest do
  it "should pass Digest.new() (default: :sha256) usage test" do
    sha = SHA3::Digest.new()
    sha.hexdigest.should eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")
    sha.reset.hexdigest.should eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    sha << (["6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa"].pack("H*"))
    sha.hexdigest.should(eq("4ea524e705020284b18284e34683725590e1ee565a6ff598ed4d42b1c987471e"))
    sha.digest_length.should(eq(32))
    sha.block_length.should(eq(136))
  end

  it "should pass Digest.new(:sha224) usage test" do
    sha = SHA3::Digest.new(:sha224)
    sha.hexdigest.should eq("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("a9cab59eb40a10b246290f2d6086e32e3689faf1d26b470c899f2802")
    sha.reset.hexdigest.should eq("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd")
    sha << (["5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d"].pack("H*"))
    sha.hexdigest.should(eq("db85af5cfce746240e6d44e73cef66a72ce5968284d35ffef7fbff6c"))
    sha.digest_length.should(eq(28))
    sha.block_length.should(eq(144))
  end

  it "should pass Digest.new(:sha256) usage test" do
    sha = SHA3::Digest.new(:sha256)
    sha.hexdigest.should eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")
    sha.reset.hexdigest.should eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    sha << (["6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa"].pack("H*"))
    sha.hexdigest.should(eq("4ea524e705020284b18284e34683725590e1ee565a6ff598ed4d42b1c987471e")) 
    sha.digest_length.should(eq(32))
    sha.block_length.should(eq(136))
  end
  
  it "should pass Digest.new(:sha384) usage test" do
    sha = SHA3::Digest.new(:sha384)
    sha.hexdigest.should eq("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("1b84e62a46e5a201861754af5dc95c4a1a69caf4a796ae405680161e29572641f5fa1e8641d7958336ee7b11c58f73e9")
    sha.reset.hexdigest.should eq("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff")
    sha << (["3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3"].pack("H*"))
    sha.hexdigest.should(eq("9172aad6c15b4dcd79bbd84fad0601119d8b4e3afed17b594ff38424157985ee27b65826b9905486e767e85aa031e07b"))
    sha.digest_length.should(eq(48))
    sha.block_length.should(eq(104))
  end

  it "should pass Digest.new(:sha512) usage test" do
    sha = SHA3::Digest.new(:sha512)
    sha.hexdigest.should eq("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e44160b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9")
    sha.reset.hexdigest.should eq("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
    sha << (["03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661"].pack("H*"))
    sha.hexdigest.should(eq("13a592b73ede487036c8816bd6fc6cdc04dc6133409a6ee990584160518f9ef573264cf04d38a3ba75d150f4f026f6df8936e13c8f4f3ecc9ecbc43fdfc488a4"))
    sha.digest_length.should(eq(64))
    sha.block_length.should(eq(72))    
  end
end

describe "SHA3::Digest::SHAxyz" do 
  it "should pass Digest.SHA224() usage test" do
    sha = SHA3::Digest::SHA224.new()
    sha.hexdigest.should eq("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("a9cab59eb40a10b246290f2d6086e32e3689faf1d26b470c899f2802")
    sha.reset.hexdigest.should eq("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd")
    sha << (["5fce8109a358570e40983e1184e541833bb9091e280f258cfb144387b05d190e431cb19baa67273ba0c58abe91308e1844dcd0b3678baa42f335f2fa05267a0240b3c718a5942b3b3e3bfa98a55c25a1466e8d7a603722cb2bbf03afa54cd769a99f310735ee5a05dae2c22d397bd95635f58c48a67f90e1b73aafcd3f82117f0166657838691005b18da6f341d6e90fc1cdb352b30fae45d348294e501b63252de14740f2b85ae5299ddec3172de8b6d0ba219a20a23bb5e10ff434d39db3f583305e9f5c039d98569e377b75a70ab837d1df269b8a4b566f40bb91b577455fd3c356c914fa06b9a7ce24c7317a172d"].pack("H*"))
    sha.hexdigest.should(eq("db85af5cfce746240e6d44e73cef66a72ce5968284d35ffef7fbff6c"))
    sha.digest_length.should(eq(28))
    sha.block_length.should(eq(144))
  end

  it "should pass Digest.SHA256() usage test" do
    sha = SHA3::Digest::SHA256.new()
    sha.hexdigest.should eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")
    sha.reset.hexdigest.should eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    sha << (["6172f1971a6e1e4e6170afbad95d5fec99bf69b24b674bc17dd78011615e502de6f56b86b1a71d3f4348087218ac7b7d09302993be272e4a591968aef18a1262d665610d1070ee91cc8da36e1f841a69a7a682c580e836941d21d909a3afc1f0b963e1ca5ab193e124a1a53df1c587470e5881fb54dae1b0d840f0c8f9d1b04c645ba1041c7d8dbf22030a623aa15638b3d99a2c400ff76f3252079af88d2b37f35ee66c1ad7801a28d3d388ac450b97d5f0f79e4541755356b3b1a5696b023f39ab7ab5f28df4202936bc97393b93bc915cb159ea1bd7a0a414cb4b7a1ac3af68f50d79f0c9c7314e750f7d02faa58bfa"].pack("H*"))
    sha.hexdigest.should(eq("4ea524e705020284b18284e34683725590e1ee565a6ff598ed4d42b1c987471e")) 
    sha.digest_length.should(eq(32))
    sha.block_length.should(eq(136))
  end
  
  it "should pass Digest.SHA384() usage test" do
    sha = SHA3::Digest::SHA384.new()
    sha.hexdigest.should eq("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("1b84e62a46e5a201861754af5dc95c4a1a69caf4a796ae405680161e29572641f5fa1e8641d7958336ee7b11c58f73e9")
    sha.reset.hexdigest.should eq("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff")
    sha << (["3b8e97c5ffc2d6a40fa7de7fcefc90f3b12c940e7ab415321e29ee692dfac799b009c99dcddb708fce5a178c5c35ee2b8617143edc4c40b4d313661f49abdd93cea79d117518805496fe6acf292c4c2a1f76b403a97d7c399daf85b46ad84e16246c67d6836757bde336c290d5d401e6c1386ab32797af6bb251e9b2d8fe754c47482b72e0b394eab76916126fd68ea7d65eb93d59f5b4c5ac40f7c3b37e7f3694f29424c24af8c8f0ef59cd9dbf1d28e0e10f799a6f78cad1d45b9db3d7dee4a7059abe99182714983b9c9d44d7f5643596d4f3"].pack("H*"))
    sha.hexdigest.should(eq("9172aad6c15b4dcd79bbd84fad0601119d8b4e3afed17b594ff38424157985ee27b65826b9905486e767e85aa031e07b"))
    sha.digest_length.should(eq(48))
    sha.block_length.should(eq(104))
  end

  it "should pass Digest.SHA512() usage test" do
    sha = SHA3::Digest::SHA512.new()
    sha.hexdigest.should eq("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
    sha.update(["cc"].pack("H*")).hexdigest.should eq("8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e44160b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9")
    sha.reset.hexdigest.should eq("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")
    sha << (["03d625488354df30e3f875a68edfcf340e8366a8e1ab67f9d5c5486a96829dfac0578289082b2a62117e1cf418b43b90e0adc881fc6ae8105c888e9ecd21aea1c9ae1a4038dfd17378fed71d02ae492087d7cdcd98f746855227967cb1ab4714261ee3bead3f4db118329d3ebef4bc48a875c19ba763966da0ebea800e01b2f50b00e9dd4caca6dcb314d00184ef71ea2391d760c950710db4a70f9212ffc54861f9dc752ce18867b8ad0c48df8466ef7231e7ac567f0eb55099e622ebb86cb237520190a61c66ad34f1f4e289cb3282ae3eaac6152ed24d2c92bae5a7658252a53c49b7b02dfe54fdb2e90074b6cf310ac661"].pack("H*"))
    sha.hexdigest.should(eq("13a592b73ede487036c8816bd6fc6cdc04dc6133409a6ee990584160518f9ef573264cf04d38a3ba75d150f4f026f6df8936e13c8f4f3ecc9ecbc43fdfc488a4"))
    sha.digest_length.should(eq(64))
    sha.block_length.should(eq(72))    
  end

end

describe "SHA3::Digest.compute" do
  it "should match SHA3-224 test vectors (subset)" do
    SHA3::Digest.compute(:sha224, ["00"].pack("H*"), 0).unpack("H*").first.should(eq("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"))
    SHA3::Digest.compute(:sha224, ["00"].pack("H*"), 1).unpack("H*").first.should(eq("860e3ec314c5cbf19c1a4314e9ea8cb85cecd18bd850b42f5c6f2a07")) 
    SHA3::Digest.compute(:sha224, ["c0"].pack("H*"), 2).unpack("H*").first.should(eq("6b22cddbd1366f7b8db2026aee8a0afa86b323aed7aa270ad928d1c5")) 
    SHA3::Digest.compute(:sha224, ["c0"].pack("H*"), 3).unpack("H*").first.should(eq("2b695a6fd92a2b3f3ce9cfca617d22c9bb52815dd59a9719b01bad25")) 
    SHA3::Digest.compute(:sha224, ["80"].pack("H*"), 4).unpack("H*").first.should(eq("bfa0740d2f2edcdee2db3f66f04fb8179967d3fb5981644d9d084bd7")) 
    SHA3::Digest.compute(:sha224, ["48"].pack("H*"), 5).unpack("H*").first.should(eq("e4384016d64610d75e0a5d73821a02d524f847a25a571b5940cd6450")) 
    SHA3::Digest.compute(:sha224, ["50"].pack("H*"), 6).unpack("H*").first.should(eq("a0fb02f1d41bc09cc4b3e85b15be85e3b3c2d43eb36dd616c640d7ca")) 
    SHA3::Digest.compute(:sha224, ["98"].pack("H*"), 7).unpack("H*").first.should(eq("c00ecd3072762c82d08f8f76fecf38be23075f9c5663d06a9184bd0b")) 
    SHA3::Digest.compute(:sha224, ["cc"].pack("H*"), 8).unpack("H*").first.should(eq("a9cab59eb40a10b246290f2d6086e32e3689faf1d26b470c899f2802")) 
  end 

  it "should match SHA3-256 test vectors (subset)" do
    SHA3::Digest.compute(:sha256, ["00"].pack("H*"), 0).unpack("H*").first.should(eq("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")) 
    SHA3::Digest.compute(:sha256, ["00"].pack("H*"), 1).unpack("H*").first.should(eq("c3e5cb55999eeff4e07b7effec77582d0a5a11a94fc268a872493099273992e1")) 
    SHA3::Digest.compute(:sha256, ["c0"].pack("H*"), 2).unpack("H*").first.should(eq("3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410")) 
    SHA3::Digest.compute(:sha256, ["c0"].pack("H*"), 3).unpack("H*").first.should(eq("7384d12118da4ad51a519806e2529fb2548b5dce2a87122b8507f71a28a35deb")) 
    SHA3::Digest.compute(:sha256, ["80"].pack("H*"), 4).unpack("H*").first.should(eq("53e5e48805ae70306bf9ddc26e9ee2db87afe95ef0bfb9f9c44211be11a4c810")) 
    SHA3::Digest.compute(:sha256, ["48"].pack("H*"), 5).unpack("H*").first.should(eq("c341f676da4d10d32d9dad5140d497fecfe9565c79f4f5aa7f1d3c36b290fe3b")) 
    SHA3::Digest.compute(:sha256, ["50"].pack("H*"), 6).unpack("H*").first.should(eq("80b7ed96c53f37ebd0a0f2f7c63b0b35480f57215ab8c5fdf9f5f6e989a53366")) 
    SHA3::Digest.compute(:sha256, ["98"].pack("H*"), 7).unpack("H*").first.should(eq("aca86ee608e0a6e31c0173f2eedee26c527f108f7f11a19a2e4327116485414c")) 
    SHA3::Digest.compute(:sha256, ["cc"].pack("H*"), 8).unpack("H*").first.should(eq("eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")) 
  end

  it "should match SHA3-384 test vectors (subset)" do
    SHA3::Digest.compute(:sha384, ["00"].pack("H*"), 0).unpack("H*").first.should(eq("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff")) 
    SHA3::Digest.compute(:sha384, ["00"].pack("H*"), 1).unpack("H*").first.should(eq("4c6d164043571a32e169a527ca3503ea391bf91f22287215df75ea243d53a0d042bc66efe2956d8606a24f39e255a081")) 
    SHA3::Digest.compute(:sha384, ["c0"].pack("H*"), 2).unpack("H*").first.should(eq("c7058511440be5d4f5688ef721000e91244ad6d10fee477dccb84e8b84db897f51db533e49964b18e5e362e5fd569e19")) 
    SHA3::Digest.compute(:sha384, ["c0"].pack("H*"), 3).unpack("H*").first.should(eq("3c297324d6f43be6a5b784c25b559910b6f79ef3c74db21575325cc9c917d935d8c3d6a9aa34f9fc65f1e9c39abc83ab")) 
    SHA3::Digest.compute(:sha384, ["80"].pack("H*"), 4).unpack("H*").first.should(eq("b43af6ccf78fc5cab63eb7cda68fd89e95c506eea63c131a82f9d9a1798002bb40d3b78473c3a66456034720ba8142e2")) 
    SHA3::Digest.compute(:sha384, ["48"].pack("H*"), 5).unpack("H*").first.should(eq("6877f31b109ebc6ddab14087739d7702f7e2aa2dd9d54b3b9c04749cb1adea194a52496dc78adcee84e705621f0564cc")) 
    SHA3::Digest.compute(:sha384, ["50"].pack("H*"), 6).unpack("H*").first.should(eq("b7136d3ef3112a47c1c59c5fab6a40c6ecd7cc89e400dc2efae388dec1028985e138a2b2f54683a8814ef3c1ba28ea9c")) 
    SHA3::Digest.compute(:sha384, ["98"].pack("H*"), 7).unpack("H*").first.should(eq("748de17dccb6b3fbaa1c938f5a3167244c83683105d45d429f0b40b31d9317860529ea54bfde1521423ceda9debd9d73")) 
    SHA3::Digest.compute(:sha384, ["cc"].pack("H*"), 8).unpack("H*").first.should(eq("1b84e62a46e5a201861754af5dc95c4a1a69caf4a796ae405680161e29572641f5fa1e8641d7958336ee7b11c58f73e9")) 
  end

  it "should match SHA3-512 test vectors (subset)" do
    SHA3::Digest.compute(:sha512, ["00"].pack("H*"), 0).unpack("H*").first.should(eq("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e")) 
    SHA3::Digest.compute(:sha512, ["00"].pack("H*"), 1).unpack("H*").first.should(eq("7d9025bb145a0814083e934baa80ede67322651de52062bf9eb93623c37efc74c62240cf8539107f9210c1e1126f79cbaeda6b82b4a8ce6821589c403fa76b9a")) 
    SHA3::Digest.compute(:sha512, ["c0"].pack("H*"), 2).unpack("H*").first.should(eq("0ae7dac687c3525d5c2a6c4119ea3968d43dfe69c2407a44d3de6b804d784530462440e4881fd42785e1cb69af4f036d96d8ff1ee35d9b3fa4a2859f592fb2dc")) 
    SHA3::Digest.compute(:sha512, ["c0"].pack("H*"), 3).unpack("H*").first.should(eq("5a844de7d6b8be77bec55021c9bfa375c4b97d79633c7ea4e7e2bc4c64ac6349d3a0142aaa50c2118b1d94af9a5b804af94f259b2d06c3f4a4997afb8f787f6b")) 
    SHA3::Digest.compute(:sha512, ["80"].pack("H*"), 4).unpack("H*").first.should(eq("b9f236b9c7ca24fe356e9375b34831b0054d4ab5cfb9e326c9e411c1805b3adb36e7d6ceccac123f27638fad3f34c48f8813a338cd53824d19bc14f6eac218b6")) 
    SHA3::Digest.compute(:sha512, ["48"].pack("H*"), 5).unpack("H*").first.should(eq("88cd5e4ab2b5cc16cf48e87b1ee3ee1fc5b1ea98142e02346429e5c8f18b570120a04040cdab16643bfd70d31ab3fd6fc360955ab4f6a9494f4fdfaa9b6576b2")) 
    SHA3::Digest.compute(:sha512, ["50"].pack("H*"), 6).unpack("H*").first.should(eq("5c69cfb002435d627390c62f2e7e74a688e537ea1dac71d97f6d99bccb64fda7d45a8e6b9dac199b78c4a3b59b04c8f1354b8d15b01db520932f1544dfbf757b")) 
    SHA3::Digest.compute(:sha512, ["98"].pack("H*"), 7).unpack("H*").first.should(eq("90e09885b5f8b9192e8380522f96d6c1c6d407aa9b73cb07ad8b84c310f08adad507b63c2c041f00119062d63421ffb51e81d39db17a022730a03d6feecbcf0b")) 
    SHA3::Digest.compute(:sha512, ["cc"].pack("H*"), 8).unpack("H*").first.should(eq("8630c13cbd066ea74bbe7fe468fec1dee10edc1254fb4c1b7c5fd69b646e44160b8ce01d05a0908ca790dfb080f4b513bc3b6225ece7a810371441a5ac666eb9"))
  end
end