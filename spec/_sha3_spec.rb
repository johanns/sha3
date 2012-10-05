require 'spec_helper'
require 'sha3'

describe SHA3 do
  it "should have a VERSION constant" do
    subject.const_get('VERSION').should_not be_empty
  end
end