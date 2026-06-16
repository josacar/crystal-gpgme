require "./spec_helper"

describe GPGME do
  it "has a version" do
    GPGME::VERSION.should eq("0.1.0")
  end

  it "checks the engine version" do
    GPGME::Engine.check_version(GPGME::PROTOCOL_OpenPGP).should be_true
  end

  it "reports engine info" do
    info = GPGME::Engine.info
    info.should_not be_empty
    info.first.protocol.should eq(GPGME::PROTOCOL_OpenPGP)
  end
end
