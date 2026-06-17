require "./spec_helper"

describe GPGME::Engine do
  it "checks the OpenPGP engine version" do
    GPGME::Engine.check_version(GPGME::PROTOCOL_OpenPGP).should be_true
  end

  it "reports engine info" do
    info = GPGME::Engine.info
    info.should_not be_empty
    info.first.protocol.should eq(GPGME::PROTOCOL_OpenPGP)
  end

  it "reports dirinfo" do
    GPGME::Engine.dirinfo("gpg-name").should_not be_nil
  end
end
