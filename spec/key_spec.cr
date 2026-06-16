require "./spec_helper"

describe GPGME::Key do
  it "finds public keys" do
    keys = GPGME::Key.find(:public)
    keys.should_not be_empty
  end

  it "finds secret keys" do
    keys = GPGME::Key.find(:secret)
    keys.should_not be_empty
  end

  it "finds by email" do
    keys = GPGME::Key.find(:public, "mrsimo@gmail.com")
    keys.size.should eq(1)
  end

  it "exports a key" do
    key = GPGME::Key.find(:public).first
    exported = key.export({"armor" => true})
    exported.to_s.should contain("BEGIN PGP PUBLIC KEY BLOCK")
  end

  it "imports a key" do
    GPGME::Test.remove_all_keys
    result = GPGME::Key.import(File.read(File.join(__DIR__, "files", "testkey_pub.gpg")))
    result.considered.should eq(1)
  end
end
