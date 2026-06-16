require "./spec_helper"

describe GPGME::Crypto do
  plain = "Hi there"

  it "encrypts and decrypts" do
    key = GPGME::Key.find(:public).first
    crypto = GPGME::Crypto.new
    encrypted = crypto.encrypt(plain, {"recipients" => key, "always_trust" => true})
    crypto.decrypt(encrypted).to_s.should eq(plain)
  end

  it "encrypts with armor" do
    key = GPGME::Key.find(:public).first
    crypto = GPGME::Crypto.new
    encrypted = crypto.encrypt(plain, {"recipients" => key, "always_trust" => true, "armor" => true})
    encrypted.to_s.should contain("BEGIN PGP MESSAGE")
  end

  it "signs and verifies" do
    crypto = GPGME::Crypto.new
    sign = crypto.sign(plain)
    signatures = 0
    verified = crypto.verify(sign) do |signature|
      signature.should be_a(GPGME::Signature)
      signature.valid?.should be_true
      signatures += 1
    end
    signatures.should eq(1)
    verified.to_s.should eq(plain)
  end

  it "clearsigns" do
    crypto = GPGME::Crypto.new
    sign = crypto.clearsign(plain)
    sign.to_s.should contain("BEGIN PGP SIGNED MESSAGE")
  end

  it "detached signs and verifies" do
    crypto = GPGME::Crypto.new
    sign = crypto.detach_sign(plain)
    signatures = 0
    crypto.verify(sign, {"signed_text" => plain}) do |signature|
      signature.valid?.should be_true
      signatures += 1
    end
    signatures.should eq(1)
  end

  it "raises when encrypting without trusted recipients" do
    crypto = GPGME::Crypto.new
    expect_raises(GPGME::Error::UnusablePublicKey) do
      crypto.encrypt(plain)
    end
  end
end
