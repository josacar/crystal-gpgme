require "./spec_helper"

describe GPGME::Ctx do
  it "creates a context with the default protocol" do
    GPGME::Ctx.new do |ctx|
      ctx.protocol.should eq(GPGME::PROTOCOL_OpenPGP)
    end
  end

  it "toggles armor" do
    GPGME::Ctx.new do |ctx|
      ctx.armor = true
      ctx.armor.should be_true
      ctx.armor = false
      ctx.armor.should be_false
    end
  end

  it "toggles textmode" do
    GPGME::Ctx.new do |ctx|
      ctx.textmode = true
      ctx.textmode.should be_true
    end
  end

  it "sets and gets keylist mode" do
    GPGME::Ctx.new do |ctx|
      mode = GPGME::KEYLIST_MODE_SIGS
      ctx.keylist_mode = mode
      ctx.keylist_mode.should eq(mode)
    end
  end

  it "toggles offline mode" do
    GPGME::Ctx.new do |ctx|
      ctx.offline = true
      ctx.offline.should be_true
    end
  end

  it "lists public keys" do
    GPGME::Ctx.new do |ctx|
      keys = ctx.keys
      keys.should_not be_empty
      keys.first.should be_a(GPGME::Key)
    end
  end

  it "lists secret keys" do
    GPGME::Ctx.new do |ctx|
      keys = ctx.keys(nil, true)
      keys.should_not be_empty
      keys.first.secret?.should be_true
    end
  end

  it "finds keys by pattern" do
    GPGME::Ctx.new do |ctx|
      keys = ctx.keys("mrsimo@gmail.com")
      keys.size.should eq(1)
    end
  end

  it "iterates keys with each_key" do
    GPGME::Ctx.new do |ctx|
      count = 0
      ctx.each_key { count += 1 }
      count.should be > 0
    end
  end

  it "gets a key by fingerprint" do
    key = GPGME::Key.find(:public).first
    fpr = key.fingerprint || ""
    fpr.should_not eq("")

    GPGME::Ctx.new do |ctx|
      found = ctx.get_key(fpr)
      found.should_not be_nil
      found.as(GPGME::Key).fingerprint.should eq(fpr)
    end
  end

  it "imports keys and reports the result" do
    GPGME::Test.remove_all_keys

    GPGME::Ctx.new do |ctx|
      data = GPGME::Data.new(File.read(File.join(__DIR__, "files", "testkey_pub.gpg")))
      ctx.import_keys(data)
      result = ctx.import_result
      result.considered.should eq(1)
    end
  end

  it "exports keys" do
    key = GPGME::Key.find(:public).first
    fpr = key.fingerprint || ""
    fpr.should_not eq("")

    GPGME::Ctx.new({"armor" => true}) do |ctx|
      output = GPGME::Data.empty!
      ctx.export_keys(fpr, output)
      output.to_s.should contain("BEGIN PGP PUBLIC KEY BLOCK")
    end
  end

  it "signs and verifies a detached signature" do
    plain = GPGME::Data.new("hello world")
    sig = GPGME::Data.empty!

    GPGME::Ctx.new do |ctx|
      ctx.sign(plain, sig, GPGME::SIG_MODE_DETACH)
      sig.seek(0, IO::Seek::Set)
      plain.seek(0, IO::Seek::Set)
      ctx.verify(sig, plain, nil)

      signature = ctx.verify_result.signatures.first
      signature.should be_a(GPGME::Signature)
      signature.valid?.should be_true
    end
  end

  it "encrypts and decrypts" do
    key = GPGME::Key.find(:public).first
    plain = GPGME::Data.new("secret message")
    cipher = GPGME::Data.empty!

    GPGME::Ctx.new do |ctx|
      ctx.encrypt([key], plain, cipher, GPGME::ENCRYPT_ALWAYS_TRUST)
      cipher.seek(0, IO::Seek::Set)
      decrypted = ctx.decrypt(cipher)
      decrypted.to_s.should eq("secret message")
    end
  end
end
