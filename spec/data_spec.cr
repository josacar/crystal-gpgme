require "./spec_helper"

describe GPGME::Data do
  it "creates an empty data object" do
    data = GPGME::Data.new
    data.read.should eq("")
  end

  it "creates data from a string" do
    data = GPGME::Data.new("hello")
    data.read.should eq("hello")
  end

  it "writes and rewinds" do
    data = GPGME::Data.new
    data.write("hello")
    data.seek(0)
    data.read.should eq("hello")
  end

  it "converts to string" do
    data = GPGME::Data.new("hello")
    data.to_s.should eq("hello")
  end
end
