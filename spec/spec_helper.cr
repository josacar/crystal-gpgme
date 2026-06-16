require "spec"
require "file_utils"
require "../src/gpgme"

module GPGME
  module Test
    class_getter home_dir : String do
      dir = File.join(Dir.tempdir, "crystal-gpgme-#{Random.new.hex(8)}")
      Dir.mkdir_p(dir)
      File.write(File.join(dir, "gpg-agent.conf"), "pinentry-program #{File.join(__DIR__, "pinentry")}\n")
      Engine.home_dir = dir
      dir
    end

    def self.import_keys
      import_key(File.join(__DIR__, "files", "testkey_pub.gpg"))
      import_key(File.join(__DIR__, "files", "testkey_sec.gpg"))
    end

    def self.import_key(path : String)
      Key.import(File.read(path))
    end

    def self.remove_all_keys
      Key.find(:public).each(&.delete!(true, true))
      Key.find(:secret).each(&.delete!(true, true))
    rescue
      # ignore
    end

    def self.reset!
      remove_all_keys
      import_keys
    end
  end
end

GPGME::Test.home_dir
GPGME::Test.import_keys

Spec.after_each do
  GPGME::Test.reset!
end
