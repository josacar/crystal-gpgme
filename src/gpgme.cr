require "./gpgme/lib_gpgme"
require "./gpgme/constants"
require "./gpgme/error"
require "./gpgme/misc"
require "./gpgme/key_common"
require "./gpgme/sub_key"
require "./gpgme/user_id"
require "./gpgme/key_sig"
require "./gpgme/key"
require "./gpgme/signature"
require "./gpgme/data"
require "./gpgme/engine"
require "./gpgme/ctx"
require "./gpgme/crypto"
require "./gpgme/io_callbacks"

module GPGME
  VERSION = "0.1.0"

  alias OptionValue = String | UInt32 | Int32 | Bool | Symbol | Key | Array(String | Key) | Data | IO | Nil

  # Initialize the GPGME library before any operations.
  LibGPGME.check_version(nil)

  # Thread-safe serialization: GPGME operations that talk to gpg-agent should
  # not overlap.  Mimics ruby-gpgme's Monitor-based synchronization.
  @@mutex = Mutex.new
  @@thread_safe = true

  def self.thread_safe? : Bool
    @@thread_safe
  end

  def self.thread_safe=(value : Bool)
    @@thread_safe = value
  end

  def self.synchronize(&)
    if @@thread_safe
      @@mutex.synchronize { yield }
    else
      yield
    end
  end

  # Convert a C char* to a String or nil.
  def self.nullable_string(ptr : Pointer(LibC::Char)) : String?
    ptr.null? ? nil : String.new(ptr)
  end
end
