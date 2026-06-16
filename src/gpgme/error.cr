module GPGME
  class Error < Exception
    getter error : UInt32

    def initialize(@error : UInt32)
      super(GPGME.strerror(@error))
    end

    def code : UInt32
      GPGME.err_code(@error)
    end

    def source : UInt32
      GPGME.err_source(@error)
    end

    class General < self; end

    class InvalidValue < self; end

    class UnusablePublicKey < self
      property keys : Array(InvalidKey)? = nil
    end

    class UnusableSecretKey < self
      property keys : Array(InvalidKey)? = nil
    end

    class NoData < self; end

    class Conflict < self; end

    class NotImplemented < self; end

    class DecryptFailed < self; end

    class BadPassphrase < self; end

    class Canceled < self; end

    class InvalidEngine < self; end

    class AmbiguousName < self; end

    class WrongKeyUsage < self
      property key_usage : Int32? = nil
    end

    class CertificateRevoked < self; end

    class CertificateExpired < self; end

    class NoCRLKnown < self; end

    class NoPolicyMatch < self; end

    class NoSecretKey < self; end

    class MissingCertificate < self; end

    class BadCertificateChain < self; end

    class UnsupportedAlgorithm < self
      property algorithm : String? = nil
    end

    class BadSignature < self; end

    class NoPublicKey < self; end

    class InvalidVersion < self; end
  end

  class EOFError < Error
    def initialize
      super(GPGME::GPG_ERR_EOF)
    end
  end

  GPG_ERR_CODE_MASK    = 0xFFFF_u32
  GPG_ERR_SOURCE_MASK  =   0x7F_u32
  GPG_ERR_SOURCE_SHIFT =         24

  def self.err_code(err : UInt32) : UInt32
    err & GPG_ERR_CODE_MASK
  end

  def self.err_source(err : UInt32) : UInt32
    (err >> GPG_ERR_SOURCE_SHIFT) & GPG_ERR_SOURCE_MASK
  end

  def self.strerror(err : UInt32) : String
    String.new(LibGPGME.cgpgme_strerror(err))
  end

  def self.error_to_exception(err : UInt32) : Error?
    case err_code(err)
    when GPG_ERR_EOF
      EOFError.new
    when GPG_ERR_NO_ERROR
      nil
    when GPG_ERR_GENERAL
      Error::General.new(err)
    when GPG_ERR_ENOMEM
      # Map to an out-of-memory exception.
      raise "Out of memory"
    when GPG_ERR_INV_VALUE
      Error::InvalidValue.new(err)
    when GPG_ERR_UNUSABLE_PUBKEY
      Error::UnusablePublicKey.new(err)
    when GPG_ERR_UNUSABLE_SECKEY
      Error::UnusableSecretKey.new(err)
    when GPG_ERR_NO_DATA
      Error::NoData.new(err)
    when GPG_ERR_CONFLICT
      Error::Conflict.new(err)
    when GPG_ERR_NOT_IMPLEMENTED
      Error::NotImplemented.new(err)
    when GPG_ERR_DECRYPT_FAILED
      Error::DecryptFailed.new(err)
    when GPG_ERR_BAD_PASSPHRASE
      Error::BadPassphrase.new(err)
    when GPG_ERR_CANCELED
      Error::Canceled.new(err)
    when GPG_ERR_INV_ENGINE
      Error::InvalidEngine.new(err)
    when GPG_ERR_AMBIGUOUS_NAME
      Error::AmbiguousName.new(err)
    when GPG_ERR_WRONG_KEY_USAGE
      Error::WrongKeyUsage.new(err)
    when GPG_ERR_CERT_REVOKED
      Error::CertificateRevoked.new(err)
    when GPG_ERR_CERT_EXPIRED
      Error::CertificateExpired.new(err)
    when GPG_ERR_NO_CRL_KNOWN
      Error::NoCRLKnown.new(err)
    when GPG_ERR_NO_POLICY_MATCH
      Error::NoPolicyMatch.new(err)
    when GPG_ERR_NO_SECKEY
      Error::NoSecretKey.new(err)
    when GPG_ERR_MISSING_CERT
      Error::MissingCertificate.new(err)
    when GPG_ERR_BAD_CERT_CHAIN
      Error::BadCertificateChain.new(err)
    when GPG_ERR_UNSUPPORTED_ALGORITHM
      Error::UnsupportedAlgorithm.new(err)
    when GPG_ERR_BAD_SIGNATURE
      Error::BadSignature.new(err)
    when GPG_ERR_NO_PUBKEY
      Error::NoPublicKey.new(err)
    else
      Error.new(err)
    end
  end

  def self.check_version(options : String | Nil = nil) : Bool
    req = options ? options.to_unsafe : Pointer(LibC::Char).null
    LibGPGME.check_version(req) ? true : false
  end
end
