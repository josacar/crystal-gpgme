module GPGME
  class EngineInfo
    getter protocol : UInt32
    getter file_name : String?
    getter version : String?
    getter req_version : String?
    getter home_dir : String?

    def initialize(@protocol, @file_name, @version, @req_version, @home_dir)
    end

    def required_version
      @req_version
    end
  end

  class VerifyResult
    getter signatures : Array(Signature)
    getter file_name : String?
    getter? is_mime : Bool

    def initialize(@signatures, @file_name, @is_mime)
    end
  end

  class Recipient
    getter keyid : String?
    getter pubkey_algo : Int32
    getter status : UInt32

    def initialize(@keyid, @pubkey_algo, @status)
    end
  end

  class DecryptResult
    getter unsupported_algorithm : String?
    getter wrong_key_usage : Bool
    getter recipients : Array(Recipient)
    getter file_name : String?

    def initialize(@unsupported_algorithm, @wrong_key_usage, @recipients, @file_name)
    end
  end

  class SignResult
    getter invalid_signers : Array(InvalidKey)
    getter signatures : Array(NewSignature)

    def initialize(@invalid_signers, @signatures)
    end
  end

  class EncryptResult
    getter invalid_recipients : Array(InvalidKey)

    def initialize(@invalid_recipients)
    end
  end

  class InvalidKey
    getter fingerprint : String?
    getter reason : UInt32

    def initialize(@fingerprint, @reason)
    end
  end

  class NewSignature
    getter type : Int32
    getter pubkey_algo : Int32
    getter hash_algo : Int32
    getter sig_class : UInt32
    getter fingerprint : String?
    getter timestamp : Time?

    def initialize(@type, @pubkey_algo, @hash_algo, @sig_class, @fingerprint, @timestamp)
    end
  end

  class ImportStatus
    getter fingerprint : String?
    getter result : UInt32
    getter status : UInt32

    def initialize(@fingerprint, @result, @status)
    end
  end

  class ImportResult
    getter considered : Int32
    getter no_user_id : Int32
    getter imported : Int32
    getter imported_rsa : Int32
    getter unchanged : Int32
    getter new_user_ids : Int32
    getter new_sub_keys : Int32
    getter new_signatures : Int32
    getter new_revocations : Int32
    getter secret_read : Int32
    getter secret_imported : Int32
    getter secret_unchanged : Int32
    getter not_imported : Int32
    getter imports : Array(ImportStatus)

    def initialize(@considered, @no_user_id, @imported, @imported_rsa, @unchanged,
                   @new_user_ids, @new_sub_keys, @new_signatures, @new_revocations,
                   @secret_read, @secret_imported, @secret_unchanged, @not_imported,
                   @imports)
    end
  end
end
