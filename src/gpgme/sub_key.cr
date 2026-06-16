module GPGME
  class SubKey
    include KeyCommon

    getter pubkey_algo : Int32
    getter length : UInt32
    getter keyid : String?
    getter fpr : String?
    getter curve : String?

    def initialize(handle : LibGPGME::SubKey)
      @revoked = LibGPGME.cgpgme_subkey_get_revoked(handle) != 0
      @expired = LibGPGME.cgpgme_subkey_get_expired(handle) != 0
      @disabled = LibGPGME.cgpgme_subkey_get_disabled(handle) != 0
      @invalid = LibGPGME.cgpgme_subkey_get_invalid(handle) != 0
      @can_encrypt = LibGPGME.cgpgme_subkey_get_can_encrypt(handle) != 0
      @can_sign = LibGPGME.cgpgme_subkey_get_can_sign(handle) != 0
      @can_certify = LibGPGME.cgpgme_subkey_get_can_certify(handle) != 0
      @can_authenticate = LibGPGME.cgpgme_subkey_get_can_authenticate(handle) != 0
      @secret = LibGPGME.cgpgme_subkey_get_secret(handle) != 0
      @pubkey_algo = LibGPGME.cgpgme_subkey_get_pubkey_algo(handle)
      @length = LibGPGME.cgpgme_subkey_get_length(handle)
      @keyid = GPGME.nullable_string(LibGPGME.cgpgme_subkey_get_keyid(handle))
      @fpr = GPGME.nullable_string(LibGPGME.cgpgme_subkey_get_fpr(handle))
      @curve = GPGME.nullable_string(LibGPGME.cgpgme_subkey_get_curve(handle))
      @timestamp = LibGPGME.cgpgme_subkey_get_timestamp(handle)
      @expires = LibGPGME.cgpgme_subkey_get_expires(handle)
    end

    def revoked? : Bool
      @revoked
    end

    def expired? : Bool
      @expired
    end

    def disabled? : Bool
      @disabled
    end

    def invalid? : Bool
      @invalid
    end

    def can_encrypt? : Bool
      @can_encrypt
    end

    def can_sign? : Bool
      @can_sign
    end

    def can_certify? : Bool
      @can_certify
    end

    def can_authenticate? : Bool
      @can_authenticate
    end

    def secret? : Bool
      @secret
    end

    def timestamp : Time?
      t = @timestamp
      t == 0 || t == 0xFFFFFFFFFFFFFFFF_u64 ? nil : Time.unix(t.to_i64)
    end

    def expires? : Bool
      @expires != 0
    end

    def expires : Time?
      expires? ? Time.unix(@expires.to_i64) : nil
    end

    def expired? : Bool
      expires? && @expires < Time.utc.to_unix.to_u64
    end

    def fingerprint : String?
      @fpr
    end

    def sha : String?
      (@fpr || @keyid).try { |s| s.size >= 8 ? s[-8..-1] : s }
    end

    PUBKEY_ALGO_LETTERS = {
      PK_RSA   => "R",
      PK_RSA_E => "r",
      PK_RSA_S => "s",
      PK_ELG_E => "g",
      PK_ELG   => "G",
      PK_DSA   => "D",
      PK_ECDSA => "E",
      PK_EDDSA => "E",
      PK_ECC   => "E",
    }

    def pubkey_algo_letter : String
      PUBKEY_ALGO_LETTERS[@pubkey_algo]? || "?"
    end

    def inspect(io : IO)
      io << "#<GPGME::SubKey "
      io << (secret? ? "ssc" : "sub")
      io << " " << @length << pubkey_algo_letter << "/" << sha
      io << " trust=" << trust.inspect << " capability=" << capability.inspect
      io << ">"
    end

    def to_s(io : IO)
      io << (secret? ? "ssc" : "sub") << "   "
      io << @length << pubkey_algo_letter << "/" << sha << " "
      io << (timestamp ? timestamp.to_s("%Y-%m-%d") : "")
      io << "\n"
    end
  end
end
