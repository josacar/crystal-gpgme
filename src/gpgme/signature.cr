module GPGME
  class Signature
    getter summary : UInt32
    getter fingerprint : String?
    getter status : UInt32
    getter validity : Int32
    getter validity_reason : UInt32
    getter pka_trust : Int32
    getter pka_address : String?
    getter pubkey_algo : Int32
    getter hash_algo : Int32

    def initialize(handle : LibGPGME::Signature)
      @summary = LibGPGME.cgpgme_signature_get_summary(handle)
      @status = LibGPGME.cgpgme_signature_get_status(handle)
      @validity = LibGPGME.cgpgme_signature_get_validity(handle)
      @validity_reason = LibGPGME.cgpgme_signature_get_validity_reason(handle)
      @wrong_key_usage = LibGPGME.cgpgme_signature_get_wrong_key_usage(handle) != 0
      @pka_trust = LibGPGME.cgpgme_signature_get_pka_trust(handle)
      @pubkey_algo = LibGPGME.cgpgme_signature_get_pubkey_algo(handle)
      @hash_algo = LibGPGME.cgpgme_signature_get_hash_algo(handle)
      @timestamp = LibGPGME.cgpgme_signature_get_timestamp(handle)
      @exp_timestamp = LibGPGME.cgpgme_signature_get_exp_timestamp(handle)
      @fingerprint = GPGME.nullable_string(LibGPGME.cgpgme_signature_get_fpr(handle))
      @pka_address = GPGME.nullable_string(LibGPGME.cgpgme_signature_get_pka_address(handle))
      @key_handle = LibGPGME.cgpgme_signature_get_key(handle)
    end

    def valid? : Bool
      status_code == GPGME::GPG_ERR_NO_ERROR
    end

    def expired_signature? : Bool
      status_code == GPGME::GPG_ERR_SIG_EXPIRED
    end

    def expired_key? : Bool
      status_code == GPGME::GPG_ERR_KEY_EXPIRED
    end

    def revoked_key? : Bool
      status_code == GPGME::GPG_ERR_CERT_REVOKED
    end

    def bad? : Bool
      status_code == GPGME::GPG_ERR_BAD_SIGNATURE
    end

    def no_key? : Bool
      status_code == GPGME::GPG_ERR_NO_PUBKEY
    end

    def status_code : UInt32
      GPGME.err_code(@status)
    end

    def timestamp : Time?
      t = @timestamp
      t == 0 ? nil : Time.unix(t.to_i64)
    end

    def exp_timestamp : Time?
      t = @exp_timestamp
      t == 0 ? nil : Time.unix(t.to_i64)
    end

    def from : String?
      return @from_cache if @from_cache

      @from_cache = if fingerprint && (key = self.key)
                      uid = key.uids.first?
                      "#{key.subkeys.first.try(&.keyid)} #{uid.try(&.uid)}"
                    else
                      fingerprint
                    end
      @from_cache
    end

    def key : Key?
      return @key if @key

      if fp = fingerprint
        @key = Key.get(fp)
      end
      @key
    end

    def to_s : String
      origin = from || "unknown"
      case status_code
      when GPGME::GPG_ERR_NO_ERROR
        "Good signature from #{origin}"
      when GPGME::GPG_ERR_SIG_EXPIRED
        "Expired signature from #{origin}"
      when GPGME::GPG_ERR_KEY_EXPIRED
        "Signature made from expired key #{origin}"
      when GPGME::GPG_ERR_CERT_REVOKED
        "Signature made from revoked key #{origin}"
      when GPGME::GPG_ERR_BAD_SIGNATURE
        "Bad signature from #{origin}"
      when GPGME::GPG_ERR_NO_PUBKEY
        "No public key for #{origin}"
      else
        "Unknown signature status from #{origin}"
      end
    end
  end
end
