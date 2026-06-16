module GPGME
  class KeySig
    getter pubkey_algo : Int32
    getter keyid : String?

    def initialize(handle : LibGPGME::KeySig)
      @revoked = LibGPGME.cgpgme_keysig_get_revoked(handle) != 0
      @expired = LibGPGME.cgpgme_keysig_get_expired(handle) != 0
      @invalid = LibGPGME.cgpgme_keysig_get_invalid(handle) != 0
      @exportable = LibGPGME.cgpgme_keysig_get_exportable(handle) != 0
      @pubkey_algo = LibGPGME.cgpgme_keysig_get_pubkey_algo(handle)
      @keyid = GPGME.nullable_string(LibGPGME.cgpgme_keysig_get_keyid(handle))
      @timestamp = LibGPGME.cgpgme_keysig_get_timestamp(handle)
      @expires = LibGPGME.cgpgme_keysig_get_expires(handle)
    end

    def revoked? : Bool
      @revoked
    end

    def expired? : Bool
      @expired
    end

    def invalid? : Bool
      @invalid
    end

    def exportable? : Bool
      @exportable
    end

    def timestamp : Time?
      t = @timestamp
      t == 0 ? nil : Time.unix(t.to_i64)
    end

    def expires : Time?
      e = @expires
      e == 0 ? nil : Time.unix(e.to_i64)
    end

    def inspect(io : IO)
      io << "#<GPGME::KeySig " << @keyid
      io << " timestamp=" << timestamp << " expires=" << expires << ">"
    end
  end
end
