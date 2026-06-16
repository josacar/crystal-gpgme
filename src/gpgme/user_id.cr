module GPGME
  class UserID
    getter validity : Int32
    getter uid : String?
    getter name : String?
    getter comment : String?
    getter email : String?
    getter signatures : Array(KeySig)

    def initialize(handle : LibGPGME::UserID)
      @revoked = LibGPGME.cgpgme_uid_get_revoked(handle) != 0
      @invalid = LibGPGME.cgpgme_uid_get_invalid(handle) != 0
      @validity = LibGPGME.cgpgme_uid_get_validity(handle)
      @uid = GPGME.nullable_string(LibGPGME.cgpgme_uid_get_uid(handle))
      @name = GPGME.nullable_string(LibGPGME.cgpgme_uid_get_name(handle))
      @email = GPGME.nullable_string(LibGPGME.cgpgme_uid_get_email(handle))
      @comment = GPGME.nullable_string(LibGPGME.cgpgme_uid_get_comment(handle))

      @signatures = [] of KeySig
      sig = LibGPGME.cgpgme_uid_get_signatures(handle)
      while sig
        @signatures << KeySig.new(sig)
        sig = LibGPGME.cgpgme_keysig_next(sig)
      end
    end

    def revoked? : Bool
      @revoked
    end

    def invalid? : Bool
      @invalid
    end

    def inspect(io : IO)
      io << "#<GPGME::UserID " << @name << " <" << @email << ">"
      io << " validity=" << (VALIDITY_NAMES[@validity]? || :unknown)
      io << " signatures=" << @signatures.inspect << ">"
    end
  end
end
