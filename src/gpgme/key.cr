module GPGME
  class Key
    include KeyCommon

    getter keylist_mode : UInt32
    getter protocol : UInt32
    getter owner_trust : Int32
    getter issuer_serial : String?
    getter issuer_name : String?
    getter chain_id : String?
    getter subkeys : Array(SubKey)
    getter uids : Array(UserID)
    getter fpr : String?
    getter handle : LibGPGME::Key

    def initialize(handle : LibGPGME::Key)
      @revoked = LibGPGME.cgpgme_key_get_revoked(handle) != 0
      @expired = LibGPGME.cgpgme_key_get_expired(handle) != 0
      @disabled = LibGPGME.cgpgme_key_get_disabled(handle) != 0
      @invalid = LibGPGME.cgpgme_key_get_invalid(handle) != 0
      @can_encrypt = LibGPGME.cgpgme_key_get_can_encrypt(handle) != 0
      @can_sign = LibGPGME.cgpgme_key_get_can_sign(handle) != 0
      @can_certify = LibGPGME.cgpgme_key_get_can_certify(handle) != 0
      @secret = LibGPGME.cgpgme_key_get_secret(handle) != 0
      @can_authenticate = LibGPGME.cgpgme_key_get_can_authenticate(handle) != 0
      @protocol = LibGPGME.cgpgme_key_get_protocol(handle).to_u32
      @owner_trust = LibGPGME.cgpgme_key_get_owner_trust(handle)
      @keylist_mode = LibGPGME.cgpgme_key_get_keylist_mode(handle)
      @issuer_serial = GPGME.nullable_string(LibGPGME.cgpgme_key_get_issuer_serial(handle))
      @issuer_name = GPGME.nullable_string(LibGPGME.cgpgme_key_get_issuer_name(handle))
      @chain_id = GPGME.nullable_string(LibGPGME.cgpgme_key_get_chain_id(handle))
      @fpr = GPGME.nullable_string(LibGPGME.cgpgme_key_get_fpr(handle))
      @handle = handle

      @subkeys = [] of SubKey
      sk = LibGPGME.cgpgme_key_get_subkeys(handle)
      while sk
        @subkeys << SubKey.new(sk)
        sk = LibGPGME.cgpgme_subkey_next(sk)
      end

      @uids = [] of UserID
      uid = LibGPGME.cgpgme_key_get_uids(handle)
      while uid
        @uids << UserID.new(uid)
        uid = LibGPGME.cgpgme_uid_next(uid)
      end
    end

    def finalize
      LibGPGME.key_unref(@handle)
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

    def secret? : Bool
      @secret
    end

    def can_authenticate? : Bool
      @can_authenticate
    end

    def primary_subkey : SubKey?
      @subkeys.first?
    end

    def sha : String?
      primary_subkey.try(&.sha)
    end

    def fingerprint : String?
      @fpr
    end

    def primary_uid : UserID?
      @uids.first?
    end

    def email : String?
      primary_uid.try(&.email)
    end

    def name : String?
      primary_uid.try(&.name)
    end

    def comment : String?
      primary_uid.try(&.comment)
    end

    def export(options : Hash(String, OptionValue) = {} of String => OptionValue) : Data
      pattern = sha || fingerprint || ""
      Key.export(pattern, options)
    end

    def delete!(allow_secret : Bool = false, force : Bool = false) : Nil
      Ctx.new do |ctx|
        ctx.delete_key(self, allow_secret, force)
      end
    end

    def expires? : Bool
      primary_subkey.try(&.expires?) || false
    end

    def expires : Time?
      primary_subkey.try(&.expires)
    end

    def expired : Bool
      @subkeys.any? { |sk| sk.expired? }
    end

    def ==(other : Key) : Bool
      fingerprint == other.fingerprint
    end

    def inspect(io : IO)
      sk = primary_subkey
      io << "#<GPGME::Key "
      io << (secret? ? "sec" : "pub") << " "
      io << sk.try(&.length) << sk.try(&.pubkey_algo_letter) << "/" << sha
      io << " trust=" << trust.inspect
      io << " capability=" << capability.inspect
      io << ">"
    end

    def to_s(io : IO)
      sk = primary_subkey
      io << (secret? ? "sec" : "pub") << "   "
      io << sk.try(&.length) << sk.try(&.pubkey_algo_letter) << "/" << sha
      io << " " << sk.try { |s| s.timestamp.try(&.to_s("%Y-%m-%d")) }
      io << "\n"
      @uids.each do |uid|
        io << "uid\t\t" << uid.name << " <" << uid.email << ">\n"
      end
      @subkeys.each do |sub|
        io << sub.to_s
      end
    end

    # Class methods

    def self.find(secret : Symbol, keys_or_names : String | Key | Array(String | Key) | Nil = nil, purposes : Symbol | Array(Symbol) = [] of Symbol) : Array(Key)
      secret_only = secret == :secret
      purposes = [purposes] if purposes.is_a?(Symbol)
      purposes = purposes.as(Array(Symbol))

      names = case keys_or_names
              when Nil
                [""] of String
              when String
                [keys_or_names]
              when Key
                [keys_or_names]
              when Array
                keys_or_names.empty? ? [""] of String | Key : keys_or_names
              else
                [""] of String | Key
              end

      keys = [] of Key
      names.each do |key_or_name|
        case key_or_name
        when Key
          keys << key_or_name
        when String
          Ctx.new do |ctx|
            ctx.keys(key_or_name, secret_only).each do |k|
              keys << k if k.usable_for?(purposes)
            end
          end
        end
      end
      keys
    end

    def self.get(fingerprint : String) : Key?
      Ctx.new do |ctx|
        ctx.get_key(fingerprint)
      end
    end

    def self.export(pattern : String | Key, options : Hash(String, OptionValue) = {} of String => OptionValue) : Data
      output = Data.new(options["output"]?.as?(Data | IO | String | Int32 | Nil))
      export_mode = options["minimal"]? == true ? 4_u32 : 0_u32

      pat = pattern.is_a?(Key) ? pattern.sha : pattern
      pat = pat || ""

      Ctx.new(options) do |ctx|
        ctx.export_keys(pat, output, export_mode)
      end

      output.seek(0, IO::Seek::Set)
      output
    end

    def self.import(keydata : String | Data | IO, options : Hash(String, OptionValue) = {} of String => OptionValue) : ImportResult
      Ctx.new(options) do |ctx|
        ctx.import_keys(Data.new(keydata))
        ctx.import_result
      end
    end

    def self.valid?(key : String | Data) : Bool
      Key.import(key).considered == 1
    end
  end
end
