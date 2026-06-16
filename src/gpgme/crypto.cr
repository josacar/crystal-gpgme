module GPGME
  class Crypto
    getter default_options : Hash(String, OptionValue)

    def initialize(default_options = {} of String => OptionValue)
      @default_options = default_options
    end

    def encrypt(plain, options = {} of String => OptionValue) : Data
      options = merge_options(options)

      plain_data = Data.new(plain)
      cipher_data = Data.new(options["output"]?.as?(Data | IO | String | Int32 | Nil))
      recipients = options["symmetric"]? == true ? nil : Key.find(:public, options["recipients"]?.as?(String | Key | Array(String | Key) | Nil))

      flags = 0_u32
      flags |= GPGME::ENCRYPT_ALWAYS_TRUST if options["always_trust"]? == true

      Ctx.new(options) do |ctx|
        begin
          if options["sign"]? == true
            if signers = options["signers"]?.as?(String | Key | Array(String | Key) | Nil)
              resolved = resolve_keys_for_signing(signers, recipients)
              resolved.each { |k| ctx.add_signer(k) }
            end
            ctx.encrypt_sign(recipients || [] of Key, plain_data, cipher_data, flags)
          else
            ctx.encrypt(recipients || [] of Key, plain_data, cipher_data, flags)
          end
        rescue exc : GPGME::Error::UnusablePublicKey
          exc.keys = ctx.encrypt_result.invalid_recipients
          raise exc
        rescue exc : GPGME::Error::UnusableSecretKey
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end
      end

      cipher_data.seek(0, IO::Seek::Set)
      cipher_data
    end

    def decrypt(cipher, options = {} of String => OptionValue) : Data
      decrypt(cipher, options) { }
    end

    def decrypt(cipher, options = {} of String => OptionValue, &block : Signature ->) : Data
      options = merge_options(options)

      plain_data = Data.new(options["output"]?.as?(Data | IO | String | Int32 | Nil))
      cipher_data = Data.new(cipher)

      Ctx.new(options) do |ctx|
        begin
          ctx.decrypt_verify(cipher_data, plain_data)
        rescue exc : GPGME::Error::UnsupportedAlgorithm
          exc.algorithm = ctx.decrypt_result.unsupported_algorithm
          raise exc
        rescue exc : GPGME::Error::WrongKeyUsage
          exc.key_usage = ctx.decrypt_result.wrong_key_usage ? 1 : 0
          raise exc
        end

        ctx.verify_result.signatures.each do |signature|
          yield signature
        end
      end

      plain_data.seek(0, IO::Seek::Set)
      plain_data
    end

    def sign(text, options = {} of String => OptionValue) : Data
      options = merge_options(options)

      plain = Data.new(text)
      output = Data.new(options["output"]?.as?(Data | IO | String | Int32 | Nil))
      mode = options["mode"]? ? options["mode"].as(UInt32) : GPGME::SIG_MODE_NORMAL

      Ctx.new(options) do |ctx|
        if signer = options["signer"]?.as?(String | Key | Array(String | Key) | Nil)
          keys = case signer
                 when String
                   Key.find(:secret, signer)
                 when Key
                   [signer]
                 when Array(String | Key)
                   signer.flat_map do |s|
                     s.is_a?(String) ? Key.find(:secret, s) : [s]
                   end
                 else
                   [] of Key
                 end
          keys.each { |k| ctx.add_signer(k) }
        end

        begin
          ctx.sign(plain, output, mode)
        rescue exc : GPGME::Error::UnusableSecretKey
          exc.keys = ctx.sign_result.invalid_signers
          raise exc
        end
      end

      output.seek(0, IO::Seek::Set)
      output
    end

    def verify(sig, options = {} of String => OptionValue) : Data?
      verify(sig, options) { }
    end

    def verify(sig, options = {} of String => OptionValue, &block : Signature ->) : Data?
      options = merge_options(options)

      sig_data = Data.new(sig)
      signed_text = Data.new(options["signed_text"]?.as?(Data | IO | String | Int32 | Nil))
      output = options["signed_text"]? ? nil : Data.new(options["output"]?.as?(Data | IO | String | Int32 | Nil))

      Ctx.new(options) do |ctx|
        ctx.verify(sig_data, signed_text, output)
        ctx.verify_result.signatures.each do |signature|
          yield signature
        end
      end

      if output
        output.seek(0, IO::Seek::Set)
        output
      end
    end

    def clearsign(text, options = {} of String => OptionValue) : Data
      sign(text, merge_options(options).merge({"mode" => GPGME::SIG_MODE_CLEAR}))
    end

    def detach_sign(text, options = {} of String => OptionValue) : Data
      sign(text, merge_options(options).merge({"mode" => GPGME::SIG_MODE_DETACH}))
    end

    def self.encrypt(plain, options = {} of String => OptionValue)
      Crypto.new.encrypt(plain, options)
    end

    def self.decrypt(cipher, options = {} of String => OptionValue)
      Crypto.new.decrypt(cipher, options)
    end

    def self.sign(text, options = {} of String => OptionValue)
      Crypto.new.sign(text, options)
    end

    def self.verify(sig, options = {} of String => OptionValue)
      Crypto.new.verify(sig, options)
    end

    private def merge_options(options)
      merged = @default_options.dup
      options.each { |k, v| merged[k] = v }
      merged
    end

    private def resolve_keys_for_signing(signers_input, recipient_keys)
      signers_input = [signers_input] unless signers_input.is_a?(Array)
      recipients = recipient_keys || [] of Key

      lookup = {} of String => Key
      recipients.each do |key|
        key.fingerprint.try { |f| lookup[f] = key }
        key.fingerprint.try { |f| lookup[f[-16..-1]] = key if f.size >= 16 }
        key.fingerprint.try { |f| lookup[f[-8..-1]] = key if f.size >= 8 }
        key.uids.each do |uid|
          uid.email.try { |e| lookup[e] = key }
        end
      end

      result = [] of Key
      needs_lookup = [] of String

      signers_input.each do |signer|
        case signer
        when Key
          result << signer if signer.usable_for?(:sign)
        when String
          if existing = lookup[signer]
            result << existing if existing.usable_for?(:sign)
          else
            needs_lookup << signer
          end
        end
      end

      unless needs_lookup.empty?
        result.concat(Key.find(:public, needs_lookup, :sign))
      end

      result
    end
  end
end
