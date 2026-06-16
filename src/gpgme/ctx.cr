module GPGME
  class Ctx
    getter handle : LibGPGME::Ctx

    def self.new(options : Hash(String, OptionValue) = {} of String => OptionValue, & : Ctx ->)
      ctx = new(options)
      begin
        GPGME.synchronize { yield ctx }
      ensure
        ctx.release
      end
    end

    def self.new(options : Hash(String, OptionValue) = {} of String => OptionValue) : Ctx
      err = LibGPGME.new(out handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc

      ctx = new(handle)
      ctx.protocol = options["protocol"].as(UInt32) if options["protocol"]? && options["protocol"].is_a?(UInt32)
      ctx.armor = true if options["armor"]? == true
      ctx.textmode = true if options["textmode"]? == true
      ctx.keylist_mode = options["keylist_mode"].as(UInt32) if options["keylist_mode"]? && options["keylist_mode"].is_a?(UInt32)
      ctx.pinentry_mode = options["pinentry_mode"].as(UInt32) if options["pinentry_mode"]? && options["pinentry_mode"].is_a?(UInt32)
      ctx.offline = true if options["offline"]? == true
      ctx.ignore_mdc_error = true if options["ignore_mdc_error"]? == true

      password = options["password"]?
      if password.is_a?(String)
        ctx.set_passphrase_callback(PASSPHRASE_CALLBACK, password)
      end

      ctx
    end

    def initialize(@handle : LibGPGME::Ctx)
    end

    def finalize
      release
    end

    def release
      return if @handle.null?
      LibGPGME.release(@handle)
      @handle = Pointer(Void).null.as(LibGPGME::Ctx)
    end

    def get_ctx_flag(flag_name : String) : String?
      GPGME.nullable_string(LibGPGME.get_ctx_flag(@handle, flag_name.to_unsafe))
    end

    def set_ctx_flag(flag_name : String, value : String) : String
      err = LibGPGME.set_ctx_flag(@handle, flag_name.to_unsafe, value.to_unsafe)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      value
    end

    def protocol=(proto : UInt32)
      err = LibGPGME.set_protocol(@handle, proto)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      proto
    end

    def protocol : UInt32
      LibGPGME.get_protocol(@handle)
    end

    def armor=(yes : Bool)
      LibGPGME.set_armor(@handle, yes ? 1 : 0)
      yes
    end

    def armor : Bool
      LibGPGME.get_armor(@handle) == 1
    end

    def textmode=(yes : Bool)
      LibGPGME.set_textmode(@handle, yes ? 1 : 0)
      yes
    end

    def textmode : Bool
      LibGPGME.get_textmode(@handle) == 1
    end

    def ignore_mdc_error=(yes : Bool)
      set_ctx_flag("ignore-mdc-error", yes ? "1" : "0")
      yes
    end

    def ignore_mdc_error : Bool
      get_ctx_flag("ignore-mdc-error") == "1"
    end

    def keylist_mode=(mode : UInt32)
      err = LibGPGME.set_keylist_mode(@handle, mode)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      mode
    end

    def keylist_mode : UInt32
      LibGPGME.get_keylist_mode(@handle)
    end

    def pinentry_mode=(mode : UInt32)
      err = LibGPGME.set_pinentry_mode(@handle, mode)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      mode
    end

    def pinentry_mode : UInt32
      LibGPGME.get_pinentry_mode(@handle)
    end

    def offline=(yes : Bool)
      LibGPGME.set_offline(@handle, yes ? 1 : 0)
      yes
    end

    def offline : Bool
      LibGPGME.get_offline(@handle) == 1
    end

    def include_certs=(nr : Int32)
      LibGPGME.set_include_certs(@handle, nr)
      nr
    end

    def include_certs : Int32
      LibGPGME.get_include_certs(@handle)
    end

    def set_passphrase_callback(callback : LibGPGME::PassphraseCb, hook_value : Void* | String | Nil = nil)
      hook = case hook_value
             when String
               hook_value.to_unsafe.as(Void*)
             when Nil
               Pointer(Void).null
             else
               hook_value.as(Void*)
             end
      LibGPGME.set_passphrase_cb(@handle, callback, hook)
    end

    def set_progress_callback(callback : LibGPGME::ProgressCb, hook_value : Void* | Nil = nil)
      LibGPGME.set_progress_cb(@handle, callback, hook_value || Pointer(Void).null)
    end

    def set_status_callback(callback : LibGPGME::StatusCb, hook_value : Void* | Nil = nil)
      LibGPGME.set_status_cb(@handle, callback, hook_value || Pointer(Void).null)
    end

    def keylist_start(pattern : String? = nil, secret_only : Bool = false)
      err = LibGPGME.op_keylist_start(@handle, pattern ? pattern.to_unsafe : Pointer(LibC::Char).null, secret_only ? 1 : 0)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
    end

    def keylist_next : Key
      err = LibGPGME.op_keylist_next(@handle, out key)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      Key.new(key)
    end

    def keylist_end
      err = LibGPGME.op_keylist_end(@handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
    end

    def each_key(pattern : String? = nil, secret_only : Bool = false, & : Key ->)
      keylist_start(pattern, secret_only)
      begin
        loop { yield keylist_next }
      rescue GPGME::EOFError
        # all keys returned
      ensure
        keylist_end
      end
    end

    def keys(pattern : String? = nil, secret_only : Bool? = nil) : Array(Key)
      only = secret_only == true
      result = [] of Key
      each_key(pattern, only) { |k| result << k }
      result
    end

    def get_key(fingerprint : String, secret : Bool = false) : Key?
      err = LibGPGME.get_key(@handle, fingerprint.to_unsafe, out key, secret ? 1 : 0)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      Key.new(key)
    end

    def generate_key(parms : String, pubkey : Data? = nil, seckey : Data? = nil)
      err = LibGPGME.op_genkey(@handle, parms.to_unsafe, pubkey ? pubkey.handle : Pointer(Void).null.as(LibGPGME::Data), seckey ? seckey.handle : Pointer(Void).null.as(LibGPGME::Data))
      exc = GPGME.error_to_exception(err)
      raise exc if exc
    end

    def export_keys(recipients : String, keydata : Data = Data.empty!, mode : UInt32 = 0_u32) : Data
      err = LibGPGME.op_export(@handle, recipients.to_unsafe, mode, keydata.handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      keydata
    end

    def import_keys(keydata : Data)
      err = LibGPGME.op_import(@handle, keydata.handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
    end

    def import_result : ImportResult
      ptr = LibGPGME.op_import_result(@handle)
      build_import_result(ptr)
    end

    def delete_key(key : Key, allow_secret : Bool = false, force : Bool = false)
      err = LibGPGME.op_delete(@handle, key.handle, allow_secret ? 1 : 0)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
    end

    def decrypt(cipher : Data, plain : Data = Data.empty!) : Data
      err = LibGPGME.op_decrypt(@handle, cipher.handle, plain.handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      plain
    end

    def decrypt_verify(cipher : Data, plain : Data = Data.empty!) : Data
      err = LibGPGME.op_decrypt_verify(@handle, cipher.handle, plain.handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      plain
    end

    def decrypt_result : DecryptResult
      ptr = LibGPGME.op_decrypt_result(@handle)
      build_decrypt_result(ptr)
    end

    def verify(sig : Data, signed_text : Data? = nil, plain : Data? = nil) : Data?
      err = LibGPGME.op_verify(
        @handle,
        sig.handle,
        signed_text ? signed_text.handle : Pointer(Void).null.as(LibGPGME::Data),
        plain ? plain.handle : Pointer(Void).null.as(LibGPGME::Data)
      )
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      plain
    end

    def verify_result : VerifyResult
      ptr = LibGPGME.op_verify_result(@handle)
      build_verify_result(ptr)
    end

    def clear_signers
      LibGPGME.signers_clear(@handle)
    end

    def add_signer(*keys : Key)
      keys.each do |key|
        err = LibGPGME.signers_add(@handle, key.handle)
        exc = GPGME.error_to_exception(err)
        raise exc if exc
      end
    end

    def sign(plain : Data, sig : Data = Data.empty!, mode : UInt32 = GPGME::SIG_MODE_NORMAL) : Data
      err = LibGPGME.op_sign(@handle, plain.handle, sig.handle, mode)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      sig
    end

    def sign_result : SignResult
      ptr = LibGPGME.op_sign_result(@handle)
      build_sign_result(ptr)
    end

    def encrypt(recp : Array(Key), plain : Data, cipher : Data = Data.empty!, flags : UInt32 = 0_u32) : Data
      key_ptrs = recp.map(&.handle)
      # Add a null terminator for the C array.
      null_key = Pointer(Void).null.as(LibGPGME::Key)
      native = (key_ptrs + [null_key]).to_unsafe
      err = LibGPGME.op_encrypt(@handle, native, flags, plain.handle, cipher.handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      cipher
    end

    def encrypt_sign(recp : Array(Key), plain : Data, cipher : Data = Data.empty!, flags : UInt32 = 0_u32) : Data
      key_ptrs = recp.map(&.handle)
      null_key = Pointer(Void).null.as(LibGPGME::Key)
      native = (key_ptrs + [null_key]).to_unsafe
      err = LibGPGME.op_encrypt_sign(@handle, native, flags, plain.handle, cipher.handle)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      cipher
    end

    def encrypt_result : EncryptResult
      ptr = LibGPGME.op_encrypt_result(@handle)
      build_encrypt_result(ptr)
    end

    def random_bytes(size : Int32, mode : UInt32 = GPGME::RANDOM_MODE_NORMAL) : Bytes
      data = Data.empty!
      err = LibGPGME.op_random_bytes(@handle, size, mode)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      data.to_slice
    end

    def random_value(limit : UInt32) : UInt32
      LibGPGME.op_random_value(@handle, limit)
    end

    def inspect(io : IO)
      io << "#<GPGME::Ctx protocol=" << (PROTOCOL_NAMES[protocol]? || protocol.to_s)
      io << " armor=" << armor << " textmode=" << textmode
      io << " keylist_mode=" << (KEYLIST_MODE_NAMES[keylist_mode]? || keylist_mode.to_s)
      io << ">"
    end

    # Result builders

    private def build_decrypt_result(ptr : LibGPGME::DecryptResult) : DecryptResult
      recipients = [] of Recipient
      r = LibGPGME.cgpgme_decrypt_result_get_recipients(ptr)
      while r
        recipients << Recipient.new(
          GPGME.nullable_string(LibGPGME.cgpgme_recipient_get_keyid(r)),
          LibGPGME.cgpgme_recipient_get_pubkey_algo(r),
          LibGPGME.cgpgme_recipient_get_status(r)
        )
        r = LibGPGME.cgpgme_recipient_next(r)
      end

      DecryptResult.new(
        GPGME.nullable_string(LibGPGME.cgpgme_decrypt_result_get_unsupported_algorithm(ptr)),
        LibGPGME.cgpgme_decrypt_result_get_wrong_key_usage(ptr) != 0,
        recipients,
        GPGME.nullable_string(LibGPGME.cgpgme_decrypt_result_get_file_name(ptr))
      )
    end

    private def build_verify_result(ptr : LibGPGME::VerifyResult) : VerifyResult
      signatures = [] of Signature
      s = LibGPGME.cgpgme_verify_result_get_signatures(ptr)
      while s
        signatures << Signature.new(s)
        s = LibGPGME.cgpgme_signature_next(s)
      end

      VerifyResult.new(
        signatures,
        GPGME.nullable_string(LibGPGME.cgpgme_verify_result_get_file_name(ptr)),
        LibGPGME.cgpgme_verify_result_get_is_mime(ptr) != 0
      )
    end

    private def build_sign_result(ptr : LibGPGME::SignResult) : SignResult
      invalid = [] of InvalidKey
      ik = LibGPGME.cgpgme_sign_result_get_invalid_signers(ptr)
      while ik
        invalid << InvalidKey.new(
          GPGME.nullable_string(LibGPGME.cgpgme_invalid_key_get_fpr(ik)),
          LibGPGME.cgpgme_invalid_key_get_reason(ik)
        )
        ik = LibGPGME.cgpgme_invalid_key_next(ik)
      end

      sigs = [] of NewSignature
      ns = LibGPGME.cgpgme_sign_result_get_signatures(ptr)
      while ns
        ts = LibGPGME.cgpgme_newsig_get_timestamp(ns)
        sigs << NewSignature.new(
          LibGPGME.cgpgme_newsig_get_type(ns),
          LibGPGME.cgpgme_newsig_get_pubkey_algo(ns),
          LibGPGME.cgpgme_newsig_get_hash_algo(ns),
          LibGPGME.cgpgme_newsig_get_sig_class(ns),
          GPGME.nullable_string(LibGPGME.cgpgme_newsig_get_fpr(ns)),
          ts == 0 ? nil : Time.unix(ts.to_i64)
        )
        ns = LibGPGME.cgpgme_newsig_next(ns)
      end

      SignResult.new(invalid, sigs)
    end

    private def build_encrypt_result(ptr : LibGPGME::EncryptResult) : EncryptResult
      invalid = [] of InvalidKey
      ik = LibGPGME.cgpgme_encrypt_result_get_invalid_recipients(ptr)
      while ik
        invalid << InvalidKey.new(
          GPGME.nullable_string(LibGPGME.cgpgme_invalid_key_get_fpr(ik)),
          LibGPGME.cgpgme_invalid_key_get_reason(ik)
        )
        ik = LibGPGME.cgpgme_invalid_key_next(ik)
      end
      EncryptResult.new(invalid)
    end

    private def build_import_result(ptr : LibGPGME::ImportResult) : ImportResult
      imports = [] of ImportStatus
      st = LibGPGME.cgpgme_import_result_get_imports(ptr)
      while st
        imports << ImportStatus.new(
          GPGME.nullable_string(LibGPGME.cgpgme_import_status_get_fpr(st)),
          LibGPGME.cgpgme_import_status_get_result(st),
          LibGPGME.cgpgme_import_status_get_status(st)
        )
        st = LibGPGME.cgpgme_import_status_next(st)
      end

      ImportResult.new(
        LibGPGME.cgpgme_import_result_get_considered(ptr),
        LibGPGME.cgpgme_import_result_get_no_user_id(ptr),
        LibGPGME.cgpgme_import_result_get_imported(ptr),
        LibGPGME.cgpgme_import_result_get_imported_rsa(ptr),
        LibGPGME.cgpgme_import_result_get_unchanged(ptr),
        LibGPGME.cgpgme_import_result_get_new_user_ids(ptr),
        LibGPGME.cgpgme_import_result_get_new_sub_keys(ptr),
        LibGPGME.cgpgme_import_result_get_new_signatures(ptr),
        LibGPGME.cgpgme_import_result_get_new_revocations(ptr),
        LibGPGME.cgpgme_import_result_get_secret_read(ptr),
        LibGPGME.cgpgme_import_result_get_secret_imported(ptr),
        LibGPGME.cgpgme_import_result_get_secret_unchanged(ptr),
        LibGPGME.cgpgme_import_result_get_not_imported(ptr),
        imports
      )
    end

    # Default passphrase callback: writes the hook value as a line to fd.
    PASSPHRASE_CALLBACK = ->(hook : Void*, _uid_hint : LibC::Char*, _passphrase_info : LibC::Char*, _prev_was_bad : Int32, fd : Int32) : UInt32 {
      pass = String.new(hook.as(Pointer(LibC::Char)))
      line = "#{pass}\n"
      # Use direct C write to avoid closing the fd.
      LibC.write(fd, line.to_unsafe, line.bytesize)
      GPGME::GPG_ERR_NO_ERROR
    }
  end
end
