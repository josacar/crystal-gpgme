@[Link(ldflags: "#{__DIR__}/../ext/gpgme_helpers.o -lgpgme")]
lib LibGPGME
  # Opaque handle types
  type Ctx = Void*
  type Data = Void*
  type Key = Void*
  type SubKey = Void*
  type UserID = Void*
  type KeySig = Void*
  type EngineInfo = Void*
  type Recipient = Void*
  type DecryptResult = Void*
  type SignResult = Void*
  type EncryptResult = Void*
  type VerifyResult = Void*
  type NewSignature = Void*
  type Signature = Void*
  type InvalidKey = Void*
  type ImportStatus = Void*
  type ImportResult = Void*
  type SigNotation = Void*

  # Engine
  fun check_version = "gpgme_check_version"(req : LibC::Char*) : LibC::Char*
  fun engine_check_version = "gpgme_engine_check_version"(proto : Int32) : UInt32
  fun get_engine_info = "gpgme_get_engine_info"(info : EngineInfo*) : UInt32
  fun set_engine_info = "gpgme_set_engine_info"(proto : Int32, file_name : LibC::Char*, home_dir : LibC::Char*) : UInt32

  # Error
  fun err_code = "gpgme_err_code"(err : UInt32) : UInt32
  fun err_source = "gpgme_err_source"(err : UInt32) : UInt32
  fun cgpgme_strerror = "cgpgme_strerror"(err : UInt32) : LibC::Char*
  fun pubkey_algo_name = "gpgme_pubkey_algo_name"(algo : Int32) : LibC::Char*
  fun hash_algo_name = "gpgme_hash_algo_name"(algo : Int32) : LibC::Char*

  # Context
  fun new = "gpgme_new"(ctx : Ctx*) : UInt32
  fun release = "gpgme_release"(ctx : Ctx)
  fun set_ctx_flag = "gpgme_set_ctx_flag"(ctx : Ctx, name : LibC::Char*, value : LibC::Char*) : UInt32
  fun get_ctx_flag = "gpgme_get_ctx_flag"(ctx : Ctx, name : LibC::Char*) : LibC::Char*
  fun set_protocol = "gpgme_set_protocol"(ctx : Ctx, proto : UInt32) : UInt32
  fun get_protocol = "gpgme_get_protocol"(ctx : Ctx) : UInt32
  fun set_armor = "gpgme_set_armor"(ctx : Ctx, yes : Int32)
  fun get_armor = "gpgme_get_armor"(ctx : Ctx) : Int32
  fun set_textmode = "gpgme_set_textmode"(ctx : Ctx, yes : Int32)
  fun get_textmode = "gpgme_get_textmode"(ctx : Ctx) : Int32
  fun set_keylist_mode = "gpgme_set_keylist_mode"(ctx : Ctx, mode : UInt32) : UInt32
  fun get_keylist_mode = "gpgme_get_keylist_mode"(ctx : Ctx) : UInt32
  fun set_include_certs = "gpgme_set_include_certs"(ctx : Ctx, nr : Int32)
  fun get_include_certs = "gpgme_get_include_certs"(ctx : Ctx) : Int32
  fun set_pinentry_mode = "gpgme_set_pinentry_mode"(ctx : Ctx, mode : UInt32) : UInt32
  fun get_pinentry_mode = "gpgme_get_pinentry_mode"(ctx : Ctx) : UInt32
  fun set_offline = "gpgme_set_offline"(ctx : Ctx, yes : Int32)
  fun get_offline = "gpgme_get_offline"(ctx : Ctx) : Int32
  fun set_ignore_mdc_error = "gpgme_set_ignore_mdc_error"(ctx : Ctx, yes : Int32)
  fun get_ignore_mdc_error = "gpgme_get_ignore_mdc_error"(ctx : Ctx) : Int32
  fun ctx_get_engine_info = "gpgme_ctx_get_engine_info"(ctx : Ctx) : EngineInfo

  # Data
  fun data_new = "gpgme_data_new"(dh : Data*) : UInt32
  fun data_new_from_mem = "gpgme_data_new_from_mem"(dh : Data*, buffer : UInt8*, size : LibC::SizeT, copy : Int32) : UInt32
  fun data_new_from_fd = "gpgme_data_new_from_fd"(dh : Data*, fd : Int32) : UInt32
  fun data_release = "gpgme_data_release"(dh : Data)
  fun data_read = "gpgme_data_read"(dh : Data, buffer : UInt8*, size : LibC::SizeT) : LibC::SSizeT
  fun data_write = "gpgme_data_write"(dh : Data, buffer : UInt8*, size : LibC::SizeT) : LibC::SSizeT
  fun data_seek = "gpgme_data_seek"(dh : Data, offset : Int64, whence : Int32) : Int64
  fun data_get_encoding = "gpgme_data_get_encoding"(dh : Data) : UInt32
  fun data_set_encoding = "gpgme_data_set_encoding"(dh : Data, enc : UInt32) : UInt32
  fun data_get_file_name = "gpgme_data_get_file_name"(dh : Data) : LibC::Char*
  fun data_set_file_name = "gpgme_data_set_file_name"(dh : Data, file_name : LibC::Char*) : UInt32

  # Callback types
  alias PassphraseCb = (Void*, LibC::Char*, LibC::Char*, Int32, Int32) -> UInt32
  alias ProgressCb = (Void*, LibC::Char*, Int32, Int32, Int32) -> Void
  alias StatusCb = (Void*, LibC::Char*, LibC::Char*) -> UInt32

  fun set_passphrase_cb = "gpgme_set_passphrase_cb"(ctx : Ctx, cb : PassphraseCb, hook_value : Void*)
  fun set_progress_cb = "gpgme_set_progress_cb"(ctx : Ctx, cb : ProgressCb, hook_value : Void*)
  fun set_status_cb = "gpgme_set_status_cb"(ctx : Ctx, cb : StatusCb, hook_value : Void*)

  # Key listing
  fun op_keylist_start = "gpgme_op_keylist_start"(ctx : Ctx, pattern : LibC::Char*, secret_only : Int32) : UInt32
  fun op_keylist_next = "gpgme_op_keylist_next"(ctx : Ctx, key : Key*) : UInt32
  fun op_keylist_end = "gpgme_op_keylist_end"(ctx : Ctx) : UInt32
  fun get_key = "gpgme_get_key"(ctx : Ctx, fpr : LibC::Char*, key : Key*, secret : Int32) : UInt32
  fun key_ref = "gpgme_key_ref"(key : Key)
  fun key_unref = "gpgme_key_unref"(key : Key)

  # Import / export
  fun op_import = "gpgme_op_import"(ctx : Ctx, keydata : Data) : UInt32
  fun op_import_result = "gpgme_op_import_result"(ctx : Ctx) : ImportResult
  fun op_export = "gpgme_op_export"(ctx : Ctx, pattern : LibC::Char*, mode : UInt32, keydata : Data) : UInt32

  # Key generation / deletion
  fun op_genkey = "gpgme_op_genkey"(ctx : Ctx, parms : LibC::Char*, pubkey : Data, seckey : Data) : UInt32
  fun op_delete = "gpgme_op_delete"(ctx : Ctx, key : Key, allow_secret : Int32) : UInt32

  # Crypto
  fun op_encrypt = "gpgme_op_encrypt"(ctx : Ctx, recp : Key*, flags : UInt32, plain : Data, cipher : Data) : UInt32
  fun op_encrypt_sign = "gpgme_op_encrypt_sign"(ctx : Ctx, recp : Key*, flags : UInt32, plain : Data, cipher : Data) : UInt32
  fun op_encrypt_result = "gpgme_op_encrypt_result"(ctx : Ctx) : EncryptResult
  fun op_decrypt = "gpgme_op_decrypt"(ctx : Ctx, cipher : Data, plain : Data) : UInt32
  fun op_decrypt_verify = "gpgme_op_decrypt_verify"(ctx : Ctx, cipher : Data, plain : Data) : UInt32
  fun op_decrypt_result = "gpgme_op_decrypt_result"(ctx : Ctx) : DecryptResult
  fun op_sign = "gpgme_op_sign"(ctx : Ctx, plain : Data, sig : Data, mode : UInt32) : UInt32
  fun op_sign_result = "gpgme_op_sign_result"(ctx : Ctx) : SignResult
  fun op_verify = "gpgme_op_verify"(ctx : Ctx, sig : Data, signed_text : Data, plain : Data) : UInt32
  fun op_verify_result = "gpgme_op_verify_result"(ctx : Ctx) : VerifyResult
  fun signers_clear = "gpgme_signers_clear"(ctx : Ctx)
  fun signers_add = "gpgme_signers_add"(ctx : Ctx, key : Key) : UInt32

  # Random (GPGME 2.0+)
  fun op_random_bytes = "gpgme_op_random_bytes"(ctx : Ctx, size : LibC::SizeT, mode : UInt32) : UInt32
  fun op_random_value = "gpgme_op_random_value"(ctx : Ctx, limit : UInt32) : UInt32

  # Directory info
  fun get_dirinfo = "gpgme_get_dirinfo"(what : LibC::Char*) : LibC::Char*

  # Engine info helpers
  fun cgpgme_engine_info_next = "cgpgme_engine_info_next"(info : EngineInfo) : EngineInfo
  fun cgpgme_engine_info_protocol = "cgpgme_engine_info_protocol"(info : EngineInfo) : Int32
  fun cgpgme_engine_info_file_name = "cgpgme_engine_info_file_name"(info : EngineInfo) : LibC::Char*
  fun cgpgme_engine_info_version = "cgpgme_engine_info_version"(info : EngineInfo) : LibC::Char*
  fun cgpgme_engine_info_req_version = "cgpgme_engine_info_req_version"(info : EngineInfo) : LibC::Char*
  fun cgpgme_engine_info_home_dir = "cgpgme_engine_info_home_dir"(info : EngineInfo) : LibC::Char*

  # Key helpers
  fun cgpgme_key_get_revoked = "cgpgme_key_get_revoked"(key : Key) : Int32
  fun cgpgme_key_get_expired = "cgpgme_key_get_expired"(key : Key) : Int32
  fun cgpgme_key_get_disabled = "cgpgme_key_get_disabled"(key : Key) : Int32
  fun cgpgme_key_get_invalid = "cgpgme_key_get_invalid"(key : Key) : Int32
  fun cgpgme_key_get_can_encrypt = "cgpgme_key_get_can_encrypt"(key : Key) : Int32
  fun cgpgme_key_get_can_sign = "cgpgme_key_get_can_sign"(key : Key) : Int32
  fun cgpgme_key_get_can_certify = "cgpgme_key_get_can_certify"(key : Key) : Int32
  fun cgpgme_key_get_secret = "cgpgme_key_get_secret"(key : Key) : Int32
  fun cgpgme_key_get_can_authenticate = "cgpgme_key_get_can_authenticate"(key : Key) : Int32
  fun cgpgme_key_get_protocol = "cgpgme_key_get_protocol"(key : Key) : Int32
  fun cgpgme_key_get_owner_trust = "cgpgme_key_get_owner_trust"(key : Key) : Int32
  fun cgpgme_key_get_keylist_mode = "cgpgme_key_get_keylist_mode"(key : Key) : UInt32
  fun cgpgme_key_get_issuer_serial = "cgpgme_key_get_issuer_serial"(key : Key) : LibC::Char*
  fun cgpgme_key_get_issuer_name = "cgpgme_key_get_issuer_name"(key : Key) : LibC::Char*
  fun cgpgme_key_get_chain_id = "cgpgme_key_get_chain_id"(key : Key) : LibC::Char*
  fun cgpgme_key_get_fpr = "cgpgme_key_get_fpr"(key : Key) : LibC::Char*
  fun cgpgme_key_get_subkeys = "cgpgme_key_get_subkeys"(key : Key) : SubKey
  fun cgpgme_key_get_uids = "cgpgme_key_get_uids"(key : Key) : UserID

  # Subkey helpers
  fun cgpgme_subkey_get_revoked = "cgpgme_subkey_get_revoked"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_expired = "cgpgme_subkey_get_expired"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_disabled = "cgpgme_subkey_get_disabled"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_invalid = "cgpgme_subkey_get_invalid"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_can_encrypt = "cgpgme_subkey_get_can_encrypt"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_can_sign = "cgpgme_subkey_get_can_sign"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_can_certify = "cgpgme_subkey_get_can_certify"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_can_authenticate = "cgpgme_subkey_get_can_authenticate"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_secret = "cgpgme_subkey_get_secret"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_pubkey_algo = "cgpgme_subkey_get_pubkey_algo"(sk : SubKey) : Int32
  fun cgpgme_subkey_get_length = "cgpgme_subkey_get_length"(sk : SubKey) : UInt32
  fun cgpgme_subkey_get_timestamp = "cgpgme_subkey_get_timestamp"(sk : SubKey) : UInt64
  fun cgpgme_subkey_get_expires = "cgpgme_subkey_get_expires"(sk : SubKey) : UInt64
  fun cgpgme_subkey_get_keyid = "cgpgme_subkey_get_keyid"(sk : SubKey) : LibC::Char*
  fun cgpgme_subkey_get_fpr = "cgpgme_subkey_get_fpr"(sk : SubKey) : LibC::Char*
  fun cgpgme_subkey_get_curve = "cgpgme_subkey_get_curve"(sk : SubKey) : LibC::Char*
  fun cgpgme_subkey_next = "cgpgme_subkey_next"(sk : SubKey) : SubKey

  # User ID helpers
  fun cgpgme_uid_get_revoked = "cgpgme_uid_get_revoked"(uid : UserID) : Int32
  fun cgpgme_uid_get_invalid = "cgpgme_uid_get_invalid"(uid : UserID) : Int32
  fun cgpgme_uid_get_validity = "cgpgme_uid_get_validity"(uid : UserID) : Int32
  fun cgpgme_uid_get_uid = "cgpgme_uid_get_uid"(uid : UserID) : LibC::Char*
  fun cgpgme_uid_get_name = "cgpgme_uid_get_name"(uid : UserID) : LibC::Char*
  fun cgpgme_uid_get_email = "cgpgme_uid_get_email"(uid : UserID) : LibC::Char*
  fun cgpgme_uid_get_comment = "cgpgme_uid_get_comment"(uid : UserID) : LibC::Char*
  fun cgpgme_uid_get_signatures = "cgpgme_uid_get_signatures"(uid : UserID) : KeySig
  fun cgpgme_uid_next = "cgpgme_uid_next"(uid : UserID) : UserID

  # KeySig helpers
  fun cgpgme_keysig_get_revoked = "cgpgme_keysig_get_revoked"(ks : KeySig) : Int32
  fun cgpgme_keysig_get_expired = "cgpgme_keysig_get_expired"(ks : KeySig) : Int32
  fun cgpgme_keysig_get_invalid = "cgpgme_keysig_get_invalid"(ks : KeySig) : Int32
  fun cgpgme_keysig_get_exportable = "cgpgme_keysig_get_exportable"(ks : KeySig) : Int32
  fun cgpgme_keysig_get_pubkey_algo = "cgpgme_keysig_get_pubkey_algo"(ks : KeySig) : Int32
  fun cgpgme_keysig_get_timestamp = "cgpgme_keysig_get_timestamp"(ks : KeySig) : UInt64
  fun cgpgme_keysig_get_expires = "cgpgme_keysig_get_expires"(ks : KeySig) : UInt64
  fun cgpgme_keysig_get_keyid = "cgpgme_keysig_get_keyid"(ks : KeySig) : LibC::Char*
  fun cgpgme_keysig_next = "cgpgme_keysig_next"(ks : KeySig) : KeySig

  # Signature helpers
  fun cgpgme_signature_get_summary = "cgpgme_signature_get_summary"(sig : Signature) : UInt32
  fun cgpgme_signature_get_status = "cgpgme_signature_get_status"(sig : Signature) : UInt32
  fun cgpgme_signature_get_timestamp = "cgpgme_signature_get_timestamp"(sig : Signature) : UInt64
  fun cgpgme_signature_get_exp_timestamp = "cgpgme_signature_get_exp_timestamp"(sig : Signature) : UInt64
  fun cgpgme_signature_get_wrong_key_usage = "cgpgme_signature_get_wrong_key_usage"(sig : Signature) : Int32
  fun cgpgme_signature_get_pka_trust = "cgpgme_signature_get_pka_trust"(sig : Signature) : Int32
  fun cgpgme_signature_get_validity = "cgpgme_signature_get_validity"(sig : Signature) : Int32
  fun cgpgme_signature_get_validity_reason = "cgpgme_signature_get_validity_reason"(sig : Signature) : UInt32
  fun cgpgme_signature_get_pubkey_algo = "cgpgme_signature_get_pubkey_algo"(sig : Signature) : Int32
  fun cgpgme_signature_get_hash_algo = "cgpgme_signature_get_hash_algo"(sig : Signature) : Int32
  fun cgpgme_signature_get_fpr = "cgpgme_signature_get_fpr"(sig : Signature) : LibC::Char*
  fun cgpgme_signature_get_pka_address = "cgpgme_signature_get_pka_address"(sig : Signature) : LibC::Char*
  fun cgpgme_signature_get_key = "cgpgme_signature_get_key"(sig : Signature) : Key
  fun cgpgme_signature_next = "cgpgme_signature_next"(sig : Signature) : Signature

  # Decrypt result helpers
  fun cgpgme_decrypt_result_get_unsupported_algorithm = "cgpgme_decrypt_result_get_unsupported_algorithm"(res : DecryptResult) : LibC::Char*
  fun cgpgme_decrypt_result_get_wrong_key_usage = "cgpgme_decrypt_result_get_wrong_key_usage"(res : DecryptResult) : Int32
  fun cgpgme_decrypt_result_get_file_name = "cgpgme_decrypt_result_get_file_name"(res : DecryptResult) : LibC::Char*
  fun cgpgme_decrypt_result_get_recipients = "cgpgme_decrypt_result_get_recipients"(res : DecryptResult) : Recipient

  # Recipient helpers
  fun cgpgme_recipient_get_keyid = "cgpgme_recipient_get_keyid"(rec : Recipient) : LibC::Char*
  fun cgpgme_recipient_get_pubkey_algo = "cgpgme_recipient_get_pubkey_algo"(rec : Recipient) : Int32
  fun cgpgme_recipient_get_status = "cgpgme_recipient_get_status"(rec : Recipient) : UInt32
  fun cgpgme_recipient_next = "cgpgme_recipient_next"(rec : Recipient) : Recipient

  # Sign result helpers
  fun cgpgme_sign_result_get_invalid_signers = "cgpgme_sign_result_get_invalid_signers"(res : SignResult) : InvalidKey
  fun cgpgme_sign_result_get_signatures = "cgpgme_sign_result_get_signatures"(res : SignResult) : NewSignature

  # New signature helpers
  fun cgpgme_newsig_get_type = "cgpgme_newsig_get_type"(ns : NewSignature) : Int32
  fun cgpgme_newsig_get_pubkey_algo = "cgpgme_newsig_get_pubkey_algo"(ns : NewSignature) : Int32
  fun cgpgme_newsig_get_hash_algo = "cgpgme_newsig_get_hash_algo"(ns : NewSignature) : Int32
  fun cgpgme_newsig_get_sig_class = "cgpgme_newsig_get_sig_class"(ns : NewSignature) : UInt32
  fun cgpgme_newsig_get_timestamp = "cgpgme_newsig_get_timestamp"(ns : NewSignature) : UInt64
  fun cgpgme_newsig_get_fpr = "cgpgme_newsig_get_fpr"(ns : NewSignature) : LibC::Char*
  fun cgpgme_newsig_next = "cgpgme_newsig_next"(ns : NewSignature) : NewSignature

  # Encrypt result helpers
  fun cgpgme_encrypt_result_get_invalid_recipients = "cgpgme_encrypt_result_get_invalid_recipients"(res : EncryptResult) : InvalidKey

  # Invalid key helpers
  fun cgpgme_invalid_key_get_fpr = "cgpgme_invalid_key_get_fpr"(ik : InvalidKey) : LibC::Char*
  fun cgpgme_invalid_key_get_reason = "cgpgme_invalid_key_get_reason"(ik : InvalidKey) : UInt32
  fun cgpgme_invalid_key_next = "cgpgme_invalid_key_next"(ik : InvalidKey) : InvalidKey

  # Verify result helpers
  fun cgpgme_verify_result_get_signatures = "cgpgme_verify_result_get_signatures"(res : VerifyResult) : Signature
  fun cgpgme_verify_result_get_file_name = "cgpgme_verify_result_get_file_name"(res : VerifyResult) : LibC::Char*
  fun cgpgme_verify_result_get_is_mime = "cgpgme_verify_result_get_is_mime"(res : VerifyResult) : Int32

  # Import result helpers
  fun cgpgme_import_result_get_considered = "cgpgme_import_result_get_considered"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_no_user_id = "cgpgme_import_result_get_no_user_id"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_imported = "cgpgme_import_result_get_imported"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_imported_rsa = "cgpgme_import_result_get_imported_rsa"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_unchanged = "cgpgme_import_result_get_unchanged"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_new_user_ids = "cgpgme_import_result_get_new_user_ids"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_new_sub_keys = "cgpgme_import_result_get_new_sub_keys"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_new_signatures = "cgpgme_import_result_get_new_signatures"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_new_revocations = "cgpgme_import_result_get_new_revocations"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_secret_read = "cgpgme_import_result_get_secret_read"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_secret_imported = "cgpgme_import_result_get_secret_imported"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_secret_unchanged = "cgpgme_import_result_get_secret_unchanged"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_not_imported = "cgpgme_import_result_get_not_imported"(res : ImportResult) : Int32
  fun cgpgme_import_result_get_imports = "cgpgme_import_result_get_imports"(res : ImportResult) : ImportStatus

  # Import status helpers
  fun cgpgme_import_status_get_fpr = "cgpgme_import_status_get_fpr"(st : ImportStatus) : LibC::Char*
  fun cgpgme_import_status_get_result = "cgpgme_import_status_get_result"(st : ImportStatus) : UInt32
  fun cgpgme_import_status_get_status = "cgpgme_import_status_get_status"(st : ImportStatus) : UInt32
  fun cgpgme_import_status_next = "cgpgme_import_status_next"(st : ImportStatus) : ImportStatus
end
