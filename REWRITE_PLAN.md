# crystal-gpgme Rewrite Plan

This document outlines the steps to rewrite the [ruby-gpgme](https://github.com/ueno/ruby-gpgme) bindings for the Crystal language, preserving the public API semantics and behavior as much as possible.

## 1. Goals and Non-Goals

### Goals
- Provide a Crystal shard named `crystal-gpgme` that wraps `libgpgme`.
- Mimic the Ruby public API (modules, classes, method names, options hashes become named args/hashes).
- Support high-level crypto operations: encrypt, decrypt, sign, verify.
- Support mid-level `GPGME::Ctx` and `GPGME::Data` APIs.
- Support key management: find, import, export, delete, get.
- Support engine configuration and error handling.
- Port or rewrite the Ruby test suite to Crystal specs.

### Non-Goals
- 100% parity with every low-level C function on day one (some advanced/async operations can be added later).
- Re-implementing GPGME itself; we bind to the system library.
- Maintaining the Ruby C extension; we replace it with Crystal `lib` bindings.

## 2. Project Structure

```
crystal-gpgme/
├── shard.yml                 # Shard metadata + dependencies
├── README.md                 # Usage adapted from ruby-gpgme README
├── REWRITE_PLAN.md           # This file
├── src/
│   ├── gpgme.cr              # Main entry point (module setup, version)
│   ├── gpgme/
│   │   ├── lib_gpgme.cr      # Crystal C bindings (lib LibGPGME)
│   │   ├── constants.cr      # GPGME_* constants and lookup hashes
│   │   ├── error.cr          # Exception hierarchy and error conversion
│   │   ├── data.cr           # GPGME::Data wrapper
│   │   ├── ctx.cr            # GPGME::Ctx mid-level API
│   │   ├── crypto.cr         # GPGME::Crypto high-level API
│   │   ├── key.cr            # GPGME::Key + class methods
│   │   ├── key_common.cr     # Shared key capabilities/trust logic
│   │   ├── sub_key.cr        # GPGME::SubKey
│   │   ├── user_id.cr        # GPGME::UserID
│   │   ├── key_sig.cr        # GPGME::KeySig
│   │   ├── signature.cr      # GPGME::Signature
│   │   ├── engine.cr         # GPGME::Engine + EngineInfo
│   │   ├── misc.cr           # Result structs (VerifyResult, etc.)
│   │   └── io_callbacks.cr   # IO callback adapter
│   └── ext/                  # Optional helper if native code needed
│       └── .gitkeep
└── spec/
    ├── spec_helper.cr        # Test helpers, key import, cleanup
    ├── support/
    │   └── resources.cr      # Test keys and text fixtures
    ├── gpgme_spec.cr
    ├── data_spec.cr
    ├── ctx_spec.cr
    ├── crypto_spec.cr
    ├── key_spec.cr
    └── engine_spec.cr
```

## 3. Technology Choices

- **Crystal 1.20+**: use explicit types, `lib` for C bindings, `Pointer` for opaque handles.
- **C bindings**: map `gpgme_data_t`, `gpgme_ctx_t`, `gpgme_key_t` as `Void*` or forward-declared struct pointers.
- **Memory management**: rely on GPGME reference counting and Crystal finalizers (`finalize`) for `Data`, `Ctx`, `Key`.
- **Thread safety**: Crystal uses fibers, not OS threads by default. Serialize access with a `Mutex` or `Monitor` equivalent when calling into GPGME from multiple fibers (mimics Ruby's `Monitor`).
- **Error handling**: map GPGME error codes to a `GPGME::Error` exception hierarchy matching Ruby.

## 4. Binding Strategy

Create `src/gpgme/lib_gpgme.cr` with a `lib LibGPGME` block. Example functions to bind:

```crystal
lib LibGPGME
  type Ctx = Void*
  type Data = Void*
  type Key = Void*

  fun check_version(req : LibC::Char*) : LibC::Char*
  fun engine_check_version(proto : Int32) : UInt32
  fun new(ctx : Ctx*) : UInt32
  fun release(ctx : Ctx)
  fun data_new(dh : Data*) : UInt32
  fun data_new_from_mem(dh : Data*, buffer : UInt8*, size : LibC::SizeT, copy : Int32) : UInt32
  fun data_release(dh : Data)
  fun data_read(dh : Data, buffer : UInt8*, size : LibC::SizeT) : LibC::SSizeT
  fun data_write(dh : Data, buffer : UInt8*, size : LibC::SizeT) : LibC::SSizeT
  fun data_seek(dh : Data, offset : Int64, whence : Int32) : Int64
  fun set_armor(ctx : Ctx, yes : Int32)
  fun get_armor(ctx : Ctx) : Int32
  fun set_textmode(ctx : Ctx, yes : Int32)
  fun get_textmode(ctx : Ctx) : Int32
  fun set_keylist_mode(ctx : Ctx, mode : UInt32) : UInt32
  fun get_keylist_mode(ctx : Ctx) : UInt32
  fun set_protocol(ctx : Ctx, proto : UInt32) : UInt32
  fun get_protocol(ctx : Ctx) : UInt32
  fun op_keylist_start(ctx : Ctx, pattern : LibC::Char*, secret_only : Int32) : UInt32
  fun op_keylist_next(ctx : Ctx, key : Key*) : UInt32
  fun op_keylist_end(ctx : Ctx) : UInt32
  fun get_key(ctx : Ctx, fpr : LibC::Char*, key : Key*, secret : Int32) : UInt32
  fun key_ref(key : Key)
  fun key_unref(key : Key)
  fun op_export(ctx : Ctx, pattern : LibC::Char*, mode : UInt32, keydata : Data) : UInt32
  fun op_import(ctx : Ctx, keydata : Data) : UInt32
  fun op_import_result(ctx : Ctx) : ImportResult*
  fun op_delete(ctx : Ctx, key : Key, allow_secret : Int32) : UInt32
  fun op_encrypt(ctx : Ctx, recp : Key*, flags : UInt32, plain : Data, cipher : Data) : UInt32
  fun op_encrypt_sign(ctx : Ctx, recp : Key*, flags : UInt32, plain : Data, cipher : Data) : UInt32
  fun op_decrypt(ctx : Ctx, cipher : Data, plain : Data) : UInt32
  fun op_decrypt_verify(ctx : Ctx, cipher : Data, plain : Data) : UInt32
  fun op_verify(ctx : Ctx, sig : Data, signed_text : Data, plain : Data) : UInt32
  fun op_sign(ctx : Ctx, plain : Data, sig : Data, mode : UInt32) : UInt32
  fun signers_clear(ctx : Ctx)
  fun signers_add(ctx : Ctx, key : Key) : UInt32
  fun pubkey_algo_name(algo : Int32) : LibC::Char*
  fun hash_algo_name(algo : Int32) : LibC::Char*
  fun strerror(err : UInt32) : LibC::Char*
  fun err_code(err : UInt32) : UInt32
  fun err_source(err : UInt32) : UInt32
  # ... additional functions as needed
end
```

## 5. API Mapping

### Module-level setup
- `GPGME::VERSION`: shard version string.
- `GPGME.thread_safe?` / `GPGME.thread_safe=` / `GPGME.synchronize { ... }`: global mutex wrapper.
- `GPGME.error_to_exception(err)`: convert GPGME error code to typed exception.
- `GPGME.check_version(options)`: wrapper around `gpgme_check_version`.

### `GPGME::Error`
Base exception with `code`, `source`, `message`, and subclasses:
`General`, `InvalidValue`, `UnusablePublicKey`, `UnusableSecretKey`, `NoData`,
`Conflict`, `NotImplemented`, `DecryptFailed`, `BadPassphrase`, `Canceled`,
`InvalidEngine`, `AmbiguousName`, `WrongKeyUsage`, `CertificateRevoked`,
`CertificateExpired`, `NoCRLKnown`, `NoPolicyMatch`, `NoSecretKey`,
`MissingCertificate`, `BadCertificateChain`, `UnsupportedAlgorithm`,
`BadSignature`, `NoPublicKey`, `InvalidVersion`, `EOFError`.

### `GPGME::Data`
- `Data.new(object)` polymorphic constructor accepting `nil`, `Data`, `String`, `IO`, `FileDescriptor` (Int32).
- `Data.empty!`, `Data.from_str`, `Data.from_io`, `Data.from_fd`.
- `read(length = nil)`, `write(buffer, length)`, `seek(offset, whence)`.
- `encoding`, `encoding=`, `file_name`, `file_name=`, `to_s`.

### `GPGME::Ctx`
- Block-based constructor releasing context automatically.
- Getters/setters: `protocol`, `armor`, `textmode`, `keylist_mode`, `pinentry_mode`, `offline`, `ignore_mdc_error`, `include_certs`.
- Callback setters: passphrase, progress, status (defer full proc support; use fun pointers where possible).
- Key operations: `keylist_start`, `keylist_next`, `keylist_end`, `each_key`, `keys`, `get_key`.
- Import/export/generate/delete/edit.
- Crypto: `encrypt`, `encrypt_sign`, `decrypt`, `decrypt_verify`, `sign`, `verify`, `clear_signers`, `add_signer`.
- Results: `encrypt_result`, `decrypt_result`, `sign_result`, `verify_result`, `import_result`.

### `GPGME::Crypto`
- `encrypt(plain, options = Hash(String, typeof(...)).new)` with `recipients`, `symmetric`, `always_trust`, `sign`, `signers`, `output`.
- `decrypt(cipher, options = ...)` with `output`, `password`, signature block.
- `sign(text, options = ...)` with `signer`, `mode`, `output`.
- `verify(sig, options = ...)` with `signed_text`, `output`, signature block.
- `clearsign`, `detach_sign`.
- Class-level `method_missing` equivalent: forward to a default instance where practical.

### `GPGME::Key`
- `Key.find(secret, keys_or_names = nil, purposes = [] of Symbol)`.
- `Key.get(fingerprint)`, `Key.export(pattern, options)`, `Key.import(keydata, options)`, `Key.valid?(key)`.
- Instance: `export(options)`, `delete!(allow_secret, force)`, `primary_subkey`, `primary_uid`, `fingerprint`, `sha`, `email`, `name`, `comment`, `expired?`, `expires`, `trust`, `capability`, `usable_for?`.

### Helper classes
- `SubKey`, `UserID`, `KeySig`, `Signature`, `EngineInfo`, result structs.
- Map C structs to Crystal structs/classes and copy attributes after each C call.

## 6. Implementation Phases

### Phase 0: Bootstrap
1. Create `shard.yml` with name, version, authors, license.
2. Add `.gitignore` and `README.md`.
3. Verify `gpgme.h` and `libgpgme` are available on the system.

### Phase 1: Core C Bindings
1. Write `src/gpgme/lib_gpgme.cr` covering the most-used functions.
2. Add compile-time `Link` flags: `@Link("gpgme")`.
3. Verify the shard compiles: `crystal build src/gpgme.cr`.

### Phase 2: Constants and Errors
1. Port `constants.rb` to `constants.cr`.
2. Implement `error.cr` and `error_to_exception`.

### Phase 3: Data and Ctx
1. Implement `Data` wrapper with memory management.
2. Implement `Ctx` wrapper and block constructor.
3. Add basic setters/getters.

### Phase 4: Key Management
1. Implement `Key`, `SubKey`, `UserID`, `KeySig`, `KeyCommon`.
2. Implement `Ctx#each_key`, `Ctx#keys`, `Ctx#get_key`.
3. Implement `Key.find`, `Key.get`, `Key.import`, `Key.export`.

### Phase 5: Crypto High-Level API
1. Implement `Crypto#encrypt`, `#decrypt`, `#sign`, `#verify`, `#clearsign`, `#detach_sign`.
2. Implement `Ctx` crypto operations used by `Crypto`.

### Phase 6: Engine and Misc
1. Implement `Engine` module and `EngineInfo`.
2. Implement result structs (`VerifyResult`, `DecryptResult`, etc.).

### Phase 7: Testing
1. Port test fixtures from `ruby-gpgme/test/files` and `support/resources.rb`.
2. Create `spec_helper.cr` with isolated GPG home directory and key import helpers.
3. Write specs mirroring Ruby tests: `crypto_spec`, `ctx_spec`, `data_spec`, `key_spec`, `engine_spec`.
4. Run `crystal spec` and iterate.

### Phase 8: Polish
1. Run `crystal tool format`.
2. Add Ameba as a dev dependency and lint.
3. Add GitHub Actions CI workflow.
4. Commit and tag initial release.

## 7. Testing Strategy

- Use a temporary GPG home directory for each spec run.
- Import the same test keys used by ruby-gpgme (`testkey_pub.gpg`, `testkey_sec.gpg`).
- Write specs covering:
  - Data creation/read/write/seek.
  - Key find, import, export, delete.
  - Encrypt/decrypt round trip (asymmetric and symmetric).
  - Sign/verify round trip and detached signatures.
  - Error cases: missing key, untrusted recipient, bad signature.
- Skip tests that require unavailable engines (e.g., CMS).

## 8. Compatibility Notes

- Ruby `options = {}` becomes Crystal `Hash(String, T)` or named arguments.
- Ruby duck typing (`respond_to?`) becomes explicit union types or overloads.
- Ruby blocks are Crystal blocks; callback C function pointers require static fun pointers.
- Ruby `IO` objects map to Crystal `IO`.
- Ruby `Time.at` maps to Crystal `Time.unix`.
- Ruby symbols for capabilities (`:encrypt`, `:sign`) are kept as Crystal `Symbol`.

## 9. Open Questions / Risks

- Callbacks (passphrase/progress/status) need stable C fun pointers; in Crystal these are usually module-level funs or closures stored in a registry.
- Thread/fiber safety with `gpg-agent` may require a global mutex.
- GPGME version differences may change struct layouts; target GPGME 1.21+ / 2.0+.
- Some functions may not be available in all GPGME versions; guard with `{% if LibGPGME.has_method?(...) %}` where appropriate.

## 10. First Steps

1. Land this plan and bootstrap files.
2. Implement `lib_gpgme.cr` and constants.
3. Get `GPGME.check_version` and `Engine.info` working.
4. Build up `Data`, `Ctx`, `Key`, then `Crypto`.
5. Add tests after each layer.
