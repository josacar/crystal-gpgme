# Agent Guide for crystal-gpgme

This is a Crystal shard that provides bindings to GPGME (GnuPG Made Easy), API-compatible with [ruby-gpgme](https://github.com/ueno/ruby-gpgme). It wraps `libgpgme` directly and ships a small C helper for struct fields Crystal cannot represent.

## Project Essentials

### Requirements
- Crystal 1.10+ (tested on 1.20.2)
- GPGME 1.21+ / 2.0+ installed on the system (`libgpgme` + headers)
- `pkg-config` (used by `Makefile` to locate GPGME flags)

### Standard Commands

```sh
# Install shards and build the C helper (postinstall runs `make`)
shards install

# Build the helper object manually (only needed if src/ext/gpgme_helpers.c changes)
make

# Run the test suite
make && crystal spec

# Run the linter
bin/ameba

# Format code
crystal tool format
```

### Build / Link Details

The shard links against the system `gpgme` library and a compiled helper object:

- `src/ext/gpgme_helpers.c` is compiled by `Makefile` into `src/ext/gpgme_helpers.o`.
- `src/gpgme/lib_gpgme.cr` declares the link line: `@[Link(ldflags: "#{__DIR__}/../ext/gpgme_helpers.o -lgpgme")]`.
- `shard.yml` has `scripts: { postinstall: make }`, so `shards install` builds the helper automatically.

**Gotcha:** If you move the source tree or build on a fresh checkout, ensure `src/ext/gpgme_helpers.o` exists. A missing object file causes linker errors, not compiler errors.

## Architecture

### Layering

The code is organized in three API layers over one C binding layer:

1. **Low-level C bindings** — `src/gpgme/lib_gpgme.cr` (`lib LibGPGME`).
   - Exposes C functions, opaque handles (`Ctx`, `Data`, `Key`, etc.), and callback types.
   - All handles are typed as `Void*` aliases.
   - Many GPGME structs are accessed through C helper functions (`cgpgme_*`) because Crystal cannot represent C bitfields directly.

2. **Mid-level wrappers** — `src/gpgme/ctx.cr`, `data.cr`, `key.cr`, etc.
   - `GPGME::Ctx` wraps a `gpgme_ctx_t`, owns its lifetime, and exposes key listing, crypto operations, and result builders.
   - `GPGME::Data` wraps `gpgme_data_t` and is used for all plaintext/ciphertext buffers.
   - `GPGME::Key` (plus `SubKey`, `UserID`, `KeySig`) mirrors GPGME key structures and is populated once at construction by walking C linked lists.

3. **High-level API** — `src/gpgme/crypto.cr`.
   - `GPGME::Crypto` provides `encrypt`, `decrypt`, `sign`, `verify`, `clearsign`, `detach_sign` with options hashes.
   - Class-level methods (`Crypto.encrypt`, etc.) delegate to a default instance.

### Control / Data Flow

- `require "gpgme"` loads `src/gpgme.cr`, which calls `LibGPGME.check_version(nil)` at module load time and sets up a global `Mutex`.
- Most operations create a `GPGME::Ctx` via the block form: `Ctx.new { |ctx| ... }`.
  - The block form automatically wraps the body in `GPGME.synchronize` and releases the context in `ensure`.
  - Do not release the context yourself inside the block.
- `GPGME::Data` objects are accepted/returned by nearly every crypto method. They behave like seekable IO buffers backed by GPGME.
- Errors from GPGME are returned as `UInt32` error codes. Almost every wrapper calls `GPGME.error_to_exception(err)` and raises a typed `GPGME::Error` subclass if non-zero.

### Thread Safety

- `GPGME.thread_safe?` / `GPGME.thread_safe=` control whether all block-based `Ctx` operations are serialized through a module-level `Mutex`.
- Default is `true`. This mimics ruby-gpgme's `Monitor` behavior because operations that talk to `gpg-agent` must not overlap.
- If you add an operation that bypasses `Ctx.new(&block)`, wrap it in `GPGME.synchronize { ... }` unless it is explicitly safe.

## Code Conventions

### Style
- Run `crystal tool format` before committing.
- Run `bin/ameba` after changes; the project requires a clean lint.
- Method parameters usually have explicit type restrictions; return types are explicit where helpful.

### Constants
- GPGME constants live in `src/gpgme/constants.cr` and are mostly `UInt32`.
- They are intentionally not Ruby-style `SCREAMING_SNAKE` in some places; `.ameba.yml` excludes `src/gpgme/constants.cr` from `Naming/ConstantNames`.

### Options Hashes
- High-level methods accept `Hash(String, OptionValue)`.
- `GPGME::OptionValue` is defined in `src/gpgme.cr` as a union of `String | UInt32 | Int32 | Bool | Symbol | Key | Array(String | Key) | Data | IO | Nil`.
- Options are merged with `Crypto#default_options` in `GPGME::Crypto`.

### Booleans vs. C Ints
- GPGME C getters return `Int32` (0/1). Wrappers convert to `Bool` with `== 1`.
- C setters take `Int32` (0/1). Wrappers pass `yes ? 1 : 0`.

### Key / SubKey / UserID Construction
- `Key.new(handle)` eagerly walks the `subkeys` and `uids` linked lists from C and copies attributes into Crystal objects.
- These objects are snapshots. If a key is modified in the keyring, create a fresh `Key` instance.

## Important Gotchas

### C Bitfields Require the Helper Library
Crystal's `lib` bindings cannot map C bitfields. Any GPGME struct field that is a bitfield (e.g., many `*_get_*` flags) is exposed via accessor functions in `src/ext/gpgme_helpers.c`. If you add a new bitfield accessor:

1. Add the C helper function in `src/ext/gpgme_helpers.c`.
2. Re-run `make`.
3. Declare the `fun` in `src/gpgme/lib_gpgme.cr`.
4. Use it from the Crystal wrapper.

### `EOFError` Is Expected in Key Listing
`Ctx#keylist_next` raises `GPGME::EOFError` when no more keys are available. `Ctx#each_key` rescues it to terminate iteration. If you call `keylist_next` directly, handle `GPGME::EOFError` or use `Ctx#keys`.

### IO Is Not Fully Streaming
`Data.from_io` currently reads the entire IO into a memory-backed `GPGME::Data` object. A true callback-based IO adapter exists only as a stub in `src/gpgme/io_callbacks.cr` and is not wired into `Data.new(IO)`.

### Passphrase Handling
- The default passphrase callback (`Ctx::PASSPHRASE_CALLBACK`) writes the provided password string to the file descriptor GPGME supplies.
- It is set automatically when a `Ctx` is constructed with `"password"` in its options hash.
- The callback is a `Proc` assigned to a class constant; it is passed to GPGME as a C function pointer.

### Result Builders Are Ctx-local
After a crypto operation, call `ctx.verify_result`, `ctx.sign_result`, `ctx.encrypt_result`, `ctx.decrypt_result`, or `ctx.import_result` **on the same context** before the context is released. The block form of `Ctx.new` makes this straightforward.

### `Key.find` Symbols
- First argument is `:public` or `:secret`.
- Optional third argument is a purpose symbol or array of symbols: `:encrypt`, `:sign`, `:certify`, `:authenticate`.
- It filters returned keys with `KeyCommon#usable_for?`.

### `Engine.home_dir=`
Tests use `Engine.home_dir = dir` to isolate the GPG home directory. This calls `gpgme_set_engine_info` under the hood and creates the directory if missing. It is a global setting for the process.

## Testing

### Test Setup
- `spec/spec_helper.cr` creates a temporary GPG home directory and points GPGME at it via `Engine.home_dir`.
- It imports `spec/files/testkey_pub.gpg` and `spec/files/testkey_sec.gpg` once at startup.
- `spec/pinentry` is a dummy pinentry script that always returns the password `gpgme`; it is referenced in `gpg-agent.conf` inside the temp home.
- `Spec.after_each { GPGME::Test.reset! }` removes all keys and re-imports the fixtures between tests.

### Running Tests
```sh
make && crystal spec
```

Tests require a working `gpg-agent` setup and the GPGME OpenPGP engine. They will fail if GPGME cannot find `gpg` or if the engine version check fails.

### Adding Tests
- Create a new `*_spec.cr` file under `spec/`.
- Start with `require "./spec_helper"`.
- Use `GPGME::Test.reset!` if you mutate keys and need a known state mid-spec.

## Linting

Ameba is the required linter. Configuration in `.ameba.yml`:
- Excludes `lib/` and `bin/`.
- Excludes `src/gpgme/constants.cr` from `Naming/ConstantNames`.
- Excludes `src/gpgme/error.cr` and `src/gpgme/ctx.cr` from `Metrics/CyclomaticComplexity`.

Before committing, run:
```sh
bin/ameba
```

## Useful Files for Orientation

- `src/gpgme.cr` — module entry point, version, thread-safety helpers, `OptionValue` alias.
- `src/gpgme/lib_gpgme.cr` — full C binding surface.
- `src/ext/gpgme_helpers.c` — C accessors for bitfield/linked-list struct fields.
- `src/gpgme/ctx.cr` — mid-level API and result builders.
- `src/gpgme/crypto.cr` — high-level API matching ruby-gpgme.
- `src/gpgme/error.cr` — error-code-to-exception mapping.
- `REWRITE_PLAN.md` — original design notes and API mapping targets.
