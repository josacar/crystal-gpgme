# crystal-gpgme

Crystal bindings for [GPGME](https://www.gnupg.org/software/gpgme/index.html)
(GnuPG Made Easy), inspired by and API-compatible with
[ruby-gpgme](https://github.com/ueno/ruby-gpgme).

## Requirements

- Crystal 1.10+
- GPGME 1.21+ / 2.0+
- `gpg-agent` (optional, but recommended)

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  gpgme:
    github: crystal-gpgme/crystal-gpgme
```

Then run `shards install`.

## API Overview

GPGME provides three levels of API:

- **High-level API:** easiest for common operations.
- **Mid-level API:** more control.
- **Low-level API:** closest to the C interface.

### High-level example

```crystal
require "gpgme"

crypto = GPGME::Crypto.new
crypto.clearsign(STDIN, output: STDOUT)
```

### Mid-level example

```crystal
plain = GPGME::Data.new(STDIN)
sig   = GPGME::Data.new(STDOUT)
GPGME::Ctx.new do |ctx|
  ctx.sign(plain, sig, GPGME::SIG_MODE_CLEAR)
end
```

### Low-level example

```crystal
GPGME::LibGPGME.check_version(nil)
ctx = GPGME::Ctx.new
# ... direct LibGPGME calls
```

## Usage

### Encrypt / decrypt

```crystal
crypto = GPGME::Crypto.new
encrypted = crypto.encrypt("Hello world!", recipients: "someone@example.com", always_trust: true)
decrypted = crypto.decrypt(encrypted)
puts decrypted.to_s
```

### Sign / verify

```crystal
crypto = GPGME::Crypto.new
sign = crypto.sign("Some text")

verified = crypto.verify(sign) do |signature|
  raise "Bad signature" unless signature.valid?
end
puts verified.to_s
```

### Key management

```crystal
keys = GPGME::Key.find(:secret, "someone@example.com")
GPGME::Key.import(File.open("my.key"))
```

## Development

```sh
shards install
make           # Build the C helper for struct accessors
crystal spec
```

## License

LGPL-2.1-or-later. See `COPYING.LESSER` for details.
