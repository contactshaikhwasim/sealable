# sealable

**Password-to-sealed-string encryption for secrets — portable, versioned, pluggable.**

[![Crates.io](https://img.shields.io/crates/v/sealable.svg)](https://crates.io/crates/sealable)
[![Docs](https://docs.rs/sealable/badge.svg)](https://docs.rs/sealable)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

`sealable` turns any small secret (API key, database password, token) into a **single, URL-safe string** protected by a passphrase.
The sealed string is self-contained, versioned, and easy to store in config files, environment variables, or secret stores.

---

## Why use `sealable`?

Secrets often require manually managing salts, nonces, and encoding while wiring together low-level cryptography primitives.

`sealable` provides:

- A simple API for encrypting and decrypting passphrase-protected secrets.
- A versioned format for future-proof compatibility.
- Pluggable traits for KDF, cipher, and codec.
- Single-string, URL-safe output.

---

## Default implementation

The default stack is:

- `Argon2id` for key derivation
- `AES-256-GCM` for authenticated encryption
- `Base64Url` for URL-safe encoding

Convenience alias:

- `sealable::prelude::DefaultSealedBox`

---

## Features

- 🔐 Default secure stack: `Argon2id` + `AES-256-GCM` + `Base64Url`
- 🧩 Pluggable backends via `KeyDerivation`, `Cipher`, and `Codec`
- 📦 Self-contained sealed strings with version, salt, nonce, and ciphertext
- 🔄 Algorithm agility through versioned payloads
- 🛡️ Zeroized secret material via `zeroize`
- 🔗 URL-safe output without padding
- 📜 Minimal API: `encrypt(passphrase, plaintext)` and `decrypt(passphrase, sealed_string)`

---

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
sealable = "0.1"
```

---

## Basic usage

```rust
use sealable::prelude::*;

fn main() -> Result<(), sealable::Error> {
    let sealed = DefaultSealedBox::encrypt("my-passphrase", b"my secret message")?;
    println!("Sealed: {}", sealed);

    let decrypted = DefaultSealedBox::decrypt("my-passphrase", &sealed)?;
    assert_eq!(&*decrypted, b"my secret message");

    Ok(())
}
```

---

## Customization

Create a custom `SealedBox` from types that implement the required traits:

```rust
use sealable::{SealedBox, traits::{KeyDerivation, Cipher, Codec}};
use sealable::crypto::{Aes256Gcm, Argon2id};
use sealable::codec::Base64Url;

type MySealedBox = SealedBox<Aes256Gcm, Argon2id, Base64Url>;

let sealed = MySealedBox::encrypt("password", b"data")?;
let decrypted = MySealedBox::decrypt("password", &sealed)?;
```

Replace any of the following components:

- `KeyDerivation` — passphrase → key
- `Cipher` — authenticated encryption
- `Codec` — string encoding and decoding

---

## Example: store a secret in config

```rust
use sealable::prelude::*;

let master_key = std::env::var("MASTER_KEY")?;
let sealed = DefaultSealedBox::encrypt(&master_key, b"supersecret123")?;

// Persist `sealed` to a config file or environment variable.

let sealed_from_config = /* read sealed string from storage */;
let decrypted = DefaultSealedBox::decrypt(&master_key, &sealed_from_config)?;
let password = String::from_utf8_lossy(&decrypted);
```

---

## Limitations

- ⚠️ Not intended for large data: encryption/decryption happens in memory.
- ⚠️ Passphrase strength matters: weak passphrases are vulnerable to offline attacks.
- ⚠️ No built-in passphrase rotation: re-seal values manually when you change the passphrase.
- ⚠️ No additional authenticated data (AAD) support in the current API.
- ⚠️ Designed for one passphrase / one secret, not multi-recipient encryption.
- ⚠️ No streaming support.

---

## Error handling

`sealable::Error` includes:

- `UnsupportedVersion`
- `InvalidFormat`
- `Crypto`
- `Encoding`

Handle errors with standard Rust `Result`.

---

## License

`sealable` is licensed under either:

- Apache License, Version 2.0
- MIT License
