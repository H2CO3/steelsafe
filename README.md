## Steelsafe: a pure Rust, safe, TUI password manager

Steelsafe is a minimalistic, portable, personal password manager with a terminal
user interface (TUI), written entirely in safe Rust (not counting dependencies).

It aims to follow best practices of cryptography and secure software engineering.
In particular:

* It uses strong, up-to-date cryptographic algorithms for key derivation (Argon2),
  encryption (XChaCha20), and authentication (Poly1305). It pads passwords to a
  reasonable block size (256 bytes) to avoid leaking their length. The settings
  of the Argon2 hash function are chosen using the recommended values (19 MB RAM,
  Argon2id algorithm variant, 2 iterations, 1 degree of parallelism).
* The length of the KDF salt follows the recommended value, too (16 bytes), and
  the variant of ChaCha20 with a longer nonce (24 bytes), XChaCha20 is used.
* Salts and nonces are generated using a cryptographically-strong PRNG, and the
  internal structure of the code makes salt or nonce reuse impossible.
* Cleartext secrets are securely overwritten after use under as many circumstances
  as possible. This is not _always_ possible, so it is done on a best effor basis.
* It doesn't expose these details to the user, so it's impossible to set them to
  potentially insecure values.
* The application authenticates both the encrypted secret and all of its cleartext
  metadata, providing tamper detection for the label, account name, and modification
  date of each stored password. No data is stored unauthenticated in the database
  (the only exception is the unique ID of the password, which is not shown to the
  user, and it is only a semantically meaningless, sequential integer anyway).
* The application itself does not use any `unsafe`, and this is enforced via the
  relevant `#![forbid(unsafe_code)]` directive. Cryptography-related dependencies
  are only from a trusted, well-known source, namely: the [RustCrypto][1] project.
* The data are stored in a battle-tested, structured, robust, and accessible format:
  [SQLite3][2]. SQLite is one of the long-term storage formats recommended by the
  United States Library of Congress.

Due to its simplicity and zero-config nature, the application is primarily intended
for **personal** use; a good use case is painless migration to a new computer.
The use of an on-file database means that the migration of the password database is
trivially done by copying over the SQLite file to the new location, as there's no
migration scripts to run or services to log in to.

Secret entries are individually encrypted using a password to be specified upon
insertion of the new entry. There is no single "master" password or master key;
if you want, you can encrypt each individual entry using a different password.

Of course, this approach has its downsides. For example:

* There is no automatic synchronization across locations, computers, and profiles.
* There is no simple way to change the password for every entry at once.

These make Steelsafe largely unsuited for corporate use, but we believe that it will
still make a fine addition to the power user's toolbox.

[1]: https://github.com/RustCrypto
[2]: https://sqlite.org
