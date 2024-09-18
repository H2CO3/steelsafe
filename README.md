## Steelsafe: a pure Rust, safe, TUI password manager

Steelsafe is a minimalistic, portable, personal password manager with a terminal
user interface (TUI), written entirely in safe Rust (not counting dependencies).

It aims to follow best practices of cryptography and secure software engineering.
In particular:

* It uses strong, up-to-date cryptographic algorithms for key derivation (Argon2),
  encryption (XChaCha20), and authentication (Poly1305). It pads passwords to an
  integer multiple of a reasonable block size (256 bytes) to avoid leaking their
  length. The settings of the Argon2 hash function are the [recommended values][1]
  (19 MB RAM, Argon2id algorithm variant, 2 iterations, 1 degree of parallelism).
* The length of the KDF salt follows the recommended value, too (16 bytes), and
  the variant of ChaCha20 with a longer nonce (24 bytes), XChaCha20 is used.
* Salts and nonces are generated using a cryptographically-strong PRNG, and the
  internal structure of the code makes salt or nonce reuse impossible.
* Cleartext secrets are securely overwritten after use under as many circumstances
  as possible. This is not _always_ possible, so it is done on a best effort basis.
* It doesn't expose these details to the user, so it's impossible to set them to
  potentially insecure values.
* The application authenticates both the encrypted secret and all of its cleartext
  metadata, providing tamper detection for the label, account name, and modification
  date of each stored password. No data is stored unauthenticated in the database
  (the only exception is the unique ID of the password, which is not shown to the
  user, and it is only a semantically meaningless, sequential integer anyway).
* The application itself does not use any `unsafe`, and this is enforced via the
  relevant `#![forbid(unsafe_code)]` directive. Cryptography-related dependencies
  are only from a trusted, well-known source, namely: the [RustCrypto][2] project.
* The data are stored in a battle-tested, structured, robust, and accessible format:
  [SQLite3][3]. SQLite is one of the long-term storage formats recommended by the
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

### Installation

You'll need the [Rust toolchain](https://www.rust-lang.org/tools/install), then simply:

```shell
cargo install steelsafe
```

### Usage & Features Overview

The program takes no command-line arguments, starting it is as simple as typing
`steelsafe` at the prompt.

Steelsafe currently offers the bare minimum functionality required for convenient
everyday use:

* Adding new password entries to the database
* Decrypting, authenticating, and copying a password to the clipboard
* Searching entries by their metadata (label/title or account/username)

The bulk of the screen is occupied by the contents of the password database, one
entry per row. The title, account name, and last modification date (currently, this
is always the date of creation) are displayed. Use the following keys to access the
basic features:

* `q`: Quit application
* ⬇️, `j`, `<TAB>`: Select next entry
* ⬆️, `k`: Select previous entry
* `1`: Select first entry
* `0`: Select last entry
* `c`, `<ENTER>`: Ask for decryption password and copy cleartext secret to clipboard
* `f`, `/`: Find secret by metadata (label or account)
* `n`: Add new secret entry

#### Adding a new entry

When you press `n`, a dialog for entering a new secret item appears. You will see text
fields for:

* The title of the entry (required)
* The account name, username, email address, etc. associated with the password (optional)
* The password itself, or in general, the secret to be encrypted (required)
* The encryption ("master") password used for encrypting the secret (required). **This may be
  different for each individual entry,** but typically, most people will use a single one.

The credential to be encrypted may contain multiple lines, while the master encryption password
**must not** contain line breaks.

Use the up/down arrow keys or `<TAB>` to cycle through the text fields.

Press `<ENTER>` to confirm the operation and add the entry, `<ESC>` to cancel and close the
dialog box, and `<CTRL>+H` or `<CTRL>+E` to show/hide the credential and the master password,
respectively. Once the new entry is added, it appears at the end of the table immediately, and
will also be selected.

#### Copying an existing credential to the clipboard

When you press `c` or `<ENTER>`, the currently selected entry will be decrypted and
copied to the clipboard. You will be asked for the decryption password, which is also
used for verifying that the additional data (currently: the title, the account name,
and the creation/last modification date) has not been tampered with.

Press `<ESC>` to cancel the operation, `<ENTER>` to confirm the decryption password 
and copy the item, and `<CTRL>+H` to show/hide the decryption password while typing.

#### Finding credentials by name

If you have many credentials in your database, you can search for them by their title or
account name. To enter search mode, press `f` or `/` (the latter should be familiar to users
of Vim, `less` and `more`). A search field will appear at the bottom. As you type, entries
in the table will be restricted to those containing the search term. The search text is
actually a SQL `LIKE` pattern, so you can use the placeholders `_` and `%` to match one or
more arbitrary characters, respectively.

When you see the desired entry appear in the table, press `<ENTER>` to shift focus from the
search text field to the main table again. Then, you can keep issuing the same commands as
normally; you'll most likely want to press `c` or `<ENTER>` to copy the entry to clipboard.

If you are done searching, press `<ESC>` to exit search mode; this will restore the table of
credentials and show the full list again. Alternatively, you can press `f` or `/` again to
re-focus the search field and refine your search term.

### A note about clipboard behavior

On some platforms, especially Linux and other platforms using X11 or Wayland, clipboard
contents are only available as long as the source application is running. Thus, in these
environments, you will have to keep Steelsafe running until you are done with the copied
secret.

### Database Path

The database is located in the [project data directory][4] by default, and it is called
`secrets.sqlite3`. You can use the `.steelsaferc` file (see below) to change the path
of the directory. The file name cannot be changed.

### Configuration

Steelsafe will search the `.steelsaferc` configuration file (in this order) at:

* the [project config directory][5]
* or `$HOME`

An example of the config file can be found [here][6]. It is a JSON with self-explanatory
structure; you can currently use it to change the colors of various UI elements and the
path of the secrets database.

[1]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[2]: https://github.com/RustCrypto
[3]: https://sqlite.org
[4]: https://docs.rs/directories/latest/directories/struct.ProjectDirs.html#method.data_dir
[5]: https://docs.rs/directories/latest/directories/struct.ProjectDirs.html#method.config_dir
[6]: https://github.com/H2CO3/steelsafe/blob/master/.steelsaferc
