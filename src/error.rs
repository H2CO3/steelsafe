//! Errors and results specific to Steelsafe.

use std::io::Error as IoError;
use thiserror::Error;
use argon2::Error as Argon2Error;
use chacha20poly1305::Error as XChaCha20Poly1305Error;
use crypto_common::InvalidLength;
use nanosql::Error as SqlError;


#[derive(Debug, Error)]
pub enum Error {
    #[error("Can't re-open screen guard while one is already open")]
    ScreenAlreadyOpen,
    #[error("Can't find database directory")]
    MissingDatabaseDir,
    #[error("Label is required and must be a single line")]
    LabelRequired,
    #[error("Secret is required")]
    SecretRequired,
    #[error("Encryption (master) password is required and must be a single line")]
    EncryptionPasswordRequired,
    #[error("Account name must be a single line if specified")]
    AccountNameSingleLine,
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("Database error: {0}")]
    Db(#[from] SqlError),
    #[error("Password hashing error: {0}")]
    Argon2(#[from] Argon2Error),
    #[error("Encryption/decryption error: {0}")]
    XChaCha20Poly1305(#[from] XChaCha20Poly1305Error),
    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
