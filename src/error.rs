//! Errors and results specific to Steelsafe.

use std::io::Error as IoError;
use thiserror::Error;
use argon2::Error as Argon2Error;
use chacha20poly1305::Error as XChaCha20Poly1305Error;
use crypto_common::InvalidLength;
use nanosql::Error as SqlError;


#[derive(Debug, Error)]
pub enum Error {
    #[error("can't re-open screen guard while one is already open")]
    ScreenAlreadyOpen,
    #[error("can't find database directory")]
    MissingDatabaseDir,
    #[error("label is required and must be a single line")]
    LabelRequired,
    #[error("secret is required")]
    SecretRequired,
    #[error("encryption (master) password is required and must be a single line")]
    EncryptionPasswordRequired,
    #[error("account name must be a single line if specified")]
    AccountNameSingleLine,
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Db(#[from] SqlError),
    #[error(transparent)]
    Argon2(#[from] Argon2Error),
    #[error(transparent)]
    XChaCha20Poly1305(#[from] XChaCha20Poly1305Error),
    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
