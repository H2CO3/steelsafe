//! Errors and results specific to Steelsafe.

use std::io::Error as IoError;
use thiserror::Error;
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
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
