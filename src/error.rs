//! Errors and results specific to Steelsafe.

use std::fmt::{self, Display, Debug, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::error::Error as StdError;
use thiserror::Error;
use serde_json::Error as JsonError;
use argon2::Error as Argon2Error;
use chacha20poly1305::Error as XChaCha20Poly1305Error;
use block_padding::UnpadError;
use crypto_common::InvalidLength;
use arboard::Error as ClipboardError;
use nanosql::Error as SqlError;


#[derive(Error)]
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

    #[error("No item is currently selected")]
    SelectionRequired,

    #[error("I/O error: {0}")]
    Io(#[from] IoError),

    #[error("Secret is not valid UTF-8: {0}")]
    Utf8(#[from] Utf8Error),

    #[error("JSON error: {0}")]
    Json(#[from] JsonError),

    #[error("Database error: {0}")]
    Db(#[from] SqlError),

    #[error("Password hashing error: {0}")]
    Argon2(#[from] Argon2Error),

    #[error("Encryption/decryption error: {0}")]
    XChaCha20Poly1305(#[from] XChaCha20Poly1305Error),

    #[error("Invalid padding in decrypted secret")]
    Unpad(#[from] UnpadError),

    #[error(transparent)]
    InvalidLength(#[from] InvalidLength),

    #[error(transparent)]
    Clipboard(#[from] ClipboardError),

    #[error("{message}: {source}")]
    Context {
        message: String,
        #[source]
        source: Box<dyn StdError + Send + Sync + 'static>,
    },
}

impl Error {
    pub fn context<E, M>(source: E, message: M) -> Self
    where
        E: StdError + Send + Sync + 'static,
        M: Into<String>,
    {
        Error::Context {
            message: message.into(),
            source: Box::new(source),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, formatter)
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub trait ResultExt<T> {
    fn context<M>(self, message: M) -> Result<T>
    where
        M: Into<String>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static
{
    fn context<M>(self, message: M) -> Result<T>
    where
        M: Into<String>
    {
        self.map_err(|error| Error::context(error, message))
    }
}
