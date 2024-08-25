//! Describes and implements the password database.

use std::path::Path;
use nanosql::{
    Connection, ConnectionExt,
    Table, Param, ResultRecord,
    DateTime, FixedOffset
};
use crate::error::Result;


#[derive(Debug)]
pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>
    {
        let mut connection = Connection::connect(path)?;
        connection.create_table::<Item>()?;

        Ok(Database { connection })
    }

    pub fn list_items(&self) -> Result<Vec<Item>> {
        self.connection.select_all().map_err(Into::into)
    }
}

/// Describes a secret item.
#[derive(Clone, Debug, Table, Param, ResultRecord)]
pub struct Item {
    /// Unique identifier of the item.
    #[nanosql(pk)]
    pub uid: u64,
    /// Human-readable identifier of the item.
    #[nanosql(unique)]
    pub tag: String,
    /// Username, email address, etc. for identification. `None` if not applicable.
    pub account: Option<String>,
    /// Last modification date of the item. If never modified, this is the creation date.
    pub last_modified_at: DateTime<FixedOffset>,
    /// The encrypted and authenticated password data.
    /// Also contains a copy of the other fields for the purpose of tamper protection.
    pub encrypted_secret: Vec<u8>,
    /// The salt for the key derivation function.
    pub kdf_salt: [u8; 16],
    /// The nonce for the authentication function.
    pub auth_nonce: [u8; 12],
}
