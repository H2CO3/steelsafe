//! Describes and implements the password database.

use std::path::Path;
use chrono::{DateTime, Utc};
use nanosql::{
    Connection, ConnectionExt, Null,
    Table, Param, ResultRecord, InsertInput,
};
use crate::crypto::{RECOMMENDED_SALT_LEN, NONCE_LEN};
use crate::error::Result;


/// Handle for the secrets database.
#[derive(Debug)]
pub struct Database {
    connection: Connection,
}

impl Database {
    /// Opens the database at the specified path.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>
    {
        let mut connection = Connection::connect(path)?;
        connection.create_table::<Item>()?;

        Ok(Database { connection })
    }

    /// Returns the list of items in the database.
    ///
    /// The returned data is human-readable: it contains fields such as the identifying
    /// name/label/title of the entry, the optional account information, and the date of
    /// creation/last modification. It does not return binary data such as the encrypted
    /// secret, the KDF salt, or the authentication nonce.
    ///
    /// If the `search_term` is `None`, then all items are returned.
    ///
    /// If the `search_term` is `Some(_)`, then only items matching the search term will
    /// be returned. The search term is interpreted as an SQL `LIKE` pattern. The pattern
    /// will be matched against the label and the account name, and entries matching either
    /// will be returned.
    pub fn list_items_for_display(&self, search_term: Option<&str>) -> Result<Vec<DisplayItem>> {
        self.connection.compile_invoke(ListItemsForDisplay, search_term).map_err(Into::into)
    }

    /// Creates a new entry in the database using an already-encrypted secret.
    pub fn add_item(&self, input: AddItemInput<'_>) -> Result<Item> {
        self.connection.insert_one(input).map_err(Into::into)
    }

    /// Retrieves a full item from the database based on its unique ID (primary key).
    /// This includes encryption and authentication data: the encrypted secret, the
    /// KDF salt, and the authentication nonce.
    pub fn item_by_id(&self, id: u64) -> Result<Item> {
        self.connection.select_by_key(id).map_err(Into::into)
    }
}

/// Describes a secret item.
#[derive(Clone, Debug, Table, ResultRecord)]
#[nanosql(insert_input_ty = AddItemInput<'p>)]
pub struct Item {
    /// Unique identifier of the item.
    #[nanosql(pk)]
    pub uid: u64,
    /// Human-readable identifier of the item.
    #[nanosql(unique)]
    pub label: String,
    /// Username, email address, etc. for identification. `None` if not applicable.
    pub account: Option<String>,
    /// Last modification date of the item. If never modified, this is the creation date.
    pub last_modified_at: DateTime<Utc>,
    /// The encrypted and authenticated password data.
    /// Also contains a copy of the other fields for the purpose of tamper protection.
    pub encrypted_secret: Vec<u8>,
    /// The salt for the key derivation function.
    pub kdf_salt: [u8; RECOMMENDED_SALT_LEN],
    /// The nonce for the authentication function.
    pub auth_nonce: [u8; NONCE_LEN],
}

#[derive(Clone, Param, InsertInput)]
#[nanosql(table = Item)]
pub struct AddItemInput<'p> {
    /// inserting a `NULL` into an `INTEGER PRIMARY KEY` auto-generates the PK
    pub uid: Null,
    pub label: &'p str,
    pub account: Option<&'p str>,
    pub last_modified_at: DateTime<Utc>,
    pub encrypted_secret: &'p [u8],
    pub kdf_salt: [u8; RECOMMENDED_SALT_LEN],
    pub auth_nonce: [u8; NONCE_LEN],
}

#[derive(Clone, Debug, ResultRecord)]
pub struct DisplayItem {
    pub uid: u64,
    pub label: String,
    pub account: Option<String>,
    pub last_modified_at: DateTime<Utc>,
}

nanosql::define_query! {
    /// The optional parameter is a search/filter term. It works with SQLite `LIKE` syntax.
    /// If not provided, no filtering will be performed, and all items will be returned.
    ListItemsForDisplay<'p>: Option<&'p str> => Vec<DisplayItem> {
        r#"
        SELECT
            "item"."uid" AS "uid",
            "item"."label" AS "label",
            "item"."account" AS "account",
            "item"."last_modified_at" AS "last_modified_at"
        FROM "item"
        WHERE ?1 IS NULL OR "item"."label" LIKE ?1 OR "item"."account" LIKE ?1
        ORDER BY "item"."uid";
        "#
    }
}
