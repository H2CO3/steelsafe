//! Describes and implements the password database.

use std::path::Path;
use nanosql::{
    Connection, ConnectionExt,
    Table, Param, ResultRecord, InsertInput,
    DateTime, Utc, Null,
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

    pub fn list_items_for_display(&self, search_term: Option<&str>) -> Result<Vec<DisplayItem>> {
        self.connection.compile_invoke(ListItemsForDisplay, search_term).map_err(Into::into)
    }

    pub fn add_item(&self, input: AddItemInput<'_>) -> Result<Item> {
        self.connection.insert_one(input).map_err(Into::into)
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
    pub kdf_salt: [u8; 16],
    /// The nonce for the authentication function.
    pub auth_nonce: [u8; 24],
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
    pub kdf_salt: [u8; 16],
    pub auth_nonce: [u8; 24],
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
