//! Describes and implements the password database.

use std::path::Path;
use chrono::{DateTime, Utc};
use nanosql::{
    Connection, ConnectionExt, Null, Value,
    Table, Param, ResultRecord, InsertInput, AsSqlTy, FromSql, ToSql,
};
use nanosql::rusqlite::TransactionBehavior;
use crate::crypto::{RECOMMENDED_SALT_LEN, NONCE_LEN};
use crate::error::{Error, Result};


/// The current version of the database schema.
const SCHEMA_VERSION: i64 = 1;

/// Handle for the secrets database.
#[derive(Debug)]
pub struct Database {
    connection: Connection,
    schema_version: i64,
}

impl Database {
    /// Opens the database at the specified path.
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>
    {
        let mut connection = Connection::connect(path)?;
        connection.create_table::<Item>()?;
        connection.create_table::<Metadata>()?;

        let schema_version = Self::schema_version(&mut connection)?;

        if SCHEMA_VERSION < schema_version {
            return Err(Error::SchemaVersionMismatch {
                expected: SCHEMA_VERSION,
                actual: schema_version,
            });
        }

        Ok(Database { connection, schema_version })
    }

    /// Retrieves the schema version of the database.
    /// If the schema version was not yet set (because the database was just created),
    /// then the schema version of the currently-running steelsafe process will be
    /// inserted (and returned).
    fn schema_version(connection: &mut Connection) -> nanosql::Result<i64> {
        // If the schema version is not yet stored in the DB, then insert it.
        // Otherwise, leave the existing version (ignore the insertion).
        let txn = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = Metadata {
            key: MetadataKey::SchemaVersion,
            value: Value::Integer(SCHEMA_VERSION),
        };

        // If we didn't insert the version, that means we didn't create the database.
        // In this case, we need to check the version to decide whether we can handle
        // it. (If we did create the database, then we are convinced we can handle it.)
        txn.insert_or_ignore_one(metadata)?;

        let Metadata { ref value, .. } = txn.select_by_key(MetadataKey::SchemaVersion)?;
        let version = <i64 as FromSql>::column_result(value.into())?;

        txn.commit()?;

        Ok(version)
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
#[derive(Clone, PartialEq, Eq, Debug, Table, ResultRecord)]
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
    ///
    /// This is `UNIQUE`, acting as an additional line of defense against
    /// salt re-use, which would result in two users with the same password
    /// and salt getting identical encryption keys.
    #[nanosql(unique)]
    pub kdf_salt: [u8; RECOMMENDED_SALT_LEN],
    /// The nonce for the authentication function.
    ///
    /// This is `UNIQUE`, acting as an additional line of defense against
    /// nonce re-use, which would allow breaking encryption/authentication.
    #[nanosql(unique)]
    pub auth_nonce: [u8; NONCE_LEN],
}

/// Used for adding an encrypted secret item to the database.
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

/// Human-readable subset (projection) of the `Item` table.
/// Does not contain the secret or the encryption details (salt/nonce).
#[derive(Clone, Debug, ResultRecord)]
pub struct DisplayItem {
    pub uid: u64,
    pub label: String,
    pub account: Option<String>,
    pub last_modified_at: DateTime<Utc>,
}

/// Internal technical bookkeeping data (e.g., database version).
#[derive(Clone, Debug, Table, Param, ResultRecord)]
struct Metadata {
    #[nanosql(pk)]
    key: MetadataKey,
    value: Value,
}

/// The kinds of metadata stored in the database.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, AsSqlTy, ToSql, FromSql, Param, ResultRecord)]
#[nanosql(rename_all = "lower_snake_case")]
enum MetadataKey {
    /// The version of the database schema that determines its format.
    SchemaVersion,
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use nanosql::{Null, Error as NanosqlError};
    use nanosql::rusqlite::{ErrorCode, Error as SqliteError};
    use crate::crypto::{RECOMMENDED_SALT_LEN, NONCE_LEN};
    use crate::error::{Error, Result};
    use super::{Database, AddItemInput};


    #[test]
    fn salt_uniqueness_is_enforced() -> Result<()> {
        let db = Database::open(":memory:")?;
        let salt: [u8; RECOMMENDED_SALT_LEN] = *b"Qk2Dw5aV65Ie8y7t";
        let nonce_1: [u8; NONCE_LEN] = *b"lMVXTMT2z2giginHeWwIajy4";
        let nonce_2: [u8; NONCE_LEN] = *b"rZNaJw3dBHmiqGhfUxLbjL6x";

        let input_1 = AddItemInput {
            uid: Null,
            label: "Some label",
            account: Some("first@account.com"),
            last_modified_at: Utc::now(),
            encrypted_secret: b"EncrYpt3d S3cre7!123",
            kdf_salt: salt,
            auth_nonce: nonce_1,
        };
        let input_2 = AddItemInput {
            uid: Null,
            label: "a completely different title",
            account: Some("second@otherserver.org"),
            last_modified_at: Utc::now(),
            encrypted_secret: b"$#an0ther-c1pherteXt-of_diff3rent^LENGTH%",
            kdf_salt: salt,
            auth_nonce: nonce_2,
        };

        // We should be able to add the first item sucessfully.
        let item = db.add_item(input_1)?;
        assert_eq!(db.item_by_id(item.uid)?, item);

        // The second item has an identical salt, so insertion must fail
        // due to the violation of the UNIQUE constraint.
        let error = db.add_item(input_2).expect_err("item with duplicate salt added");
        let Error::Db(NanosqlError::Sqlite(SqliteError::SqliteFailure(error, _))) = error else {
            panic!("unexpected error: {}", error);
        };

        assert_eq!(error.code, ErrorCode::ConstraintViolation);

        Ok(())
    }

    #[test]
    fn nonce_uniqueness_is_enforced() -> Result<()> {
        let db = Database::open(":memory:")?;
        let salt_1: [u8; RECOMMENDED_SALT_LEN] = *b"NdBIIex0BLnkThWH";
        let salt_2: [u8; RECOMMENDED_SALT_LEN] = *b"xS8HYP2XAjgSnEOJ";
        let nonce: [u8; NONCE_LEN] = *b"vb4yngPRSgEOrBLNGw8YcGpG";

        let input_1 = AddItemInput {
            uid: Null,
            label: "Not a useful label",
            account: Some("foo@bar.qux"),
            last_modified_at: Utc::now(),
            encrypted_secret: b"more stuff, I've run out of ideas",
            kdf_salt: salt_1,
            auth_nonce: nonce,
        };
        let input_2 = AddItemInput {
            uid: Null,
            label: "...but neither is this!",
            account: Some("lol@wut.gov"),
            last_modified_at: Utc::now(),
            encrypted_secret: b"some different blob",
            kdf_salt: salt_2,
            auth_nonce: nonce,
        };

        // We should be able to add the first item sucessfully.
        let item = db.add_item(input_1)?;
        assert_eq!(db.item_by_id(item.uid)?, item);

        // The second item has an identical nonce, so insertion must fail
        // due to the violation of the UNIQUE constraint.
        let error = db.add_item(input_2).expect_err("item with duplicate nonce added");
        let Error::Db(NanosqlError::Sqlite(SqliteError::SqliteFailure(error, _))) = error else {
            panic!("unexpected error: {}", error);
        };

        assert_eq!(error.code, ErrorCode::ConstraintViolation);

        Ok(())
    }
}
