//! Key derivation, encryption, and authentication.

use serde::Serialize;
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;
use block_padding::{RawPadding, Iso7816};
use crypto_common::typenum::Unsigned;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::{Aead, Payload, KeySizeUser}};
use crate::Result;


/// The length of the per-item password salt, in bytes.
pub use argon2::RECOMMENDED_SALT_LEN;

/// The length of the per-item authentication nonce, in bytes.
pub const NONCE_LEN: usize = 24;

/// The length of the padding block size, in bytes. The plaintext secret will be
/// padded before encryption, so that its length is a multiple of this block size.
pub const PADDING_BLOCK_SIZE: usize = 256;

/// The pieces of data that are not encrypted but still validated using the
/// specified encryption password, for tamper detection.
///
/// Fields are in alphabetical order, so that round-tripping through `Value`
/// results in bitwise-identical JSON. (This is a precautionary measure.)
#[derive(Clone, Copy, Debug, Serialize)]
struct AdditionalData<'a> {
    account: Option<&'a str>,
    label: &'a str,
    last_modified_at: DateTime<Utc>,
}

/// The result of encrypting and authenticating the secret, and authenticating
/// the additional data, using the specified password. The salt for the Key
/// Derivation Function and the nonce for the authentication are generated
/// _inside_ the encryption function, so that the API ensures fresh,
/// cryptographically strong random values, so accidental re-use is prevented.
/// This means that the encryption function needs to return these as well.
#[derive(Clone, Debug)]
pub struct EncryptionOutput {
    /// The already-encrypted and authenticated secret.
    pub encrypted_secret: Vec<u8>,
    /// The randomly-generated salt, used for seeding the KDF.
    pub kdf_salt: [u8; RECOMMENDED_SALT_LEN],
    /// The randomly-generated nonce, used for initializing the AEAD hash.
    pub auth_nonce: [u8; NONCE_LEN],
}

/// The plain old data input for encryption, except for the password.
#[derive(Clone, Copy, Debug)]
pub struct EncryptionInput<'a> {
    pub plaintext_secret: &'a [u8],
    pub label: &'a str,
    pub account: Option<&'a str>,
    pub last_modified_at: DateTime<Utc>,
}

impl EncryptionInput<'_> {
    /// Encrypts and authenticates the secret, and authenticates the additional data,
    /// using a key derived from the `encryption_password`.
    pub fn encrypt_and_authenticate(self, encryption_password: &[u8]) -> Result<EncryptionOutput> {
        // Pad the secret to a multiple of the block size.
        // Directly extending the String could re-allocate, which would leave
        // the contents of the old allocation in the memory, without zeroizing it.
        // To prevent this, what we do instead is pre-allocate a buffer of the
        // required size, then copy the secret over, and perform the padding in
        // the new buffer.
        let unpadded_secret = self.plaintext_secret;
        let total_len = (unpadded_secret.len() / PADDING_BLOCK_SIZE + 1) * PADDING_BLOCK_SIZE;
        let mut padded_secret = Zeroizing::new(vec![0x00_u8; total_len]);

        padded_secret[..unpadded_secret.len()].copy_from_slice(unpadded_secret);
        Iso7816::raw_pad(padded_secret.as_mut_slice(), unpadded_secret.len());

        // Create the additional authenticated data.
        let additional_data = AdditionalData {
            account: self.account,
            label: self.label,
            last_modified_at: self.last_modified_at,
        };
        let additional_data_str = serde_json::to_string(&additional_data)?;

        // Generate random salt and nonce. `rand::random()` uses a CSPRNG.
        let kdf_salt: [u8; RECOMMENDED_SALT_LEN] = rand::random();
        let auth_nonce: [u8; NONCE_LEN] = rand::random();

        // Create KDF context.
        // This uses recommended parameters (19 MB memory, 2 rounds, 1 degree of parallelism).
        let hasher = Argon2::default();

        // The actual encryption key is cleared (overwritten with all 0s) upon drop.
        let mut key = Zeroizing::new([0_u8; <XChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE]);
        hasher.hash_password_into(encryption_password, &kdf_salt, &mut *key)?;

        // Create encryption and authentication context.
        let aead = XChaCha20Poly1305::new_from_slice(key.as_slice())?;

        // Actually perform the encryption and authentication.
        let payload = Payload {
            msg: padded_secret.as_slice(),
            aad: additional_data_str.as_bytes(),
        };
        let encrypted_secret = aead.encrypt(<_>::from(&auth_nonce), payload)?;

        Ok(EncryptionOutput {
            encrypted_secret,
            kdf_salt,
            auth_nonce,
        })
    }
}

/// Plain old data input for decrypting and verifying the secret, and
/// verifying the authenticity  of the non-encrypted additional data.
#[derive(Clone, Copy, Debug)]
pub struct DecryptionInput<'a> {
    pub encrypted_secret: &'a [u8],
    pub kdf_salt: [u8; RECOMMENDED_SALT_LEN],
    pub auth_nonce: [u8; NONCE_LEN],
    pub label: &'a str,
    pub account: Option<&'a str>,
    pub last_modified_at: DateTime<Utc>,
}

impl DecryptionInput<'_> {
    /// Decrypts and verifies the secret, and verifies the additional data,
    /// using a key derived from the `decryption_password`.
    pub fn decrypt_and_verify(self, decryption_password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        // Re-create the additional authenticated data. This helps detect when
        // the displayed label or account have been tampered with in the database.
        // This **must** be bitwise identical to the data used during encryption.
        let additional_data = AdditionalData {
            account: self.account,
            label: self.label,
            last_modified_at: self.last_modified_at,
        };
        let additional_data_str = serde_json::to_string(&additional_data)?;

        // Create KDF context.
        // This MUST use the same parameters as hashing during encryption.
        let hasher = Argon2::default();

        // The actual encryption key is cleared (overwritten with all 0s) upon drop.
        let mut key = Zeroizing::new([0_u8; <XChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE]);
        hasher.hash_password_into(decryption_password, &self.kdf_salt, &mut *key)?;

        // Create decryption and verification context.
        let aead = XChaCha20Poly1305::new_from_slice(key.as_slice())?;

        // Actually perform the decryption and verification.
        let payload = Payload {
            msg: self.encrypted_secret,
            aad: additional_data_str.as_bytes(),
        };
        let plaintext_secret = aead.decrypt(<_>::from(&self.auth_nonce), payload)?;
        let mut plaintext_secret = Zeroizing::new(plaintext_secret);

        // Un-pad the decrypted plaintext
        let unpadded_len = Iso7816::raw_unpad(plaintext_secret.as_slice())?.len();
        plaintext_secret.truncate(unpadded_len);

        Ok(plaintext_secret)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Utc, Days};
    use rand::{Rng, RngCore, distributions::{Standard, DistString}};
    use crate::error::{Error, Result};
    use super::{EncryptionInput, DecryptionInput, PADDING_BLOCK_SIZE};


    #[test]
    fn correct_encryption_and_decryption_succeeds() -> Result<()> {
        let timestamp = Utc::now();
        let mut rng = rand::thread_rng();
        let p0 = vec![]; // empty payload edge case
        let mut p1 = vec![0_u8; PADDING_BLOCK_SIZE - 1];
        let mut p2 = vec![0_u8; PADDING_BLOCK_SIZE];
        let mut p3 = vec![0_u8; PADDING_BLOCK_SIZE + 1];

        rng.fill_bytes(&mut p1);
        rng.fill_bytes(&mut p2);
        rng.fill_bytes(&mut p3);

        for payload in [p0, p1, p2, p3] {
            let password_len: usize = rng.gen_range(8..64);
            let password = Standard.sample_string(&mut rng, password_len);
            let encryption_input = EncryptionInput {
                plaintext_secret: payload.as_slice(),
                label: "the precise label does not matter",
                account: Some("my uninteresting account name"),
                last_modified_at: timestamp,
            };

            let output = encryption_input.encrypt_and_authenticate(password.as_bytes())?;
            let decryption_input = DecryptionInput {
                encrypted_secret: output.encrypted_secret.as_slice(),
                kdf_salt: output.kdf_salt,
                auth_nonce: output.auth_nonce,
                label: encryption_input.label,
                account: encryption_input.account,
                last_modified_at: timestamp,
            };
            let decrypted_secret = decryption_input.decrypt_and_verify(password.as_bytes())?;

            assert_eq!(decrypted_secret.as_slice(), payload.as_slice());
        }

        Ok(())
    }

    #[test]
    fn incorrect_password_fails_decryption() -> Result<()> {
        let timestamp = Utc::now();
        let mut rng = rand::thread_rng();
        let p0 = vec![]; // empty payload edge case
        let mut p1 = vec![0_u8; PADDING_BLOCK_SIZE - 1];
        let mut p2 = vec![0_u8; PADDING_BLOCK_SIZE];
        let mut p3 = vec![0_u8; PADDING_BLOCK_SIZE + 1];

        rng.fill_bytes(&mut p1);
        rng.fill_bytes(&mut p2);
        rng.fill_bytes(&mut p3);

        for payload in [p0, p1, p2, p3] {
            let password_len: usize = rng.gen_range(8..64);
            let password = Standard.sample_string(&mut rng, password_len);
            let encryption_input = EncryptionInput {
                plaintext_secret: payload.as_slice(),
                label: "the precise label does not matter",
                account: Some("my uninteresting account name"),
                last_modified_at: timestamp,
            };

            let output = encryption_input.encrypt_and_authenticate(password.as_bytes())?;
            let decryption_input = DecryptionInput {
                encrypted_secret: output.encrypted_secret.as_slice(),
                kdf_salt: output.kdf_salt,
                auth_nonce: output.auth_nonce,
                label: encryption_input.label,
                account: encryption_input.account,
                last_modified_at: timestamp,
            };

            let wrong_password = b"this is NOT the right password!";
            let result = decryption_input.decrypt_and_verify(wrong_password);

            assert!(
                matches!(
                    result,
                    Err(Error::XChaCha20Poly1305(chacha20poly1305::Error))
                ),
                "unexpected result: {:#?}",
                result,
            );
        }

        Ok(())
    }

    #[test]
    fn altered_additional_data_fails_verification() -> Result<()> {
        let timestamp = Utc::now();
        let mut rng = rand::thread_rng();
        let p0 = vec![]; // empty payload edge case
        let mut p1 = vec![0_u8; PADDING_BLOCK_SIZE - 1];
        let mut p2 = vec![0_u8; PADDING_BLOCK_SIZE];
        let mut p3 = vec![0_u8; PADDING_BLOCK_SIZE + 1];

        rng.fill_bytes(&mut p1);
        rng.fill_bytes(&mut p2);
        rng.fill_bytes(&mut p3);

        for payload in [p0, p1, p2, p3] {
            let password_len: usize = rng.gen_range(8..64);
            let password = Standard.sample_string(&mut rng, password_len);
            let encryption_input = EncryptionInput {
                plaintext_secret: payload.as_slice(),
                label: "the precise label does not matter",
                account: Some("my uninteresting account name"),
                last_modified_at: timestamp,
            };

            let output = encryption_input.encrypt_and_authenticate(password.as_bytes())?;

            // Case #1: the account is altered (None instead of Some)
            {
                let decryption_input = DecryptionInput {
                    encrypted_secret: output.encrypted_secret.as_slice(),
                    kdf_salt: output.kdf_salt,
                    auth_nonce: output.auth_nonce,
                    label: encryption_input.label,
                    account: None,
                    last_modified_at: timestamp,
                };

                let result = decryption_input.decrypt_and_verify(password.as_bytes());

                assert!(
                    matches!(
                        result,
                        Err(Error::XChaCha20Poly1305(chacha20poly1305::Error))
                    ),
                    "unexpected result: {:#?}",
                    result,
                );
            }

            // Case #2: the label is (slightly) altered
            {
                let decryption_input = DecryptionInput {
                    encrypted_secret: output.encrypted_secret.as_slice(),
                    kdf_salt: output.kdf_salt,
                    auth_nonce: output.auth_nonce,
                    label: &encryption_input.label[1..],
                    account: encryption_input.account,
                    last_modified_at: timestamp,
                };

                let result = decryption_input.decrypt_and_verify(password.as_bytes());

                assert!(
                    matches!(
                        result,
                        Err(Error::XChaCha20Poly1305(chacha20poly1305::Error))
                    ),
                    "unexpected result: {:#?}",
                    result,
                );
            }

            // Case #2: the last modification date is tampered with
            {
                let decryption_input = DecryptionInput {
                    encrypted_secret: output.encrypted_secret.as_slice(),
                    kdf_salt: output.kdf_salt,
                    auth_nonce: output.auth_nonce,
                    label: encryption_input.label,
                    account: encryption_input.account,
                    last_modified_at: timestamp.checked_sub_days(Days::new(1)).unwrap(),
                };

                let result = decryption_input.decrypt_and_verify(password.as_bytes());

                assert!(
                    matches!(
                        result,
                        Err(Error::XChaCha20Poly1305(chacha20poly1305::Error))
                    ),
                    "unexpected result: {:#?}",
                    result,
                );
            }
        }

        Ok(())
    }
}
