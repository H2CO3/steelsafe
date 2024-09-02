use serde_json::json;
use zeroize::Zeroizing;
use block_padding::{RawPadding, Iso7816};
use crypto_common::typenum::Unsigned;
use argon2::{Argon2, RECOMMENDED_SALT_LEN};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::{Aead, Payload, KeySizeUser}};
use crate::Result;


const PADDING_BLOCK_SIZE: usize = 256;

#[derive(Clone, Debug)]
pub struct EncryptionOutput {
    /// The already-encrypted and authenticated secret.
    pub enc_secret: Vec<u8>,
    /// The randomly-generated salt, used for seeding the KDF.
    pub kdf_salt: [u8; RECOMMENDED_SALT_LEN],
    /// The randomly-generated nonce, used for initializing the AEAD hash.
    pub auth_nonce: [u8; 24],
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptionInput<'a> {
    pub plaintext_secret: &'a [u8],
    pub label: &'a str,
    pub account: Option<&'a str>,
}

impl EncryptionInput<'_> {
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
        let additional_data_val = json!({
            "label": self.label,
            "account": self.account,
        });
        let additional_data_str = additional_data_val.to_string();

        // Generate random salt and nonce. `rand::random()` uses a CSPRNG.
        let kdf_salt: [u8; RECOMMENDED_SALT_LEN] = rand::random();
        let auth_nonce: [u8; 24] = rand::random();

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
        let enc_secret = aead.encrypt(<_>::from(&auth_nonce), payload)?;

        Ok(EncryptionOutput {
            enc_secret,
            kdf_salt,
            auth_nonce,
        })
    }
}
