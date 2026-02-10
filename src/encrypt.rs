use std::io::{Read, Write};
use std::str::FromStr;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[derive(Debug)]
pub struct KmsEncryptOutput {
    pub encrypted_data_key: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn age_encrypt(recipients: &[String], plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::AgeNoRecipients);
    }

    let mut recips: Vec<age::x25519::Recipient> = Vec::with_capacity(recipients.len());
    for r in recipients {
        let recip =
            age::x25519::Recipient::from_str(r.trim()).map_err(|_| EncryptError::AgeRecipientInvalid)?;
        recips.push(recip);
    }

    let encryptor = age::Encryptor::with_recipients(recips.iter().map(|r| r as &dyn age::Recipient))
        .map_err(EncryptError::AgeEncryptorFailed)?;
    let mut out = vec![];
    let mut w = encryptor.wrap_output(&mut out).map_err(EncryptError::AgeWrapFailed)?;
    w.write_all(plaintext).map_err(EncryptError::AgeWriteFailed)?;
    w.finish().map_err(EncryptError::AgeFinishFailed)?;
    Ok(out)
}

pub fn age_decrypt(identity_str: &str, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let id = age::x25519::Identity::from_str(identity_str.trim())
        .map_err(|_| EncryptError::AgeIdentityInvalid)?;

    let decryptor = age::Decryptor::new(std::io::Cursor::new(ciphertext))
        .map_err(EncryptError::AgeDecryptorFailed)?;
    let mut r = decryptor
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(EncryptError::AgeDecryptFailed)?;

    let mut out = vec![];
    r.read_to_end(&mut out).map_err(EncryptError::AgeReadFailed)?;
    Ok(out)
}

#[async_trait]
pub trait KmsProvider: Send + Sync {
    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError>;
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptError>;
}

pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
}

impl AwsKmsProvider {
    pub fn new(client: aws_sdk_kms::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl KmsProvider for AwsKmsProvider {
    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let resp = self
            .client
            .encrypt()
            .key_id(key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext.to_vec()))
            .send()
            .await
            .map_err(|e| EncryptError::AwsKmsEncryptFailed(e.to_string()))?;
        let blob = resp
            .ciphertext_blob()
            .ok_or(EncryptError::AwsKmsEncryptNoCiphertext)?;
        Ok(blob.as_ref().to_vec())
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let resp = self
            .client
            .decrypt()
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext.to_vec()))
            .send()
            .await
            .map_err(|e| EncryptError::AwsKmsDecryptFailed(e.to_string()))?;
        let blob = resp
            .plaintext()
            .ok_or(EncryptError::AwsKmsDecryptNoPlaintext)?;
        Ok(blob.as_ref().to_vec())
    }
}

pub async fn kms_encrypt<R: RngCore + CryptoRng>(
    kms_key_id: &str,
    plaintext: &[u8],
    kms: &dyn KmsProvider,
    rng: &mut R,
) -> Result<KmsEncryptOutput, EncryptError> {
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);

    let encrypted_data_key = kms.encrypt(kms_key_id, &dek).await?;

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| EncryptError::AeadEncryptFailed)?;

    dek.zeroize();

    Ok(KmsEncryptOutput {
        encrypted_data_key,
        nonce,
        ciphertext,
    })
}

pub async fn kms_decrypt(
    encrypted_data_key: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    kms: &dyn KmsProvider,
) -> Result<Vec<u8>, EncryptError> {
    let mut dek = kms.decrypt(encrypted_data_key).await?;
    if dek.len() != 32 {
        return Err(EncryptError::AeadKeyLenInvalid(dek.len()));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| EncryptError::AeadDecryptFailed)?;

    dek.zeroize();
    Ok(pt)
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("age_no_recipients")]
    AgeNoRecipients,
    #[error("age_recipient_invalid")]
    AgeRecipientInvalid,
    #[error("age_encryptor_failed: {0}")]
    AgeEncryptorFailed(age::EncryptError),
    #[error("age_identity_invalid")]
    AgeIdentityInvalid,
    #[error("age_wrap_failed: {0}")]
    AgeWrapFailed(std::io::Error),
    #[error("age_write_failed: {0}")]
    AgeWriteFailed(std::io::Error),
    #[error("age_finish_failed: {0}")]
    AgeFinishFailed(std::io::Error),
    #[error("age_decryptor_failed: {0}")]
    AgeDecryptorFailed(age::DecryptError),
    #[error("age_decrypt_failed: {0}")]
    AgeDecryptFailed(age::DecryptError),
    #[error("age_read_failed: {0}")]
    AgeReadFailed(std::io::Error),
    // For future extension (passphrase-encrypted files).

    #[error("aead_encrypt_failed")]
    AeadEncryptFailed,
    #[error("aead_decrypt_failed")]
    AeadDecryptFailed,
    #[error("aead_key_len_invalid: {0}")]
    AeadKeyLenInvalid(usize),

    #[error("aws_kms_encrypt_failed: {0}")]
    AwsKmsEncryptFailed(String),
    #[error("aws_kms_encrypt_no_ciphertext")]
    AwsKmsEncryptNoCiphertext,
    #[error("aws_kms_decrypt_failed: {0}")]
    AwsKmsDecryptFailed(String),
    #[error("aws_kms_decrypt_no_plaintext")]
    AwsKmsDecryptNoPlaintext,
}
