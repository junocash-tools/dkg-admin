use serde::{Deserialize, Serialize};

use crate::config::Network;

pub const KEY_PACKAGE_VERSION: &str = "redpallas_frost_v1";
pub const ENVELOPE_VERSION: &str = "keypackage_envelope_v1";
pub const RECEIPT_VERSION: &str = "key_import_receipt_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagePlaintextV1 {
    pub keypackage_version: String,
    pub created_at: String, // RFC3339

    pub operator_id: String,
    pub identifier: u16,
    pub threshold: u16,
    pub max_signers: u16,
    pub network: Network,

    pub roster_hash_hex: String,
    pub public_key_package_hash_hex: String,

    /// Frost KeyPackage bytes (postcard via frost-core serialization).
    pub key_package_bytes_b64: String,
    /// Frost PublicKeyPackage bytes (postcard via frost-core serialization).
    pub public_key_package_bytes_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKeyPackageEnvelopeV1 {
    pub envelope_version: String,
    pub created_at: String, // RFC3339

    #[serde(flatten)]
    pub backend: EncryptionBackendV1,

    /// Backend-specific ciphertext bytes, base64-encoded.
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "encryption_backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum EncryptionBackendV1 {
    Age { recipients: Vec<String> },
    AwsKms {
        kms_key_id: String,
        encrypted_data_key_b64: String,
        nonce_b64: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyImportReceiptV1 {
    pub receipt_version: String,
    pub created_at: String, // RFC3339

    pub operator_id: String,
    pub identifier: u16,
    pub threshold: u16,
    pub max_signers: u16,
    pub network: Network,

    pub roster_hash_hex: String,
    pub public_key_package_hash_hex: String,
    pub keyset_id: String,

    pub encrypted_blob_sha256_hex: String,

    pub storage: ReceiptStorageV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptStorageV1 {
    File { path: String },
    S3 { bucket: String, key: String },
}

