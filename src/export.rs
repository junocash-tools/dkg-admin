use std::path::{Path, PathBuf};

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use base64::Engine as _;
use rand_core::{CryptoRng, RngCore};
use reddsa::frost::redpallas;
use time::format_description::well_known::Rfc3339;

use crate::config::ValidatedAdminConfig;
use crate::crypto;
use crate::envelope::{
    EncryptionBackendV1, EncryptedKeyPackageEnvelopeV1, KeyImportReceiptV1, KeyPackagePlaintextV1,
    ReceiptStorageV1, ENVELOPE_VERSION, KEY_PACKAGE_VERSION, RECEIPT_VERSION,
};
use crate::hash;
use crate::storage;

pub struct Exporter {
    cfg: ValidatedAdminConfig,
}

impl Exporter {
    pub fn new(cfg: ValidatedAdminConfig) -> Self {
        Self { cfg }
    }

    pub fn state_dir(&self) -> &Path {
        &self.cfg.cfg.state_dir
    }

    pub fn load_key_material(
        &self,
    ) -> Result<(redpallas::keys::KeyPackage, redpallas::keys::PublicKeyPackage, [u8; 32]), ExportError>
    {
        let kp_bytes = storage::read(&self.state_dir().join("key_package.bin"))
            .map_err(ExportError::StateRead)?;
        let pkp_bytes = storage::read(&self.state_dir().join("public_key_package.bin"))
            .map_err(ExportError::StateRead)?;

        let key_package =
            redpallas::keys::KeyPackage::deserialize(&kp_bytes).map_err(ExportError::Frost)?;
        let public_key_package = redpallas::keys::PublicKeyPackage::deserialize(&pkp_bytes)
            .map_err(ExportError::Frost)?;

        let pk_hash = crypto::public_key_package_hash(&public_key_package, self.cfg.cfg.max_signers)
            .map_err(ExportError::Crypto)?;
        Ok((key_package, public_key_package, pk_hash))
    }

    pub async fn export_to_file_age(
        &self,
        recipients: &[String],
        out_path: &Path,
    ) -> Result<Vec<u8>, ExportError> {
        let (key_package, public_key_package, pk_hash) = self.load_key_material()?;
        let created_at = now_rfc3339()?;

        let plaintext = KeyPackagePlaintextV1 {
            keypackage_version: KEY_PACKAGE_VERSION.to_string(),
            created_at: created_at.clone(),
            operator_id: self.cfg.cfg.operator_id.clone(),
            identifier: self.cfg.cfg.identifier,
            threshold: self.cfg.cfg.threshold,
            max_signers: self.cfg.cfg.max_signers,
            network: self.cfg.cfg.network,
            roster_hash_hex: self.cfg.cfg.roster_hash_hex.clone(),
            public_key_package_hash_hex: hex::encode(pk_hash),
            key_package_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(key_package.serialize().map_err(ExportError::Frost)?),
            public_key_package_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(public_key_package.serialize().map_err(ExportError::Frost)?),
        };

        let plaintext_bytes =
            serde_json::to_vec(&plaintext).map_err(|_| ExportError::PlaintextSerializeFailed)?;
        let ciphertext = crate::encrypt::age_encrypt(recipients, &plaintext_bytes)
            .map_err(ExportError::Encrypt)?;

        let envelope = EncryptedKeyPackageEnvelopeV1 {
            envelope_version: ENVELOPE_VERSION.to_string(),
            created_at: created_at.clone(),
            backend: EncryptionBackendV1::Age {
                recipients: recipients.to_vec(),
            },
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        };
        let blob_bytes =
            serde_json::to_vec(&envelope).map_err(|_| ExportError::EnvelopeSerializeFailed)?;

        storage::write_file_0600_fsync(out_path, &blob_bytes).map_err(ExportError::StateWrite)?;

        let receipt = KeyImportReceiptV1 {
            receipt_version: RECEIPT_VERSION.to_string(),
            created_at,
            operator_id: self.cfg.cfg.operator_id.clone(),
            identifier: self.cfg.cfg.identifier,
            threshold: self.cfg.cfg.threshold,
            max_signers: self.cfg.cfg.max_signers,
            network: self.cfg.cfg.network,
            roster_hash_hex: self.cfg.cfg.roster_hash_hex.clone(),
            public_key_package_hash_hex: hex::encode(pk_hash),
            keyset_id: hex::encode(pk_hash),
            encrypted_blob_sha256_hex: hash::sha256_hex(&blob_bytes),
            storage: ReceiptStorageV1::File {
                path: out_path.display().to_string(),
            },
        };
        let receipt_bytes =
            serde_json::to_vec(&receipt).map_err(|_| ExportError::ReceiptSerializeFailed)?;
        let receipt_path = receipt_path_for_file(out_path);
        storage::write_file_0600_fsync(&receipt_path, &receipt_bytes).map_err(ExportError::StateWrite)?;

        Ok(receipt_bytes)
    }

    pub async fn export_to_file_kms<R: RngCore + CryptoRng>(
        &self,
        kms: &dyn crate::encrypt::KmsProvider,
        kms_key_id: &str,
        out_path: &Path,
        rng: &mut R,
    ) -> Result<Vec<u8>, ExportError> {
        let (key_package, public_key_package, pk_hash) = self.load_key_material()?;
        let created_at = now_rfc3339()?;

        let plaintext = KeyPackagePlaintextV1 {
            keypackage_version: KEY_PACKAGE_VERSION.to_string(),
            created_at: created_at.clone(),
            operator_id: self.cfg.cfg.operator_id.clone(),
            identifier: self.cfg.cfg.identifier,
            threshold: self.cfg.cfg.threshold,
            max_signers: self.cfg.cfg.max_signers,
            network: self.cfg.cfg.network,
            roster_hash_hex: self.cfg.cfg.roster_hash_hex.clone(),
            public_key_package_hash_hex: hex::encode(pk_hash),
            key_package_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(key_package.serialize().map_err(ExportError::Frost)?),
            public_key_package_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(public_key_package.serialize().map_err(ExportError::Frost)?),
        };

        let plaintext_bytes =
            serde_json::to_vec(&plaintext).map_err(|_| ExportError::PlaintextSerializeFailed)?;

        let kms_out = crate::encrypt::kms_encrypt(kms_key_id, &plaintext_bytes, kms, rng)
            .await
            .map_err(ExportError::Encrypt)?;

        let envelope = EncryptedKeyPackageEnvelopeV1 {
            envelope_version: ENVELOPE_VERSION.to_string(),
            created_at: created_at.clone(),
            backend: EncryptionBackendV1::AwsKms {
                kms_key_id: kms_key_id.to_string(),
                encrypted_data_key_b64: base64::engine::general_purpose::STANDARD
                    .encode(kms_out.encrypted_data_key),
                nonce_b64: base64::engine::general_purpose::STANDARD.encode(kms_out.nonce),
            },
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(kms_out.ciphertext),
        };
        let blob_bytes =
            serde_json::to_vec(&envelope).map_err(|_| ExportError::EnvelopeSerializeFailed)?;

        storage::write_file_0600_fsync(out_path, &blob_bytes).map_err(ExportError::StateWrite)?;

        let receipt = KeyImportReceiptV1 {
            receipt_version: RECEIPT_VERSION.to_string(),
            created_at,
            operator_id: self.cfg.cfg.operator_id.clone(),
            identifier: self.cfg.cfg.identifier,
            threshold: self.cfg.cfg.threshold,
            max_signers: self.cfg.cfg.max_signers,
            network: self.cfg.cfg.network,
            roster_hash_hex: self.cfg.cfg.roster_hash_hex.clone(),
            public_key_package_hash_hex: hex::encode(pk_hash),
            keyset_id: hex::encode(pk_hash),
            encrypted_blob_sha256_hex: hash::sha256_hex(&blob_bytes),
            storage: ReceiptStorageV1::File {
                path: out_path.display().to_string(),
            },
        };
        let receipt_bytes =
            serde_json::to_vec(&receipt).map_err(|_| ExportError::ReceiptSerializeFailed)?;
        let receipt_path = receipt_path_for_file(out_path);
        storage::write_file_0600_fsync(&receipt_path, &receipt_bytes).map_err(ExportError::StateWrite)?;

        Ok(receipt_bytes)
    }

    pub async fn export_to_s3(
        &self,
        blob_bytes: Vec<u8>,
        receipt_bytes: Vec<u8>,
        bucket: &str,
        key: &str,
        sse_kms_key_id: &str,
    ) -> Result<(), ExportError> {
        let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3 = aws_sdk_s3::Client::new(&aws_cfg);

        s3.put_object()
            .bucket(bucket)
            .key(key)
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id(sse_kms_key_id)
            .body(ByteStream::from(blob_bytes))
            .send()
            .await
            .map_err(|e| ExportError::S3PutFailed(e.to_string()))?;

        let receipt_key = format!("{key}.KeyImportReceipt.json");
        s3.put_object()
            .bucket(bucket)
            .key(receipt_key)
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id(sse_kms_key_id)
            .body(ByteStream::from(receipt_bytes))
            .send()
            .await
            .map_err(|e| ExportError::S3PutFailed(e.to_string()))?;

        Ok(())
    }
}

fn now_rfc3339() -> Result<String, ExportError> {
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ExportError::TimeFormatFailed)
}

fn receipt_path_for_file(out_path: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.KeyImportReceipt.json",
        out_path.display()
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("state_read_failed: {0}")]
    StateRead(std::io::Error),
    #[error("state_write_failed: {0}")]
    StateWrite(std::io::Error),
    #[error("frost_error: {0}")]
    Frost(redpallas::Error),
    #[error("crypto_error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("plaintext_serialize_failed")]
    PlaintextSerializeFailed,
    #[error("envelope_serialize_failed")]
    EnvelopeSerializeFailed,
    #[error("receipt_serialize_failed")]
    ReceiptSerializeFailed,
    #[error("time_format_failed")]
    TimeFormatFailed,
    #[error("encryption_failed: {0}")]
    Encrypt(#[from] crate::encrypt::EncryptError),
    #[error("s3_put_failed: {0}")]
    S3PutFailed(String),
}
