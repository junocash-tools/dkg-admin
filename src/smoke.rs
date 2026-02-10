use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand_core::{CryptoRng, RngCore};
use reddsa::frost::redpallas;

use crate::storage;

const DIR_SMOKE: &str = "smoke";
const FILE_SESSION: &str = "session.json";
const FILE_NONCES: &str = "nonces.bin";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SmokeSessionV1 {
    session_version: u32,
    alpha_hex: String,
    message_hash_hex: String,
}

pub fn smoke_commit<R: RngCore + CryptoRng>(
    state_dir: &Path,
    key_package: &redpallas::keys::KeyPackage,
    message: &[u8],
    alpha_bytes: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, SmokeError> {
    let alpha_hex = hex::encode(alpha_bytes);
    let message_hash_hex = crate::hash::sha256_hex(message);

    let (nonces, commitments) =
        redpallas::round1::commit(key_package.signing_share(), rng);

    // Persist nonces for round2, and bind them to (message, alpha) so they can't be replayed.
    let smoke_dir = state_dir.join(DIR_SMOKE);
    storage::ensure_dir(&smoke_dir).map_err(SmokeError::StateWriteFailed)?;

    let session = SmokeSessionV1 {
        session_version: 1,
        alpha_hex,
        message_hash_hex,
    };
    let session_bytes =
        serde_json::to_vec(&session).map_err(|_| SmokeError::SessionSerializeFailed)?;
    storage::write_file_0600_fsync(&smoke_dir.join(FILE_SESSION), &session_bytes)
        .map_err(SmokeError::StateWriteFailed)?;

    let nonces_bytes = nonces.serialize().map_err(SmokeError::Frost)?;
    storage::write_file_0600_fsync(&smoke_dir.join(FILE_NONCES), &nonces_bytes)
        .map_err(SmokeError::StateWriteFailed)?;

    commitments.serialize().map_err(SmokeError::Frost)
}

pub fn smoke_sign_share(
    state_dir: &Path,
    key_package: &redpallas::keys::KeyPackage,
    signing_package_bytes: &[u8],
    alpha_bytes: &[u8],
) -> Result<Vec<u8>, SmokeError> {
    let smoke_dir = state_dir.join(DIR_SMOKE);

    let session_path = smoke_dir.join(FILE_SESSION);
    let session_bytes = storage::read(&session_path).map_err(|e| SmokeError::StateReadFailed {
        path: session_path.clone(),
        source: e,
    })?;
    let session: SmokeSessionV1 =
        serde_json::from_slice(&session_bytes).map_err(|_| SmokeError::SessionParseFailed)?;

    if session.session_version != 1 {
        return Err(SmokeError::SessionVersionUnsupported(session.session_version));
    }
    if session.alpha_hex != hex::encode(alpha_bytes) {
        return Err(SmokeError::AlphaMismatch);
    }

    let signing_package =
        redpallas::SigningPackage::deserialize(signing_package_bytes).map_err(SmokeError::Frost)?;
    if session.message_hash_hex != crate::hash::sha256_hex(signing_package.message()) {
        return Err(SmokeError::MessageMismatch);
    }

    let nonces_path = smoke_dir.join(FILE_NONCES);
    let nonces_bytes = storage::read(&nonces_path).map_err(|e| SmokeError::StateReadFailed {
        path: nonces_path.clone(),
        source: e,
    })?;
    let nonces =
        redpallas::round1::SigningNonces::deserialize(&nonces_bytes).map_err(SmokeError::Frost)?;

    let randomizer = parse_randomizer(alpha_bytes)?;
    let sig_share = redpallas::round2::sign(&signing_package, &nonces, key_package, randomizer)
        .map_err(SmokeError::Frost)?;

    // Best-effort: delete nonces immediately to avoid accidental reuse.
    let _ = std::fs::remove_file(&nonces_path);
    let _ = std::fs::remove_file(&session_path);

    Ok(sig_share.serialize())
}

pub fn make_signing_package(
    commitments_by_signer: BTreeMap<u16, Vec<u8>>,
    message: &[u8],
) -> Result<Vec<u8>, SmokeError> {
    let mut commitments = BTreeMap::new();
    for (id_u16, bytes) in commitments_by_signer {
        let id: redpallas::Identifier = id_u16
            .try_into()
            .map_err(|_| SmokeError::IdentifierInvalid(id_u16))?;
        let c = redpallas::round1::SigningCommitments::deserialize(&bytes).map_err(SmokeError::Frost)?;
        commitments.insert(id, c);
    }
    let signing_package = redpallas::SigningPackage::new(commitments, message);
    signing_package.serialize().map_err(SmokeError::Frost)
}

fn parse_randomizer(alpha_bytes: &[u8]) -> Result<redpallas::Randomizer, SmokeError> {
    if alpha_bytes.is_empty() {
        return redpallas::Randomizer::deserialize(&[0u8; 32]).map_err(SmokeError::Frost);
    }
    if alpha_bytes.len() != 32 {
        return Err(SmokeError::AlphaLenInvalid(alpha_bytes.len()));
    }
    redpallas::Randomizer::deserialize(alpha_bytes).map_err(SmokeError::Frost)
}

#[derive(Debug, thiserror::Error)]
pub enum SmokeError {
    #[error("identifier_invalid: {0}")]
    IdentifierInvalid(u16),
    #[error("alpha_len_invalid: {0}")]
    AlphaLenInvalid(usize),
    #[error("alpha_mismatch")]
    AlphaMismatch,
    #[error("message_mismatch")]
    MessageMismatch,
    #[error("session_parse_failed")]
    SessionParseFailed,
    #[error("session_serialize_failed")]
    SessionSerializeFailed,
    #[error("session_version_unsupported: {0}")]
    SessionVersionUnsupported(u32),
    #[error("state_write_failed: {0}")]
    StateWriteFailed(std::io::Error),
    #[error("state_read_failed: {path}: {source}")]
    StateReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("frost_error: {0}")]
    Frost(redpallas::Error),
}
