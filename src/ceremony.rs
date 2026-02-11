use crate::config::Network;

pub const CEREMONY_HASH_DOMAIN_V1: &[u8] = b"junocash_dkg_ceremony_v1";

pub fn ceremony_hash_hex_v1(
    network: Network,
    threshold: u16,
    max_signers: u16,
    roster_hash_hex: &str,
    ceremony_id: &uuid::Uuid,
) -> Result<String, CeremonyHashError> {
    let roster_hash = hex::decode(roster_hash_hex.trim()).map_err(|_| CeremonyHashError::RosterHashHexInvalid)?;
    if roster_hash.len() != 32 {
        return Err(CeremonyHashError::RosterHashLenInvalid(roster_hash.len()));
    }

    let mut buf = Vec::with_capacity(
        CEREMONY_HASH_DOMAIN_V1.len() + network.as_str().len() + 2 + 2 + roster_hash.len() + 16,
    );
    buf.extend_from_slice(CEREMONY_HASH_DOMAIN_V1);
    buf.extend_from_slice(network.as_str().as_bytes());
    buf.extend_from_slice(&threshold.to_le_bytes());
    buf.extend_from_slice(&max_signers.to_le_bytes());
    buf.extend_from_slice(&roster_hash);
    buf.extend_from_slice(ceremony_id.as_bytes());

    Ok(crate::hash::sha256_hex(&buf))
}

#[derive(Debug, thiserror::Error)]
pub enum CeremonyHashError {
    #[error("roster_hash_hex_invalid")]
    RosterHashHexInvalid,
    #[error("roster_hash_len_invalid: {0}")]
    RosterHashLenInvalid(usize),
}
