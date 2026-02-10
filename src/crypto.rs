use reddsa::frost::redpallas;

use crate::hash;

pub fn ak_bytes_from_public_key_package(
    pubkeys: &redpallas::keys::PublicKeyPackage,
) -> Result<[u8; 32], CryptoError> {
    let vk = pubkeys.verifying_key();
    let bytes = vk
        .serialize()
        .map_err(|_| CryptoError::PublicKeySerializeFailed)?;
    let ak: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::PublicKeyBytesLenInvalid)?;
    Ok(ak)
}

pub fn is_canonical_ak_bytes(ak_bytes: &[u8; 32]) -> bool {
    (ak_bytes[31] & 0x80) == 0
}

pub fn public_key_package_hash(
    pubkeys: &redpallas::keys::PublicKeyPackage,
    max_signers: u16,
) -> Result<[u8; 32], CryptoError> {
    let ak_bytes = ak_bytes_from_public_key_package(pubkeys)?;

    let mut buf = Vec::with_capacity(32 + (max_signers as usize) * (2 + 32) + 64);
    buf.extend_from_slice(b"junocash_pubkeypkg_v1");
    buf.extend_from_slice(&ak_bytes);

    let shares = pubkeys.verifying_shares();
    for id in 1..=max_signers {
        let identifier: redpallas::Identifier = id
            .try_into()
            .map_err(|_| CryptoError::IdentifierInvalid(id))?;
        let share = shares
            .get(&identifier)
            .ok_or(CryptoError::VerifyingShareMissing(id))?;
        let share_bytes = share
            .serialize()
            .map_err(|_| CryptoError::VerifyingShareSerializeFailed)?;
        let share_bytes: [u8; 32] = share_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::VerifyingShareBytesLenInvalid)?;
        buf.extend_from_slice(&id.to_le_bytes());
        buf.extend_from_slice(&share_bytes);
    }

    Ok(hash::sha256(&buf))
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("public_key_serialize_failed")]
    PublicKeySerializeFailed,
    #[error("public_key_bytes_len_invalid")]
    PublicKeyBytesLenInvalid,
    #[error("identifier_invalid: {0}")]
    IdentifierInvalid(u16),
    #[error("verifying_share_missing: {0}")]
    VerifyingShareMissing(u16),
    #[error("verifying_share_serialize_failed")]
    VerifyingShareSerializeFailed,
    #[error("verifying_share_bytes_len_invalid")]
    VerifyingShareBytesLenInvalid,
}

