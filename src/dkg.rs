use std::collections::BTreeMap;
use std::path::PathBuf;

use rand_core::{CryptoRng, RngCore};
use reddsa::frost::redpallas;
use reddsa::frost::redpallas::keys::EvenY;

use crate::config::ValidatedAdminConfig;
use crate::crypto;
use crate::hash;
use crate::storage;

const FILE_ROUND1_SECRET: &str = "round1_secret.bin";
const FILE_ROUND1_PACKAGE: &str = "round1_package.bin";
const FILE_ROUND2_SECRET: &str = "round2_secret.bin";
const FILE_KEY_PACKAGE: &str = "key_package.bin";
const FILE_PUBLIC_KEY_PACKAGE: &str = "public_key_package.bin";
const FILE_PUBLIC_KEY_PACKAGE_HASH: &str = "public_key_package_hash.hex";
const FILE_AK_BYTES: &str = "ak_bytes.hex";

#[derive(Debug, Clone)]
pub struct AdminDkg {
    cfg: ValidatedAdminConfig,
}

#[derive(Debug, Clone)]
pub struct Part1Output {
    pub round1_package_bytes: Vec<u8>,
    pub round1_package_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Part2Output {
    pub round2_packages: BTreeMap<u16, Round2PackageOut>,
}

#[derive(Debug, Clone)]
pub struct Round2PackageOut {
    pub package_bytes: Vec<u8>,
    pub package_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Part3Output {
    pub public_key_package_bytes: Vec<u8>,
    pub public_key_package_hash: [u8; 32],
    pub ak_bytes: [u8; 32],
    pub canonicalized: bool,
}

impl AdminDkg {
    pub fn new(cfg: ValidatedAdminConfig) -> Self {
        Self { cfg }
    }

    pub fn state_dir(&self) -> &std::path::Path {
        &self.cfg.cfg.state_dir
    }

    pub fn part1<R: RngCore + CryptoRng>(&self, rng: R) -> Result<Part1Output, DkgError> {
        let identifier: redpallas::Identifier = self
            .cfg
            .cfg
            .identifier
            .try_into()
            .map_err(|_| DkgError::IdentifierInvalid(self.cfg.cfg.identifier))?;

        let (secret, pkg) = redpallas::keys::dkg::part1(
            identifier,
            self.cfg.cfg.max_signers,
            self.cfg.cfg.threshold,
            rng,
        )
        .map_err(DkgError::Dkg)?;

        let secret_bytes = secret.serialize().map_err(DkgError::Dkg)?;
        storage::write_file_0600_fsync(&self.state_dir().join(FILE_ROUND1_SECRET), &secret_bytes)
            .map_err(DkgError::StateWriteFailed)?;

        let pkg_bytes = pkg.serialize().map_err(DkgError::Dkg)?;
        storage::write_file_0600_fsync(&self.state_dir().join(FILE_ROUND1_PACKAGE), &pkg_bytes)
            .map_err(DkgError::StateWriteFailed)?;

        Ok(Part1Output {
            round1_package_hash: hash::sha256(&pkg_bytes),
            round1_package_bytes: pkg_bytes,
        })
    }

    pub fn part2(
        &self,
        round1_packages: BTreeMap<u16, Vec<u8>>,
    ) -> Result<Part2Output, DkgError> {
        let secret_path = self.state_dir().join(FILE_ROUND1_SECRET);
        let secret_bytes = storage::read(&secret_path).map_err(|e| DkgError::StateReadFailed {
            path: secret_path,
            source: e,
        })?;
        let secret =
            redpallas::keys::dkg::round1::SecretPackage::deserialize(&secret_bytes).map_err(DkgError::Dkg)?;

        let mut parsed = BTreeMap::new();
        for (sender_u16, bytes) in round1_packages {
            let sender: redpallas::Identifier =
                sender_u16.try_into().map_err(|_| DkgError::IdentifierInvalid(sender_u16))?;
            let pkg = redpallas::keys::dkg::round1::Package::deserialize(&bytes)
                .map_err(DkgError::Dkg)?;
            parsed.insert(sender, pkg);
        }

        let (round2_secret, round2_packages) =
            redpallas::keys::dkg::part2(secret, &parsed).map_err(DkgError::Dkg)?;

        let round2_secret_bytes = round2_secret.serialize().map_err(DkgError::Dkg)?;
        storage::write_file_0600_fsync(
            &self.state_dir().join(FILE_ROUND2_SECRET),
            &round2_secret_bytes,
        )
        .map_err(DkgError::StateWriteFailed)?;

        let mut out = BTreeMap::new();
        for (receiver_id, pkg) in round2_packages {
            let receiver_u16 = identifier_to_u16(&receiver_id, self.cfg.cfg.max_signers)?;
            let bytes = pkg.serialize().map_err(DkgError::Dkg)?;
            out.insert(
                receiver_u16,
                Round2PackageOut {
                    package_hash: hash::sha256(&bytes),
                    package_bytes: bytes,
                },
            );
        }

        Ok(Part2Output { round2_packages: out })
    }

    pub fn part3(
        &self,
        round1_packages: BTreeMap<u16, Vec<u8>>,
        round2_packages: BTreeMap<u16, Vec<u8>>,
    ) -> Result<Part3Output, DkgError> {
        let round2_secret_path = self.state_dir().join(FILE_ROUND2_SECRET);
        let round2_secret_bytes =
            storage::read(&round2_secret_path).map_err(|e| DkgError::StateReadFailed {
                path: round2_secret_path,
                source: e,
            })?;
        let round2_secret = redpallas::keys::dkg::round2::SecretPackage::deserialize(&round2_secret_bytes)
            .map_err(DkgError::Dkg)?;

        let mut parsed_r1 = BTreeMap::new();
        for (sender_u16, bytes) in round1_packages {
            let sender: redpallas::Identifier =
                sender_u16.try_into().map_err(|_| DkgError::IdentifierInvalid(sender_u16))?;
            let pkg = redpallas::keys::dkg::round1::Package::deserialize(&bytes)
                .map_err(DkgError::Dkg)?;
            parsed_r1.insert(sender, pkg);
        }

        let mut parsed_r2 = BTreeMap::new();
        for (sender_u16, bytes) in round2_packages {
            let sender: redpallas::Identifier =
                sender_u16.try_into().map_err(|_| DkgError::IdentifierInvalid(sender_u16))?;
            let pkg =
                redpallas::keys::dkg::round2::Package::deserialize(&bytes).map_err(DkgError::Dkg)?;
            parsed_r2.insert(sender, pkg);
        }

        let (key_package, public_key_package) =
            redpallas::keys::dkg::part3(&round2_secret, &parsed_r1, &parsed_r2)
                .map_err(DkgError::Dkg)?;

        let canonicalized = public_key_package.has_even_y();

        let key_package_bytes = key_package.serialize().map_err(DkgError::Dkg)?;
        storage::write_file_0600_fsync(&self.state_dir().join(FILE_KEY_PACKAGE), &key_package_bytes)
            .map_err(DkgError::StateWriteFailed)?;

        let public_key_package_bytes = public_key_package.serialize().map_err(DkgError::Dkg)?;
        storage::write_file_0600_fsync(
            &self.state_dir().join(FILE_PUBLIC_KEY_PACKAGE),
            &public_key_package_bytes,
        )
        .map_err(DkgError::StateWriteFailed)?;

        let pk_hash =
            crypto::public_key_package_hash(&public_key_package, self.cfg.cfg.max_signers)
                .map_err(DkgError::Crypto)?;
        storage::write_file_0600_fsync(
            &self.state_dir().join(FILE_PUBLIC_KEY_PACKAGE_HASH),
            hex::encode(pk_hash).as_bytes(),
        )
        .map_err(DkgError::StateWriteFailed)?;

        let ak_bytes = crypto::ak_bytes_from_public_key_package(&public_key_package)
            .map_err(DkgError::Crypto)?;
        storage::write_file_0600_fsync(
            &self.state_dir().join(FILE_AK_BYTES),
            hex::encode(ak_bytes).as_bytes(),
        )
        .map_err(DkgError::StateWriteFailed)?;

        Ok(Part3Output {
            public_key_package_hash: pk_hash,
            public_key_package_bytes,
            ak_bytes,
            canonicalized,
        })
    }
}

fn identifier_to_u16(id: &redpallas::Identifier, max_signers: u16) -> Result<u16, DkgError> {
    // Identifiers are scalar field elements. For our ceremony we restrict to u16 assignments,
    // so we can serialize and recover the original u16 by checking against all expected ids.
    //
    // We only need this conversion for routing round2 outputs. Use serialize() and match on a
    // small table of 1..=65535 to avoid relying on internal scalar representations.
    let serialized = id.serialize();
    for n in 1u16..=max_signers {
        let cand: redpallas::Identifier = n
            .try_into()
            .map_err(|_| DkgError::IdentifierInvalid(n))?;
        if cand.serialize() == serialized {
            return Ok(n);
        }
    }
    Err(DkgError::IdentifierNotU16)
}

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("identifier_invalid: {0}")]
    IdentifierInvalid(u16),
    #[error("identifier_not_u16")]
    IdentifierNotU16,
    #[error("dkg_error: {0}")]
    Dkg(redpallas::Error),
    #[error("crypto_error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("state_write_failed: {0}")]
    StateWriteFailed(std::io::Error),
    #[error("state_read_failed: {path}: {source}")]
    StateReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
