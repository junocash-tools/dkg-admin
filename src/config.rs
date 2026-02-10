use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::roster::{AssignedIdentifier, AssignedOperator, RosterError, RosterV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfigV1 {
    pub config_version: u32,

    pub operator_id: String,
    pub identifier: u16,

    pub threshold: u16,
    pub max_signers: u16,
    pub network: Network,

    pub roster: RosterV1,
    pub roster_hash_hex: String,

    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,

    /// Optional age identity file to decrypt offline ceremony inputs (Round 2 packages)
    /// and to encrypt exports in age mode.
    #[serde(default)]
    pub age_identity_file: Option<PathBuf>,

    #[serde(default)]
    pub grpc: Option<GrpcConfigV1>,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("state")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfigV1 {
    pub listen_addr: String,

    pub tls_ca_cert_pem_path: PathBuf,
    pub tls_server_cert_pem_path: PathBuf,
    pub tls_server_key_pem_path: PathBuf,

    /// Optional hex SHA256 of the coordinator client certificate DER.
    /// If set, requests from other clients are rejected even if they chain to the CA.
    #[serde(default)]
    pub coordinator_client_cert_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedAdminConfig {
    pub cfg: AdminConfigV1,
    pub canonical_operators: Vec<AssignedOperator>,
}

impl AdminConfigV1 {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|e| ConfigError::ReadFailed {
            path: path.to_path_buf(),
            source: e,
        })?;
        serde_json::from_slice(&bytes).map_err(|e| ConfigError::ParseFailed {
            path: path.to_path_buf(),
            source: e,
        })
    }

    pub fn validate(self) -> Result<ValidatedAdminConfig, ConfigError> {
        if self.config_version != 1 {
            return Err(ConfigError::ConfigVersionUnsupported(self.config_version));
        }

        if !(1 < self.threshold && self.threshold <= self.max_signers) {
            return Err(ConfigError::ThresholdInvalid {
                threshold: self.threshold,
                max_signers: self.max_signers,
            });
        }

        let operator_id = self.operator_id.trim();
        if operator_id.is_empty() {
            return Err(ConfigError::OperatorIdEmpty);
        }

        let roster_hash = self
            .roster
            .roster_hash_hex()
            .map_err(ConfigError::Roster)?;
        if roster_hash != self.roster_hash_hex.trim() {
            return Err(ConfigError::RosterHashMismatch {
                expected: self.roster_hash_hex,
                got: roster_hash,
            });
        }

        let canonical_operators = self
            .roster
            .canonical_operators()
            .map_err(ConfigError::Roster)?;
        if canonical_operators.len() != self.max_signers as usize {
            return Err(ConfigError::MaxSignersMismatch {
                expected: self.max_signers,
                got: canonical_operators.len() as u16,
            });
        }

        let expected_identifier = canonical_operators
            .iter()
            .find(|o| o.operator_id == operator_id)
            .map(|o| o.identifier)
            .ok_or_else(|| ConfigError::OperatorNotInRoster(operator_id.to_string()))?;
        if expected_identifier.0 != self.identifier {
            return Err(ConfigError::IdentifierMismatch {
                expected: expected_identifier.0,
                got: self.identifier,
            });
        }

        // Ensure identifier is non-zero (FROST Identifier invariant).
        if AssignedIdentifier(self.identifier).0 == 0 {
            return Err(ConfigError::IdentifierZero);
        }

        Ok(ValidatedAdminConfig {
            cfg: AdminConfigV1 {
                operator_id: operator_id.to_string(),
                roster_hash_hex: self.roster_hash_hex.trim().to_string(),
                ..self
            },
            canonical_operators,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read_failed: {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse_failed: {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("config_version_unsupported: {0}")]
    ConfigVersionUnsupported(u32),
    #[error("operator_id_empty")]
    OperatorIdEmpty,
    #[error("operator_not_in_roster: {0}")]
    OperatorNotInRoster(String),
    #[error("identifier_zero")]
    IdentifierZero,
    #[error("identifier_mismatch: expected={expected} got={got}")]
    IdentifierMismatch { expected: u16, got: u16 },
    #[error("threshold_invalid: threshold={threshold} max_signers={max_signers}")]
    ThresholdInvalid { threshold: u16, max_signers: u16 },
    #[error("max_signers_mismatch: expected={expected} got={got}")]
    MaxSignersMismatch { expected: u16, got: u16 },
    #[error("roster_hash_mismatch: expected={expected} got={got}")]
    RosterHashMismatch { expected: String, got: String },
    #[error("{0}")]
    Roster(#[from] RosterError),
}

