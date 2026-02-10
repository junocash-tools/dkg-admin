use serde::{Deserialize, Serialize};

use crate::hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterV1 {
    pub roster_version: u32,
    pub operators: Vec<RosterOperatorV1>,

    /// Optional offline-ceremony coordinator age recipient (age1...).
    ///
    /// If present, operators can encrypt Round 2 packages to the coordinator for routing.
    #[serde(default)]
    pub coordinator_age_recipient: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterOperatorV1 {
    pub operator_id: String,

    #[serde(default)]
    pub grpc_endpoint: Option<String>,

    #[serde(default)]
    pub age_recipient: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssignedIdentifier(pub u16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedOperator {
    pub operator_id: String,
    pub identifier: AssignedIdentifier,
}

impl RosterV1 {
    pub fn canonical_operators(&self) -> Result<Vec<AssignedOperator>, RosterError> {
        if self.operators.is_empty() {
            return Err(RosterError::OperatorsEmpty);
        }
        if self.operators.len() > (u16::MAX as usize) {
            return Err(RosterError::TooManyOperators);
        }

        let mut ops = self
            .operators
            .iter()
            .map(|o| o.operator_id.trim().to_string())
            .collect::<Vec<_>>();
        ops.sort();
        ops.dedup();
        if ops.len() != self.operators.len() {
            return Err(RosterError::DuplicateOperatorId);
        }

        Ok(ops
            .into_iter()
            .enumerate()
            .map(|(i, operator_id)| AssignedOperator {
                operator_id,
                identifier: AssignedIdentifier((i + 1) as u16),
            })
            .collect())
    }

    /// Computes the roster hash used for identity pinning.
    ///
    /// Hash input is a stable JSON structure with operators sorted by operator_id.
    pub fn roster_hash_hex(&self) -> Result<String, RosterError> {
        let mut ops = self
            .operators
            .iter()
            .map(|o| RosterOperatorHashV1 {
                operator_id: o.operator_id.trim().to_string(),
                grpc_endpoint: o.grpc_endpoint.clone().map(|s| s.trim().to_string()),
                age_recipient: o.age_recipient.clone().map(|s| s.trim().to_string()),
            })
            .collect::<Vec<_>>();
        ops.sort_by(|a, b| a.operator_id.cmp(&b.operator_id));

        let v = RosterHashV1 {
            roster_version: self.roster_version,
            operators: ops,
            coordinator_age_recipient: self
                .coordinator_age_recipient
                .clone()
                .map(|s| s.trim().to_string()),
        };

        let bytes = serde_json::to_vec(&v).map_err(|_| RosterError::RosterHashSerializeFailed)?;
        Ok(hash::sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct RosterHashV1 {
    roster_version: u32,
    operators: Vec<RosterOperatorHashV1>,

    #[serde(skip_serializing_if = "Option::is_none")]
    coordinator_age_recipient: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct RosterOperatorHashV1 {
    operator_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    grpc_endpoint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    age_recipient: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RosterError {
    #[error("operators_empty")]
    OperatorsEmpty,
    #[error("too_many_operators")]
    TooManyOperators,
    #[error("duplicate_operator_id")]
    DuplicateOperatorId,
    #[error("roster_hash_serialize_failed")]
    RosterHashSerializeFailed,
}

