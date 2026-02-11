use std::path::PathBuf;

use dkg_admin::config::{AdminConfigV1, ConfigError, Network};
use dkg_admin::roster::{RosterOperatorV1, RosterV1};

fn make_roster() -> RosterV1 {
    RosterV1 {
        roster_version: 1,
        operators: vec![
            RosterOperatorV1 {
                operator_id: "0xbbb".to_string(),
                grpc_endpoint: None,
                age_recipient: None,
            },
            RosterOperatorV1 {
                operator_id: "0xaaa".to_string(),
                grpc_endpoint: None,
                age_recipient: None,
            },
            RosterOperatorV1 {
                operator_id: "0xccc".to_string(),
                grpc_endpoint: None,
                age_recipient: None,
            },
        ],
        coordinator_age_recipient: None,
    }
}

#[test]
fn validate_rejects_identifier_mismatch() {
    let roster = make_roster();
    let roster_hash_hex = roster.roster_hash_hex().unwrap();

    let cfg = AdminConfigV1 {
        config_version: 1,
        ceremony_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        operator_id: "0xbbb".to_string(),
        identifier: 1, // should be 2 after sorting
        threshold: 2,
        max_signers: 3,
        network: Network::Regtest,
        roster,
        roster_hash_hex,
        state_dir: PathBuf::from("state"),
        age_identity_file: None,
        grpc: None,
    };

    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::IdentifierMismatch { .. }));
}

#[test]
fn validate_rejects_roster_hash_mismatch() {
    let roster = make_roster();

    let cfg = AdminConfigV1 {
        config_version: 1,
        ceremony_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        operator_id: "0xaaa".to_string(),
        identifier: 1,
        threshold: 2,
        max_signers: 3,
        network: Network::Regtest,
        roster,
        roster_hash_hex: "00".to_string(),
        state_dir: PathBuf::from("state"),
        age_identity_file: None,
        grpc: None,
    };

    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::RosterHashMismatch { .. }));
}
