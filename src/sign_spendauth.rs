use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use reddsa::frost::redpallas;
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroize;

use crate::config::ValidatedAdminConfig;
use crate::proto::v1 as pb;
use crate::storage;

const V0: &str = "v0";
const SESSION_VERSION: u32 = 1;
const DIR_SIGN_SPENDAUTH: &str = "sign_spendauth";
const DIR_SESSIONS: &str = "sessions";
const ENV_TEST_ABORT_AFTER_ACTION: &str = "DKG_ADMIN_TEST_ABORT_AFTER_ACTION";

#[derive(Debug, Clone)]
pub struct SignSpendAuthArgs {
    pub session_id: String,
    pub requests_path: PathBuf,
    pub out_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SignSpendAuthError {
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Runtime(String),
}

impl SignSpendAuthError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SignSpendAuthError::Validation(_) => 2,
            SignSpendAuthError::Runtime(_) => 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestV0 {
    sighash: String,
    action_index: u32,
    alpha: String,
    rk: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestsV0 {
    version: String,
    requests: Vec<SigningRequestV0>,
}

#[derive(Debug, Clone)]
struct NormalizedRequest {
    action_index: u32,
    sighash: [u8; 32],
    alpha: [u8; 32],
    rk: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
struct SpendAuthSigV0 {
    action_index: u32,
    spend_auth_sig: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SpendAuthSigSubmissionV0 {
    version: String,
    signatures: Vec<SpendAuthSigV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SessionStatusV1 {
    InProgress,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRecordV1 {
    session_version: u32,
    session_id_hex: String,
    request_set_hash_hex: String,
    status: SessionStatusV1,
    #[serde(default)]
    output_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestSetHashV0 {
    version: String,
    requests: Vec<RequestSetHashEntryV0>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestSetHashEntryV0 {
    action_index: u32,
    sighash: String,
    alpha: String,
    rk: String,
}

#[derive(Debug)]
enum SessionOpen {
    Resume,
    Completed { output_bytes: Vec<u8> },
}

pub async fn run(
    cfg: ValidatedAdminConfig,
    args: SignSpendAuthArgs,
) -> Result<(), SignSpendAuthError> {
    let session_id_hex = parse_session_id(&args.session_id)?;

    let requests_raw = std::fs::read(&args.requests_path).map_err(|_| {
        SignSpendAuthError::Validation(format!(
            "requests_read_failed: {}",
            args.requests_path.display()
        ))
    })?;
    let requests = parse_requests(&requests_raw)?;
    let request_set_hash_hex = hex::encode(request_set_hash(&requests)?);

    let sessions_dir = cfg
        .cfg
        .state_dir
        .join(DIR_SIGN_SPENDAUTH)
        .join(DIR_SESSIONS);
    let session_path = sessions_dir.join(format!("{session_id_hex}.json"));

    match open_or_init_session(&session_path, &session_id_hex, &request_set_hash_hex)? {
        SessionOpen::Completed { output_bytes } => {
            storage::write_file_0600_fsync(&args.out_path, &output_bytes).map_err(|_| {
                SignSpendAuthError::Runtime(format!(
                    "output_write_failed: {}",
                    args.out_path.display()
                ))
            })?;
            return Ok(());
        }
        SessionOpen::Resume => {}
    }

    let public_key_package = load_public_key_package(&cfg)?;
    let mut clients = connect_all_operators(&cfg).await?;

    let abort_after = parse_abort_after_action();
    let mut signatures = Vec::with_capacity(requests.len());
    for (idx, req) in requests.iter().enumerate() {
        let sig_bytes = sign_one_action(&cfg, &mut clients, &public_key_package, req).await?;
        signatures.push(SpendAuthSigV0 {
            action_index: req.action_index,
            spend_auth_sig: hex::encode(sig_bytes),
        });

        if abort_after.is_some() && abort_after == Some(idx + 1) {
            return Err(SignSpendAuthError::Runtime(
                "session_interrupted".to_string(),
            ));
        }
    }
    signatures.sort_by_key(|s| s.action_index);

    let out = SpendAuthSigSubmissionV0 {
        version: V0.to_string(),
        signatures,
    };

    let mut out_bytes = serde_json::to_vec(&out)
        .map_err(|_| SignSpendAuthError::Runtime("output_serialize_failed".to_string()))?;
    out_bytes.push(b'\n');

    let complete = SessionRecordV1 {
        session_version: SESSION_VERSION,
        session_id_hex: session_id_hex.clone(),
        request_set_hash_hex: request_set_hash_hex.clone(),
        status: SessionStatusV1::Complete,
        output_b64: Some(base64::engine::general_purpose::STANDARD.encode(&out_bytes)),
    };
    save_session(&session_path, &complete)?;

    storage::write_file_0600_fsync(&args.out_path, &out_bytes).map_err(|_| {
        SignSpendAuthError::Runtime(format!("output_write_failed: {}", args.out_path.display()))
    })?;

    out_bytes.zeroize();
    Ok(())
}

fn parse_abort_after_action() -> Option<usize> {
    let v = std::env::var(ENV_TEST_ABORT_AFTER_ACTION).ok()?;
    let t = v.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<usize>().ok().filter(|n| *n > 0)
}

fn parse_session_id(input: &str) -> Result<String, SignSpendAuthError> {
    let t = input.trim();
    if !t.starts_with("0x") {
        return Err(SignSpendAuthError::Validation(
            "session_id_invalid".to_string(),
        ));
    }
    let raw = &t[2..];
    let bytes = decode_hex_exact::<32>(raw, "session_id")?;
    Ok(hex::encode(bytes))
}

fn parse_requests(bytes: &[u8]) -> Result<Vec<NormalizedRequest>, SignSpendAuthError> {
    let parsed: SigningRequestsV0 = serde_json::from_slice(bytes)
        .map_err(|_| SignSpendAuthError::Validation("signing_requests_invalid".to_string()))?;

    if parsed.version != V0 {
        return Err(SignSpendAuthError::Validation(
            "signing_requests_version_invalid".to_string(),
        ));
    }
    if parsed.requests.is_empty() {
        return Err(SignSpendAuthError::Validation(
            "signing_requests_empty".to_string(),
        ));
    }

    let mut seen = BTreeSet::<u32>::new();
    let mut out = Vec::with_capacity(parsed.requests.len());
    for r in parsed.requests {
        if !seen.insert(r.action_index) {
            return Err(SignSpendAuthError::Validation(
                "duplicate_action_index".to_string(),
            ));
        }
        let sighash = decode_hex_exact::<32>(&r.sighash, "sighash")?;
        let alpha = decode_hex_exact::<32>(&r.alpha, "alpha")?;
        let rk = decode_hex_exact::<32>(&r.rk, "rk")?;
        out.push(NormalizedRequest {
            action_index: r.action_index,
            sighash,
            alpha,
            rk,
        });
    }

    out.sort_by_key(|r| r.action_index);
    Ok(out)
}

fn decode_hex_exact<const N: usize>(
    input: &str,
    label: &str,
) -> Result<[u8; N], SignSpendAuthError> {
    let t = input.trim();
    if t.len() != N * 2 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SignSpendAuthError::Validation(format!("{label}_invalid")));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(t, &mut out)
        .map_err(|_| SignSpendAuthError::Validation(format!("{label}_invalid")))?;
    Ok(out)
}

fn request_set_hash(requests: &[NormalizedRequest]) -> Result<[u8; 32], SignSpendAuthError> {
    let hash_input = RequestSetHashV0 {
        version: V0.to_string(),
        requests: requests
            .iter()
            .map(|r| RequestSetHashEntryV0 {
                action_index: r.action_index,
                sighash: hex::encode(r.sighash),
                alpha: hex::encode(r.alpha),
                rk: hex::encode(r.rk),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&hash_input).map_err(|_| {
        SignSpendAuthError::Runtime("request_set_hash_serialize_failed".to_string())
    })?;
    Ok(crate::hash::sha256(&bytes))
}

fn open_or_init_session(
    session_path: &Path,
    session_id_hex: &str,
    request_set_hash_hex: &str,
) -> Result<SessionOpen, SignSpendAuthError> {
    if session_path.exists() {
        let bytes = storage::read(session_path).map_err(|_| {
            SignSpendAuthError::Runtime(format!(
                "session_state_read_failed: {}",
                session_path.display()
            ))
        })?;
        let rec: SessionRecordV1 = serde_json::from_slice(&bytes).map_err(|_| {
            SignSpendAuthError::Runtime(format!(
                "session_state_parse_failed: {}",
                session_path.display()
            ))
        })?;
        if rec.session_version != SESSION_VERSION {
            return Err(SignSpendAuthError::Runtime(
                "session_state_version_invalid".to_string(),
            ));
        }
        if rec.session_id_hex != session_id_hex {
            return Err(SignSpendAuthError::Runtime("session_conflict".to_string()));
        }
        if rec.request_set_hash_hex != request_set_hash_hex {
            return Err(SignSpendAuthError::Runtime("session_conflict".to_string()));
        }
        match rec.status {
            SessionStatusV1::InProgress => Ok(SessionOpen::Resume),
            SessionStatusV1::Complete => {
                let output_b64 = rec.output_b64.ok_or_else(|| {
                    SignSpendAuthError::Runtime("session_output_missing".to_string())
                })?;
                let output_bytes = base64::engine::general_purpose::STANDARD
                    .decode(output_b64)
                    .map_err(|_| {
                        SignSpendAuthError::Runtime("session_output_decode_failed".to_string())
                    })?;
                Ok(SessionOpen::Completed { output_bytes })
            }
        }
    } else {
        let rec = SessionRecordV1 {
            session_version: SESSION_VERSION,
            session_id_hex: session_id_hex.to_string(),
            request_set_hash_hex: request_set_hash_hex.to_string(),
            status: SessionStatusV1::InProgress,
            output_b64: None,
        };
        save_session(session_path, &rec)?;
        Ok(SessionOpen::Resume)
    }
}

fn save_session(path: &Path, rec: &SessionRecordV1) -> Result<(), SignSpendAuthError> {
    let bytes = serde_json::to_vec(rec)
        .map_err(|_| SignSpendAuthError::Runtime("session_state_serialize_failed".to_string()))?;
    storage::write_file_0600_fsync(path, &bytes).map_err(|_| {
        SignSpendAuthError::Runtime(format!("session_state_write_failed: {}", path.display()))
    })?;
    Ok(())
}

fn load_public_key_package(
    cfg: &ValidatedAdminConfig,
) -> Result<reddsa::frost::redpallas::keys::PublicKeyPackage, SignSpendAuthError> {
    let path = cfg.cfg.state_dir.join("public_key_package.bin");
    let bytes = storage::read(&path).map_err(|_| {
        SignSpendAuthError::Runtime(format!(
            "public_key_package_read_failed: {}",
            path.display()
        ))
    })?;
    reddsa::frost::redpallas::keys::PublicKeyPackage::deserialize(&bytes).map_err(|_| {
        SignSpendAuthError::Runtime("public_key_package_deserialize_failed".to_string())
    })
}

async fn connect_all_operators(
    cfg: &ValidatedAdminConfig,
) -> Result<BTreeMap<u16, pb::dkg_admin_client::DkgAdminClient<Channel>>, SignSpendAuthError> {
    let grpc_cfg = cfg
        .cfg
        .grpc
        .as_ref()
        .ok_or_else(|| SignSpendAuthError::Runtime("grpc_config_missing".to_string()))?;

    let ca_pem = std::fs::read(&grpc_cfg.tls_ca_cert_pem_path).map_err(|_| {
        SignSpendAuthError::Runtime(format!(
            "tls_ca_cert_read_failed: {}",
            grpc_cfg.tls_ca_cert_pem_path.display()
        ))
    })?;

    let client_cert_path = grpc_cfg
        .tls_client_cert_pem_path
        .as_ref()
        .unwrap_or(&grpc_cfg.tls_server_cert_pem_path);
    let client_key_path = grpc_cfg
        .tls_client_key_pem_path
        .as_ref()
        .unwrap_or(&grpc_cfg.tls_server_key_pem_path);

    let client_cert_pem = std::fs::read(client_cert_path).map_err(|_| {
        SignSpendAuthError::Runtime(format!(
            "tls_client_cert_read_failed: {}",
            client_cert_path.display()
        ))
    })?;
    let client_key_pem = std::fs::read(client_key_path).map_err(|_| {
        SignSpendAuthError::Runtime(format!(
            "tls_client_key_read_failed: {}",
            client_key_path.display()
        ))
    })?;

    let mut clients = BTreeMap::<u16, pb::dkg_admin_client::DkgAdminClient<Channel>>::new();
    for assigned in &cfg.canonical_operators {
        let op = cfg
            .cfg
            .roster
            .operators
            .iter()
            .find(|o| o.operator_id.trim() == assigned.operator_id)
            .ok_or_else(|| {
                SignSpendAuthError::Runtime(format!(
                    "roster_operator_missing: {}",
                    assigned.operator_id
                ))
            })?;
        let endpoint = op.grpc_endpoint.clone().ok_or_else(|| {
            SignSpendAuthError::Runtime(format!("grpc_endpoint_missing: {}", assigned.operator_id))
        })?;

        match connect_admin(
            &endpoint,
            &ca_pem,
            &client_cert_pem,
            &client_key_pem,
            grpc_cfg.tls_domain_name_override.as_deref(),
        )
        .await
        {
            Ok(client) => {
                clients.insert(assigned.identifier.0, client);
            }
            Err(SignSpendAuthError::Runtime(msg)) if msg == "grpc_connect_failed" => {
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(clients)
}

async fn connect_admin(
    endpoint: &str,
    ca_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
    domain_override: Option<&str>,
) -> Result<pb::dkg_admin_client::DkgAdminClient<Channel>, SignSpendAuthError> {
    let ca = Certificate::from_pem(ca_pem);
    let ident = Identity::from_pem(client_cert_pem, client_key_pem);

    let ep = Endpoint::from_shared(endpoint.to_string())
        .map_err(|_| SignSpendAuthError::Runtime("grpc_endpoint_invalid".to_string()))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true);

    let uri = endpoint
        .parse::<http::Uri>()
        .map_err(|_| SignSpendAuthError::Runtime("grpc_endpoint_invalid".to_string()))?;
    let default_domain = uri
        .host()
        .ok_or_else(|| SignSpendAuthError::Runtime("grpc_endpoint_invalid".to_string()))?;
    let domain = domain_override.unwrap_or(default_domain);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(ident)
        .domain_name(domain.to_string());

    let ep = ep
        .tls_config(tls)
        .map_err(|_| SignSpendAuthError::Runtime("grpc_tls_config_failed".to_string()))?;
    let channel = ep
        .connect()
        .await
        .map_err(|_| SignSpendAuthError::Runtime("grpc_connect_failed".to_string()))?;
    Ok(pb::dkg_admin_client::DkgAdminClient::new(channel))
}

async fn sign_one_action(
    cfg: &ValidatedAdminConfig,
    clients: &mut BTreeMap<u16, pb::dkg_admin_client::DkgAdminClient<Channel>>,
    public_key_package: &redpallas::keys::PublicKeyPackage,
    req: &NormalizedRequest,
) -> Result<[u8; 64], SignSpendAuthError> {
    let randomizer = redpallas::Randomizer::deserialize(&req.alpha)
        .map_err(|_| SignSpendAuthError::Validation("alpha_invalid".to_string()))?;

    let randomized_params = redpallas::RandomizedParams::from_randomizer(
        public_key_package.verifying_key(),
        randomizer,
    );

    let rk_expected = randomized_params
        .randomized_verifying_key()
        .serialize()
        .map_err(|_| SignSpendAuthError::Runtime("rk_serialize_failed".to_string()))?;
    if rk_expected != req.rk {
        return Err(SignSpendAuthError::Validation("rk_mismatch".to_string()));
    }

    let threshold = cfg.cfg.threshold as usize;
    let mut excluded = BTreeSet::<u16>::new();

    for _attempt in 0..(cfg.cfg.max_signers as usize) {
        let candidate_ids = clients
            .keys()
            .copied()
            .filter(|id| !excluded.contains(id))
            .collect::<Vec<_>>();

        if candidate_ids.len() < threshold {
            return Err(SignSpendAuthError::Runtime(format!(
                "threshold_unmet: need={threshold} have={}",
                candidate_ids.len()
            )));
        }

        let mut commitments_by_signer = BTreeMap::<u16, Vec<u8>>::new();
        let mut commit_failed = vec![];
        for id in candidate_ids {
            let Some(client) = clients.get_mut(&id) else {
                continue;
            };

            match client
                .smoke_sign_commit(tonic::Request::new(pb::SmokeSignCommitRequest {
                    ceremony_hash: cfg.ceremony_hash_hex.clone(),
                    message: req.sighash.to_vec(),
                    alpha: req.alpha.to_vec(),
                }))
                .await
            {
                Ok(resp) => {
                    commitments_by_signer.insert(id, resp.into_inner().signing_commitments);
                }
                Err(_) => commit_failed.push(id),
            }
        }

        if commitments_by_signer.len() < threshold {
            for id in commit_failed {
                excluded.insert(id);
            }
            continue;
        }

        let selected_ids = commitments_by_signer
            .keys()
            .copied()
            .take(threshold)
            .collect::<Vec<_>>();

        let mut selected_commitments = BTreeMap::<u16, Vec<u8>>::new();
        for id in &selected_ids {
            if let Some(bytes) = commitments_by_signer.remove(id) {
                selected_commitments.insert(*id, bytes);
            }
        }

        let signing_package_bytes =
            crate::smoke::make_signing_package(selected_commitments, &req.sighash).map_err(
                |_| SignSpendAuthError::Runtime("signing_package_build_failed".to_string()),
            )?;
        let signing_package = redpallas::SigningPackage::deserialize(&signing_package_bytes)
            .map_err(|_| {
                SignSpendAuthError::Runtime("signing_package_deserialize_failed".to_string())
            })?;

        let mut sig_shares = BTreeMap::new();
        let mut share_failed = vec![];
        for id in selected_ids {
            let Some(client) = clients.get_mut(&id) else {
                share_failed.push(id);
                continue;
            };

            match client
                .smoke_sign_share(tonic::Request::new(pb::SmokeSignShareRequest {
                    ceremony_hash: cfg.ceremony_hash_hex.clone(),
                    signing_package: signing_package_bytes.clone(),
                    alpha: req.alpha.to_vec(),
                }))
                .await
            {
                Ok(resp) => {
                    let mut bytes = resp.into_inner().signature_share;
                    let share =
                        redpallas::round2::SignatureShare::deserialize(&bytes).map_err(|_| {
                            SignSpendAuthError::Runtime("signature_share_invalid".to_string())
                        })?;
                    bytes.zeroize();
                    let ident: redpallas::Identifier = id.try_into().map_err(|_| {
                        SignSpendAuthError::Runtime("identifier_invalid".to_string())
                    })?;
                    sig_shares.insert(ident, share);
                }
                Err(_) => share_failed.push(id),
            }
        }

        if !share_failed.is_empty() {
            for id in share_failed {
                excluded.insert(id);
            }
            continue;
        }

        let sig = redpallas::aggregate(
            &signing_package,
            &sig_shares,
            public_key_package,
            &randomized_params,
        )
        .map_err(|_| SignSpendAuthError::Runtime("aggregate_failed".to_string()))?;

        randomized_params
            .randomized_verifying_key()
            .verify(&req.sighash, &sig)
            .map_err(|_| SignSpendAuthError::Runtime("signature_verify_failed".to_string()))?;

        let sig_bytes_vec = sig
            .serialize()
            .map_err(|_| SignSpendAuthError::Runtime("signature_serialize_failed".to_string()))?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_bytes_vec);
        return Ok(sig_bytes);
    }

    Err(SignSpendAuthError::Runtime(format!(
        "threshold_unmet: need={threshold} have=0"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn req_json(requests: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "v0",
            "requests": requests
        }))
        .unwrap()
    }

    #[test]
    fn parse_requests_rejects_unknown_fields() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": "v0",
            "requests": [{
                "sighash": "11".repeat(32),
                "action_index": 0,
                "alpha": "22".repeat(32),
                "rk": "33".repeat(32),
                "extra": true
            }]
        }))
        .unwrap();
        let err = parse_requests(&bytes).unwrap_err();
        assert!(matches!(err, SignSpendAuthError::Validation(_)));
    }

    #[test]
    fn parse_requests_rejects_duplicate_action_index() {
        let bytes = req_json(serde_json::json!([
            {
                "sighash": "11".repeat(32),
                "action_index": 9,
                "alpha": "22".repeat(32),
                "rk": "33".repeat(32)
            },
            {
                "sighash": "44".repeat(32),
                "action_index": 9,
                "alpha": "55".repeat(32),
                "rk": "66".repeat(32)
            }
        ]));
        let err = parse_requests(&bytes).unwrap_err();
        assert_eq!(err.to_string(), "duplicate_action_index");
    }

    #[test]
    fn parse_requests_sorts_by_action_index() {
        let bytes = req_json(serde_json::json!([
            {
                "sighash": "11".repeat(32),
                "action_index": 5,
                "alpha": "22".repeat(32),
                "rk": "33".repeat(32)
            },
            {
                "sighash": "44".repeat(32),
                "action_index": 1,
                "alpha": "55".repeat(32),
                "rk": "66".repeat(32)
            }
        ]));
        let parsed = parse_requests(&bytes).unwrap();
        assert_eq!(parsed[0].action_index, 1);
        assert_eq!(parsed[1].action_index, 5);
    }

    #[test]
    fn parse_session_id_requires_strict_format() {
        assert!(parse_session_id("abcd").is_err());
        assert!(parse_session_id("0x11").is_err());
        assert!(parse_session_id(
            "0X1111111111111111111111111111111111111111111111111111111111111111"
        )
        .is_err());
        assert!(parse_session_id(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        )
        .is_ok());
    }

    #[test]
    fn session_conflict_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let session_path = tmp.path().join("s.json");

        let rec = SessionRecordV1 {
            session_version: SESSION_VERSION,
            session_id_hex: "11".repeat(32),
            request_set_hash_hex: "aa".repeat(32),
            status: SessionStatusV1::InProgress,
            output_b64: None,
        };
        save_session(&session_path, &rec).unwrap();

        let err =
            open_or_init_session(&session_path, &"11".repeat(32), &"bb".repeat(32)).unwrap_err();
        assert_eq!(err.to_string(), "session_conflict");
    }
}
