//! Opt-in signing policy enforced by every `serve` peer before it contributes a
//! commitment or a signature share for a spend-authorization signature.
//!
//! The coordinator sends the full txplan, the prepared transaction produced by
//! `juno-txsign ext-prepare` and the signing requests. Each peer:
//! - recomputes the Orchard sighash from the prepared PCZT effects and checks it
//!   against every requested sighash, rk and alpha;
//! - binds the requested spends to the plan notes (decrypted with the policy
//!   UFVK, nullifiers must match exactly);
//! - recovers every output it can decrypt with its OVKs and requires them to be
//!   exactly the plan outputs plus the change output;
//! - enforces change address, fee cap and spend count limits;
//! - runs an external verifier command for the non-change outputs.
//!
//! Only approved `(sighash, alpha)` pairs can be committed to and signed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use ff::PrimeField;
use orchard::bundle::EffectsOnly;
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note::{ExtractedNoteCommitment, Nullifier};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use orchard::Address;
use reddsa::frost::redpallas;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes};
use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{TransactionData, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::value::ZatBalance;

use crate::config::Network;
use crate::zip316;

pub const POLICY_VERSION_V1: &str = "v1";
pub const VERIFIER_CONTEXT_VERSION_V1: &str = "v1";
pub const DEFAULT_MAX_FEE_ZAT: u64 = 10_000_000;
pub const DEFAULT_MAX_SPENDS: u32 = 200;
pub const DEFAULT_VERIFIER_TIMEOUT_SECS: u64 = 20;
/// The coordinator uses a 30s per-call gRPC timeout; keep the verifier below it.
pub const MAX_VERIFIER_TIMEOUT_SECS: u64 = 25;
pub const DEFAULT_APPROVAL_TTL_SECS: u64 = 300;
pub const MAX_APPROVAL_TTL_SECS: u64 = 3600;
pub const MAX_APPROVALS: usize = 4096;
pub const POLICY_REJECTED: &str = "policy_rejected";

/// Plans with more outputs than this are rejected (same limit as juno-txsign).
pub const MAX_OUTPUTS: usize = 200;
/// Concurrent approvals (evaluation + verifier) per peer.
pub const MAX_CONCURRENT_APPROVALS: usize = 4;

const TYPECODE_ORCHARD: u64 = 0x03;
const MAX_STDERR_IN_REASON: usize = 512;
const MAX_STDERR_CAPTURE: usize = 64 * 1024;
const STDERR_DRAIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignPolicyFileV1 {
    pub version: String,
    /// UFVK of the DKG wallet. Its spend validating key must equal the group key.
    pub ufvk: String,
    /// Required change address (must belong to `ufvk`).
    pub change_address: String,
    #[serde(default)]
    pub max_fee_zat: Option<u64>,
    #[serde(default)]
    pub max_spends: Option<u32>,
    /// argv of the external verifier. It gets the verifier context JSON on stdin;
    /// exit code 0 allows the spend, anything else rejects it.
    pub verifier_cmd: Vec<String>,
    /// Extra environment for the verifier. The verifier does not inherit the
    /// peer's environment; only PATH is passed through.
    #[serde(default)]
    pub verifier_env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub verifier_timeout_secs: Option<u64>,
    #[serde(default)]
    pub approval_ttl_secs: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SignPolicyConfigError(pub String);

/// Reason a signing request was refused by policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRejection {
    pub code: &'static str,
    pub detail: String,
}

impl PolicyRejection {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn code(code: &'static str) -> Self {
        Self::new(code, String::new())
    }
}

impl fmt::Display for PolicyRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignPolicy {
    network: Network,
    fvk: FullViewingKey,
    change_address: Address,
    change_address_str: String,
    max_fee_zat: u64,
    max_spends: u32,
    verifier_cmd: Vec<String>,
    verifier_env: BTreeMap<String, String>,
    verifier_timeout: Duration,
    approval_ttl: Duration,
}

impl SignPolicy {
    pub fn from_path(path: &Path, network: Network) -> Result<Self, SignPolicyConfigError> {
        let bytes = std::fs::read(path).map_err(|e| {
            SignPolicyConfigError(format!("sign_policy_read_failed: {}: {e}", path.display()))
        })?;
        let file: SignPolicyFileV1 = serde_json::from_slice(&bytes)
            .map_err(|e| SignPolicyConfigError(format!("sign_policy_invalid: {e}")))?;
        Self::from_file(file, network)
    }

    pub fn from_file(
        file: SignPolicyFileV1,
        network: Network,
    ) -> Result<Self, SignPolicyConfigError> {
        let invalid = |m: &str| SignPolicyConfigError(format!("sign_policy_invalid: {m}"));

        if file.version != POLICY_VERSION_V1 {
            return Err(invalid("version must be v1"));
        }
        let fvk = decode_fvk_from_ufvk(network, &file.ufvk)
            .map_err(|e| invalid(&format!("ufvk: {e}")))?;
        let change_address = decode_orchard_address(network, &file.change_address)
            .map_err(|e| invalid(&format!("change_address: {e}")))?;
        if fvk.scope_for_address(&change_address).is_none() {
            return Err(invalid("change_address is not owned by ufvk"));
        }

        let max_fee_zat = file.max_fee_zat.unwrap_or(DEFAULT_MAX_FEE_ZAT);
        let max_spends = file.max_spends.unwrap_or(DEFAULT_MAX_SPENDS);
        if max_spends == 0 {
            return Err(invalid("max_spends must be >= 1"));
        }

        if file.verifier_cmd.is_empty() || file.verifier_cmd[0].trim().is_empty() {
            return Err(invalid("verifier_cmd must be a non-empty argv array"));
        }
        let verifier_env = file.verifier_env.unwrap_or_default();
        for (k, v) in &verifier_env {
            if k.is_empty() || k.contains('=') || k.contains('\0') {
                return Err(invalid(
                    "verifier_env keys must be non-empty and contain no '=' or NUL",
                ));
            }
            if v.contains('\0') {
                return Err(invalid("verifier_env values must not contain NUL"));
            }
        }

        let verifier_timeout_secs = file
            .verifier_timeout_secs
            .unwrap_or(DEFAULT_VERIFIER_TIMEOUT_SECS);
        if verifier_timeout_secs == 0 || verifier_timeout_secs > MAX_VERIFIER_TIMEOUT_SECS {
            return Err(invalid(&format!(
                "verifier_timeout_secs must be 1..={MAX_VERIFIER_TIMEOUT_SECS}"
            )));
        }
        let approval_ttl_secs = file.approval_ttl_secs.unwrap_or(DEFAULT_APPROVAL_TTL_SECS);
        if approval_ttl_secs == 0 || approval_ttl_secs > MAX_APPROVAL_TTL_SECS {
            return Err(invalid(&format!(
                "approval_ttl_secs must be 1..={MAX_APPROVAL_TTL_SECS}"
            )));
        }

        Ok(Self {
            network,
            fvk,
            change_address,
            change_address_str: encode_orchard_address(network, &change_address),
            max_fee_zat,
            max_spends,
            verifier_cmd: file.verifier_cmd,
            verifier_env,
            verifier_timeout: Duration::from_secs(verifier_timeout_secs),
            approval_ttl: Duration::from_secs(approval_ttl_secs),
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn max_fee_zat(&self) -> u64 {
        self.max_fee_zat
    }

    pub fn max_spends(&self) -> u32 {
        self.max_spends
    }

    pub fn approval_ttl(&self) -> Duration {
        self.approval_ttl
    }

    pub fn change_address(&self) -> &str {
        &self.change_address_str
    }

    /// The UFVK spend validating key must be the DKG group key.
    pub fn check_group_key(
        &self,
        group_key: &redpallas::VerifyingKey,
    ) -> Result<(), PolicyRejection> {
        let ak = group_key
            .serialize()
            .map_err(|_| PolicyRejection::code("group_key_invalid"))?;
        if ak.as_slice() != &self.fvk.to_bytes()[..32] {
            return Err(PolicyRejection::code("ufvk_group_key_mismatch"));
        }
        Ok(())
    }

    /// Static policy checks. Deterministic, no I/O.
    pub fn evaluate(
        &self,
        group_key: &redpallas::VerifyingKey,
        txplan: &[u8],
        prepared_tx: &[u8],
        signing_requests: &[u8],
    ) -> Result<ApprovedSpend, PolicyRejection> {
        self.check_group_key(group_key)?;

        // Plan.
        let plan_value: serde_json::Value =
            serde_json::from_slice(txplan).map_err(|_| PolicyRejection::code("txplan_invalid"))?;
        let plan: TxPlanV0 = serde_json::from_value(plan_value.clone())
            .map_err(|e| PolicyRejection::new("txplan_invalid", e.to_string()))?;
        if plan.version != "v0" {
            return Err(PolicyRejection::code("txplan_version_invalid"));
        }
        if plan.coin_type != coin_type(self.network) {
            return Err(PolicyRejection::new(
                "coin_type_mismatch",
                format!("got={} want={}", plan.coin_type, coin_type(self.network)),
            ));
        }
        if plan.notes.is_empty() {
            return Err(PolicyRejection::code("txplan_notes_empty"));
        }
        if plan.notes.len() > self.max_spends as usize {
            return Err(PolicyRejection::new(
                "too_many_spends",
                format!("notes={} max_spends={}", plan.notes.len(), self.max_spends),
            ));
        }
        let fee_zat = parse_u64_decimal(&plan.fee_zat)
            .ok_or_else(|| PolicyRejection::code("txplan_fee_invalid"))?;
        if fee_zat > self.max_fee_zat {
            return Err(PolicyRejection::new(
                "fee_over_cap",
                format!("fee_zat={fee_zat} max_fee_zat={}", self.max_fee_zat),
            ));
        }
        let plan_change = decode_orchard_address(self.network, &plan.change_address)
            .map_err(|e| PolicyRejection::new("change_address_mismatch", e))?;
        if plan_change != self.change_address {
            return Err(PolicyRejection::new(
                "change_address_mismatch",
                format!("got={}", plan.change_address.trim()),
            ));
        }
        if plan.outputs.is_empty() {
            return Err(PolicyRejection::code("txplan_outputs_empty"));
        }
        if plan.outputs.len() > MAX_OUTPUTS {
            return Err(PolicyRejection::new(
                "txplan_outputs_too_many",
                format!("outputs={} max={MAX_OUTPUTS}", plan.outputs.len()),
            ));
        }
        let mut expected_outputs = Vec::with_capacity(plan.outputs.len() + 1);
        let mut verified_outputs = Vec::with_capacity(plan.outputs.len());
        let mut total_out: u64 = 0;
        for (i, o) in plan.outputs.iter().enumerate() {
            let addr = decode_orchard_address(self.network, &o.to_address).map_err(|e| {
                PolicyRejection::new("txplan_output_invalid", format!("index={i} {e}"))
            })?;
            let amount = parse_u64_decimal(&o.amount_zat)
                .filter(|v| *v > 0)
                .ok_or_else(|| {
                    PolicyRejection::new("txplan_output_invalid", format!("index={i} amount"))
                })?;
            let memo = memo_bytes(o.memo_hex.as_deref()).ok_or_else(|| {
                PolicyRejection::new("txplan_output_invalid", format!("index={i} memo"))
            })?;
            total_out = total_out
                .checked_add(amount)
                .ok_or_else(|| PolicyRejection::code("txplan_value_overflow"))?;
            expected_outputs.push((addr.to_raw_address_bytes(), amount, memo));
            verified_outputs.push(VerifiedOutputV1 {
                to_address: encode_orchard_address(self.network, &addr),
                amount_zat: amount.to_string(),
                memo_hex: hex::encode(memo),
            });
        }

        // Prepared tx.
        let prepared: PreparedTxV0 = serde_json::from_slice(prepared_tx)
            .map_err(|e| PolicyRejection::new("prepared_tx_invalid", e.to_string()))?;
        if prepared.version != "v0" {
            return Err(PolicyRejection::code("prepared_tx_version_invalid"));
        }
        if prepared.branch_id != plan.branch_id {
            return Err(PolicyRejection::new("prepared_tx_mismatch", "branch_id"));
        }
        if prepared.expiry_height != plan.expiry_height || prepared.expiry_height == 0 {
            return Err(PolicyRejection::new(
                "prepared_tx_mismatch",
                "expiry_height",
            ));
        }
        if parse_u64_decimal(&prepared.fee_zat) != Some(fee_zat) {
            return Err(PolicyRejection::new("prepared_tx_mismatch", "fee_zat"));
        }
        // External signing is only defined for NU6.2 v5 transactions; older
        // branches use a sighash that does not commit to the Orchard bundle.
        let branch_id = match BranchId::try_from(prepared.branch_id) {
            Ok(BranchId::Nu6_2) => BranchId::Nu6_2,
            _ => {
                return Err(PolicyRejection::new(
                    "branch_id_unsupported",
                    format!("branch_id=0x{:08x}", prepared.branch_id),
                ))
            }
        };
        let plan_anchor = decode_hex_exact::<32>(&plan.anchor)
            .ok_or_else(|| PolicyRejection::code("txplan_anchor_invalid"))?;
        let pczt = orchard_pczt_bundle_from_v0(&prepared.orchard_pczt)?;
        if pczt.anchor().to_bytes() != plan_anchor {
            return Err(PolicyRejection::new("prepared_tx_mismatch", "anchor"));
        }
        let effects = pczt
            .extract_effects::<ZatBalance>()
            .map_err(|_| PolicyRejection::code("prepared_tx_pczt_invalid"))?
            .ok_or_else(|| PolicyRejection::code("prepared_tx_pczt_invalid"))?;
        let value_balance = i64::from(*effects.value_balance());
        if value_balance < 0 || value_balance as u64 != fee_zat {
            return Err(PolicyRejection::new(
                "value_balance_mismatch",
                format!("value_balance={value_balance} fee_zat={fee_zat}"),
            ));
        }
        let sighash =
            shielded_sighash_orchard_effects(branch_id, prepared.expiry_height, effects.clone());

        // Signing requests.
        let requests = parse_signing_requests(signing_requests)?;
        let actions = pczt.actions();
        // One spend-auth signature verifies for every action with the same rk, so a
        // signature for a requested action would also authorize any other action
        // reusing its rk. Honest bundles never repeat rk.
        let mut seen_rks = BTreeSet::new();
        for a in actions {
            let rk: [u8; 32] = a.spend().rk().into();
            if !seen_rks.insert(rk) {
                return Err(PolicyRejection::code("rk_reused"));
            }
        }
        let mut requested_nullifiers = BTreeSet::new();
        let mut alphas = Vec::with_capacity(requests.len());
        for r in &requests {
            if r.sighash != sighash {
                return Err(PolicyRejection::new(
                    "sighash_mismatch",
                    format!(
                        "action_index={} requested={} computed={}",
                        r.action_index,
                        hex::encode(r.sighash),
                        hex::encode(sighash)
                    ),
                ));
            }
            let action = actions.get(r.action_index as usize).ok_or_else(|| {
                PolicyRejection::new(
                    "request_action_index_invalid",
                    format!("action_index={}", r.action_index),
                )
            })?;
            let spend = action.spend();
            let action_rk: [u8; 32] = spend.rk().into();
            if action_rk != r.rk {
                return Err(PolicyRejection::new(
                    "rk_mismatch",
                    format!("action_index={}", r.action_index),
                ));
            }
            if let Some(alpha) = spend.alpha() {
                if alpha.to_repr() != r.alpha {
                    return Err(PolicyRejection::new(
                        "alpha_mismatch",
                        format!("action_index={}", r.action_index),
                    ));
                }
            }
            let randomizer = redpallas::Randomizer::deserialize(&r.alpha).map_err(|_| {
                PolicyRejection::new("alpha_invalid", format!("action_index={}", r.action_index))
            })?;
            let derived_rk = redpallas::RandomizedParams::from_randomizer(group_key, randomizer)
                .randomized_verifying_key()
                .serialize()
                .map_err(|_| {
                    PolicyRejection::new("rk_mismatch", format!("action_index={}", r.action_index))
                })?;
            if derived_rk.as_slice() != r.rk {
                return Err(PolicyRejection::new(
                    "rk_mismatch",
                    format!("action_index={}", r.action_index),
                ));
            }
            if !requested_nullifiers.insert(spend.nullifier().to_bytes()) {
                return Err(PolicyRejection::code("spend_set_mismatch"));
            }
            alphas.push(r.alpha);
        }

        // Bind requested spends to plan notes.
        let pivk_ext = self.fvk.to_ivk(Scope::External).prepare();
        let pivk_int = self.fvk.to_ivk(Scope::Internal).prepare();
        let mut plan_nullifiers = BTreeSet::new();
        let mut total_in: u64 = 0;
        for (i, n) in plan.notes.iter().enumerate() {
            let note = decrypt_plan_note(n, &pivk_ext, &pivk_int).ok_or_else(|| {
                PolicyRejection::new("txplan_note_not_owned", format!("index={i}"))
            })?;
            if !plan_nullifiers.insert(note.nullifier(&self.fvk).to_bytes()) {
                return Err(PolicyRejection::new(
                    "txplan_note_duplicate",
                    format!("index={i}"),
                ));
            }
            total_in = total_in
                .checked_add(note.value().inner())
                .ok_or_else(|| PolicyRejection::code("txplan_value_overflow"))?;
        }
        if plan_nullifiers != requested_nullifiers {
            return Err(PolicyRejection::new(
                "spend_set_mismatch",
                format!(
                    "plan_notes={} requested={}",
                    plan_nullifiers.len(),
                    requested_nullifiers.len()
                ),
            ));
        }

        let change_zat = total_in
            .checked_sub(total_out)
            .and_then(|v| v.checked_sub(fee_zat))
            .ok_or_else(|| {
                PolicyRejection::new(
                    "insufficient_funds",
                    format!("total_in={total_in} total_out={total_out} fee_zat={fee_zat}"),
                )
            })?;
        if change_zat > 0 {
            expected_outputs.push((
                self.change_address.to_raw_address_bytes(),
                change_zat,
                empty_memo(),
            ));
        }
        // The Orchard builder pads to max(spends, outputs, 2) actions.
        let max_actions = plan.notes.len().max(expected_outputs.len()).max(2);
        if actions.len() > max_actions {
            return Err(PolicyRejection::new(
                "actions_too_many",
                format!("actions={} max={max_actions}", actions.len()),
            ));
        }

        // Every output we can recover must be exactly a plan output or the change.
        // Our only inputs are the plan notes (requested nullifiers == plan
        // nullifiers, and no other action shares a signed rk), and value_balance ==
        // fee, so plan outputs + change + fee already consume all of our value.
        // Anything else in the bundle has to be funded by inputs we don't sign for.
        let ovks = [
            self.fvk.to_ovk(Scope::External),
            self.fvk.to_ovk(Scope::Internal),
        ];
        let mut recovered: Vec<([u8; 43], u64, [u8; 512])> = effects
            .recover_outputs_with_ovks(&ovks)
            .into_iter()
            .map(|(_, _, note, addr, memo)| {
                (addr.to_raw_address_bytes(), note.value().inner(), memo)
            })
            .collect();
        recovered.sort();
        expected_outputs.sort();
        if recovered != expected_outputs {
            return Err(PolicyRejection::new(
                "outputs_mismatch",
                format!(
                    "expected={} recovered={}",
                    expected_outputs.len(),
                    recovered.len()
                ),
            ));
        }

        Ok(ApprovedSpend {
            sighash,
            alphas,
            fee_zat,
            change_zat,
            spend_count: plan.notes.len(),
            outputs: verified_outputs,
            signing_requests: requests
                .iter()
                .map(|r| VerifierSigningRequestV1 {
                    action_index: r.action_index,
                    alpha: hex::encode(r.alpha),
                    rk: hex::encode(r.rk),
                })
                .collect(),
            txplan: plan_value,
        })
    }

    /// Runs the external verifier. Exit code 0 allows; anything else (including a
    /// timeout or spawn failure) rejects.
    ///
    /// The verifier runs with a clean environment (PATH plus `verifier_env`), in
    /// its own process group on unix so a timeout kills everything it started.
    pub async fn run_verifier(&self, context: &[u8]) -> Result<(), PolicyRejection> {
        let mut cmd = tokio::process::Command::new(&self.verifier_cmd[0]);
        cmd.args(&self.verifier_cmd[1..])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd.envs(&self.verifier_env);
        #[cfg(unix)]
        cmd.process_group(0);

        let mut child = cmd
            .spawn()
            .map_err(|e| PolicyRejection::new("verifier_failed", format!("spawn: {e}")))?;
        // Declared after `child` so it drops first: if this future is cancelled
        // (coordinator gone), the group is killed while the leader is unreaped.
        let mut group = ProcessGroupGuard(child.id());
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| PolicyRejection::new("verifier_failed", "stdin"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| PolicyRejection::new("verifier_failed", "stderr"))?;

        // A verifier may exit without reading stdin; its exit code decides.
        let context = context.to_vec();
        let writer = tokio::spawn(async move {
            let _ = stdin.write_all(&context).await;
            let _ = stdin.shutdown().await;
        });
        let reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = stderr
                .take(MAX_STDERR_CAPTURE as u64)
                .read_to_end(&mut buf)
                .await;
            buf
        });

        let status = tokio::time::timeout(self.verifier_timeout, child.wait()).await;
        writer.abort();
        // Don't leave anything the verifier started behind. Linux and macOS don't
        // hand out a pid that is still in use as a process group id.
        group.kill_now();
        let status = match status {
            Err(_) => {
                reader.abort();
                let _ = child.kill().await;
                return Err(PolicyRejection::new(
                    "verifier_rejected",
                    format!("timeout after {}s", self.verifier_timeout.as_secs()),
                ));
            }
            Ok(Err(e)) => {
                reader.abort();
                return Err(PolicyRejection::new(
                    "verifier_failed",
                    format!("wait: {e}"),
                ));
            }
            Ok(Ok(status)) => status,
        };
        if status.success() {
            reader.abort();
            return Ok(());
        }
        let abort = reader.abort_handle();
        let stderr = match tokio::time::timeout(STDERR_DRAIN_GRACE, reader).await {
            Ok(r) => r.unwrap_or_default(),
            Err(_) => {
                abort.abort();
                Vec::new()
            }
        };

        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr = stderr.trim();
        let mut detail = format!("exit={code}");
        if !stderr.is_empty() {
            let mut s: String = stderr.chars().take(MAX_STDERR_IN_REASON).collect();
            if s.len() < stderr.len() {
                s.push_str("...");
            }
            detail.push_str(&format!(" stderr={s}"));
        }
        Err(PolicyRejection::new("verifier_rejected", detail))
    }
}

/// Kills the verifier's process group once, either explicitly or on drop.
struct ProcessGroupGuard(Option<u32>);

impl ProcessGroupGuard {
    fn kill_now(&mut self) {
        kill_process_group(self.0.take());
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        kill_process_group(self.0.take());
    }
}

#[cfg(unix)]
fn kill_process_group(pid: Option<u32>) {
    // The verifier was started with process_group(0), so its pgid is its pid.
    if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 0) {
        // SAFETY: plain syscall; a stale or empty group just returns ESRCH.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: Option<u32>) {}

/// Result of a successful static evaluation.
#[derive(Debug, Clone)]
pub struct ApprovedSpend {
    pub sighash: [u8; 32],
    pub alphas: Vec<[u8; 32]>,
    pub fee_zat: u64,
    pub change_zat: u64,
    pub spend_count: usize,
    pub outputs: Vec<VerifiedOutputV1>,
    pub signing_requests: Vec<VerifierSigningRequestV1>,
    pub txplan: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedOutputV1 {
    pub to_address: String,
    pub amount_zat: String,
    pub memo_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifierSigningRequestV1 {
    pub action_index: u32,
    pub alpha: String,
    pub rk: String,
}

/// JSON document written to the verifier's stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierContextV1 {
    pub version: String,
    pub operator_id: String,
    pub identifier: u16,
    pub ceremony_hash: String,
    pub network: String,
    pub sighash: String,
    pub fee_zat: String,
    pub change_address: String,
    pub change_zat: String,
    pub spend_count: usize,
    /// Non-change outputs from the plan, already matched against the transaction.
    pub outputs: Vec<VerifiedOutputV1>,
    pub signing_requests: Vec<VerifierSigningRequestV1>,
    /// The txplan exactly as received.
    pub txplan: serde_json::Value,
}

impl ApprovedSpend {
    pub fn verifier_context(
        &self,
        policy: &SignPolicy,
        operator_id: &str,
        identifier: u16,
        ceremony_hash: &str,
    ) -> VerifierContextV1 {
        VerifierContextV1 {
            version: VERIFIER_CONTEXT_VERSION_V1.to_string(),
            operator_id: operator_id.to_string(),
            identifier,
            ceremony_hash: ceremony_hash.to_string(),
            network: policy.network.as_str().to_string(),
            sighash: hex::encode(self.sighash),
            fee_zat: self.fee_zat.to_string(),
            change_address: policy.change_address_str.clone(),
            change_zat: self.change_zat.to_string(),
            spend_count: self.spend_count,
            outputs: self.outputs.clone(),
            signing_requests: self.signing_requests.clone(),
            txplan: self.txplan.clone(),
        }
    }
}

/// In-memory set of approved `(sighash, alpha)` pairs with a TTL.
#[derive(Debug)]
pub struct ApprovalCache {
    ttl: Duration,
    max_entries: usize,
    entries: HashMap<([u8; 32], [u8; 32]), Instant>,
}

impl ApprovalCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn prune(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, at| now.saturating_duration_since(*at) < ttl);
    }

    pub fn insert(&mut self, sighash: [u8; 32], alpha: [u8; 32], now: Instant) {
        self.prune(now);
        if !self.entries.contains_key(&(sighash, alpha)) {
            while self.entries.len() >= self.max_entries {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(k, _)| *k);
                match oldest {
                    Some(k) => {
                        self.entries.remove(&k);
                    }
                    None => break,
                }
            }
        }
        self.entries.insert((sighash, alpha), now);
    }

    pub fn contains(&mut self, sighash: &[u8], alpha: &[u8], now: Instant) -> bool {
        self.prune(now);
        let (Ok(sighash), Ok(alpha)) = (<[u8; 32]>::try_from(sighash), <[u8; 32]>::try_from(alpha))
        else {
            return false;
        };
        self.entries.contains_key(&(sighash, alpha))
    }
}

// ---------------------------------------------------------------------------
// txplan / prepared tx / signing requests

#[derive(Debug, Clone, Deserialize)]
struct TxPlanV0 {
    version: String,
    coin_type: u32,
    branch_id: u32,
    anchor: String,
    expiry_height: u32,
    outputs: Vec<TxPlanOutputV0>,
    change_address: String,
    fee_zat: String,
    notes: Vec<TxPlanNoteV0>,
}

#[derive(Debug, Clone, Deserialize)]
struct TxPlanOutputV0 {
    to_address: String,
    amount_zat: String,
    #[serde(default)]
    memo_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TxPlanNoteV0 {
    action_nullifier: String,
    cmx: String,
    ephemeral_key: String,
    enc_ciphertext: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTxV0 {
    version: String,
    branch_id: u32,
    expiry_height: u32,
    fee_zat: String,
    #[allow(dead_code)]
    orchard_output_action_indices: Vec<u32>,
    #[allow(dead_code)]
    orchard_change_action_index: Option<u32>,
    #[allow(dead_code)]
    orchard_required_spend_action_indices: Vec<u32>,
    orchard_pczt: OrchardPcztBundleV0,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztBundleV0 {
    actions: Vec<OrchardPcztActionV0>,
    flags: u8,
    value_sum: OrchardValueSumV0,
    anchor: String,
    zkproof: Option<String>,
    bsk: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardValueSumV0 {
    magnitude: u64,
    is_negative: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztActionV0 {
    cv_net: String,
    spend: OrchardPcztSpendV0,
    output: OrchardPcztOutputV0,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztSpendV0 {
    nullifier: String,
    rk: String,
    spend_auth_sig: Option<String>,
    alpha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztOutputV0 {
    cmx: String,
    ephemeral_key: String,
    enc_ciphertext: String,
    out_ciphertext: String,
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

struct ParsedRequest {
    action_index: u32,
    sighash: [u8; 32],
    alpha: [u8; 32],
    rk: [u8; 32],
}

fn parse_signing_requests(bytes: &[u8]) -> Result<Vec<ParsedRequest>, PolicyRejection> {
    let parsed: SigningRequestsV0 = serde_json::from_slice(bytes)
        .map_err(|_| PolicyRejection::code("signing_requests_invalid"))?;
    if parsed.version != "v0" {
        return Err(PolicyRejection::code("signing_requests_version_invalid"));
    }
    if parsed.requests.is_empty() {
        return Err(PolicyRejection::code("signing_requests_empty"));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(parsed.requests.len());
    for r in parsed.requests {
        if !seen.insert(r.action_index) {
            return Err(PolicyRejection::code("duplicate_action_index"));
        }
        let bad = || {
            PolicyRejection::new(
                "signing_requests_invalid",
                format!("action_index={}", r.action_index),
            )
        };
        out.push(ParsedRequest {
            action_index: r.action_index,
            sighash: decode_hex_exact::<32>(&r.sighash).ok_or_else(bad)?,
            alpha: decode_hex_exact::<32>(&r.alpha).ok_or_else(bad)?,
            rk: decode_hex_exact::<32>(&r.rk).ok_or_else(bad)?,
        });
    }
    out.sort_by_key(|r| r.action_index);
    Ok(out)
}

fn decrypt_plan_note(
    n: &TxPlanNoteV0,
    pivk_ext: &PreparedIncomingViewingKey,
    pivk_int: &PreparedIncomingViewingKey,
) -> Option<orchard::Note> {
    let nf = decode_hex_exact::<32>(&n.action_nullifier)?;
    let cmx = decode_hex_exact::<32>(&n.cmx)?;
    let epk = decode_hex_exact::<32>(&n.ephemeral_key)?;
    let enc = decode_hex_exact::<52>(&n.enc_ciphertext)?;
    let nf: Nullifier = Option::from(Nullifier::from_bytes(&nf))?;
    let cmx: ExtractedNoteCommitment = Option::from(ExtractedNoteCommitment::from_bytes(&cmx))?;
    let compact = CompactAction::from_parts(nf, cmx, EphemeralKeyBytes(epk), enc);
    let domain = OrchardDomain::for_compact_action(&compact);
    try_compact_note_decryption(&domain, pivk_ext, &compact)
        .or_else(|| try_compact_note_decryption(&domain, pivk_int, &compact))
        .map(|(note, _)| note)
}

// ---------------------------------------------------------------------------
// Orchard helpers (kept in line with juno-txsign)

struct OrchardEffectsOnlyAuth;

impl zcash_primitives::transaction::Authorization for OrchardEffectsOnlyAuth {
    type TransparentAuth = transparent::builder::Unauthorized;
    type SaplingAuth =
        sapling::builder::InProgress<sapling::builder::Proven, sapling::builder::Unsigned>;
    type OrchardAuth = EffectsOnly;
}

fn shielded_sighash_orchard_effects(
    branch_id: BranchId,
    expiry_height: u32,
    effects: orchard::Bundle<EffectsOnly, ZatBalance>,
) -> [u8; 32] {
    let tx: TransactionData<OrchardEffectsOnlyAuth> = TransactionData::from_parts(
        TxVersion::suggested_for_branch(branch_id),
        branch_id,
        0,
        BlockHeight::from(expiry_height),
        None,
        None,
        None,
        Some(effects),
    );
    let txid_parts = tx.digest(TxIdDigester);
    *signature_hash(&tx, &SignableInput::Shielded, &txid_parts).as_ref()
}

/// Shielded sighash of a prepared tx v0 JSON (as written by juno-txsign ext-prepare).
pub fn prepared_tx_sighash(prepared_tx: &[u8]) -> Result<[u8; 32], PolicyRejection> {
    let prepared: PreparedTxV0 = serde_json::from_slice(prepared_tx)
        .map_err(|e| PolicyRejection::new("prepared_tx_invalid", e.to_string()))?;
    let pczt = orchard_pczt_bundle_from_v0(&prepared.orchard_pczt)?;
    shielded_sighash_for_orchard_pczt(prepared.branch_id, prepared.expiry_height, &pczt)
        .map_err(|e| PolicyRejection::new("prepared_tx_pczt_invalid", e))
}

/// Shielded sighash of an Orchard-only transaction built from a PCZT bundle.
/// Only NU6.2 (v5 sighash) is supported, as for external signing in juno-txsign.
pub fn shielded_sighash_for_orchard_pczt(
    branch_id: u32,
    expiry_height: u32,
    pczt: &orchard::pczt::Bundle,
) -> Result<[u8; 32], String> {
    let branch_id = BranchId::try_from(branch_id).map_err(|_| "branch_id_invalid".to_string())?;
    if branch_id != BranchId::Nu6_2 {
        return Err("branch_id_unsupported".to_string());
    }
    let effects = pczt
        .extract_effects::<ZatBalance>()
        .map_err(|_| "pczt_invalid".to_string())?
        .ok_or_else(|| "pczt_empty".to_string())?;
    Ok(shielded_sighash_orchard_effects(
        branch_id,
        expiry_height,
        effects,
    ))
}

fn orchard_pczt_bundle_from_v0(
    b: &OrchardPcztBundleV0,
) -> Result<orchard::pczt::Bundle, PolicyRejection> {
    let bad = |what: &str| PolicyRejection::new("prepared_tx_pczt_invalid", what.to_string());
    let mut actions = Vec::with_capacity(b.actions.len());
    for (i, a) in b.actions.iter().enumerate() {
        let at = |what: &str| bad(&format!("action={i} {what}"));
        let cv_net = decode_hex_exact::<32>(&a.cv_net).ok_or_else(|| at("cv_net"))?;
        let nullifier =
            decode_hex_exact::<32>(&a.spend.nullifier).ok_or_else(|| at("nullifier"))?;
        let rk = decode_hex_exact::<32>(&a.spend.rk).ok_or_else(|| at("rk"))?;
        let spend_auth_sig = match a.spend.spend_auth_sig.as_deref() {
            Some(s) => Some(decode_hex_exact::<64>(s).ok_or_else(|| at("spend_auth_sig"))?),
            None => None,
        };
        let alpha = match a.spend.alpha.as_deref() {
            Some(s) => Some(decode_hex_exact::<32>(s).ok_or_else(|| at("alpha"))?),
            None => None,
        };
        let spend = orchard::pczt::Spend::parse(
            nullifier,
            rk,
            spend_auth_sig,
            None,
            None,
            None,
            None,
            None,
            None,
            alpha,
            None,
            None,
            BTreeMap::new(),
        )
        .map_err(|_| at("spend"))?;

        let cmx = decode_hex_exact::<32>(&a.output.cmx).ok_or_else(|| at("cmx"))?;
        let epk =
            decode_hex_exact::<32>(&a.output.ephemeral_key).ok_or_else(|| at("ephemeral_key"))?;
        let enc = hex::decode(a.output.enc_ciphertext.trim()).map_err(|_| at("enc_ciphertext"))?;
        let out = hex::decode(a.output.out_ciphertext.trim()).map_err(|_| at("out_ciphertext"))?;
        let output = orchard::pczt::Output::parse(
            *spend.nullifier(),
            cmx,
            epk,
            enc,
            out,
            None,
            None,
            None,
            None,
            None,
            None,
            BTreeMap::new(),
        )
        .map_err(|_| at("output"))?;

        actions.push(
            orchard::pczt::Action::parse(cv_net, spend, output, None).map_err(|_| at("action"))?,
        );
    }

    let anchor = decode_hex_exact::<32>(&b.anchor).ok_or_else(|| bad("anchor"))?;
    let zkproof = match b.zkproof.as_deref() {
        Some(s) => Some(hex::decode(s.trim()).map_err(|_| bad("zkproof"))?),
        None => None,
    };
    let bsk = match b.bsk.as_deref() {
        Some(s) => Some(decode_hex_exact::<32>(s).ok_or_else(|| bad("bsk"))?),
        None => None,
    };
    orchard::pczt::Bundle::parse(
        actions,
        b.flags,
        (b.value_sum.magnitude, b.value_sum.is_negative),
        anchor,
        zkproof,
        bsk,
    )
    .map_err(|_| bad("bundle"))
}

pub fn coin_type(network: Network) -> u32 {
    match network {
        Network::Mainnet => 8133,
        Network::Testnet => 8134,
        Network::Regtest => 8135,
    }
}

pub fn ua_hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "j",
        Network::Testnet => "jtest",
        Network::Regtest => "jregtest",
    }
}

pub fn ufvk_hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "jview",
        Network::Testnet => "jviewtest",
        Network::Regtest => "jviewregtest",
    }
}

pub fn decode_orchard_address(network: Network, s: &str) -> Result<Address, String> {
    let (typecode, value) = zip316::decode_single_tlv_container(ua_hrp(network), s.trim())
        .map_err(|e| match e {
            zip316::Zip316Error::HrpMismatch => "address_network_mismatch".to_string(),
            _ => "address_invalid".to_string(),
        })?;
    if typecode != TYPECODE_ORCHARD {
        return Err("address_not_orchard".to_string());
    }
    let raw: [u8; 43] = value
        .as_slice()
        .try_into()
        .map_err(|_| "address_invalid".to_string())?;
    Option::from(Address::from_raw_address_bytes(&raw)).ok_or_else(|| "address_invalid".to_string())
}

/// Canonical (lowercase bech32m) encoding of an Orchard-only unified address.
pub fn encode_orchard_address(network: Network, addr: &Address) -> String {
    zip316::encode_unified_container(
        ua_hrp(network),
        TYPECODE_ORCHARD,
        &addr.to_raw_address_bytes(),
    )
    .expect("orchard address encodes")
}

pub fn decode_fvk_from_ufvk(network: Network, s: &str) -> Result<FullViewingKey, String> {
    let items = zip316::decode_tlv_container(ufvk_hrp(network), s.trim()).map_err(|e| match e {
        zip316::Zip316Error::HrpMismatch => "ufvk_network_mismatch".to_string(),
        _ => "ufvk_invalid".to_string(),
    })?;
    let mut orchard_items = items.iter().filter(|(tc, _)| *tc == TYPECODE_ORCHARD);
    let (_, value) = orchard_items
        .next()
        .ok_or_else(|| "ufvk_missing_orchard".to_string())?;
    if orchard_items.next().is_some() {
        return Err("ufvk_invalid".to_string());
    }
    let raw: [u8; 96] = value
        .as_slice()
        .try_into()
        .map_err(|_| "ufvk_invalid".to_string())?;
    FullViewingKey::from_bytes(&raw).ok_or_else(|| "ufvk_invalid".to_string())
}

fn empty_memo() -> [u8; 512] {
    let mut m = [0u8; 512];
    m[0] = 0xF6;
    m
}

fn memo_bytes(memo_hex: Option<&str>) -> Option<[u8; 512]> {
    let t = memo_hex.map(str::trim).unwrap_or("");
    if t.is_empty() {
        return Some(empty_memo());
    }
    let b = hex::decode(t).ok()?;
    if b.len() > 512 {
        return None;
    }
    let mut out = [0u8; 512];
    out[..b.len()].copy_from_slice(&b);
    Some(out)
}

fn parse_u64_decimal(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

fn decode_hex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    let t = s.trim();
    if t.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(t, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fvk(seed: u8) -> FullViewingKey {
        let sk: orchard::keys::SpendingKey =
            Option::from(orchard::keys::SpendingKey::from_bytes([seed; 32])).unwrap();
        FullViewingKey::from(&sk)
    }

    fn ufvk(fvk: &FullViewingKey) -> String {
        zip316::encode_unified_container(
            ufvk_hrp(Network::Regtest),
            TYPECODE_ORCHARD,
            &fvk.to_bytes(),
        )
        .unwrap()
    }

    fn ua(addr: &Address) -> String {
        zip316::encode_unified_container(
            ua_hrp(Network::Regtest),
            TYPECODE_ORCHARD,
            &addr.to_raw_address_bytes(),
        )
        .unwrap()
    }

    fn policy_file(fvk: &FullViewingKey) -> SignPolicyFileV1 {
        SignPolicyFileV1 {
            version: "v1".to_string(),
            ufvk: ufvk(fvk),
            change_address: ua(&fvk.address_at(0u32, Scope::Internal)),
            max_fee_zat: None,
            max_spends: None,
            verifier_cmd: vec!["true".to_string()],
            verifier_env: None,
            verifier_timeout_secs: None,
            approval_ttl_secs: None,
        }
    }

    #[test]
    fn policy_defaults() {
        let fvk = test_fvk(1);
        let p = SignPolicy::from_file(policy_file(&fvk), Network::Regtest).unwrap();
        assert_eq!(p.max_fee_zat(), 10_000_000);
        assert_eq!(p.max_spends(), 200);
        assert_eq!(p.approval_ttl(), Duration::from_secs(300));
        assert_eq!(p.verifier_timeout, Duration::from_secs(20));
    }

    #[test]
    fn policy_file_rejects_unknown_fields() {
        let fvk = test_fvk(1);
        let mut v = serde_json::to_value(policy_file(&fvk)).unwrap();
        v["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<SignPolicyFileV1>(v).is_err());
    }

    #[test]
    fn policy_validation_errors() {
        let fvk = test_fvk(1);
        let other = test_fvk(2);

        let mut f = policy_file(&fvk);
        f.version = "v2".into();
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());

        let mut f = policy_file(&fvk);
        f.change_address = ua(&other.address_at(0u32, Scope::External));
        let err = SignPolicy::from_file(f, Network::Regtest).unwrap_err();
        assert!(err.0.contains("not owned"), "{err}");

        let mut f = policy_file(&fvk);
        f.verifier_cmd = vec![];
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());

        let mut f = policy_file(&fvk);
        f.max_spends = Some(0);
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());

        let mut f = policy_file(&fvk);
        f.verifier_timeout_secs = Some(MAX_VERIFIER_TIMEOUT_SECS + 1);
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());

        let mut f = policy_file(&fvk);
        f.approval_ttl_secs = Some(0);
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());

        // Regtest UFVK on a mainnet config.
        let err = SignPolicy::from_file(policy_file(&fvk), Network::Mainnet).unwrap_err();
        assert!(err.0.contains("ufvk_network_mismatch"), "{err}");
    }

    #[test]
    fn address_roundtrip() {
        let fvk = test_fvk(3);
        let a = fvk.address_at(7u32, Scope::External);
        assert_eq!(
            decode_orchard_address(Network::Regtest, &ua(&a)).unwrap(),
            a
        );
        assert_eq!(
            decode_orchard_address(Network::Testnet, &ua(&a)).unwrap_err(),
            "address_network_mismatch"
        );
        assert_eq!(
            decode_fvk_from_ufvk(Network::Regtest, &ufvk(&fvk)).unwrap(),
            fvk
        );
    }

    #[test]
    fn memo_and_amount_parsing() {
        assert_eq!(memo_bytes(None).unwrap(), empty_memo());
        assert_eq!(memo_bytes(Some("  ")).unwrap(), empty_memo());
        let m = memo_bytes(Some("abcd")).unwrap();
        assert_eq!(&m[..3], &[0xab, 0xcd, 0x00]);
        assert!(memo_bytes(Some(&"00".repeat(513))).is_none());
        assert!(memo_bytes(Some("zz")).is_none());

        assert_eq!(parse_u64_decimal(" 42 "), Some(42));
        assert_eq!(parse_u64_decimal("-1"), None);
        assert_eq!(parse_u64_decimal("+1"), None);
        assert_eq!(parse_u64_decimal(""), None);
    }

    #[test]
    fn rejection_display() {
        assert_eq!(
            PolicyRejection::code("fee_over_cap").to_string(),
            "fee_over_cap"
        );
        assert_eq!(
            PolicyRejection::new("fee_over_cap", "fee_zat=2").to_string(),
            "fee_over_cap: fee_zat=2"
        );
    }

    #[test]
    fn approval_cache_ttl_and_capacity() {
        let t0 = Instant::now();
        let mut c = ApprovalCache::new(Duration::from_secs(10), 2);
        c.insert([1; 32], [2; 32], t0);
        assert!(c.contains(&[1; 32], &[2; 32], t0 + Duration::from_secs(9)));
        assert!(!c.contains(&[1; 32], &[3; 32], t0));
        assert!(!c.contains(&[1; 31], &[2; 32], t0));
        assert!(!c.contains(&[1; 32], &[2; 32], t0 + Duration::from_secs(10)));
        assert!(c.is_empty());

        c.insert([1; 32], [1; 32], t0);
        c.insert([2; 32], [2; 32], t0 + Duration::from_secs(1));
        c.insert([3; 32], [3; 32], t0 + Duration::from_secs(2));
        assert_eq!(c.len(), 2);
        let now = t0 + Duration::from_secs(3);
        assert!(!c.contains(&[1; 32], &[1; 32], now));
        assert!(c.contains(&[2; 32], &[2; 32], now));
        assert!(c.contains(&[3; 32], &[3; 32], now));
    }

    #[cfg(unix)]
    fn verifier_policy(cmd: &[&str], timeout: u64) -> SignPolicy {
        let fvk = test_fvk(1);
        let mut f = policy_file(&fvk);
        f.verifier_cmd = cmd.iter().map(|s| s.to_string()).collect();
        f.verifier_timeout_secs = Some(timeout);
        SignPolicy::from_file(f, Network::Regtest).unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verifier_exit_codes() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("stdin.json");
        let script = format!("cat > '{}'; exit 0", out.display());
        let p = verifier_policy(&["sh", "-c", &script], 5);
        p.run_verifier(br#"{"hello":1}"#).await.unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), br#"{"hello":1}"#);

        let p = verifier_policy(&["sh", "-c", "echo not allowed >&2; exit 3"], 5);
        let err = p.run_verifier(b"{}").await.unwrap_err();
        assert_eq!(err.code, "verifier_rejected");
        assert!(err.detail.contains("exit=3"), "{}", err.detail);
        assert!(err.detail.contains("not allowed"), "{}", err.detail);

        // Exits without reading a large stdin.
        let p = verifier_policy(&["sh", "-c", "exit 0"], 5);
        p.run_verifier(&vec![b'x'; 1 << 20]).await.unwrap();

        let p = verifier_policy(&["/nonexistent/verifier"], 5);
        let err = p.run_verifier(b"{}").await.unwrap_err();
        assert_eq!(err.code, "verifier_failed");

        let p = verifier_policy(&["sh", "-c", "sleep 30"], 1);
        let err = p.run_verifier(b"{}").await.unwrap_err();
        assert_eq!(err.code, "verifier_rejected");
        assert!(err.detail.contains("timeout"), "{}", err.detail);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verifier_gets_clean_environment() {
        let fvk = test_fvk(1);
        let mut f = policy_file(&fvk);
        f.verifier_cmd = ["sh", "-c", r#"[ -z "$HOME" ] && [ -z "$USER" ] && [ "$ALLOW_LIST" = "/etc/allow" ] && [ -n "$PATH" ]"#]
            .iter()
            .map(|s| s.to_string())
            .collect();
        f.verifier_env = Some(BTreeMap::from([(
            "ALLOW_LIST".to_string(),
            "/etc/allow".to_string(),
        )]));
        let p = SignPolicy::from_file(f.clone(), Network::Regtest).unwrap();
        p.run_verifier(b"{}").await.unwrap();

        f.verifier_env = Some(BTreeMap::from([("A=B".to_string(), "x".to_string())]));
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verifier_background_children_do_not_hang_or_survive() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        // The background sleep keeps stderr open and would outlive the verifier.
        let script = format!("sleep 30 & echo $! > '{}'; exit 0", pidfile.display());
        let p = verifier_policy(&["sh", "-c", &script], 10);
        let started = Instant::now();
        p.run_verifier(b"{}").await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );

        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal 0 only probes for existence.
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "verifier child {pid} still running"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Same on timeout, with the child also holding stderr.
        let script = format!("sleep 30 & echo $! > '{}'; sleep 30", pidfile.display());
        let p = verifier_policy(&["sh", "-c", &script], 1);
        let err = p.run_verifier(b"{}").await.unwrap_err();
        assert!(err.detail.contains("timeout"), "{}", err.detail);
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                Instant::now() < deadline,
                "verifier child {pid} survived timeout"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_verifier_does_not_leave_children() {
        // The request future is dropped mid-verifier (coordinator went away).
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > '{}'; sleep 30", pidfile.display());
        let p = verifier_policy(&["sh", "-c", &script], 20);
        let run = p.run_verifier(b"{}");
        let res = tokio::time::timeout(Duration::from_millis(500), run).await;
        assert!(res.is_err(), "verifier should still be running");

        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        // SAFETY: signal 0 only probes for existence.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                Instant::now() < deadline,
                "verifier child {pid} survived cancellation"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[test]
    fn verifier_env_values_reject_nul() {
        let fvk = test_fvk(1);
        let mut f = policy_file(&fvk);
        f.verifier_env = Some(BTreeMap::from([("A".to_string(), "x\0y".to_string())]));
        assert!(SignPolicy::from_file(f, Network::Regtest).is_err());
    }
}
