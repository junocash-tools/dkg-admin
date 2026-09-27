//! Shared fixtures for sign policy tests.
//!
//! Builds Orchard transactions the same way `juno-txsign ext-prepare` does (outputs and
//! change encrypted to the wallet's external OVK) and renders the txplan, prepared tx and
//! signing requests JSON that the coordinator hands to `dkg-admin sign-spendauth`.

#![allow(dead_code)]

use ff::PrimeField as _;
use orchard::builder::{Builder, BundleType};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Nullifier};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::{NoteValue, Sign};
use orchard::{Address, Anchor, Note};
use rand_core::OsRng;
use serde_json::{json, Value};
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes};

use dkg_admin::config::Network;
use dkg_admin::sign_policy;
use dkg_admin::zip316;

pub const BRANCH_ID_NU6_2: u32 = 0x5437_f330;
pub const EXPIRY_HEIGHT: u32 = 1_000;
const TYPECODE_ORCHARD: u64 = 0x03;

pub fn spending_fvk(seed: u8) -> FullViewingKey {
    let sk: SpendingKey = Option::from(SpendingKey::from_bytes([seed; 32])).expect("spending key");
    FullViewingKey::from(&sk)
}

/// FVK whose spend validating key is `ak` (for example a DKG group key) and whose
/// nk/rivk come from a fixed spending key.
pub fn fvk_with_ak(ak: [u8; 32], seed: u8) -> FullViewingKey {
    let mut bytes = spending_fvk(seed).to_bytes();
    bytes[..32].copy_from_slice(&ak);
    FullViewingKey::from_bytes(&bytes).expect("fvk from ak")
}

pub fn encode_ua(addr: &Address) -> String {
    zip316::encode_unified_container(
        sign_policy::ua_hrp(Network::Regtest),
        TYPECODE_ORCHARD,
        &addr.to_raw_address_bytes(),
    )
    .expect("encode ua")
}

pub fn encode_ufvk(fvk: &FullViewingKey) -> String {
    zip316::encode_unified_container(
        sign_policy::ufvk_hrp(Network::Regtest),
        TYPECODE_ORCHARD,
        &fvk.to_bytes(),
    )
    .expect("encode ufvk")
}

pub fn external_address(fvk: &FullViewingKey, j: u32) -> Address {
    fvk.address_at(j, Scope::External)
}

pub fn change_address(fvk: &FullViewingKey) -> Address {
    fvk.address_at(0u32, Scope::Internal)
}

pub fn foreign_address(seed: u8, j: u32) -> Address {
    spending_fvk(seed).address_at(j, Scope::External)
}

fn empty_memo() -> [u8; 512] {
    let mut m = [0u8; 512];
    m[0] = 0xF6;
    m
}

/// A wallet note as the scanner reports it (compact ciphertext parts).
#[derive(Clone)]
pub struct FundedNote {
    pub note: Note,
    pub action_nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_compact: [u8; 52],
}

/// Creates a note of `value` paid to `recipient` by building a throwaway funding bundle.
pub fn fund_note(fvk: &FullViewingKey, recipient: Address, value: u64) -> FundedNote {
    let mut b = Builder::new(BundleType::DEFAULT, Anchor::empty_tree());
    b.add_output(None, recipient, NoteValue::from_raw(value), empty_memo())
        .expect("funding output");
    let (pczt, meta) = b.build_for_pczt(OsRng).expect("funding bundle");
    let idx = meta.output_action_index(0).expect("funding output index");
    let action = &pczt.actions()[idx];
    let action_nullifier = action.spend().nullifier().to_bytes();
    let cmx = action.output().cmx().to_bytes();
    let enc = action.output().encrypted_note();
    let ephemeral_key = enc.epk_bytes;
    let mut enc_compact = [0u8; 52];
    enc_compact.copy_from_slice(&enc.enc_ciphertext[..52]);

    let nf: Nullifier = Option::from(Nullifier::from_bytes(&action_nullifier)).unwrap();
    let cmx_v: ExtractedNoteCommitment =
        Option::from(ExtractedNoteCommitment::from_bytes(&cmx)).unwrap();
    let compact =
        CompactAction::from_parts(nf, cmx_v, EphemeralKeyBytes(ephemeral_key), enc_compact);
    let domain = OrchardDomain::for_compact_action(&compact);
    let ext = fvk.to_ivk(Scope::External).prepare();
    let int = fvk.to_ivk(Scope::Internal).prepare();
    let (note, _) = try_compact_note_decryption(&domain, &ext, &compact)
        .or_else(|| try_compact_note_decryption(&domain, &int, &compact))
        .expect("funded note decrypts");
    FundedNote {
        note,
        action_nullifier,
        cmx,
        ephemeral_key,
        enc_compact,
    }
}

/// Merkle paths for up to two leaves at positions 0 and 1 sharing one anchor.
/// Upper siblings are arbitrary constants; nothing here verifies them against a real tree.
fn merkle_paths(cmxs: &[[u8; 32]]) -> (Vec<MerklePath>, Anchor) {
    assert!(
        !cmxs.is_empty() && cmxs.len() <= 2,
        "fixture supports 1 or 2 notes"
    );
    let filler: MerkleHashOrchard =
        Option::from(MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
    let leaf = |c: &[u8; 32]| {
        let cmx: ExtractedNoteCommitment =
            Option::from(ExtractedNoteCommitment::from_bytes(c)).unwrap();
        MerkleHashOrchard::from_cmx(&cmx)
    };
    let mut paths = Vec::new();
    for (pos, _) in cmxs.iter().enumerate() {
        let mut auth = [filler; 32];
        if cmxs.len() == 2 {
            auth[0] = leaf(&cmxs[1 - pos]);
        }
        paths.push(MerklePath::from_parts(pos as u32, auth));
    }
    let cmx0: ExtractedNoteCommitment =
        Option::from(ExtractedNoteCommitment::from_bytes(&cmxs[0])).unwrap();
    let anchor = paths[0].root(cmx0);
    (paths, anchor)
}

#[derive(Clone)]
pub struct PlanOutput {
    pub to: Address,
    pub amount: u64,
    pub memo: Option<[u8; 512]>,
}

pub struct SpendSpec {
    pub fvk: FullViewingKey,
    pub note_values: Vec<u64>,
    pub outputs: Vec<PlanOutput>,
    pub fee: u64,
    pub change: Address,
    /// Output added to the transaction but not to the plan, with no OVK (unrecoverable).
    pub hidden_output: Option<(Address, u64)>,
}

impl SpendSpec {
    pub fn simple(fvk: FullViewingKey) -> Self {
        let change = change_address(&fvk);
        Self {
            fvk,
            note_values: vec![1_000_000],
            outputs: vec![PlanOutput {
                to: foreign_address(0x77, 0),
                amount: 250_000,
                memo: None,
            }],
            fee: 15_000,
            change,
            hidden_output: None,
        }
    }
}

#[derive(Clone)]
pub struct SpendFixture {
    pub txplan: Value,
    pub prepared_tx: Value,
    pub requests: Value,
    pub sighash: [u8; 32],
    /// Spend nullifier (hex) of each plan note, in plan order.
    pub note_nullifiers: Vec<String>,
}

impl SpendFixture {
    pub fn txplan_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.txplan).unwrap()
    }
    pub fn prepared_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.prepared_tx).unwrap()
    }
    pub fn requests_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.requests).unwrap()
    }
}

pub fn build_spend(spec: &SpendSpec) -> SpendFixture {
    let notes: Vec<FundedNote> = spec
        .note_values
        .iter()
        .enumerate()
        .map(|(i, v)| fund_note(&spec.fvk, external_address(&spec.fvk, i as u32), *v))
        .collect();
    let cmxs: Vec<[u8; 32]> = notes.iter().map(|n| n.cmx).collect();
    let (paths, anchor) = merkle_paths(&cmxs);

    let total_in: u64 = spec.note_values.iter().sum();
    let total_out: u64 = spec.outputs.iter().map(|o| o.amount).sum();
    let hidden = spec.hidden_output.map(|(_, v)| v).unwrap_or(0);
    let change = total_in - total_out - spec.fee - hidden;

    let ovk = spec.fvk.to_ovk(Scope::External);
    let mut b = Builder::new(BundleType::DEFAULT, anchor);
    for (n, p) in notes.iter().zip(paths.iter()) {
        b.add_spend(spec.fvk.clone(), n.note, p.clone())
            .expect("add spend");
    }
    for o in &spec.outputs {
        b.add_output(
            Some(ovk.clone()),
            o.to,
            NoteValue::from_raw(o.amount),
            o.memo.unwrap_or_else(empty_memo),
        )
        .expect("add output");
    }
    if change > 0 {
        b.add_output(
            Some(ovk.clone()),
            spec.change,
            NoteValue::from_raw(change),
            empty_memo(),
        )
        .expect("add change");
    }
    if let Some((addr, v)) = spec.hidden_output {
        b.add_output(None, addr, NoteValue::from_raw(v), empty_memo())
            .expect("add hidden output");
    }
    let (mut pczt, meta) = b.build_for_pczt(OsRng).expect("build pczt");
    let sighash =
        sign_policy::shielded_sighash_for_orchard_pczt(BRANCH_ID_NU6_2, EXPIRY_HEIGHT, &pczt)
            .expect("sighash");
    pczt.finalize_io(sighash, OsRng).expect("finalize io");

    let mut spend_indices: Vec<u32> = (0..notes.len())
        .map(|i| meta.spend_action_index(i).expect("spend index") as u32)
        .collect();
    spend_indices.sort_unstable();
    let output_indices: Vec<u32> = (0..spec.outputs.len())
        .map(|i| meta.output_action_index(i).expect("output index") as u32)
        .collect();
    let change_index = if change > 0 {
        Some(
            meta.output_action_index(spec.outputs.len())
                .expect("change index") as u32,
        )
    } else {
        None
    };

    let (magnitude, sign) = pczt.value_sum().magnitude_sign();
    let actions: Vec<Value> = pczt
        .actions()
        .iter()
        .map(|a| {
            let spend = a.spend();
            let enc = a.output().encrypted_note();
            json!({
                "cv_net": hex::encode(a.cv_net().to_bytes()),
                "spend": {
                    "nullifier": hex::encode(spend.nullifier().to_bytes()),
                    "rk": hex::encode(<[u8; 32]>::from(spend.rk())),
                    "spend_auth_sig": spend.spend_auth_sig().as_ref().map(|s| hex::encode(<[u8; 64]>::from(s))),
                    "alpha": spend.alpha().as_ref().map(|a| hex::encode(a.to_repr())),
                },
                "output": {
                    "cmx": hex::encode(a.output().cmx().to_bytes()),
                    "ephemeral_key": hex::encode(enc.epk_bytes),
                    "enc_ciphertext": hex::encode(enc.enc_ciphertext),
                    "out_ciphertext": hex::encode(enc.out_ciphertext),
                },
            })
        })
        .collect();
    let prepared_tx = json!({
        "version": "v0",
        "branch_id": BRANCH_ID_NU6_2,
        "expiry_height": EXPIRY_HEIGHT,
        "fee_zat": spec.fee.to_string(),
        "orchard_output_action_indices": output_indices,
        "orchard_change_action_index": change_index,
        "orchard_required_spend_action_indices": spend_indices,
        "orchard_pczt": {
            "actions": actions,
            "flags": pczt.flags().to_byte(),
            "value_sum": { "magnitude": magnitude, "is_negative": matches!(sign, Sign::Negative) },
            "anchor": hex::encode(pczt.anchor().to_bytes()),
            "zkproof": pczt.zkproof().as_ref().map(|p| hex::encode(p.as_ref())),
            "bsk": pczt.bsk().as_ref().map(|k| hex::encode(<[u8; 32]>::from(k))),
        },
    });

    let requests: Vec<Value> = spend_indices
        .iter()
        .map(|&i| {
            let spend = pczt.actions()[i as usize].spend();
            json!({
                "sighash": hex::encode(sighash),
                "action_index": i,
                "alpha": hex::encode(spend.alpha().expect("alpha").to_repr()),
                "rk": hex::encode(<[u8; 32]>::from(spend.rk())),
            })
        })
        .collect();

    let plan_notes: Vec<Value> = notes
        .iter()
        .zip(paths.iter())
        .enumerate()
        .map(|(i, (n, p))| {
            json!({
                "note_id": format!("{}:{}", "ab".repeat(32), i),
                "action_nullifier": hex::encode(n.action_nullifier),
                "cmx": hex::encode(n.cmx),
                "position": p.position(),
                "path": p.auth_path().iter().map(|h| hex::encode(h.to_bytes())).collect::<Vec<_>>(),
                "ephemeral_key": hex::encode(n.ephemeral_key),
                "enc_ciphertext": hex::encode(n.enc_compact),
            })
        })
        .collect();
    let plan_outputs: Vec<Value> = spec
        .outputs
        .iter()
        .map(|o| {
            let mut v =
                json!({ "to_address": encode_ua(&o.to), "amount_zat": o.amount.to_string() });
            if let Some(m) = o.memo {
                v["memo_hex"] = json!(hex::encode(m));
            }
            v
        })
        .collect();
    let txplan = json!({
        "version": "v0",
        "kind": "withdrawal",
        "wallet_id": "test-wallet",
        "coin_type": sign_policy::coin_type(Network::Regtest),
        "account": 0,
        "chain": "regtest",
        "branch_id": BRANCH_ID_NU6_2,
        "anchor_height": 100,
        "anchor": hex::encode(anchor.to_bytes()),
        "expiry_height": EXPIRY_HEIGHT,
        "outputs": plan_outputs,
        "change_address": encode_ua(&spec.change),
        "fee_zat": spec.fee.to_string(),
        "notes": plan_notes,
        "metadata": { "withdrawal_ids": ["0x01"] },
    });

    SpendFixture {
        txplan,
        prepared_tx,
        requests: json!({ "version": "v0", "requests": requests }),
        sighash,
        note_nullifiers: notes
            .iter()
            .map(|n| hex::encode(n.note.nullifier(&spec.fvk).to_bytes()))
            .collect(),
    }
}

/// Policy file JSON for `fvk` with the given overrides.
pub fn policy_json(fvk: &FullViewingKey, change: &Address, verifier_cmd: Vec<String>) -> Value {
    json!({
        "version": "v1",
        "ufvk": encode_ufvk(fvk),
        "change_address": encode_ua(change),
        "verifier_cmd": verifier_cmd,
    })
}
