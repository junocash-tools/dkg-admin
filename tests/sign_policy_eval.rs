mod support;

use reddsa::frost::redpallas;
use serde_json::json;

use dkg_admin::config::Network;
use dkg_admin::sign_policy::{PolicyRejection, SignPolicy, SignPolicyFileV1};

use support::*;

fn group_key(fvk: &orchard::keys::FullViewingKey) -> redpallas::VerifyingKey {
    redpallas::VerifyingKey::deserialize(&fvk.to_bytes()[..32]).unwrap()
}

fn policy_for(
    fvk: &orchard::keys::FullViewingKey,
    edit: impl FnOnce(&mut serde_json::Value),
) -> SignPolicy {
    let mut v = policy_json(fvk, &change_address(fvk), vec!["true".into()]);
    edit(&mut v);
    let file: SignPolicyFileV1 = serde_json::from_value(v).unwrap();
    SignPolicy::from_file(file, Network::Regtest).unwrap()
}

fn eval(
    policy: &SignPolicy,
    fvk: &orchard::keys::FullViewingKey,
    fx: &SpendFixture,
) -> Result<dkg_admin::sign_policy::ApprovedSpend, PolicyRejection> {
    policy.evaluate(
        &group_key(fvk),
        &fx.txplan_bytes(),
        &fx.prepared_bytes(),
        &fx.requests_bytes(),
    )
}

fn expect_code(r: Result<dkg_admin::sign_policy::ApprovedSpend, PolicyRejection>, code: &str) {
    match r {
        Ok(_) => panic!("expected rejection {code}, got approval"),
        Err(e) => assert_eq!(e.code, code, "unexpected rejection: {e}"),
    }
}

#[test]
fn approves_matching_spend() {
    let fvk = spending_fvk(1);
    let spec = SpendSpec::simple(fvk.clone());
    let fx = build_spend(&spec);
    let policy = policy_for(&fvk, |_| {});

    let ok = eval(&policy, &fvk, &fx).unwrap();
    assert_eq!(ok.sighash, fx.sighash);
    assert_eq!(ok.fee_zat, 15_000);
    assert_eq!(ok.change_zat, 1_000_000 - 250_000 - 15_000);
    assert_eq!(ok.spend_count, 1);
    assert_eq!(ok.alphas.len(), 1);
    assert_eq!(ok.outputs.len(), 1);
    assert_eq!(
        ok.outputs[0].to_address,
        encode_ua(&foreign_address(0x77, 0))
    );
    assert_eq!(ok.outputs[0].amount_zat, "250000");
    assert_eq!(ok.outputs[0].memo_hex, format!("f6{}", "00".repeat(511)));

    let ctx = ok.verifier_context(&policy, "0x01", 1, "cafe");
    assert_eq!(ctx.version, "v1");
    assert_eq!(ctx.sighash, hex::encode(fx.sighash));
    assert_eq!(ctx.txplan, fx.txplan);
}

#[test]
fn approves_two_notes_with_memo_and_multiple_outputs() {
    let fvk = spending_fvk(2);
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.note_values = vec![400_000, 300_000];
    let mut memo = [0u8; 512];
    memo[..5].copy_from_slice(b"hello");
    spec.outputs = vec![
        PlanOutput {
            to: foreign_address(0x71, 0),
            amount: 100_000,
            memo: Some(memo),
        },
        PlanOutput {
            to: foreign_address(0x72, 3),
            amount: 200_000,
            memo: None,
        },
    ];
    let fx = build_spend(&spec);
    let ok = eval(&policy_for(&fvk, |_| {}), &fvk, &fx).unwrap();
    assert_eq!(ok.spend_count, 2);
    assert_eq!(ok.alphas.len(), 2);
    assert_eq!(ok.change_zat, 700_000 - 300_000 - 15_000);
}

#[test]
fn approves_spend_without_change() {
    let fvk = spending_fvk(3);
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.outputs[0].amount = 1_000_000 - 15_000;
    let fx = build_spend(&spec);
    let ok = eval(&policy_for(&fvk, |_| {}), &fvk, &fx).unwrap();
    assert_eq!(ok.change_zat, 0);
}

#[test]
fn rejects_change_address_mismatch() {
    let fvk = spending_fvk(4);
    let mut spec = SpendSpec::simple(fvk.clone());
    // Wallet-owned, but not the configured change address.
    spec.change = external_address(&fvk, 9);
    let fx = build_spend(&spec);
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "change_address_mismatch",
    );
}

#[test]
fn rejects_fee_over_cap() {
    let fvk = spending_fvk(5);
    let spec = SpendSpec::simple(fvk.clone());
    let fx = build_spend(&spec);
    let policy = policy_for(&fvk, |v| v["max_fee_zat"] = json!(10_000));
    expect_code(eval(&policy, &fvk, &fx), "fee_over_cap");

    // Default cap is 10,000,000 zat.
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.note_values = vec![20_000_000];
    spec.fee = 10_000_001;
    let fx = build_spend(&spec);
    expect_code(eval(&policy_for(&fvk, |_| {}), &fvk, &fx), "fee_over_cap");
}

#[test]
fn rejects_too_many_spends() {
    let fvk = spending_fvk(6);
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.note_values = vec![600_000, 600_000];
    let fx = build_spend(&spec);
    let policy = policy_for(&fvk, |v| v["max_spends"] = json!(1));
    expect_code(eval(&policy, &fvk, &fx), "too_many_spends");
}

#[test]
fn rejects_requested_sighash_mismatch() {
    let fvk = spending_fvk(7);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    let mut fx2 = fx.clone();
    fx2.requests["requests"][0]["sighash"] = json!("11".repeat(32));
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx2),
        "sighash_mismatch",
    );
}

#[test]
fn rejects_plan_fee_that_does_not_match_transaction() {
    let fvk = spending_fvk(8);
    let mut fx = build_spend(&SpendSpec::simple(fvk.clone()));
    fx.txplan["fee_zat"] = json!("10000");
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "prepared_tx_mismatch",
    );

    // Fee rewritten consistently in plan and prepared tx: value balance no longer matches.
    let mut fx = build_spend(&SpendSpec::simple(fvk.clone()));
    fx.txplan["fee_zat"] = json!("10000");
    fx.prepared_tx["fee_zat"] = json!("10000");
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "value_balance_mismatch",
    );
}

#[test]
fn rejects_plan_output_that_differs_from_transaction() {
    let fvk = spending_fvk(9);
    let mut fx = build_spend(&SpendSpec::simple(fvk.clone()));
    // Plan claims a different recipient than the transaction pays.
    fx.txplan["outputs"][0]["to_address"] = json!(encode_ua(&foreign_address(0x78, 0)));
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "outputs_mismatch",
    );

    let mut fx = build_spend(&SpendSpec::simple(fvk.clone()));
    fx.txplan["outputs"][0]["memo_hex"] = json!("00ff");
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "outputs_mismatch",
    );
}

#[test]
fn rejects_hidden_output_without_ovk() {
    let fvk = spending_fvk(10);
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.hidden_output = Some((foreign_address(0x79, 0), 100_000));
    let fx = build_spend(&spec);
    // One spend and two expected outputs leave no room for a third action.
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "actions_too_many",
    );

    // Redirect the whole change to the hidden output: the action count now fits,
    // so it has to be caught by the OVK output match instead.
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.hidden_output = Some((foreign_address(0x79, 0), 1_000_000 - 250_000 - 15_000));
    let fx = build_spend(&spec);
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx),
        "outputs_mismatch",
    );
}

#[test]
fn rejects_spend_set_that_differs_from_plan() {
    let fvk = spending_fvk(11);
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.note_values = vec![600_000, 600_000];
    let fx = build_spend(&spec);

    // Plan only lists one of the two notes being spent.
    let mut fx1 = fx.clone();
    fx1.txplan["notes"].as_array_mut().unwrap().pop();
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx1),
        "spend_set_mismatch",
    );

    // Coordinator only asks for one of the two spend signatures.
    let mut fx2 = fx;
    fx2.requests["requests"].as_array_mut().unwrap().pop();
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &fx2),
        "spend_set_mismatch",
    );
}

#[test]
fn rejects_alpha_and_rk_tampering() {
    let fvk = spending_fvk(12);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    let policy = policy_for(&fvk, |_| {});

    let mut t = fx.clone();
    t.requests["requests"][0]["rk"] = json!("22".repeat(32));
    expect_code(eval(&policy, &fvk, &t), "rk_mismatch");

    let mut t = fx.clone();
    t.requests["requests"][0]["alpha"] = json!(format!("01{}", "00".repeat(31)));
    expect_code(eval(&policy, &fvk, &t), "alpha_mismatch");

    let mut t = fx;
    let idx = t.requests["requests"][0]["action_index"].as_u64().unwrap();
    t.requests["requests"][0]["action_index"] = json!(if idx == 0 { 1 } else { 0 });
    let r = eval(&policy, &fvk, &t);
    assert!(r.is_err(), "moved action index must be rejected");
}

#[test]
fn rejects_wrong_group_key_and_foreign_notes() {
    let fvk = spending_fvk(13);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    let policy = policy_for(&fvk, |_| {});
    let other = spending_fvk(14);
    let r = policy.evaluate(
        &group_key(&other),
        &fx.txplan_bytes(),
        &fx.prepared_bytes(),
        &fx.requests_bytes(),
    );
    assert_eq!(r.unwrap_err().code, "ufvk_group_key_mismatch");

    // A transaction built for another wallet is not ours to sign.
    let fx_other = build_spend(&SpendSpec {
        change: change_address(&fvk),
        ..SpendSpec::simple(other.clone())
    });
    let r = eval(&policy, &fvk, &fx_other);
    assert!(r.is_err(), "foreign wallet spend must be rejected");
}

#[test]
fn rejects_malformed_inputs() {
    let fvk = spending_fvk(15);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    let policy = policy_for(&fvk, |_| {});
    let gk = group_key(&fvk);
    assert_eq!(
        policy
            .evaluate(&gk, b"{", &fx.prepared_bytes(), &fx.requests_bytes())
            .unwrap_err()
            .code,
        "txplan_invalid"
    );
    assert_eq!(
        policy
            .evaluate(&gk, &fx.txplan_bytes(), b"{}", &fx.requests_bytes())
            .unwrap_err()
            .code,
        "prepared_tx_invalid"
    );
    assert_eq!(
        policy
            .evaluate(&gk, &fx.txplan_bytes(), &fx.prepared_bytes(), b"[]")
            .unwrap_err()
            .code,
        "signing_requests_invalid"
    );

    let mut t = fx.clone();
    t.txplan["coin_type"] = json!(8133);
    expect_code(eval(&policy, &fvk, &t), "coin_type_mismatch");

    let mut t = fx;
    t.txplan["expiry_height"] = json!(999);
    expect_code(eval(&policy, &fvk, &t), "prepared_tx_mismatch");
}

#[test]
fn policy_file_rejects_change_address_not_owned() {
    let fvk = spending_fvk(16);
    let v = policy_json(&fvk, &foreign_address(0x70, 0), vec!["true".into()]);
    let file: SignPolicyFileV1 = serde_json::from_value(v).unwrap();
    let err = SignPolicy::from_file(file, Network::Regtest).unwrap_err();
    assert!(err.to_string().contains("change_address"), "{err}");
}

fn set_request_sighash(fx: &mut SpendFixture) {
    let sighash = dkg_admin::sign_policy::prepared_tx_sighash(&fx.prepared_bytes()).unwrap();
    for r in fx.requests["requests"].as_array_mut().unwrap() {
        r["sighash"] = json!(hex::encode(sighash));
    }
}

fn action_index_of(fx: &SpendFixture, nullifier_hex: &str) -> usize {
    fx.prepared_tx["orchard_pczt"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|a| a["spend"]["nullifier"] == json!(nullifier_hex))
        .expect("note is spent in the bundle")
}

#[test]
fn rejects_unrequested_spend_reusing_a_signed_rk() {
    // A coordinator hides a second wallet note in the bundle, gives it the same rk
    // as the requested spend and sends its value to an output we can't recover.
    // One signature over the sighash would authorize both spends.
    let fvk = spending_fvk(17);
    let mut spec = SpendSpec::simple(fvk.clone());
    spec.note_values = vec![600_000, 400_000];
    spec.hidden_output = Some((foreign_address(0x7a, 0), 400_000));
    let fx = build_spend(&spec);

    let signed = action_index_of(&fx, &fx.note_nullifiers[0]);
    let hidden = action_index_of(&fx, &fx.note_nullifiers[1]);
    let mut t = fx.clone();
    t.txplan["notes"].as_array_mut().unwrap().remove(1);
    t.requests["requests"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["action_index"] == json!(signed));
    let actions = t.prepared_tx["orchard_pczt"]["actions"]
        .as_array_mut()
        .unwrap();
    let signed_spend = actions[signed]["spend"].clone();
    actions[hidden]["spend"]["rk"] = signed_spend["rk"].clone();
    actions[hidden]["spend"]["alpha"] = signed_spend["alpha"].clone();
    t.prepared_tx["orchard_required_spend_action_indices"] = json!([signed]);
    set_request_sighash(&mut t);

    expect_code(eval(&policy_for(&fvk, |_| {}), &fvk, &t), "rk_reused");
}

#[test]
fn rejects_branch_other_than_nu6_2() {
    let fvk = spending_fvk(18);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    // NU5 and Sapling (v4 sighash does not cover the Orchard bundle).
    for branch in [0xc2d6_d0b4u32, 0x76b8_09bb] {
        let mut t = fx.clone();
        t.txplan["branch_id"] = json!(branch);
        t.prepared_tx["branch_id"] = json!(branch);
        expect_code(
            eval(&policy_for(&fvk, |_| {}), &fvk, &t),
            "branch_id_unsupported",
        );
    }
}

#[test]
fn rejects_padding_actions_beyond_what_the_plan_needs() {
    let fvk = spending_fvk(19);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    // Take an unrelated action (distinct rk and nullifier) from another bundle.
    let other = build_spend(&SpendSpec::simple(spending_fvk(20)));
    let extra = other.prepared_tx["orchard_pczt"]["actions"][0].clone();

    let mut t = fx.clone();
    t.prepared_tx["orchard_pczt"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    set_request_sighash(&mut t);
    expect_code(
        eval(&policy_for(&fvk, |_| {}), &fvk, &t),
        "actions_too_many",
    );
}

#[test]
fn verifier_sees_canonical_addresses() {
    let fvk = spending_fvk(21);
    let fx = build_spend(&SpendSpec::simple(fvk.clone()));
    let canonical = encode_ua(&foreign_address(0x77, 0));
    let mut t = fx.clone();
    t.txplan["outputs"][0]["to_address"] = json!(format!("  {}\n", canonical.to_uppercase()));
    let policy = policy_for(&fvk, |_| {});
    match eval(&policy, &fvk, &t) {
        Ok(ok) => assert_eq!(ok.outputs[0].to_address, canonical),
        Err(e) => assert_eq!(e.code, "txplan_output_invalid", "{e}"),
    }
    assert_eq!(policy.change_address(), encode_ua(&change_address(&fvk)));
}
