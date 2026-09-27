//! Sign policy enforced by real `dkg-admin serve` peers (3-of-5, mTLS, in-process DKG).

mod support;

use std::collections::BTreeMap;
use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use orchard::keys::{FullViewingKey, Scope};
use orchard::primitives::redpallas;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use reddsa::frost::redpallas as frost;
use serde_json::{json, Value};

use dkg_admin::config::{AdminConfigV1, ValidatedAdminConfig};
use dkg_admin::dkg::AdminDkg;
use dkg_admin::roster::{RosterOperatorV1, RosterV1};
use dkg_admin::storage;

use support::{build_spend, change_address, encode_ua, fvk_with_ak, policy_json, SpendSpec};

const N: u16 = 5;
const T: u16 = 3;

#[test]
fn policy_allows_matching_spend_and_signatures_verify() {
    let mut h = Harness::new().unwrap();
    let fixture = build_spend(&SpendSpec::simple(h.fvk.clone()));
    let inputs = h.write_inputs(
        "ok",
        &fixture.txplan,
        &fixture.prepared_tx,
        &fixture.requests,
    );

    let ctx_dir = h.tmp.path().join("verifier-ctx");
    std::fs::create_dir_all(&ctx_dir).unwrap();
    let script = format!("cat > {}/ctx-$$.json", ctx_dir.display());
    let policy = h.policy(vec!["sh".into(), "-c".into(), script], |_| {});
    h.start_all(|_| Some(policy.clone()));

    let out = h.tmp.path().join("sigs.json");
    let res = h.run_sign(1, &session(1), &inputs, true, &out);
    assert_success(&res);

    let sigs: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let reqs = fixture.requests["requests"].as_array().unwrap();
    let got = sigs["signatures"].as_array().unwrap();
    assert_eq!(got.len(), reqs.len());
    for (req, sig) in reqs.iter().zip(got) {
        assert_eq!(req["action_index"], sig["action_index"]);
        let rk: [u8; 32] = hex_arr(req["rk"].as_str().unwrap());
        let sig: [u8; 64] = hex_arr(sig["spend_auth_sig"].as_str().unwrap());
        let vk = redpallas::VerificationKey::<redpallas::SpendAuth>::try_from(rk).unwrap();
        vk.verify(&fixture.sighash, &redpallas::Signature::from(sig))
            .expect("spend auth sig verifies");
    }

    // Every peer that approved ran the verifier with the full context.
    let ctxs: Vec<Value> = std::fs::read_dir(&ctx_dir)
        .unwrap()
        .map(|e| serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap())
        .collect();
    assert_eq!(ctxs.len(), N as usize);
    let mut ids: Vec<u64> = ctxs
        .iter()
        .map(|c| c["identifier"].as_u64().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (1..=N as u64).collect::<Vec<_>>());
    for c in &ctxs {
        assert_eq!(c["version"], "v1");
        assert_eq!(c["network"], "regtest");
        assert_eq!(c["sighash"], hex::encode(fixture.sighash));
        assert_eq!(c["fee_zat"], "15000");
        assert_eq!(c["change_zat"], "735000");
        assert_eq!(c["spend_count"], 1);
        assert_eq!(c["txplan"], fixture.txplan);
        assert_eq!(c["outputs"][0]["amount_zat"], "250000");
        assert_eq!(
            c["outputs"][0]["to_address"],
            fixture.txplan["outputs"][0]["to_address"]
        );
    }
    for id in 1..=N {
        let log = h.serve_log(id);
        assert!(
            log.contains("sign policy approved spend"),
            "op{id} log: {log}"
        );
    }
}

#[test]
fn policy_blocks_signing_without_approval() {
    let mut h = Harness::new().unwrap();
    let fixture = build_spend(&SpendSpec::simple(h.fvk.clone()));
    let inputs = h.write_inputs(
        "ok",
        &fixture.txplan,
        &fixture.prepared_tx,
        &fixture.requests,
    );
    let policy = h.policy(vec!["true".into()], |_| {});
    h.start_all(|_| Some(policy.clone()));

    // Same requests, but the coordinator does not send the plan: peers refuse to commit.
    let res = h.run_sign(
        1,
        &session(2),
        &inputs,
        false,
        &h.tmp.path().join("sigs.json"),
    );
    assert!(!res.status.success());
    assert_eq!(res.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("threshold_unmet"), "stderr={stderr}");
    let log = h.serve_log(2);
    assert!(log.contains("not_approved"), "log={log}");
}

#[test]
fn policy_rejections_are_typed_and_logged() {
    let mut h = Harness::new().unwrap();
    let simple = build_spend(&SpendSpec::simple(h.fvk.clone()));
    let two_notes = build_spend(&SpendSpec {
        note_values: vec![600_000, 400_000],
        ..SpendSpec::simple(h.fvk.clone())
    });
    let mut tampered_requests = simple.requests.clone();
    tampered_requests["requests"][0]["sighash"] = json!(hex::encode([0x42u8; 32]));
    let other_change = encode_ua(&h.fvk.address_at(7u32, Scope::Internal));

    struct Case {
        name: &'static str,
        policy: Value,
        txplan: Value,
        prepared: Value,
        requests: Value,
        code: &'static str,
    }
    let allow = || vec!["true".to_string()];
    let cases = vec![
        Case {
            name: "change_address",
            policy: h.policy(allow(), |p| p["change_address"] = json!(other_change)),
            txplan: simple.txplan.clone(),
            prepared: simple.prepared_tx.clone(),
            requests: simple.requests.clone(),
            code: "change_address_mismatch",
        },
        Case {
            name: "fee_cap",
            policy: h.policy(allow(), |p| p["max_fee_zat"] = json!(10_000)),
            txplan: simple.txplan.clone(),
            prepared: simple.prepared_tx.clone(),
            requests: simple.requests.clone(),
            code: "fee_over_cap",
        },
        Case {
            name: "max_spends",
            policy: h.policy(allow(), |p| p["max_spends"] = json!(1)),
            txplan: two_notes.txplan.clone(),
            prepared: two_notes.prepared_tx.clone(),
            requests: two_notes.requests.clone(),
            code: "too_many_spends",
        },
        Case {
            name: "verifier",
            policy: h.policy(
                vec!["sh".into(), "-c".into(), "echo nope >&2; exit 3".into()],
                |_| {},
            ),
            txplan: simple.txplan.clone(),
            prepared: simple.prepared_tx.clone(),
            requests: simple.requests.clone(),
            code: "verifier_rejected",
        },
        Case {
            name: "sighash",
            policy: h.policy(allow(), |_| {}),
            txplan: simple.txplan.clone(),
            prepared: simple.prepared_tx.clone(),
            requests: tampered_requests,
            code: "sighash_mismatch",
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let inputs = h.write_inputs(case.name, &case.txplan, &case.prepared, &case.requests);
        h.start_all(|_| Some(case.policy.clone()));
        let out = h.tmp.path().join(format!("sigs-{}.json", case.name));
        let res = h.run_sign(1, &session(10 + i as u8), &inputs, true, &out);
        let stderr = String::from_utf8_lossy(&res.stderr);
        assert!(!res.status.success(), "{}: expected failure", case.name);
        assert_eq!(res.status.code(), Some(1), "{}: stderr={stderr}", case.name);
        assert!(
            stderr.contains("policy_rejected: need=3 have=0"),
            "{}: stderr={stderr}",
            case.name
        );
        assert!(stderr.contains(case.code), "{}: stderr={stderr}", case.name);
        assert!(!out.exists(), "{}: no signatures expected", case.name);
        for id in 1..=N {
            let log = h.serve_log(id);
            assert!(
                log.contains("sign policy rejected spend") && log.contains(case.code),
                "{}: op{id} log={log}",
                case.name
            );
        }
        if case.name == "verifier" {
            assert!(stderr.contains("exit=3"), "stderr={stderr}");
            assert!(stderr.contains("nope"), "stderr={stderr}");
        }
    }
}

#[test]
fn threshold_of_approving_peers_is_enough() {
    let mut h = Harness::new().unwrap();
    let fixture = build_spend(&SpendSpec::simple(h.fvk.clone()));
    let inputs = h.write_inputs(
        "ok",
        &fixture.txplan,
        &fixture.prepared_tx,
        &fixture.requests,
    );

    // Two peers reject, three approve: signing succeeds with the three.
    let allow = h.policy(vec!["true".into()], |_| {});
    let deny = h.policy(vec!["false".into()], |_| {});
    h.start_all(|id| Some(if id <= 2 { deny.clone() } else { allow.clone() }));
    let res = h.run_sign(3, &session(20), &inputs, true, &h.tmp.path().join("a.json"));
    assert_success(&res);

    // Three peers reject: below threshold.
    h.start_all(|id| Some(if id <= 3 { deny.clone() } else { allow.clone() }));
    let res = h.run_sign(4, &session(21), &inputs, true, &h.tmp.path().join("b.json"));
    assert!(!res.status.success());
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("policy_rejected: need=3 have=2"),
        "stderr={stderr}"
    );
}

#[test]
fn peers_without_policy_sign_as_before() {
    let mut h = Harness::new().unwrap();
    let fixture = build_spend(&SpendSpec::simple(h.fvk.clone()));
    let inputs = h.write_inputs(
        "ok",
        &fixture.txplan,
        &fixture.prepared_tx,
        &fixture.requests,
    );
    h.start_all(|_| None);

    let a = h.tmp.path().join("a.json");
    assert_success(&h.run_sign(1, &session(30), &inputs, false, &a));
    let b = h.tmp.path().join("b.json");
    assert_success(&h.run_sign(2, &session(31), &inputs, true, &b));

    // Mixed fleet: policy peers enforce, legacy peers keep signing.
    let allow = h.policy(vec!["true".into()], |_| {});
    h.start_all(|id| if id <= 2 { Some(allow.clone()) } else { None });
    let c = h.tmp.path().join("c.json");
    assert_success(&h.run_sign(5, &session(32), &inputs, true, &c));

    // Only one of --txplan/--prepared-tx is a usage error.
    let cfg = h.config_paths[&1].clone();
    let res = Command::new(&h.bin_path)
        .arg("--config")
        .arg(cfg)
        .arg("sign-spendauth")
        .arg("--session-id")
        .arg(session(33))
        .arg("--requests")
        .arg(&inputs.requests)
        .arg("--txplan")
        .arg(&inputs.txplan)
        .arg("--out")
        .arg(h.tmp.path().join("d.json"))
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("--prepared-tx"), "{stderr}");
}

#[test]
fn serve_refuses_policy_for_a_different_key() {
    let mut h = Harness::new().unwrap();
    let other = support::spending_fvk(0x31);
    let bad = policy_json(&other, &change_address(&other), vec!["true".into()]);
    let path = h.tmp.path().join("bad-policy.json");
    write_json(&path, &bad).unwrap();

    let res = Command::new(&h.bin_path)
        .arg("--config")
        .arg(&h.config_paths[&1])
        .arg("serve")
        .arg("--sign-policy-file")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!res.status.success());
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("ufvk_group_key_mismatch"),
        "stderr={stderr}"
    );

    let broken = h.tmp.path().join("broken-policy.json");
    std::fs::write(&broken, b"{\"version\":\"v1\"}").unwrap();
    let res = Command::new(&h.bin_path)
        .arg("--config")
        .arg(&h.config_paths[&1])
        .arg("serve")
        .arg("--sign-policy-file")
        .arg(&broken)
        .output()
        .unwrap();
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("sign_policy_invalid"));
    h.stop_all();
}

fn session(n: u8) -> String {
    format!("0x{}", hex::encode([n; 32]))
}

fn hex_arr<const L: usize>(s: &str) -> [u8; L] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn assert_success(res: &Output) {
    assert!(
        res.status.success(),
        "status={:?} stderr={}",
        res.status,
        String::from_utf8_lossy(&res.stderr)
    );
}

struct Inputs {
    txplan: PathBuf,
    prepared: PathBuf,
    requests: PathBuf,
}

struct Harness {
    tmp: tempfile::TempDir,
    bin_path: PathBuf,
    config_paths: BTreeMap<u16, PathBuf>,
    ports: BTreeMap<u16, u16>,
    processes: BTreeMap<u16, ChildGuard>,
    fvk: FullViewingKey,
    starts: u32,
}

impl Harness {
    fn new() -> anyhow::Result<Self> {
        let tmp = tempfile::TempDir::new().context("tempdir")?;
        let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_dkg-admin"));

        let (ca_pem, client_cert_pem, client_key_pem, server_cert_pem, server_key_pem) =
            gen_test_mtls_material();
        let tls_dir = tmp.path().join("tls");
        std::fs::create_dir_all(&tls_dir).context("mkdir tls")?;
        let ca_path = tls_dir.join("ca.pem");
        let client_cert_path = tls_dir.join("client.pem");
        let client_key_path = tls_dir.join("client.key");
        let server_cert_path = tls_dir.join("server.pem");
        let server_key_path = tls_dir.join("server.key");
        std::fs::write(&ca_path, &ca_pem)?;
        std::fs::write(&client_cert_path, &client_cert_pem)?;
        std::fs::write(&client_key_path, &client_key_pem)?;
        std::fs::write(&server_cert_path, &server_cert_pem)?;
        std::fs::write(&server_key_path, &server_key_pem)?;

        let mut ports = BTreeMap::new();
        for id in 1..=N {
            ports.insert(id, pick_unused_port()?);
        }
        let roster = RosterV1 {
            roster_version: 1,
            operators: (1..=N)
                .map(|id| RosterOperatorV1 {
                    operator_id: format!("0x{id:040x}"),
                    grpc_endpoint: Some(format!("https://localhost:{}", ports[&id])),
                    age_recipient: None,
                })
                .collect(),
            coordinator_age_recipient: None,
        };
        let roster_hash_hex = roster.roster_hash_hex().context("roster hash")?;

        let mut cfgs = Vec::new();
        let mut config_paths = BTreeMap::new();
        for id in 1..=N {
            let state_dir = tmp.path().join(format!("op{id:02}/state"));
            std::fs::create_dir_all(&state_dir)?;
            let cfg_path = tmp.path().join(format!("op{id:02}/config.json"));
            let cfg_json = json!({
                "config_version": 1,
                "ceremony_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "operator_id": format!("0x{id:040x}"),
                "identifier": id,
                "threshold": T,
                "max_signers": N,
                "network": "regtest",
                "roster": &roster,
                "roster_hash_hex": &roster_hash_hex,
                "state_dir": state_dir,
                "age_identity_file": null,
                "grpc": {
                    "listen_addr": format!("127.0.0.1:{}", ports[&id]),
                    "tls_ca_cert_pem_path": &ca_path,
                    "tls_server_cert_pem_path": &server_cert_path,
                    "tls_server_key_pem_path": &server_key_path,
                    "tls_client_cert_pem_path": &client_cert_path,
                    "tls_client_key_pem_path": &client_key_path,
                    "tls_domain_name_override": "localhost",
                    "coordinator_client_cert_sha256": null
                }
            });
            write_json(&cfg_path, &cfg_json)?;
            cfgs.push(AdminConfigV1::from_path(&cfg_path)?.validate()?);
            config_paths.insert(id, cfg_path);
        }

        run_dkg(&cfgs)?;
        let pkp_bytes = storage::read(&cfgs[0].cfg.state_dir.join("public_key_package.bin"))?;
        let pkp = frost::keys::PublicKeyPackage::deserialize(&pkp_bytes)?;
        let ak: [u8; 32] = pkp.verifying_key().serialize()?.try_into().unwrap();
        let fvk = fvk_with_ak(ak, 0x11);

        Ok(Self {
            tmp,
            bin_path,
            config_paths,
            ports,
            processes: BTreeMap::new(),
            fvk,
            starts: 0,
        })
    }

    /// Policy file JSON for the group wallet, edited by `edit`.
    fn policy(&self, verifier_cmd: Vec<String>, edit: impl FnOnce(&mut Value)) -> Value {
        let mut p = policy_json(&self.fvk, &change_address(&self.fvk), verifier_cmd);
        edit(&mut p);
        p
    }

    fn write_inputs(
        &self,
        name: &str,
        txplan: &Value,
        prepared: &Value,
        requests: &Value,
    ) -> Inputs {
        let dir = self.tmp.path().join(format!("inputs-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        let inputs = Inputs {
            txplan: dir.join("txplan.json"),
            prepared: dir.join("prepared.json"),
            requests: dir.join("requests.json"),
        };
        write_json(&inputs.txplan, txplan).unwrap();
        write_json(&inputs.prepared, prepared).unwrap();
        write_json(&inputs.requests, requests).unwrap();
        inputs
    }

    /// (Re)starts every operator; `policy_for(id)` picks its policy file, if any.
    fn start_all(&mut self, policy_for: impl Fn(u16) -> Option<Value>) {
        self.stop_all();
        self.starts += 1;
        for id in 1..=N {
            let dir = self.tmp.path().join(format!("op{id:02}"));
            let log_path = dir.join("serve.log");
            let log = File::create(&log_path).unwrap();
            let log_err = log.try_clone().unwrap();
            let mut cmd = Command::new(&self.bin_path);
            cmd.arg("--config")
                .arg(&self.config_paths[&id])
                .arg("serve");
            if let Some(policy) = policy_for(id) {
                let path = dir.join(format!("policy-{}.json", self.starts));
                write_json(&path, &policy).unwrap();
                cmd.arg("--sign-policy-file").arg(path);
            }
            cmd.stdout(Stdio::from(log)).stderr(Stdio::from(log_err));
            self.processes
                .insert(id, ChildGuard(cmd.spawn().expect("spawn serve")));
        }
        for id in 1..=N {
            wait_for_tcp(self.ports[&id], Duration::from_secs(20)).unwrap();
        }
    }

    fn stop_all(&mut self) {
        self.processes.clear();
        for id in 1..=N {
            wait_for_port_free(self.ports[&id], Duration::from_secs(10));
        }
    }

    fn run_sign(
        &self,
        config_identifier: u16,
        session_id: &str,
        inputs: &Inputs,
        with_policy_inputs: bool,
        out: &Path,
    ) -> Output {
        let mut cmd = Command::new(&self.bin_path);
        cmd.arg("--config")
            .arg(&self.config_paths[&config_identifier])
            .arg("sign-spendauth")
            .arg("--session-id")
            .arg(session_id)
            .arg("--requests")
            .arg(&inputs.requests)
            .arg("--out")
            .arg(out);
        if with_policy_inputs {
            cmd.arg("--txplan")
                .arg(&inputs.txplan)
                .arg("--prepared-tx")
                .arg(&inputs.prepared);
        }
        cmd.output().unwrap()
    }

    fn serve_log(&self, id: u16) -> String {
        std::fs::read_to_string(self.tmp.path().join(format!("op{id:02}/serve.log")))
            .unwrap_or_default()
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_dkg(cfgs: &[ValidatedAdminConfig]) -> anyhow::Result<()> {
    let mut round1 = BTreeMap::<u16, Vec<u8>>::new();
    for cfg in cfgs {
        let mut seed = [0u8; 32];
        seed[0..2].copy_from_slice(&cfg.cfg.identifier.to_le_bytes());
        seed[2] = 0x5a;
        let out = AdminDkg::new(cfg.clone()).part1(ChaCha20Rng::from_seed(seed))?;
        round1.insert(cfg.cfg.identifier, out.round1_package_bytes);
    }
    let mut round2_to = BTreeMap::<u16, BTreeMap<u16, Vec<u8>>>::new();
    for cfg in cfgs {
        let mut others = round1.clone();
        others.remove(&cfg.cfg.identifier);
        let out = AdminDkg::new(cfg.clone()).part2(others)?;
        for (receiver, pkg) in out.round2_packages {
            if receiver != cfg.cfg.identifier {
                round2_to
                    .entry(receiver)
                    .or_default()
                    .insert(cfg.cfg.identifier, pkg.package_bytes);
            }
        }
    }
    for cfg in cfgs {
        let mut others = round1.clone();
        others.remove(&cfg.cfg.identifier);
        let to_me = round2_to
            .remove(&cfg.cfg.identifier)
            .ok_or_else(|| anyhow!("round2 missing"))?;
        AdminDkg::new(cfg.clone()).part3(others, to_me)?;
    }
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn pick_unused_port() -> anyhow::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn wait_for_tcp(port: u16, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        if start.elapsed() > timeout {
            return Err(anyhow!("tcp_timeout: {port}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn wait_for_port_free(port: u16, timeout: Duration) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_ok() && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[allow(clippy::type_complexity)]
fn gen_test_mtls_material() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-test-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params = CertificateParams::new(vec!["coordinator".to_string()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    (
        ca_cert.pem().into_bytes(),
        client_cert.pem().into_bytes(),
        client_key.serialize_pem().into_bytes(),
        server_cert.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}
