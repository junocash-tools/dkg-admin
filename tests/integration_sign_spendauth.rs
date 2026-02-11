use std::collections::BTreeMap;
use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use reddsa::frost::redpallas;

use dkg_admin::config::{AdminConfigV1, ValidatedAdminConfig};
use dkg_admin::dkg::AdminDkg;
use dkg_admin::roster::{RosterOperatorV1, RosterV1};
use dkg_admin::storage;

const N: u16 = 5;
const T: u16 = 3;

#[test]
fn sign_spendauth_success_conflict_and_idempotency() {
    let harness = TestHarness::new().unwrap();

    let requests_path = harness.tmp.path().join("requests.v0.json");
    let out1 = harness.tmp.path().join("sigs1.v0.json");
    let out2 = harness.tmp.path().join("sigs2.v0.json");
    let out3 = harness.tmp.path().join("sigs3.v0.json");

    write_requests_file(
        &requests_path,
        &harness.public_key_package,
        vec![(9, [0x11; 32], [1u8; 32]), (2, [0x22; 32], [0u8; 32])],
    )
    .unwrap();

    let session = format!("0x{}", "11".repeat(32));
    let ok = harness.run_sign(1, &session, &requests_path, &out1, &[]);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let sigs = read_output(&out1).unwrap();
    assert_eq!(sigs.version, "v0");
    assert_eq!(sigs.signatures.len(), 2);
    assert_eq!(sigs.signatures[0].action_index, 2);
    assert_eq!(sigs.signatures[1].action_index, 9);
    assert_eq!(sigs.signatures[0].spend_auth_sig.len(), 128);
    assert_eq!(sigs.signatures[1].spend_auth_sig.len(), 128);

    // Re-run the same session/inputs: output must be byte-identical.
    let ok2 = harness.run_sign(1, &session, &requests_path, &out2, &[]);
    assert!(
        ok2.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok2.stderr)
    );
    assert_eq!(std::fs::read(&out1).unwrap(), std::fs::read(&out2).unwrap());

    // Same session id + different request set must fail with session_conflict.
    let requests_conflict = harness.tmp.path().join("requests_conflict.v0.json");
    write_requests_file(
        &requests_conflict,
        &harness.public_key_package,
        vec![(3, [0x33; 32], [0u8; 32])],
    )
    .unwrap();

    let bad = harness.run_sign(1, &session, &requests_conflict, &out3, &[]);
    assert_eq!(bad.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("session_conflict"), "stderr={stderr}");
}

#[test]
fn sign_spendauth_fault_tolerance_and_threshold_failure() {
    let mut harness = TestHarness::new().unwrap();

    let requests_path = harness.tmp.path().join("requests_fault.v0.json");
    let out_ok = harness.tmp.path().join("sigs_fault_ok.v0.json");
    let out_fail = harness.tmp.path().join("sigs_fault_fail.v0.json");

    write_requests_file(
        &requests_path,
        &harness.public_key_package,
        vec![(7, [0x44; 32], [0u8; 32])],
    )
    .unwrap();

    // Drop one low-id operator; with 4 online and threshold 3, signing must succeed.
    harness.stop_operator(2).unwrap();
    let session_ok = format!("0x{}", "22".repeat(32));
    let ok = harness.run_sign(1, &session_ok, &requests_path, &out_ok, &[]);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // Drop below threshold: now only 2 remain online.
    harness.stop_operator(3).unwrap();
    harness.stop_operator(4).unwrap();
    let session_fail = format!("0x{}", "33".repeat(32));
    let fail = harness.run_sign(1, &session_fail, &requests_path, &out_fail, &[]);
    assert_eq!(fail.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&fail.stderr);
    assert!(stderr.contains("threshold_unmet"), "stderr={stderr}");
}

#[test]
fn sign_spendauth_recovery_after_interrupted_session() {
    let harness = TestHarness::new().unwrap();

    let requests_path = harness.tmp.path().join("requests_recovery.v0.json");
    let out_a = harness.tmp.path().join("sigs_recovery_a.v0.json");
    let out_b = harness.tmp.path().join("sigs_recovery_b.v0.json");
    let out_c = harness.tmp.path().join("sigs_recovery_c.v0.json");

    write_requests_file(
        &requests_path,
        &harness.public_key_package,
        vec![(5, [0x55; 32], [1u8; 32]), (6, [0x66; 32], [0u8; 32])],
    )
    .unwrap();

    let session = format!("0x{}", "44".repeat(32));

    // Simulate crash/interruption after first action.
    let fail = harness.run_sign(
        1,
        &session,
        &requests_path,
        &out_a,
        &[("DKG_ADMIN_TEST_ABORT_AFTER_ACTION", "1")],
    );
    assert_eq!(fail.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&fail.stderr);
    assert!(stderr.contains("session_interrupted"), "stderr={stderr}");

    // Re-run same session and request set: should resume safely and succeed.
    let ok = harness.run_sign(1, &session, &requests_path, &out_b, &[]);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // Re-run again: idempotent and byte-identical.
    let ok2 = harness.run_sign(1, &session, &requests_path, &out_c, &[]);
    assert!(
        ok2.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok2.stderr)
    );
    assert_eq!(
        std::fs::read(&out_b).unwrap(),
        std::fs::read(&out_c).unwrap()
    );
}

#[derive(Debug)]
struct SpendAuthSigSubmissionV0 {
    version: String,
    signatures: Vec<SpendAuthSigV0>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendAuthSigV0 {
    action_index: u32,
    spend_auth_sig: String,
}

#[derive(Debug)]
struct TestHarness {
    tmp: tempfile::TempDir,
    bin_path: PathBuf,
    config_paths: BTreeMap<u16, PathBuf>,
    processes: BTreeMap<u16, ChildGuard>,
    public_key_package: redpallas::keys::PublicKeyPackage,
}

impl TestHarness {
    fn new() -> anyhow::Result<Self> {
        let tmp = tempfile::TempDir::new().context("tempdir")?;
        let bin_path = PathBuf::from(env!("CARGO_BIN_EXE_dkg-admin"));
        if !bin_path.exists() {
            return Err(anyhow!("dkg-admin binary missing: {}", bin_path.display()));
        }

        let (ca_pem, client_cert_pem, client_key_pem, server_cert_pem, server_key_pem) =
            gen_test_mtls_material();
        let tls_dir = tmp.path().join("tls");
        std::fs::create_dir_all(&tls_dir).context("mkdir tls")?;

        let ca_path = tls_dir.join("ca.pem");
        let client_cert_path = tls_dir.join("client.pem");
        let client_key_path = tls_dir.join("client.key");
        let server_cert_path = tls_dir.join("server.pem");
        let server_key_path = tls_dir.join("server.key");
        std::fs::write(&ca_path, &ca_pem).context("write ca")?;
        std::fs::write(&client_cert_path, &client_cert_pem).context("write client cert")?;
        std::fs::write(&client_key_path, &client_key_pem).context("write client key")?;
        std::fs::write(&server_cert_path, &server_cert_pem).context("write server cert")?;
        std::fs::write(&server_key_path, &server_key_pem).context("write server key")?;

        let mut ports = Vec::with_capacity(N as usize);
        for _ in 0..N {
            ports.push(pick_unused_port()?);
        }

        let operator_ids = (1u16..=N)
            .map(|i| format!("0x{i:040x}"))
            .collect::<Vec<_>>();
        let roster = RosterV1 {
            roster_version: 1,
            operators: operator_ids
                .iter()
                .enumerate()
                .map(|(i, op)| RosterOperatorV1 {
                    operator_id: op.clone(),
                    grpc_endpoint: Some(format!("https://localhost:{}", ports[i])),
                    age_recipient: None,
                })
                .collect(),
            coordinator_age_recipient: None,
        };
        let roster_hash_hex = roster.roster_hash_hex().context("roster hash")?;

        let mut cfgs = Vec::with_capacity(N as usize);
        let mut config_paths = BTreeMap::<u16, PathBuf>::new();
        for (i, operator_id) in operator_ids.iter().enumerate() {
            let identifier = (i + 1) as u16;
            let state_dir = tmp.path().join(format!("op{identifier:02}/state"));
            std::fs::create_dir_all(&state_dir).context("mkdir state")?;

            let cfg_path = tmp.path().join(format!("op{identifier:02}/config.json"));
            let cfg_json = serde_json::json!({
                "config_version": 1,
                "operator_id": operator_id,
                "identifier": identifier,
                "threshold": T,
                "max_signers": N,
                "network": "regtest",
                "roster": &roster,
                "roster_hash_hex": &roster_hash_hex,
                "state_dir": state_dir,
                "age_identity_file": null,
                "grpc": {
                    "listen_addr": format!("127.0.0.1:{}", ports[i]),
                    "tls_ca_cert_pem_path": &ca_path,
                    "tls_server_cert_pem_path": &server_cert_path,
                    "tls_server_key_pem_path": &server_key_path,
                    "tls_client_cert_pem_path": &client_cert_path,
                    "tls_client_key_pem_path": &client_key_path,
                    "tls_domain_name_override": "localhost",
                    "coordinator_client_cert_sha256": null
                }
            });
            write_json_pretty(&cfg_path, &cfg_json)?;

            let cfg = AdminConfigV1::from_path(&cfg_path)
                .with_context(|| format!("read {}", cfg_path.display()))?
                .validate()
                .context("validate config")?;
            cfgs.push(cfg);
            config_paths.insert(identifier, cfg_path);
        }

        run_dkg(&cfgs)?;
        let pkp_bytes = storage::read(&cfgs[0].cfg.state_dir.join("public_key_package.bin"))
            .context("read public_key_package.bin")?;
        let public_key_package = redpallas::keys::PublicKeyPackage::deserialize(&pkp_bytes)
            .context("deserialize pkp")?;

        let mut processes = BTreeMap::<u16, ChildGuard>::new();
        for id in 1u16..=N {
            let cfg_path = config_paths.get(&id).unwrap();
            let log_path = tmp.path().join(format!("op{id:02}/serve.log"));
            let log_file = File::create(&log_path).context("create log")?;
            let log_err = log_file.try_clone().context("clone log")?;

            let mut cmd = Command::new(&bin_path);
            cmd.arg("--config")
                .arg(cfg_path)
                .arg("serve")
                .stdout(Stdio::from(log_file))
                .stderr(Stdio::from(log_err));
            let child = cmd.spawn().with_context(|| format!("spawn serve op{id}"))?;
            processes.insert(id, ChildGuard::new(child));
        }

        for (i, p) in ports.iter().enumerate() {
            wait_for_tcp("127.0.0.1", *p, Duration::from_secs(20))
                .with_context(|| format!("wait tcp op{}", i + 1))?;
        }

        Ok(Self {
            tmp,
            bin_path,
            config_paths,
            processes,
            public_key_package,
        })
    }

    fn run_sign(
        &self,
        config_identifier: u16,
        session_id: &str,
        requests_path: &Path,
        out_path: &Path,
        extra_env: &[(&str, &str)],
    ) -> Output {
        let cfg = self.config_paths.get(&config_identifier).unwrap();
        let mut cmd = Command::new(&self.bin_path);
        cmd.arg("--config")
            .arg(cfg)
            .arg("sign-spendauth")
            .arg("--session-id")
            .arg(session_id)
            .arg("--requests")
            .arg(requests_path)
            .arg("--out")
            .arg(out_path);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn stop_operator(&mut self, identifier: u16) -> anyhow::Result<()> {
        let mut p = self
            .processes
            .remove(&identifier)
            .ok_or_else(|| anyhow!("operator process missing: {identifier}"))?;
        p.kill_now()?;
        Ok(())
    }
}

#[derive(Debug)]
struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn kill_now(&mut self) -> anyhow::Result<()> {
        self.child.kill().context("kill child")?;
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_dkg(cfgs: &[ValidatedAdminConfig]) -> anyhow::Result<()> {
    let n = cfgs[0].cfg.max_signers;

    let mut round1 = BTreeMap::<u16, Vec<u8>>::new();
    for cfg in cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut seed = [0u8; 32];
        seed[0..2].copy_from_slice(&cfg.cfg.identifier.to_le_bytes());
        let rng = ChaCha20Rng::from_seed(seed);
        let out = dkg.part1(rng).context("dkg part1")?;
        round1.insert(cfg.cfg.identifier, out.round1_package_bytes);
    }

    let mut round2_to = BTreeMap::<u16, BTreeMap<u16, Vec<u8>>>::new();
    for cfg in cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut round1_others = round1.clone();
        round1_others.remove(&cfg.cfg.identifier);
        let out = dkg.part2(round1_others).context("dkg part2")?;
        for (receiver, pkg) in out.round2_packages {
            if receiver == cfg.cfg.identifier {
                continue;
            }
            round2_to
                .entry(receiver)
                .or_default()
                .insert(cfg.cfg.identifier, pkg.package_bytes);
        }
    }

    let mut expected_pk_hash: Option<[u8; 32]> = None;
    for cfg in cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut round1_others = round1.clone();
        round1_others.remove(&cfg.cfg.identifier);
        let to_me = round2_to
            .get(&cfg.cfg.identifier)
            .cloned()
            .ok_or_else(|| anyhow!("round2 missing for {}", cfg.cfg.identifier))?;
        let out = dkg.part3(round1_others, to_me).context("dkg part3")?;
        if let Some(prev) = expected_pk_hash {
            if prev != out.public_key_package_hash {
                return Err(anyhow!("public_key_package_hash_mismatch"));
            }
        } else {
            expected_pk_hash = Some(out.public_key_package_hash);
        }
    }

    if n != N {
        return Err(anyhow!("max_signers mismatch"));
    }
    Ok(())
}

fn write_requests_file(
    path: &Path,
    pkp: &redpallas::keys::PublicKeyPackage,
    reqs: Vec<(u32, [u8; 32], [u8; 32])>,
) -> anyhow::Result<()> {
    let mut requests = vec![];
    for (action_index, sighash, alpha) in reqs {
        let randomizer = redpallas::Randomizer::deserialize(&alpha).context("alpha deserialize")?;
        let params = redpallas::RandomizedParams::from_randomizer(pkp.verifying_key(), randomizer);
        let rk = params
            .randomized_verifying_key()
            .serialize()
            .context("serialize rk")?;
        requests.push(serde_json::json!({
            "sighash": hex::encode(sighash),
            "action_index": action_index,
            "alpha": hex::encode(alpha),
            "rk": hex::encode(rk),
        }));
    }

    let json = serde_json::json!({
        "version": "v0",
        "requests": requests
    });
    write_json_pretty(path, &json)
}

fn read_output(path: &Path) -> anyhow::Result<SpendAuthSigSubmissionV0> {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Outer {
        version: String,
        signatures: Vec<SpendAuthSigV0>,
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let outer: Outer = serde_json::from_slice(&bytes).context("parse output")?;
    Ok(SpendAuthSigSubmissionV0 {
        version: outer.version,
        signatures: outer.signatures,
    })
}

fn write_json_pretty<P: AsRef<Path>, T: serde::Serialize>(
    path: P,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize json")?;
    std::fs::write(path.as_ref(), bytes)
        .with_context(|| format!("write {}", path.as_ref().display()))?;
    Ok(())
}

fn pick_unused_port() -> anyhow::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").context("bind port 0")?;
    Ok(l.local_addr().context("local_addr")?.port())
}

fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> anyhow::Result<()> {
    let addr = format!("{host}:{port}");
    let start = Instant::now();
    loop {
        match TcpStream::connect(addr.as_str()) {
            Ok(_) => return Ok(()),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(anyhow!("tcp_timeout: {addr}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

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
    let ca_pem = ca_cert.pem().into_bytes();

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-test-server");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params = CertificateParams::new(vec!["coordinator".to_string()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-test-client");
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    (
        ca_pem,
        client_cert.pem().into_bytes(),
        client_key.serialize_pem().into_bytes(),
        server_cert.pem().into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
}
