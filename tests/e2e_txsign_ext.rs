use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use dkg_admin::config::Network;
use dkg_admin::roster::{RosterOperatorV1, RosterV1};

const JUNOCASH_VERSION: &str = "0.9.13";
const JUNOCASH_RPC_USER: &str = "rpcuser";
const JUNOCASH_RPC_PASS: &str = "rpcpass";

// E2E:
// - Run an online DKG with real dkg-admin services.
// - Build a transaction with juno-txbuild and prepare external signing with juno-txsign.
// - Produce spend-auth signatures via dkg-admin sign-spendauth.
// - Finalize, broadcast, and mine on regtest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn e2e_txsign_ext_prepare_sign_spendauth_finalize() {
    if let Err(e) = e2e_impl().await {
        panic!("{e:#}");
    }
}

async fn e2e_impl() -> anyhow::Result<()> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = repo_root
        .parent()
        .ok_or_else(|| anyhow!("workspace_root_missing"))?
        .to_path_buf();

    let dkg_admin_bin = repo_root.join("bin/dkg-admin");
    let dkg_ceremony_repo = workspace_root.join("dkg-ceremony");
    let dkg_ceremony_bin = dkg_ceremony_repo.join("bin/dkg-ceremony");
    let juno_scan_repo = workspace_root.join("juno-scan");
    let juno_scan_bin = juno_scan_repo.join("bin/juno-scan");
    let juno_txbuild_repo = workspace_root.join("juno-txbuild");
    let juno_txbuild_bin = juno_txbuild_repo.join("bin/juno-txbuild");
    let juno_txsign_repo = workspace_root.join("juno-txsign");
    let juno_txsign_bin = juno_txsign_repo.join("bin/juno-txsign");

    run_make_build(&repo_root)?;
    run_make_build(&dkg_ceremony_repo)?;
    run_make_build(&juno_scan_repo)?;
    run_make_build(&juno_txbuild_repo)?;
    run_make_build(&juno_txsign_repo)?;

    for (name, path) in [
        ("dkg-admin", &dkg_admin_bin),
        ("dkg-ceremony", &dkg_ceremony_bin),
        ("juno-scan", &juno_scan_bin),
        ("juno-txbuild", &juno_txbuild_bin),
        ("juno-txsign", &juno_txsign_bin),
    ] {
        if !path.exists() {
            return Err(anyhow!("{name}_bin_missing: {}", path.display()));
        }
    }

    let tmp = tempfile::TempDir::new().context("tempdir")?;

    let (ca_pem, client_cert_pem, client_key_pem, server_cert_pem, server_key_pem) =
        gen_test_mtls_material();
    let ca_path = tmp.path().join("ca.pem");
    let client_cert_path = tmp.path().join("client.pem");
    let client_key_path = tmp.path().join("client.key");
    let server_cert_path = tmp.path().join("server.pem");
    let server_key_path = tmp.path().join("server.key");
    std::fs::write(&ca_path, &ca_pem).context("write ca")?;
    std::fs::write(&client_cert_path, &client_cert_pem).context("write client cert")?;
    std::fs::write(&client_key_path, &client_key_pem).context("write client key")?;
    std::fs::write(&server_cert_path, &server_cert_pem).context("write server cert")?;
    std::fs::write(&server_key_path, &server_key_pem).context("write server key")?;

    let n: u16 = 5;
    let t: u16 = 3;
    let mut admin_ports = vec![];
    for _ in 0..n {
        admin_ports.push(pick_unused_port()?);
    }

    let operator_ids = (1u16..=n)
        .map(|i| format!("0x{i:040x}"))
        .collect::<Vec<_>>();
    let roster = RosterV1 {
        roster_version: 1,
        operators: operator_ids
            .iter()
            .enumerate()
            .map(|(i, op_id)| RosterOperatorV1 {
                operator_id: op_id.clone(),
                grpc_endpoint: Some(format!("https://localhost:{}", admin_ports[i])),
                age_recipient: None,
            })
            .collect(),
        coordinator_age_recipient: None,
    };
    let roster_hash_hex = roster.roster_hash_hex().context("roster hash")?;

    let mut admin_nodes: Vec<AdminNode> = vec![];
    let mut op1_config_path: Option<PathBuf> = None;
    for (i, op_id) in operator_ids.iter().enumerate() {
        let identifier = (i + 1) as u16;
        let state_dir = tmp.path().join(format!("op{identifier:02}/state"));
        std::fs::create_dir_all(&state_dir).context("mkdir state")?;

        let cfg_path = tmp.path().join(format!("op{identifier:02}/config.json"));
        if identifier == 1 {
            op1_config_path = Some(cfg_path.clone());
        }

        let cfg_json = serde_json::json!({
            "config_version": 1,
            "ceremony_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "operator_id": op_id,
            "identifier": identifier,
            "threshold": t,
            "max_signers": n,
            "network": "regtest",
            "roster": &roster,
            "roster_hash_hex": &roster_hash_hex,
            "state_dir": state_dir,
            "age_identity_file": null,
            "grpc": {
                "listen_addr": format!("127.0.0.1:{}", admin_ports[i]),
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
        admin_nodes.push(AdminNode {
            identifier,
            port: admin_ports[i],
            config_path: cfg_path,
            dir: tmp.path().join(format!("op{identifier:02}")),
        });
    }

    let mut admins = spawn_admins(&dkg_admin_bin, &admin_nodes, "dkg", |_| None)?;

    let ceremony_cfg = serde_json::json!({
        "config_version": 1,
        "ceremony_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "threshold": t,
        "max_signers": n,
        "network": "regtest",
        "roster": &roster,
        "roster_hash_hex": &roster_hash_hex,
        "out_dir": tmp.path().join("out"),
        "transcript_dir": tmp.path().join("transcript")
    });
    let ceremony_cfg_path = tmp.path().join("ceremony_config.json");
    write_json_pretty(&ceremony_cfg_path, &ceremony_cfg)?;

    let mut dkg_ceremony_cmd = Command::new(&dkg_ceremony_bin);
    dkg_ceremony_cmd
        .arg("--config")
        .arg(&ceremony_cfg_path)
        .arg("online")
        .arg("--tls-ca-cert-pem-path")
        .arg(&ca_path)
        .arg("--tls-client-cert-pem-path")
        .arg(&client_cert_path)
        .arg("--tls-client-key-pem-path")
        .arg(&client_key_path)
        .arg("--tls-domain-name-override")
        .arg("localhost")
        .current_dir(&dkg_ceremony_repo);
    run_cmd(dkg_ceremony_cmd).context("run dkg-ceremony online")?;

    let manifest_path = tmp.path().join("out/KeysetManifest.json");
    let manifest_raw = std::fs::read(&manifest_path).context("read KeysetManifest.json")?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_raw).context("parse KeysetManifest.json")?;
    let ufvk = manifest["ufvk"]
        .as_str()
        .ok_or_else(|| anyhow!("manifest.ufvk_missing"))?
        .to_string();
    let owallet_ua = manifest["owallet_ua"]
        .as_str()
        .ok_or_else(|| anyhow!("manifest.owallet_ua_missing"))?
        .to_string();

    ensure_docker_available()?;
    ensure_junocashd_image(&dkg_ceremony_repo)?;

    let container_name = format!(
        "dkg-admin-e2e-{}-{}",
        std::process::id(),
        pick_unused_port()?
    );
    let _docker = DockerContainerGuard::start(&container_name)?;

    wait_for_junocashd_rpc(&container_name, Duration::from_secs(180))?;
    let rpc_host_port = docker_port(&container_name, "8232/tcp")?;
    let rpc_url = format!("http://{rpc_host_port}");

    let scan_port = pick_unused_port()?;
    let scan_listen = format!("127.0.0.1:{scan_port}");
    let scan_url = format!("http://{scan_listen}");

    let db_path = tmp.path().join("scan.db");
    let scan_log_path = tmp.path().join("juno-scan.log");
    let scan_log = File::create(&scan_log_path).context("create scan log")?;
    let scan_log_err = scan_log.try_clone().context("clone scan log")?;

    let mut scan_cmd = Command::new(&juno_scan_bin);
    scan_cmd
        .arg("-listen")
        .arg(&scan_listen)
        .arg("-rpc-url")
        .arg(&rpc_url)
        .arg("-rpc-user")
        .arg(JUNOCASH_RPC_USER)
        .arg("-rpc-pass")
        .arg(JUNOCASH_RPC_PASS)
        .arg("-ua-hrp")
        .arg("jregtest")
        .arg("-confirmations")
        .arg("1")
        .arg("-poll-interval")
        .arg("200ms")
        .arg("-db-driver")
        .arg("rocksdb")
        .arg("-db-path")
        .arg(&db_path)
        .stdout(Stdio::from(scan_log))
        .stderr(Stdio::from(scan_log_err));
    let _scan = ChildGuard::new(scan_cmd.spawn().context("spawn juno-scan")?);
    wait_for_http_ok(&format!("{scan_url}/v1/health"), Duration::from_secs(60))?;

    let wallet_id = format!("dkg-admin-e2e-{}", std::process::id());
    http_post_json(
        &format!("{scan_url}/v1/wallets"),
        &serde_json::json!({ "wallet_id": &wallet_id, "ufvk": &ufvk }),
        Duration::from_secs(15),
    )?;

    // Two shielded notes, so the consolidate plan below needs two spends. Shield
    // both mature coinbases one per call before mining: shielding again after new
    // blocks hits a wallet anchor bug in junocashd 0.9.13 (commit fails, then asserts).
    docker_cli(&container_name, &["generate", "102"])?;
    let shield_txid = shield_coinbase_to(&container_name, &owallet_ua)?;
    let shield_txid_2 = shield_coinbase_to(&container_name, &owallet_ua)?;
    docker_cli(&container_name, &["generate", "2"])?;

    wait_for_scan_notes(&scan_url, &wallet_id, 2, Duration::from_secs(120))?;
    http_post_json(
        &format!("{scan_url}/v1/wallets/{wallet_id}/backfill"),
        &serde_json::json!({ "batch_size": 10_000 }),
        Duration::from_secs(120),
    )?;
    wait_for_scanner_ready_at_node(&scan_url, &container_name, Duration::from_secs(120))?;

    let node_ua = junocash_get_address_for_account(&container_name, 0)?;
    let txplan_path = tmp.path().join("txplan.json");
    let mut txbuild_cmd = Command::new(&juno_txbuild_bin);
    txbuild_cmd
        .arg("send")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--rpc-user")
        .arg(JUNOCASH_RPC_USER)
        .arg("--rpc-pass")
        .arg(JUNOCASH_RPC_PASS)
        .arg("--scan-url")
        .arg(&scan_url)
        .arg("--wallet-id")
        .arg(&wallet_id)
        .arg("--coin-type")
        .arg("8135")
        .arg("--account")
        .arg("0")
        .arg("--to")
        .arg(&node_ua)
        .arg("--amount-zat")
        .arg("1000000")
        .arg("--change-address")
        .arg(&owallet_ua)
        .arg("--minconf")
        .arg("1")
        .arg("--out")
        .arg(&txplan_path);
    run_cmd(txbuild_cmd).context("juno-txbuild send")?;

    let prepared_path = tmp.path().join("prepared.json");
    let requests_path = tmp.path().join("requests.v0.json");
    let mut txsign_prepare_cmd = Command::new(&juno_txsign_bin);
    txsign_prepare_cmd
        .arg("ext-prepare")
        .arg("--txplan")
        .arg(&txplan_path)
        .arg("--ufvk")
        .arg(manifest["ufvk"].as_str().unwrap())
        .arg("--out-prepared")
        .arg(&prepared_path)
        .arg("--out-requests")
        .arg(&requests_path);
    run_cmd(txsign_prepare_cmd).context("juno-txsign ext-prepare")?;

    let txplan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&txplan_path).context("read txplan")?)
            .context("parse txplan")?;
    let plan_fee: u64 = txplan["fee_zat"]
        .as_str()
        .ok_or_else(|| anyhow!("txplan fee_zat missing"))?
        .parse()
        .context("parse txplan fee_zat")?;

    // A two-note consolidation plan, used for the max_spends case.
    let consolidate_plan_path = tmp.path().join("txplan-consolidate.json");
    let mut consolidate_cmd = Command::new(&juno_txbuild_bin);
    consolidate_cmd
        .arg("consolidate")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--rpc-user")
        .arg(JUNOCASH_RPC_USER)
        .arg("--rpc-pass")
        .arg(JUNOCASH_RPC_PASS)
        .arg("--scan-url")
        .arg(&scan_url)
        .arg("--wallet-id")
        .arg(&wallet_id)
        .arg("--coin-type")
        .arg("8135")
        .arg("--account")
        .arg("0")
        .arg("--to")
        .arg(&owallet_ua)
        .arg("--change-address")
        .arg(&owallet_ua)
        .arg("--max-spends")
        .arg("2")
        .arg("--minconf")
        .arg("1")
        .arg("--out")
        .arg(&consolidate_plan_path);
    run_cmd(consolidate_cmd).context("juno-txbuild consolidate")?;
    let consolidate_prepared_path = tmp.path().join("prepared-consolidate.json");
    let consolidate_requests_path = tmp.path().join("requests-consolidate.v0.json");
    let mut consolidate_prepare_cmd = Command::new(&juno_txsign_bin);
    consolidate_prepare_cmd
        .arg("ext-prepare")
        .arg("--txplan")
        .arg(&consolidate_plan_path)
        .arg("--ufvk")
        .arg(&ufvk)
        .arg("--out-prepared")
        .arg(&consolidate_prepared_path)
        .arg("--out-requests")
        .arg(&consolidate_requests_path);
    run_cmd(consolidate_prepare_cmd).context("juno-txsign ext-prepare consolidate")?;
    let consolidate_plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&consolidate_plan_path).context("read consolidate plan")?,
    )
    .context("parse consolidate plan")?;
    let consolidate_notes = consolidate_plan["notes"]
        .as_array()
        .map(|n| n.len())
        .unwrap_or(0);
    if consolidate_notes < 2 {
        return Err(anyhow!(
            "consolidate plan should spend 2 notes, got {consolidate_notes}"
        ));
    }

    let op1_cfg = op1_config_path.ok_or_else(|| anyhow!("op1 config missing"))?;
    let session = |n: u8| format!("0x{}", format!("{n:02x}").repeat(32));

    // Peers without a policy sign exactly as before.
    let legacy_sigs_path = tmp.path().join("sigs-legacy.v0.json");
    let out = run_sign(
        &dkg_admin_bin,
        &op1_cfg,
        &session(0x55),
        &requests_path,
        None,
        &legacy_sigs_path,
    )?;
    if !out.status.success() {
        return Err(anyhow!(
            "legacy sign-spendauth failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // Policy cases. Every peer runs the same policy, so a rejection means no
    // peer released a commitment.
    let owned_other_ua = {
        let fvk = dkg_admin::sign_policy::decode_fvk_from_ufvk(Network::Regtest, &ufvk)
            .map_err(|e| anyhow!("decode ufvk: {e}"))?;
        let addr = fvk.address_at(1u32, orchard::keys::Scope::External);
        dkg_admin::zip316::encode_unified_container(
            dkg_admin::sign_policy::ua_hrp(Network::Regtest),
            0x03,
            &addr.to_raw_address_bytes(),
        )
        .map_err(|e| anyhow!("encode ua: {e:?}"))?
    };
    let ctx_dir = tmp.path().join("verifier-ctx");
    std::fs::create_dir_all(&ctx_dir).context("mkdir verifier ctx")?;
    let recording_verifier = serde_json::json!([
        "sh",
        "-c",
        format!("cat > {}/ctx-$$.json", ctx_dir.display())
    ]);
    let base_policy = serde_json::json!({
        "version": "v1",
        "ufvk": &ufvk,
        "change_address": &owallet_ua,
        "verifier_cmd": &recording_verifier,
    });
    let with = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut p = base_policy.clone();
        edit(&mut p);
        p
    };

    let tampered_requests_path = tmp.path().join("requests-tampered.v0.json");
    {
        let mut reqs: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&requests_path).context("read requests")?)
                .context("parse requests")?;
        let sighash = reqs["requests"][0]["sighash"]
            .as_str()
            .ok_or_else(|| anyhow!("requests sighash missing"))?
            .to_string();
        let flipped = if sighash.starts_with('0') { "1" } else { "0" };
        let tampered = format!("{flipped}{}", &sighash[1..]);
        for r in reqs["requests"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("requests missing"))?
        {
            r["sighash"] = serde_json::Value::String(tampered.clone());
        }
        write_json_pretty(&tampered_requests_path, &reqs)?;
    }

    struct RejectCase<'a> {
        name: &'a str,
        policy: serde_json::Value,
        txplan: &'a Path,
        prepared: &'a Path,
        requests: &'a Path,
        code: &'a str,
    }
    let reject_cases = [
        RejectCase {
            name: "change",
            policy: with(&|p| p["change_address"] = serde_json::json!(&owned_other_ua)),
            txplan: &txplan_path,
            prepared: &prepared_path,
            requests: &requests_path,
            code: "change_address_mismatch",
        },
        RejectCase {
            name: "fee",
            policy: with(&|p| p["max_fee_zat"] = serde_json::json!(plan_fee - 1)),
            txplan: &txplan_path,
            prepared: &prepared_path,
            requests: &requests_path,
            code: "fee_over_cap",
        },
        RejectCase {
            name: "spends",
            policy: with(&|p| p["max_spends"] = serde_json::json!(1)),
            txplan: &consolidate_plan_path,
            prepared: &consolidate_prepared_path,
            requests: &consolidate_requests_path,
            code: "too_many_spends",
        },
        RejectCase {
            name: "verifier",
            policy: with(&|p| {
                p["verifier_cmd"] = serde_json::json!(["sh", "-c", "echo nope >&2; exit 7"])
            }),
            txplan: &txplan_path,
            prepared: &prepared_path,
            requests: &requests_path,
            code: "verifier_rejected",
        },
        RejectCase {
            name: "sighash",
            policy: base_policy.clone(),
            txplan: &txplan_path,
            prepared: &prepared_path,
            requests: &tampered_requests_path,
            code: "sighash_mismatch",
        },
    ];
    for (i, case) in reject_cases.iter().enumerate() {
        drop(admins);
        admins = spawn_admins(&dkg_admin_bin, &admin_nodes, case.name, |_| {
            Some(case.policy.clone())
        })?;
        let out_path = tmp.path().join(format!("sigs-{}.v0.json", case.name));
        let out = run_sign(
            &dkg_admin_bin,
            &op1_cfg,
            &session(0x60 + i as u8),
            case.requests,
            Some((case.txplan, case.prepared)),
            &out_path,
        )?;
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if out.status.success() || out_path.exists() {
            return Err(anyhow!("case {}: signing should fail", case.name));
        }
        if !stderr.contains("policy_rejected") || !stderr.contains(case.code) {
            return Err(anyhow!(
                "case {}: want policy_rejected/{}, got: {stderr}",
                case.name,
                case.code
            ));
        }
        for node in &admin_nodes {
            let log = std::fs::read_to_string(node.log_path(case.name)).unwrap_or_default();
            if !log.contains("sign policy rejected spend") || !log.contains(case.code) {
                return Err(anyhow!(
                    "case {}: identifier {} did not log the rejection",
                    case.name,
                    node.identifier
                ));
            }
        }
    }

    // The policy allows the real plan.
    drop(admins);
    admins = spawn_admins(&dkg_admin_bin, &admin_nodes, "allow", |_| {
        Some(base_policy.clone())
    })?;
    let sigs_path = tmp.path().join("sigs.v0.json");
    let out = run_sign(
        &dkg_admin_bin,
        &op1_cfg,
        &session(0x70),
        &requests_path,
        Some((&txplan_path, &prepared_path)),
        &sigs_path,
    )?;
    if !out.status.success() {
        return Err(anyhow!(
            "policy sign-spendauth failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let contexts = std::fs::read_dir(&ctx_dir)
        .context("read verifier ctx dir")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect::<Vec<_>>();
    if contexts.len() != admin_nodes.len() {
        return Err(anyhow!(
            "want {} verifier contexts, got {}",
            admin_nodes.len(),
            contexts.len()
        ));
    }
    for path in &contexts {
        let ctx: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).context("read ctx")?)
                .context("parse ctx")?;
        if ctx["txplan"] != txplan
            || ctx["change_address"].as_str() != Some(owallet_ua.as_str())
            || ctx["fee_zat"].as_str() != Some(plan_fee.to_string().as_str())
            || ctx["outputs"][0]["to_address"].as_str() != Some(node_ua.as_str())
        {
            return Err(anyhow!("unexpected verifier context: {ctx}"));
        }
    }

    let mut txsign_finalize_cmd = Command::new(&juno_txsign_bin);
    txsign_finalize_cmd
        .arg("ext-finalize")
        .arg("--prepared-tx")
        .arg(&prepared_path)
        .arg("--sigs")
        .arg(&sigs_path)
        .arg("--json");
    let finalize_out = run_cmd(txsign_finalize_cmd).context("juno-txsign ext-finalize")?;
    let finalize_json: serde_json::Value =
        serde_json::from_slice(finalize_out.as_bytes()).context("parse ext-finalize json")?;
    if finalize_json["status"].as_str() != Some("ok") {
        return Err(anyhow!("ext-finalize status != ok"));
    }

    let raw_tx_hex = finalize_json["data"]["raw_tx_hex"]
        .as_str()
        .ok_or_else(|| anyhow!("raw_tx_hex missing"))?
        .to_string();
    let txid = finalize_json["data"]["txid"]
        .as_str()
        .ok_or_else(|| anyhow!("txid missing"))?
        .to_string();

    let accepted = docker_cli(&container_name, &["sendrawtransaction", &raw_tx_hex])?;
    if !accepted.trim().eq_ignore_ascii_case(txid.trim()) {
        return Err(anyhow!(
            "txid_mismatch: accepted={} want={}",
            accepted.trim(),
            txid
        ));
    }
    docker_cli(&container_name, &["generate", "1"])?;

    let height: u64 = docker_cli(&container_name, &["getblockcount"])?
        .trim()
        .parse()
        .context("parse height")?;
    let hash = docker_cli(&container_name, &["getblockhash", &height.to_string()])?
        .trim()
        .to_string();
    let blk_raw = docker_cli(&container_name, &["getblock", &hash, "1"])?;
    let blk: serde_json::Value =
        serde_json::from_slice(blk_raw.as_bytes()).context("parse block")?;
    let txs = blk["tx"]
        .as_array()
        .ok_or_else(|| anyhow!("block tx missing"))?;
    let mined = txs
        .iter()
        .filter_map(|v| v.as_str())
        .any(|id| id.eq_ignore_ascii_case(&txid));
    if !mined {
        return Err(anyhow!("tx_not_mined"));
    }

    let _ = (shield_txid, shield_txid_2);
    drop(admins);
    Ok(())
}

fn run_make_build(dir: &Path) -> anyhow::Result<()> {
    let out = Command::new("make")
        .arg("build")
        .current_dir(dir)
        .output()
        .with_context(|| format!("run make build in {}", dir.display()))?;
    if !out.status.success() {
        return Err(anyhow!(
            "make build failed in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn write_json_pretty<P: AsRef<Path>, T: serde::Serialize>(path: P, v: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(v).context("serialize json")?;
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

fn run_cmd(mut cmd: Command) -> anyhow::Result<String> {
    let out = cmd.output().with_context(|| format!("run {:?}", cmd))?;
    if !out.status.success() {
        return Err(anyhow!(
            "command failed: {:?}\nstdout: {}\nstderr: {}",
            cmd,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn ensure_docker_available() -> anyhow::Result<()> {
    let out = Command::new("docker")
        .arg("version")
        .output()
        .context("docker version")?;
    if !out.status.success() {
        return Err(anyhow!("docker_unavailable"));
    }
    Ok(())
}

fn ensure_junocashd_image(dkg_ceremony_repo: &Path) -> anyhow::Result<()> {
    let tag = format!("dkg-ceremony-junocashd:{JUNOCASH_VERSION}");
    let inspect = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(&tag)
        .output()
        .context("docker image inspect")?;
    if inspect.status.success() {
        return Ok(());
    }

    let out = Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg(&tag)
        .arg("-f")
        .arg("docker/junocashd/Dockerfile")
        .arg(".")
        .current_dir(dkg_ceremony_repo)
        .output()
        .context("docker build")?;
    if !out.status.success() {
        return Err(anyhow!(
            "docker build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

struct DockerContainerGuard {
    name: String,
}

impl DockerContainerGuard {
    fn start(name: &str) -> anyhow::Result<Self> {
        let tag = format!("dkg-ceremony-junocashd:{JUNOCASH_VERSION}");
        let out = Command::new("docker")
            .arg("run")
            .arg("-d")
            .arg("--rm")
            .arg("-p")
            .arg("127.0.0.1::8232")
            .arg("--name")
            .arg(name)
            .arg(tag)
            .arg("-regtest")
            .arg("-server=1")
            .arg("-daemon=0")
            .arg("-listen=0")
            .arg("-txindex=1")
            .arg("-printtoconsole=1")
            .arg("-nuparams=5437f330:1")
            .arg("-txunpaidactionlimit=10000")
            .arg("-blockunpaidactionlimit=0")
            .arg("-txexpirydelta=4")
            .arg("-blockmintxfee=0")
            .arg("-datadir=/data")
            .arg("-rpcbind=0.0.0.0")
            .arg("-rpcallowip=0.0.0.0/0")
            .arg("-rpcport=8232")
            .arg(format!("-rpcuser={JUNOCASH_RPC_USER}"))
            .arg(format!("-rpcpassword={JUNOCASH_RPC_PASS}"))
            .output()
            .context("docker run")?;
        if !out.status.success() {
            return Err(anyhow!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(Self {
            name: name.to_string(),
        })
    }
}

impl Drop for DockerContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("rm")
            .arg("-f")
            .arg(&self.name)
            .output();
    }
}

fn docker_port(container: &str, port_proto: &str) -> anyhow::Result<String> {
    let out = Command::new("docker")
        .arg("port")
        .arg(container)
        .arg(port_proto)
        .output()
        .context("docker port")?;
    if !out.status.success() {
        return Err(anyhow!("docker port failed"));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Err(anyhow!("docker port empty"));
    }
    Ok(s)
}

fn docker_cli(container: &str, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = Command::new("docker");
    cmd.arg("exec")
        .arg(container)
        .arg("junocash-cli")
        .arg("-regtest")
        .arg("-datadir=/data")
        .arg(format!("-rpcuser={JUNOCASH_RPC_USER}"))
        .arg(format!("-rpcpassword={JUNOCASH_RPC_PASS}"))
        .arg("-rpcport=8232");
    for a in args {
        cmd.arg(a);
    }
    run_cmd(cmd)
}

fn wait_for_junocashd_rpc(container: &str, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        if docker_cli(container, &["getblockcount"]).is_ok() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("junocashd_rpc_timeout"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn junocash_get_address_for_account(container: &str, account: u32) -> anyhow::Result<String> {
    let raw = docker_cli(container, &["z_getaddressforaccount", &account.to_string()])?;
    let v: serde_json::Value = serde_json::from_slice(raw.as_bytes()).context("parse json")?;
    let addr = v["address"]
        .as_str()
        .ok_or_else(|| anyhow!("missing address"))?
        .trim()
        .to_string();
    if addr.is_empty() {
        return Err(anyhow!("empty address"));
    }
    Ok(addr)
}

fn shield_coinbase_to(container: &str, to_addr: &str) -> anyhow::Result<String> {
    // Default fee, at most one coinbase UTXO per call.
    let raw = docker_cli(container, &["z_shieldcoinbase", "*", to_addr, "null", "1"])?;
    let v: serde_json::Value = serde_json::from_slice(raw.as_bytes()).context("parse json")?;
    let opid = v["opid"]
        .as_str()
        .ok_or_else(|| anyhow!("missing opid"))?
        .trim()
        .to_string();
    if opid.is_empty() {
        return Err(anyhow!("empty opid"));
    }

    let start = Instant::now();
    loop {
        let status_raw = docker_cli(
            container,
            &["z_getoperationstatus", &format!("[\"{opid}\"]")],
        )?;
        let ops: serde_json::Value =
            serde_json::from_slice(status_raw.as_bytes()).context("parse op status")?;
        let arr = ops
            .as_array()
            .ok_or_else(|| anyhow!("op status not array"))?;
        if arr.len() != 1 {
            return Err(anyhow!("unexpected op status len"));
        }
        let st = arr[0]["status"].as_str().unwrap_or("").to_lowercase();
        match st.as_str() {
            "success" => {
                let txid = arr[0]["result"]["txid"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing txid"))?
                    .trim()
                    .to_string();
                if txid.is_empty() {
                    return Err(anyhow!("empty txid"));
                }
                return Ok(txid);
            }
            "failed" => {
                let msg = arr[0]["error"]["message"].as_str().unwrap_or("");
                return Err(anyhow!("shield failed: {msg}"));
            }
            _ => {}
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err(anyhow!("shield_timeout"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_http_ok(url: &str, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        let out = Command::new("curl")
            .arg("-sS")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg(url)
            .output()
            .context("curl")?;
        if out.status.success() {
            let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if code == "200" {
                return Ok(());
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("http_timeout: {url}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn http_post_json(url: &str, body: &serde_json::Value, timeout: Duration) -> anyhow::Result<()> {
    let payload = serde_json::to_string(body).context("json stringify")?;
    let out = Command::new("curl")
        .arg("-sS")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("content-type: application/json")
        .arg("--max-time")
        .arg(format!("{}", timeout.as_secs()))
        .arg(url)
        .arg("-d")
        .arg(payload)
        .output()
        .context("curl post")?;
    if !out.status.success() {
        return Err(anyhow!(
            "http_post_failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn wait_for_scan_notes(
    scan_url: &str,
    wallet_id: &str,
    want: usize,
    timeout: Duration,
) -> anyhow::Result<()> {
    let url = format!("{scan_url}/v1/wallets/{wallet_id}/notes");
    let start = Instant::now();
    loop {
        let out = Command::new("curl")
            .arg("-sS")
            .arg("--max-time")
            .arg("5")
            .arg(&url)
            .output()
            .context("curl notes")?;
        if out.status.success() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(notes) = v["notes"].as_array() {
                    let ready = notes
                        .iter()
                        .filter(|n| n["position"].is_number() && n["height"].is_number())
                        .count();
                    if ready >= want {
                        return Ok(());
                    }
                }
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("scan_note_timeout"));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn wait_for_scanner_ready_at_node(
    scan_url: &str,
    container: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let node_height = docker_cli(container, &["getblockcount"])?
        .trim()
        .parse::<i64>()
        .context("parse node height")?;
    let node_hash = docker_cli(container, &["getblockhash", &node_height.to_string()])?
        .trim()
        .to_string();
    let url = format!("{scan_url}/v1/health");
    let start = Instant::now();
    loop {
        let out = Command::new("curl")
            .arg("-sS")
            .arg("--max-time")
            .arg("5")
            .arg(&url)
            .output()
            .context("curl scanner health")?;
        let last_health = if out.status.success() {
            let health = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let hash_matches = v["scanned_hash"]
                    .as_str()
                    .map(|hash| hash.trim().eq_ignore_ascii_case(&node_hash))
                    .unwrap_or(false);
                if v["status"].as_str() == Some("ok")
                    && v["ready"].as_bool() == Some(true)
                    && v["scanned_height"].as_i64() == Some(node_height)
                    && hash_matches
                {
                    return Ok(());
                }
            }
            health
        } else {
            String::from_utf8_lossy(&out.stderr).trim().to_string()
        };
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "scanner_ready_timeout: node_height={node_height} node_hash={node_hash} last_health={last_health}"
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

struct AdminNode {
    identifier: u16,
    port: u16,
    config_path: PathBuf,
    dir: PathBuf,
}

impl AdminNode {
    fn log_path(&self, label: &str) -> PathBuf {
        self.dir.join(format!("dkg-admin-{label}.log"))
    }
}

/// Starts every admin, optionally with a sign policy, and waits for the ports.
/// Callers drop the previous set first so the ports are free again.
fn spawn_admins(
    bin: &Path,
    nodes: &[AdminNode],
    label: &str,
    policy_for: impl Fn(u16) -> Option<serde_json::Value>,
) -> anyhow::Result<Vec<ChildGuard>> {
    for node in nodes {
        wait_for_port_free(node.port, Duration::from_secs(30))?;
    }
    let mut admins = vec![];
    for node in nodes {
        let log_file = File::create(node.log_path(label)).context("create admin log")?;
        let log_err = log_file.try_clone().context("clone admin log")?;
        let mut cmd = Command::new(bin);
        cmd.arg("--config").arg(&node.config_path).arg("serve");
        if let Some(policy) = policy_for(node.identifier) {
            let policy_path = node.dir.join(format!("sign-policy-{label}.json"));
            write_json_pretty(&policy_path, &policy)?;
            cmd.arg("--sign-policy-file").arg(&policy_path);
        }
        cmd.stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_err));
        let child = cmd.spawn().context("spawn dkg-admin serve")?;
        admins.push(ChildGuard::new(child));
    }
    for node in nodes {
        wait_for_tcp("127.0.0.1", node.port, Duration::from_secs(30)).with_context(|| {
            format!(
                "wait for dkg-admin: identifier={} port={} label={label}",
                node.identifier, node.port
            )
        })?;
    }
    Ok(admins)
}

fn wait_for_port_free(port: u16, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("port_busy: {port}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn run_sign(
    bin: &Path,
    config: &Path,
    session_id: &str,
    requests: &Path,
    policy_inputs: Option<(&Path, &Path)>,
    out: &Path,
) -> anyhow::Result<Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("--config")
        .arg(config)
        .arg("sign-spendauth")
        .arg("--session-id")
        .arg(session_id)
        .arg("--requests")
        .arg(requests)
        .arg("--out")
        .arg(out);
    if let Some((txplan, prepared)) = policy_inputs {
        cmd.arg("--txplan").arg(txplan).arg("--prepared-tx").arg(prepared);
    }
    cmd.output().context("run dkg-admin sign-spendauth")
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
