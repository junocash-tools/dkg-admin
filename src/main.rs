use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use clap::{Parser, Subcommand};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use dkg_admin::config::{AdminConfigV1, ValidatedAdminConfig};
use dkg_admin::envelope::ReceiptStorageV1;
use dkg_admin::export::Exporter;

#[derive(Debug, Parser)]
#[command(name = "dkg-admin", version, about)]
struct Cli {
    /// Path to the local admin config JSON.
    #[arg(long, default_value = "config.json")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the mTLS gRPC service for an online DKG ceremony.
    Serve,

    /// Offline DKG file-mode commands.
    Dkg {
        #[command(subcommand)]
        cmd: DkgCommand,
    },

    /// Export an encrypted key package blob (for import into tss-host).
    ExportKeyPackage(ExportKeyPackageArgs),

    /// Destroy local state (best-effort).
    Destroy,
}

#[derive(Debug, Subcommand)]
enum DkgCommand {
    /// Generate and export the Round 1 package.
    Part1 {
        /// Output file for the Round 1 package bytes.
        #[arg(long)]
        out: PathBuf,
    },

    /// Import all Round 1 packages and export per-recipient encrypted Round 2 packages.
    Part2 {
        /// Directory containing all Round 1 package files (round1_<id>.bin).
        #[arg(long)]
        round1_dir: PathBuf,
        /// Output directory for encrypted Round 2 packages (round2_to_<id>_from_<id>.age).
        #[arg(long)]
        out_dir: PathBuf,
    },

    /// Import Round 1 + Round 2 packages and finalize Part 3.
    Part3 {
        /// Directory containing all Round 1 package files (round1_<id>.bin).
        #[arg(long)]
        round1_dir: PathBuf,
        /// Directory containing encrypted Round 2 packages addressed to this operator.
        #[arg(long)]
        round2_dir: PathBuf,
        /// Optional override of the age identity file for decrypting Round 2 packages.
        #[arg(long)]
        age_identity_file: Option<PathBuf>,
    },
}

#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("encryption")
        .required(true)
        .args(["age_recipient", "kms_key_id"]),
))]
#[command(group(
    clap::ArgGroup::new("target")
        .required(true)
        .args(["out", "s3_bucket"]),
))]
struct ExportKeyPackageArgs {
    /// age recipients (age1...) for offline portability.
    #[arg(long, value_name = "AGE_RECIPIENT", num_args = 1..)]
    age_recipient: Vec<String>,

    /// AWS KMS key id/arn for envelope encryption.
    #[arg(long, value_name = "KMS_KEY_ID")]
    kms_key_id: Option<String>,

    /// Output path for file target.
    #[arg(long)]
    out: Option<PathBuf>,

    /// S3 bucket (requires also --s3-key and --s3-sse-kms-key-id).
    #[arg(long)]
    s3_bucket: Option<String>,
    /// S3 key (object path) for the encrypted blob.
    #[arg(long)]
    s3_key: Option<String>,
    /// S3 SSE-KMS key id for storage encryption.
    #[arg(long)]
    s3_sse_kms_key_id: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();

    let cfg = AdminConfigV1::from_path(&cli.config)
        .with_context(|| format!("read config {}", cli.config.display()))?
        .validate()
        .context("validate config")?;

    match cli.cmd {
        Command::Serve => serve(cfg).await,
        Command::Dkg { cmd } => offline_dkg(cfg, cmd).await,
        Command::ExportKeyPackage(args) => export_key_package(cfg, args).await,
        Command::Destroy => destroy(cfg).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{}=info", env!("CARGO_PKG_NAME"))));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_max_level(Level::INFO)
        .init();
}

async fn serve(cfg: ValidatedAdminConfig) -> anyhow::Result<()> {
    let grpc = cfg
        .cfg
        .grpc
        .clone()
        .ok_or_else(|| anyhow!("grpc config missing"))?;

    let ca_pem = tokio::fs::read(&grpc.tls_ca_cert_pem_path)
        .await
        .with_context(|| format!("read {}", grpc.tls_ca_cert_pem_path.display()))?;
    let server_cert_pem = tokio::fs::read(&grpc.tls_server_cert_pem_path)
        .await
        .with_context(|| format!("read {}", grpc.tls_server_cert_pem_path.display()))?;
    let server_key_pem = tokio::fs::read(&grpc.tls_server_key_pem_path)
        .await
        .with_context(|| format!("read {}", grpc.tls_server_key_pem_path.display()))?;

    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let client_ca = Certificate::from_pem(ca_pem);

    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let svc = dkg_admin::service::AdminService::new(cfg);
    let svc = dkg_admin::proto::v1::dkg_admin_server::DkgAdminServer::new(svc);

    tracing::info!("listening on {}", grpc.listen_addr);
    let addr = grpc
        .listen_addr
        .parse()
        .context("parse grpc.listen_addr")?;

    Server::builder()
        .tls_config(tls)
        .context("tls_config")?
        .concurrency_limit_per_connection(32)
        .load_shed(true)
        .serve_with_shutdown(addr, svc, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("serve")?;

    Ok(())
}

async fn offline_dkg(cfg: ValidatedAdminConfig, cmd: DkgCommand) -> anyhow::Result<()> {
    let dkg = dkg_admin::dkg::AdminDkg::new(cfg.clone());

    match cmd {
        DkgCommand::Part1 { out } => {
            let pkg_path = dkg.state_dir().join("round1_package.bin");
            let secret_path = dkg.state_dir().join("round1_secret.bin");

            let (pkg_bytes, pkg_hash) = if secret_path.exists() && pkg_path.exists() {
                let bytes = dkg_admin::storage::read(&pkg_path)
                    .with_context(|| format!("read {}", pkg_path.display()))?;
                (bytes.clone(), dkg_admin::hash::sha256(&bytes))
            } else if !secret_path.exists() && !pkg_path.exists() {
                let out = dkg.part1(rand_core::OsRng).context("dkg part1")?;
                (out.round1_package_bytes, out.round1_package_hash)
            } else {
                return Err(anyhow!("round1_state_incomplete"));
            };

            dkg_admin::storage::write_file_0600_fsync(&out, &pkg_bytes)
                .with_context(|| format!("write {}", out.display()))?;
            println!(
                "round1_package_hash_hex={}",
                hex::encode(pkg_hash)
            );
            Ok(())
        }
        DkgCommand::Part2 { round1_dir, out_dir } => {
            ensure_part1_state(dkg.state_dir())?;
            let round1_map = read_round1_dir(&cfg, &round1_dir).context("read round1_dir")?;

            let out = dkg.part2(round1_map).context("dkg part2")?;

            dkg_admin::storage::ensure_dir(&out_dir).context("ensure out_dir")?;

            // Encrypt each Round 2 package to its recipient using age.
            for (receiver_id, pkg) in out.round2_packages {
                if receiver_id == cfg.cfg.identifier {
                    continue;
                }

                let recipient = age_recipient_for_identifier(&cfg, receiver_id)?;
                let mut recipients = vec![recipient];
                if let Some(coord) = cfg.cfg.roster.coordinator_age_recipient.clone() {
                    let coord = coord.trim().to_string();
                    if !coord.is_empty() && !recipients.iter().any(|r| r == &coord) {
                        recipients.push(coord);
                    }
                }
                let ct = dkg_admin::encrypt::age_encrypt(&recipients, &pkg.package_bytes)
                    .context("age encrypt round2")?;

                let out_path = out_dir.join(format!(
                    "round2_to_{receiver_id}_from_{}.age",
                    cfg.cfg.identifier
                ));
                dkg_admin::storage::write_file_0600_fsync(&out_path, &ct)
                    .with_context(|| format!("write {}", out_path.display()))?;
            }

            println!("round2_packages_written=true");
            Ok(())
        }
        DkgCommand::Part3 {
            round1_dir,
            round2_dir,
            age_identity_file,
        } => {
            let round2_secret_path = dkg.state_dir().join("round2_secret.bin");
            if !round2_secret_path.exists() {
                return Err(anyhow!("round2_state_missing"));
            }

            let round1_map = read_round1_dir(&cfg, &round1_dir).context("read round1_dir")?;
            let identity = read_age_identity(&cfg, age_identity_file.as_deref())
                .context("read age identity")?;
            let round2_map = read_round2_dir_to_me(&cfg, &round2_dir, &identity)
                .context("read round2_dir")?;

            let out = dkg.part3(round1_map, round2_map).context("dkg part3")?;

            println!(
                "public_key_package_hash_hex={}",
                hex::encode(out.public_key_package_hash)
            );
            println!("ak_bytes_hex={}", hex::encode(out.ak_bytes));
            Ok(())
        }
    }
}

async fn export_key_package(cfg: ValidatedAdminConfig, args: ExportKeyPackageArgs) -> anyhow::Result<()> {
    let exporter = Exporter::new(cfg.clone());

    let receipt = if let Some(out_path) = args.out.as_deref() {
        if !args.age_recipient.is_empty() {
            exporter
                .export_to_file_age(&args.age_recipient, out_path)
                .await
                .context("export_to_file_age")?
        } else {
            let kms_key_id = args.kms_key_id.as_deref().ok_or_else(|| anyhow!("kms_key_id missing"))?;
            let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let kms_client = aws_sdk_kms::Client::new(&aws_cfg);
            let kms_provider = dkg_admin::encrypt::AwsKmsProvider::new(kms_client);
            exporter
                .export_to_file_kms(&kms_provider, kms_key_id, out_path, &mut rand_core::OsRng)
                .await
                .context("export_to_file_kms")?
        }
    } else {
        let bucket = args.s3_bucket.as_deref().ok_or_else(|| anyhow!("s3_bucket missing"))?;
        let key = args.s3_key.as_deref().ok_or_else(|| anyhow!("s3_key missing"))?;
        let sse_kms_key_id = args
            .s3_sse_kms_key_id
            .as_deref()
            .ok_or_else(|| anyhow!("s3_sse_kms_key_id missing"))?;

        let artifacts = if !args.age_recipient.is_empty() {
            exporter
                .build_artifacts_age(
                    &args.age_recipient,
                    ReceiptStorageV1::S3 {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                    },
                )
                .await
                .context("build_artifacts_age")?
        } else {
            let kms_key_id = args.kms_key_id.as_deref().ok_or_else(|| anyhow!("kms_key_id missing"))?;
            let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let kms_client = aws_sdk_kms::Client::new(&aws_cfg);
            let kms_provider = dkg_admin::encrypt::AwsKmsProvider::new(kms_client);
            exporter
                .build_artifacts_kms(
                    &kms_provider,
                    kms_key_id,
                    ReceiptStorageV1::S3 {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                    },
                    &mut rand_core::OsRng,
                )
                .await
                .context("build_artifacts_kms")?
        };

        let receipt = artifacts.receipt_bytes.clone();
        exporter
            .export_to_s3(artifacts, bucket, key, sse_kms_key_id)
            .await
            .context("export_to_s3")?;
        receipt
    };

    println!("{}", String::from_utf8_lossy(&receipt));
    Ok(())
}

async fn destroy(cfg: ValidatedAdminConfig) -> anyhow::Result<()> {
    if cfg.cfg.state_dir.exists() {
        tokio::fs::remove_dir_all(&cfg.cfg.state_dir)
            .await
            .with_context(|| format!("remove {}", cfg.cfg.state_dir.display()))?;
    }
    Ok(())
}

fn read_round1_dir(
    cfg: &ValidatedAdminConfig,
    round1_dir: &Path,
) -> anyhow::Result<BTreeMap<u16, Vec<u8>>> {
    let mut map = BTreeMap::<u16, Vec<u8>>::new();

    for entry in std::fs::read_dir(round1_dir).with_context(|| format!("read_dir {}", round1_dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("round1_") || !name.ends_with(".bin") {
            continue;
        }

        let id_str = name.trim_start_matches("round1_").trim_end_matches(".bin");
        let id: u16 = id_str.parse().context("parse round1 id")?;
        if id == 0 || id > cfg.cfg.max_signers {
            return Err(anyhow!("round1_sender_identifier_out_of_range: {id}"));
        }
        if id == cfg.cfg.identifier {
            continue;
        }

        let bytes = std::fs::read(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        map.insert(id, bytes);
    }

    if map.len() != (cfg.cfg.max_signers - 1) as usize {
        return Err(anyhow!(
            "round1_dir_incomplete: expected={} got={}",
            cfg.cfg.max_signers - 1,
            map.len()
        ));
    }

    Ok(map)
}

fn ensure_part1_state(state_dir: &Path) -> anyhow::Result<()> {
    let secret_path = state_dir.join("round1_secret.bin");
    let pkg_path = state_dir.join("round1_package.bin");
    if !secret_path.exists() || !pkg_path.exists() {
        return Err(anyhow!("round1_state_missing"));
    }
    Ok(())
}

fn age_recipient_for_identifier(cfg: &ValidatedAdminConfig, receiver_id: u16) -> anyhow::Result<String> {
    let op_id = cfg
        .canonical_operators
        .iter()
        .find(|o| o.identifier.0 == receiver_id)
        .map(|o| o.operator_id.clone())
        .ok_or_else(|| anyhow!("operator_for_identifier_missing: {receiver_id}"))?;

    let recip = cfg
        .cfg
        .roster
        .operators
        .iter()
        .find(|o| o.operator_id.trim() == op_id)
        .and_then(|o| o.age_recipient.clone())
        .ok_or_else(|| anyhow!("age_recipient_missing_for_identifier: {receiver_id}"))?;

    Ok(recip.trim().to_string())
}

fn read_age_identity(cfg: &ValidatedAdminConfig, override_path: Option<&Path>) -> anyhow::Result<String> {
    let path = if let Some(p) = override_path {
        p.to_path_buf()
    } else if let Some(p) = &cfg.cfg.age_identity_file {
        p.clone()
    } else {
        return Err(anyhow!("age_identity_file_missing"));
    };

    let s = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(s.trim().to_string())
}

fn read_round2_dir_to_me(
    cfg: &ValidatedAdminConfig,
    round2_dir: &Path,
    age_identity: &str,
) -> anyhow::Result<BTreeMap<u16, Vec<u8>>> {
    let mut map = BTreeMap::<u16, Vec<u8>>::new();

    for entry in std::fs::read_dir(round2_dir).with_context(|| format!("read_dir {}", round2_dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("round2_to_") || !name.ends_with(".age") {
            continue;
        }

        // round2_to_<recv>_from_<sender>.age
        let name = name.trim_end_matches(".age");
        let Some(rest) = name.strip_prefix("round2_to_") else {
            continue;
        };
        let parts: Vec<&str> = rest.split("_from_").collect();
        if parts.len() != 2 {
            continue;
        }
        let recv: u16 = parts[0].parse().context("parse round2 recv")?;
        let sender: u16 = parts[1].parse().context("parse round2 sender")?;

        if recv != cfg.cfg.identifier {
            continue;
        }
        if sender == 0 || sender > cfg.cfg.max_signers || sender == cfg.cfg.identifier {
            return Err(anyhow!("round2_sender_identifier_invalid: {sender}"));
        }

        let ct = std::fs::read(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        let pt = dkg_admin::encrypt::age_decrypt(age_identity, &ct)
            .context("age decrypt round2")?;
        map.insert(sender, pt);
    }

    if map.len() != (cfg.cfg.max_signers - 1) as usize {
        return Err(anyhow!(
            "round2_dir_incomplete: expected={} got={}",
            cfg.cfg.max_signers - 1,
            map.len()
        ));
    }

    Ok(map)
}
