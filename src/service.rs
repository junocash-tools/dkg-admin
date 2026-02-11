use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Request, Response, Status};

use crate::config::{GrpcConfigV1, ValidatedAdminConfig};
use crate::crypto;
use crate::dkg::AdminDkg;
use crate::dkg::DkgError;
use crate::envelope::ReceiptStorageV1;
use crate::export::Exporter;
use crate::proto::v1 as pb;
use crate::storage;

pub struct AdminService {
    cfg: Arc<ValidatedAdminConfig>,
    lock: Mutex<()>,
    rate: Mutex<RateState>,
}

#[derive(Debug)]
struct RateState {
    window_start: Instant,
    count: u32,
}

const RATE_LIMIT_PER_SEC: u32 = 64;
const BIN_VERSION: &str = env!("CARGO_PKG_VERSION");
const BIN_COMMIT: &str = env!("DKG_ADMIN_GIT_COMMIT");

impl AdminService {
    pub fn new(cfg: ValidatedAdminConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            lock: Mutex::new(()),
            rate: Mutex::new(RateState {
                window_start: Instant::now(),
                count: 0,
            }),
        }
    }

    fn grpc_cfg(&self) -> Result<&GrpcConfigV1, Status> {
        self.cfg
            .cfg
            .grpc
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("grpc_config_missing"))
    }

    fn validate_ceremony_hash(&self, got: &str) -> Result<(), Status> {
        if got != self.cfg.ceremony_hash_hex {
            return Err(Status::permission_denied("ceremony_hash_mismatch"));
        }
        Ok(())
    }

    fn validate_peer(&self, req: &Request<impl std::fmt::Debug>) -> Result<(), Status> {
        let grpc_cfg = self.grpc_cfg()?;

        let tls = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .ok_or_else(|| Status::unauthenticated("tls_connect_info_missing"))?;

        let certs = tls
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("mtls_peer_cert_missing"))?;
        let first = certs
            .first()
            .ok_or_else(|| Status::unauthenticated("mtls_peer_cert_missing"))?;

        if let Some(expected_hex) = &grpc_cfg.coordinator_client_cert_sha256 {
            let mut hasher = Sha256::new();
            hasher.update(first.as_ref());
            let got_hex = hex::encode(hasher.finalize());
            if got_hex != expected_hex.trim().to_lowercase() {
                return Err(Status::permission_denied("client_cert_fingerprint_mismatch"));
            }
        }

        Ok(())
    }

    async fn check_rate_limit(&self) -> Result<(), Status> {
        let mut st = self.rate.lock().await;
        let now = Instant::now();
        if now.duration_since(st.window_start) >= Duration::from_secs(1) {
            st.window_start = now;
            st.count = 0;
        }
        if st.count >= RATE_LIMIT_PER_SEC {
            return Err(Status::resource_exhausted("rate_limited"));
        }
        st.count += 1;
        Ok(())
    }

    fn validate_round1_packages(
        &self,
        pkgs: &[pb::Round1Package],
    ) -> Result<BTreeMap<u16, Vec<u8>>, Status> {
        let expected_n = (self.cfg.cfg.max_signers - 1) as usize;
        if pkgs.len() != expected_n {
            return Err(Status::invalid_argument("round1_packages_len_invalid"));
        }

        let mut seen = BTreeSet::<u16>::new();
        let mut out = BTreeMap::<u16, Vec<u8>>::new();
        for p in pkgs {
            let sender_u16 = u16::try_from(p.sender_identifier)
                .map_err(|_| Status::invalid_argument("sender_identifier_invalid"))?;
            if sender_u16 == 0 || sender_u16 > self.cfg.cfg.max_signers {
                return Err(Status::invalid_argument("sender_identifier_out_of_range"));
            }
            if sender_u16 == self.cfg.cfg.identifier {
                return Err(Status::invalid_argument("round1_sender_is_self"));
            }
            if !seen.insert(sender_u16) {
                return Err(Status::invalid_argument("sender_identifier_duplicate"));
            }

            if p.package_hash.len() != 32 {
                return Err(Status::invalid_argument("round1_package_hash_len_invalid"));
            }
            let got_hash = crate::hash::sha256(&p.package);
            if got_hash.as_slice() != p.package_hash.as_slice() {
                return Err(Status::invalid_argument("round1_package_hash_mismatch"));
            }

            out.insert(sender_u16, p.package.clone());
        }

        for id in 1..=self.cfg.cfg.max_signers {
            if id == self.cfg.cfg.identifier {
                continue;
            }
            if !out.contains_key(&id) {
                return Err(Status::invalid_argument("round1_package_missing_sender"));
            }
        }

        Ok(out)
    }

    fn validate_round2_packages_to_me(
        &self,
        pkgs: &[pb::Round2PackageToMe],
    ) -> Result<BTreeMap<u16, Vec<u8>>, Status> {
        let expected_n = (self.cfg.cfg.max_signers - 1) as usize;
        if pkgs.len() != expected_n {
            return Err(Status::invalid_argument("round2_packages_len_invalid"));
        }

        let mut seen = BTreeSet::<u16>::new();
        let mut out = BTreeMap::<u16, Vec<u8>>::new();
        for p in pkgs {
            let sender_u16 = u16::try_from(p.sender_identifier)
                .map_err(|_| Status::invalid_argument("sender_identifier_invalid"))?;
            if sender_u16 == 0 || sender_u16 > self.cfg.cfg.max_signers {
                return Err(Status::invalid_argument("sender_identifier_out_of_range"));
            }
            if sender_u16 == self.cfg.cfg.identifier {
                return Err(Status::invalid_argument("round2_sender_is_self"));
            }
            if !seen.insert(sender_u16) {
                return Err(Status::invalid_argument("sender_identifier_duplicate"));
            }

            if p.package_hash.len() != 32 {
                return Err(Status::invalid_argument("round2_package_hash_len_invalid"));
            }
            let got_hash = crate::hash::sha256(&p.package);
            if got_hash.as_slice() != p.package_hash.as_slice() {
                return Err(Status::invalid_argument("round2_package_hash_mismatch"));
            }

            out.insert(sender_u16, p.package.clone());
        }

        for id in 1..=self.cfg.cfg.max_signers {
            if id == self.cfg.cfg.identifier {
                continue;
            }
            if !out.contains_key(&id) {
                return Err(Status::invalid_argument("round2_package_missing_sender"));
            }
        }

        Ok(out)
    }

    async fn load_key_package(&self) -> Result<reddsa::frost::redpallas::keys::KeyPackage, Status> {
        let kp_path = self.cfg.cfg.state_dir.join("key_package.bin");
        let kp_bytes = storage::read(&kp_path).map_err(|_| Status::failed_precondition("key_package_missing"))?;
        reddsa::frost::redpallas::keys::KeyPackage::deserialize(&kp_bytes)
            .map_err(|_| Status::internal("key_package_deserialize_failed"))
    }

    fn map_part2_error(err: DkgError) -> Status {
        match err {
            DkgError::Part2InputMismatch => Status::failed_precondition("part2_input_mismatch"),
            _ => Status::internal("dkg_part2_failed"),
        }
    }

    fn map_part3_error(err: DkgError) -> Status {
        match err {
            DkgError::Part3InputMismatch => Status::failed_precondition("part3_input_mismatch"),
            _ => Status::internal("dkg_part3_failed"),
        }
    }
}

#[tonic::async_trait]
impl pb::dkg_admin_server::DkgAdmin for AdminService {
    async fn get_status(
        &self,
        request: Request<pb::GetStatusRequest>,
    ) -> Result<Response<pb::GetStatusResponse>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;
        let dkg = AdminDkg::new((*self.cfg).clone());

        let round1_pkg_path = dkg.state_dir().join("round1_package.bin");
        let round2_secret_path = dkg.state_dir().join("round2_secret.bin");
        let key_pkg_path = dkg.state_dir().join("key_package.bin");
        let public_pkg_path = dkg.state_dir().join("public_key_package.bin");

        let round1_package_hash = if round1_pkg_path.exists() {
            let pkg = storage::read(&round1_pkg_path)
                .map_err(|_| Status::internal("round1_package_read_failed"))?;
            crate::hash::sha256(&pkg).to_vec()
        } else {
            vec![]
        };

        let part2_input_hash = if let Some(binding) = dkg
            .read_part2_binding()
            .map_err(|_| Status::internal("part2_binding_read_failed"))?
        {
            let bytes = hex::decode(binding.input_hash_hex.trim())
                .map_err(|_| Status::internal("part2_binding_parse_failed"))?;
            if bytes.len() != 32 {
                return Err(Status::internal("part2_binding_hash_len_invalid"));
            }
            bytes
        } else {
            vec![]
        };

        let part3_input_hash = if let Some(binding) = dkg
            .read_part3_binding()
            .map_err(|_| Status::internal("part3_binding_read_failed"))?
        {
            let bytes = hex::decode(binding.input_hash_hex.trim())
                .map_err(|_| Status::internal("part3_binding_parse_failed"))?;
            if bytes.len() != 32 {
                return Err(Status::internal("part3_binding_hash_len_invalid"));
            }
            bytes
        } else {
            vec![]
        };

        let phase = if !part3_input_hash.is_empty() || (key_pkg_path.exists() && public_pkg_path.exists()) {
            pb::CeremonyPhase::Part3 as i32
        } else if !part2_input_hash.is_empty() || round2_secret_path.exists() {
            pb::CeremonyPhase::Round2 as i32
        } else if !round1_package_hash.is_empty() {
            pb::CeremonyPhase::Round1 as i32
        } else {
            pb::CeremonyPhase::Empty as i32
        };

        Ok(Response::new(pb::GetStatusResponse {
            operator_id: self.cfg.cfg.operator_id.clone(),
            identifier: self.cfg.cfg.identifier as u32,
            ceremony_hash: self.cfg.ceremony_hash_hex.clone(),
            phase,
            round1_package_hash,
            part2_input_hash,
            part3_input_hash,
            binary_version: BIN_VERSION.to_string(),
            binary_commit: BIN_COMMIT.to_string(),
        }))
    }

    async fn get_round1_package(
        &self,
        request: Request<pb::GetRound1PackageRequest>,
    ) -> Result<Response<pb::GetRound1PackageResponse>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;
        let dkg = AdminDkg::new((*self.cfg).clone());

        let secret_path = dkg.state_dir().join("round1_secret.bin");
        let pkg_path = dkg.state_dir().join("round1_package.bin");

        let (pkg_bytes, pkg_hash) = if secret_path.exists() && pkg_path.exists() {
            let bytes = storage::read(&pkg_path).map_err(|_| Status::internal("round1_package_read_failed"))?;
            (bytes.clone(), crate::hash::sha256(&bytes).to_vec())
        } else if !secret_path.exists() && !pkg_path.exists() {
            let out = dkg
                .part1(rand_core::OsRng)
                .map_err(|_| Status::internal("dkg_part1_failed"))?;
            (out.round1_package_bytes, out.round1_package_hash.to_vec())
        } else {
            return Err(Status::internal("round1_state_incomplete"));
        };

        Ok(Response::new(pb::GetRound1PackageResponse {
            round1_package: pkg_bytes,
            round1_package_hash: pkg_hash,
        }))
    }

    async fn part2(
        &self,
        request: Request<pb::Part2Request>,
    ) -> Result<Response<pb::Part2Response>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;
        let dkg = AdminDkg::new((*self.cfg).clone());

        let round1_map = self.validate_round1_packages(&request.get_ref().round1_packages)?;

        // Ensure we have local part1 state.
        let secret_path = dkg.state_dir().join("round1_secret.bin");
        let pkg_path = dkg.state_dir().join("round1_package.bin");
        if !secret_path.exists() || !pkg_path.exists() {
            return Err(Status::failed_precondition("round1_state_missing"));
        }

        let out = dkg
            .part2(round1_map)
            .map_err(Self::map_part2_error)?;

        let mut pkgs = Vec::with_capacity(out.round2_packages.len());
        for (receiver_u16, pkg) in out.round2_packages {
            if receiver_u16 == self.cfg.cfg.identifier {
                continue;
            }
            pkgs.push(pb::Round2PackageOut {
                receiver_identifier: receiver_u16 as u32,
                package: pkg.package_bytes,
                package_hash: pkg.package_hash.to_vec(),
            });
        }

        Ok(Response::new(pb::Part2Response { round2_packages: pkgs }))
    }

    async fn part3(
        &self,
        request: Request<pb::Part3Request>,
    ) -> Result<Response<pb::Part3Response>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;
        let dkg = AdminDkg::new((*self.cfg).clone());

        let round1_map = self.validate_round1_packages(&request.get_ref().round1_packages)?;
        let round2_map = self.validate_round2_packages_to_me(&request.get_ref().round2_packages)?;

        let secret_path = dkg.state_dir().join("round2_secret.bin");
        if !secret_path.exists() {
            return Err(Status::failed_precondition("round2_state_missing"));
        }

        let out = dkg
            .part3(round1_map, round2_map)
            .map_err(Self::map_part3_error)?;

        // Enforce Orchard-compatible canonical sign bit (EvenY).
        if !crypto::is_canonical_ak_bytes(&out.ak_bytes) {
            return Err(Status::internal("ak_bytes_non_canonical"));
        }

        Ok(Response::new(pb::Part3Response {
            public_key_package: out.public_key_package_bytes,
            public_key_package_hash: out.public_key_package_hash.to_vec(),
            ak_bytes: out.ak_bytes.to_vec(),
            canonicalized: true,
        }))
    }

    async fn smoke_sign_commit(
        &self,
        request: Request<pb::SmokeSignCommitRequest>,
    ) -> Result<Response<pb::SmokeSignCommitResponse>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;

        let key_package = self.load_key_package().await?;

        let alpha = request.get_ref().alpha.clone();
        if !alpha.is_empty() && alpha.len() != 32 {
            return Err(Status::invalid_argument("alpha_len_invalid"));
        }

        let commitments = crate::smoke::smoke_commit(
            &self.cfg.cfg.state_dir,
            &key_package,
            &request.get_ref().message,
            &alpha,
            &mut rand_core::OsRng,
        )
        .map_err(|_| Status::internal("smoke_commit_failed"))?;

        Ok(Response::new(pb::SmokeSignCommitResponse {
            signing_commitments: commitments,
        }))
    }

    async fn smoke_sign_share(
        &self,
        request: Request<pb::SmokeSignShareRequest>,
    ) -> Result<Response<pb::SmokeSignShareResponse>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;

        let key_package = self.load_key_package().await?;

        let alpha = request.get_ref().alpha.clone();
        if !alpha.is_empty() && alpha.len() != 32 {
            return Err(Status::invalid_argument("alpha_len_invalid"));
        }

        let sig_share = crate::smoke::smoke_sign_share(
            &self.cfg.cfg.state_dir,
            &key_package,
            &request.get_ref().signing_package,
            &alpha,
        )
        .map_err(|_| Status::internal("smoke_sign_share_failed"))?;

        Ok(Response::new(pb::SmokeSignShareResponse {
            signature_share: sig_share,
        }))
    }

    async fn export_encrypted_key_package(
        &self,
        request: Request<pb::ExportEncryptedKeyPackageRequest>,
    ) -> Result<Response<pb::ExportEncryptedKeyPackageResponse>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;

        // Ensure key material exists.
        let kp_path = self.cfg.cfg.state_dir.join("key_package.bin");
        if !kp_path.exists() {
            return Err(Status::failed_precondition("key_package_missing"));
        }

        let exporter = Exporter::new((*self.cfg).clone());

        let encryption = request
            .get_ref()
            .encryption
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("encryption_missing"))?;
        let target = request
            .get_ref()
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("target_missing"))?;

        let receipt = match (encryption.backend.as_ref(), target.target.as_ref()) {
            (Some(pb::encryption_config::Backend::Age(age)), Some(pb::export_target::Target::File(f))) => {
                let out_path = std::path::Path::new(&f.path);
                exporter
                    .export_to_file_age(&age.recipients, out_path)
                    .await
                    .map_err(|_| Status::internal("export_failed"))?
            }
            (Some(pb::encryption_config::Backend::Age(age)), Some(pb::export_target::Target::S3(s3))) => {
                let artifacts = exporter
                    .build_artifacts_age(
                        &age.recipients,
                        ReceiptStorageV1::S3 {
                            bucket: s3.bucket.clone(),
                            key: s3.key.clone(),
                        },
                    )
                    .await
                    .map_err(|_| Status::internal("export_failed"))?;
                let receipt = artifacts.receipt_bytes.clone();
                exporter
                    .export_to_s3(artifacts, &s3.bucket, &s3.key, &s3.sse_kms_key_id)
                    .await
                    .map_err(|_| Status::internal("s3_put_failed"))?;
                receipt
            }
            (Some(pb::encryption_config::Backend::AwsKms(kms)), Some(pb::export_target::Target::File(f))) => {
                let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
                    .await;
                let kms_client = aws_sdk_kms::Client::new(&aws_cfg);
                let kms_provider = crate::encrypt::AwsKmsProvider::new(kms_client);
                let out_path = std::path::Path::new(&f.path);
                exporter
                    .export_to_file_kms(&kms_provider, &kms.kms_key_id, out_path, &mut rand_core::OsRng)
                    .await
                    .map_err(|_| Status::internal("export_failed"))?
            }
            (Some(pb::encryption_config::Backend::AwsKms(kms)), Some(pb::export_target::Target::S3(s3))) => {
                let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
                    .await;
                let kms_client = aws_sdk_kms::Client::new(&aws_cfg);
                let kms_provider = crate::encrypt::AwsKmsProvider::new(kms_client);

                let artifacts = exporter
                    .build_artifacts_kms(
                        &kms_provider,
                        &kms.kms_key_id,
                        ReceiptStorageV1::S3 {
                            bucket: s3.bucket.clone(),
                            key: s3.key.clone(),
                        },
                        &mut rand_core::OsRng,
                    )
                    .await
                    .map_err(|_| Status::internal("export_failed"))?;
                let receipt = artifacts.receipt_bytes.clone();
                exporter
                    .export_to_s3(artifacts, &s3.bucket, &s3.key, &s3.sse_kms_key_id)
                    .await
                    .map_err(|_| Status::internal("s3_put_failed"))?;
                receipt
            }
            _ => return Err(Status::invalid_argument("invalid_export_request")),
        };

        Ok(Response::new(pb::ExportEncryptedKeyPackageResponse {
            receipt_json: receipt,
        }))
    }

    async fn destroy(
        &self,
        request: Request<pb::DestroyRequest>,
    ) -> Result<Response<pb::DestroyResponse>, Status> {
        self.validate_peer(&request)?;
        self.validate_ceremony_hash(&request.get_ref().ceremony_hash)?;
        self.check_rate_limit().await?;

        let _g = self.lock.lock().await;

        // Best-effort cleanup of all state.
        if self.cfg.cfg.state_dir.exists() {
            std::fs::remove_dir_all(&self.cfg.cfg.state_dir)
                .map_err(|_| Status::internal("state_dir_remove_failed"))?;
        }

        Ok(Response::new(pb::DestroyResponse {}))
    }
}
